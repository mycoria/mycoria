package m

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"go4.org/netipx"
)

// RoutingTable is a routing table.
type RoutingTable struct {
	lock sync.RWMutex

	cfg     RoutingTableConfig
	entries []*RoutingTableEntry
}

// RoutingTableConfig holds the configuration for a routing table.
type RoutingTableConfig struct {
	// RoutablePrefixes defines for which prefixes routes should be held and in
	// what detail. This only applies to entries sourced from gossip.
	RoutablePrefixes []RoutablePrefix

	// RouterIP is ip address of router of the routing table.
	RouterIP netip.Addr
}

// RoutablePrefix configures how routing entries of a defined base prefix should be handled.
type RoutablePrefix struct {
	// BasePrefix is the prefix for which these settings should apply.
	BasePrefix netip.Prefix

	// RoutingBits is the length of the bitmask with which to create the routing
	// prefix for the table entry.
	RoutingBits int

	// EntryTTL is the entry TTL for entries in this prefix.
	EntryTTL time.Duration

	// EntriesPerPrefix defines how many routing entries to keep per
	// identical routing prefix.
	EntriesPerPrefix int
}

// RoutingTableEntry represents an entry in the routing table.
// All fields must be treated as constants.
type RoutingTableEntry struct {
	DstIP         netip.Addr
	RoutingPrefix netip.Prefix

	NextHop netip.Addr
	Path    SwitchPath

	Source  RouteSource
	Expires time.Time
}

// RouteSource is the source of a route.
type RouteSource uint8

// Route Sources.
const (
	// Source not known or not defined.
	RouteSourceUnknown RouteSource = iota

	// Directly connected.
	// Entries are never auto-cleared.
	RouteSourcePeer

	// Route to other network that was learned through gossip.
	// Entries are automatically removed after expiry or when abundant.
	RouteSourceGossip

	// Discovered by active probing (for own use).
	// Entries are automatically removed after expiry.
	RouteSourceDiscovered
)

// NewRoutingTable returns a new routing table with the given config.
func NewRoutingTable(cfg RoutingTableConfig) *RoutingTable {
	// Create new table with initial sizes.
	rt := &RoutingTable{
		cfg:     cfg,
		entries: make([]*RoutingTableEntry, 0, 128),
	}

	// Apply defaults.
	if len(rt.cfg.RoutablePrefixes) == 0 {
		rt.cfg.RoutablePrefixes = []RoutablePrefix{{
			BasePrefix:  BaseNetPrefix,
			RoutingBits: ContinentPrefixBits,
		}}
	}

	return rt
}

// AddRoute adds the given route to the routing table.
func (rt *RoutingTable) AddRoute(entry RoutingTableEntry) (added bool, err error) {
	// Get routable prefix.
	rp, ok := rt.getRoutablePrefixConfig(entry.DstIP)
	if !ok {
		return false, errors.New("destination address is not routable by this table")
	}

	// Apply defaults from routable prefix.
	if rp.EntryTTL > 0 && entry.Source != RouteSourcePeer {
		ttlExpiry := time.Now().Add(rp.EntryTTL)
		if entry.Expires.IsZero() || ttlExpiry.Before(entry.Expires) {
			entry.Expires = ttlExpiry
		}
	}
	if rp.RoutingBits > 0 {
		entry.RoutingPrefix, _ = entry.DstIP.Prefix(rp.RoutingBits)
	}

	// Check if the source is valid.
	switch entry.Source {
	case RouteSourceGossip:
	case RouteSourcePeer:
	case RouteSourceDiscovered:
	case RouteSourceUnknown:
		fallthrough
	default:
		return false, fmt.Errorf("unknown routing source %d", entry.Source)
	}

	// Check if entry has all required fields.
	switch {
	case !entry.DstIP.IsValid():
		return false, errors.New("dst ip is invalid/missing")
	case !entry.NextHop.IsValid():
		return false, errors.New("next hop is invalid/missing")
	case !entry.RoutingPrefix.IsValid():
		return false, errors.New("routing prefix is invalid/missing")
	case entry.Source != RouteSourcePeer && len(entry.Path.Hops) < 2:
		return false, errors.New("missing or incomplete switch path")
	}

	// Check expiry. Be graceful with routers that have time lag.
	if entry.Source != RouteSourcePeer {
		switch {
		case entry.Expires.IsZero():
			return false, errors.New("missing expiration")
		case time.Since(entry.Expires) > time.Hour:
			return false, errors.New("already expired")
		case time.Until(entry.Expires) < 10*time.Minute:
			// Raise expire to at least 10 minutes.
			entry.Expires = time.Now().Add(10 * time.Minute)
		}
	}

	// Finish processing the switch path.
	err = entry.Path.BuildBlocks()
	if err != nil {
		return false, fmt.Errorf("failed to build switch blocks: %w", err)
	}
	entry.Path.CalculateTotals()

	// Lock table for inserting new route.
	rt.lock.Lock()
	defer rt.lock.Unlock()

	// Always add peers.
	if entry.Source == RouteSourcePeer {
		// Get insert index.
		insertIndex, _ := slices.BinarySearchFunc[[]*RoutingTableEntry, *RoutingTableEntry, *RoutingTableEntry](
			rt.entries,
			&entry,
			rt.stdSort,
		)
		// Insert
		rt.entries = slices.Insert[[]*RoutingTableEntry, *RoutingTableEntry](
			rt.entries, insertIndex, &entry,
		)
		return true, nil
	}

	// Get destination section.
	start, end := rt.getDstSection(entry.DstIP)
	if start >= end {
		// We don't have this destination yet.
		// Add it as a new destination.
		return rt.addNewDestination(entry, rp)
	}

	// Check if we have this exact route already.
	for i := start; i < end; i++ {
		if rt.entries[i].RouteEquals(&entry) {
			// Replace entry.
			rt.entries[i] = &entry
			// Sort section.
			slices.SortFunc[[]*RoutingTableEntry, *RoutingTableEntry](
				rt.entries[start:end],
				rt.stdSort,
			)
			// Return as added.
			return true, nil
		}
	}

	// We have a new route for a known destination.

	// If we don't have 3 routes to this destination yet, add it.
	if end-start < 3 {
		// Get insert index.
		insertIndex, _ := slices.BinarySearchFunc[[]*RoutingTableEntry, *RoutingTableEntry, *RoutingTableEntry](
			rt.entries,
			&entry,
			rt.stdSort,
		)
		// Insert
		rt.entries = slices.Insert[[]*RoutingTableEntry, *RoutingTableEntry](
			rt.entries, insertIndex, &entry,
		)
		return true, nil
	}

	// Check if the entry is good enough to make it into the top 3.
	if rt.stdSort(&entry, rt.entries[start+2]) < 0 {
		// Replace third entry.
		rt.entries[start+2] = &entry
		// Sort section.
		slices.SortFunc[[]*RoutingTableEntry, *RoutingTableEntry](
			rt.entries[start:end],
			rt.stdSort,
		)
		// Return as added.
		return true, nil
	}

	// Entry does not meet any criteria for addding.
	return false, nil
}

func (rt *RoutingTable) addNewDestination(entry RoutingTableEntry, rp RoutablePrefix) (added bool, err error) { //nolint:unparam // Makes usage easier.
	// Gossip routes are limited per prefix, check the limit.
	if entry.Source == RouteSourceGossip {
		// Get prefix section.
		start, end := rt.getPrefixSection(entry.RoutingPrefix)
		if end-start > rp.EntriesPerPrefix*2 {
			// We already have 2 times the entries we want for this prefix.
			return false, nil
		}
	}

	// If permitted to add route, go ahead.

	// Get insert index.
	insertIndex, _ := slices.BinarySearchFunc[[]*RoutingTableEntry, *RoutingTableEntry, *RoutingTableEntry](
		rt.entries,
		&entry,
		rt.stdSort,
	)
	// Insert
	rt.entries = slices.Insert[[]*RoutingTableEntry, *RoutingTableEntry](
		rt.entries, insertIndex, &entry,
	)
	return true, nil
}

func (rt *RoutingTable) getDstSection(dst netip.Addr) (startIndex, endIndex int) {
	// Find start index.
	startIndex, _ = slices.BinarySearchFunc[[]*RoutingTableEntry, *RoutingTableEntry, *RoutingTableEntry](
		rt.entries,
		&RoutingTableEntry{
			DstIP: dst,
			Path: SwitchPath{
				TotalDelay: 0, // Lower than possible normal values.
				TotalHops:  0, // Lower than possible normal values.
			},
		},
		rt.stdSort,
	)

	// Find end index.
	endIndex, _ = slices.BinarySearchFunc[[]*RoutingTableEntry, *RoutingTableEntry, *RoutingTableEntry](
		rt.entries,
		&RoutingTableEntry{
			DstIP: dst,
			Path: SwitchPath{
				TotalDelay: 65535, // Higher than possible normal values.
				TotalHops:  255,   // Higher than possible normal values.
			},
		},
		rt.stdSort,
	)

	return
}

func (rt *RoutingTable) getPrefixSection(prefix netip.Prefix) (startIndex, endIndex int) {
	// Find start index.
	startIndex, _ = slices.BinarySearchFunc[[]*RoutingTableEntry, *RoutingTableEntry, *RoutingTableEntry](
		rt.entries,
		&RoutingTableEntry{
			DstIP: prefix.Masked().Addr(),
			Path: SwitchPath{
				TotalDelay: 0, // Lower than possible normal values.
				TotalHops:  0, // Lower than possible normal values.
			},
		},
		rt.stdSort,
	)

	// Find end index.
	endIndex, _ = slices.BinarySearchFunc[[]*RoutingTableEntry, *RoutingTableEntry, *RoutingTableEntry](
		rt.entries,
		&RoutingTableEntry{
			DstIP: netipx.PrefixLastIP(prefix),
			Path: SwitchPath{
				TotalDelay: 65535, // Higher than possible normal values.
				TotalHops:  255,   // Higher than possible normal values.
			},
		},
		rt.stdSort,
	)

	return
}

// LookupNearest returns the best matching table entry for the given destination.
func (rt *RoutingTable) LookupNearest(dst netip.Addr) (rte *RoutingTableEntry, isDestination bool) {
	rt.lock.RLock()
	defer rt.lock.RUnlock()

	index, dstMatched := rt.findIndex(dst)
	if index < 0 {
		return nil, false
	}
	rte = rt.entries[index]
	return rte, dstMatched
}

// LookupPossiblePaths looks the best possible entires for the given destination.
func (rt *RoutingTable) LookupPossiblePaths(dst netip.Addr, maxMatches int, maxDistance AddrDistance, distinctNextHop bool, avoid []netip.Addr) []*RoutingTableEntry {
	rt.lock.RLock()
	defer rt.lock.RUnlock()

	// Get index of best matching entry.
	index, _ := rt.findIndex(dst)
	if index < 0 {
		return nil
	}

	var (
		possibleNextHops = make([]*RoutingTableEntry, 0, maxMatches)
		done             bool

		nextNextIndex = index + 1
		nextEntry     *RoutingTableEntry
		nextDistance  AddrDistance

		prevNextIndex = index - 1
		prevEntry     *RoutingTableEntry
		prevDistance  AddrDistance
	)
	// Add matched entry.
	possibleNextHops, done = addToPossiblePaths(possibleNextHops, rt.entries[index], maxMatches, distinctNextHop, avoid)
	if done {
		return possibleNextHops
	}
	// Search for more entries.
	for {
		// Get Distances.
		if nextEntry == nil && nextNextIndex < len(rt.entries) {
			nextEntry = rt.entries[nextNextIndex]
			nextDistance = IPDistance(nextEntry.DstIP, dst)

			if maxDistance.IsZero() || nextDistance.Less(maxDistance) {
				nextNextIndex++
			} else {
				// Reached max on next, stop processing next entries.
				nextNextIndex = len(rt.entries)
				nextEntry = nil
				nextDistance = AddrDistance{}
			}
		}
		if prevEntry == nil && prevNextIndex >= 0 {
			prevEntry = rt.entries[prevNextIndex]
			prevDistance = IPDistance(prevEntry.DstIP, dst)

			if maxDistance.IsZero() || prevDistance.Less(maxDistance) {
				prevNextIndex--
			} else {
				// Reached max on previous, stop processing previous entries.
				prevNextIndex = len(rt.entries)
				prevEntry = nil
				prevDistance = AddrDistance{}
			}
		}

		// Check what we have and add best entry to list.
		switch {
		case prevEntry == nil && nextEntry == nil:
			// No new data, return what we have.
			return possibleNextHops

		case nextEntry == nil:
			// Next reached limit, add prev.
			possibleNextHops, done = addToPossiblePaths(possibleNextHops, prevEntry, maxMatches, distinctNextHop, avoid)
			prevEntry = nil
			prevDistance = AddrDistance{}

		case prevEntry == nil:
			// Prev reached limit, add next.
			possibleNextHops, done = addToPossiblePaths(possibleNextHops, nextEntry, maxMatches, distinctNextHop, avoid)
			nextEntry = nil
			nextDistance = AddrDistance{}

		default:
			// Add better entry, use prev in a draw.
			if prevDistance.Compare(nextDistance) <= 0 {
				possibleNextHops, done = addToPossiblePaths(possibleNextHops, prevEntry, maxMatches, distinctNextHop, avoid)
				prevEntry = nil
				prevDistance = AddrDistance{}
			} else {
				possibleNextHops, done = addToPossiblePaths(possibleNextHops, nextEntry, maxMatches, distinctNextHop, avoid)
				nextEntry = nil
				nextDistance = AddrDistance{}
			}
		}
		if done {
			return possibleNextHops
		}
	}
}

func addToPossiblePaths(list []*RoutingTableEntry, add *RoutingTableEntry, maxMatches int, distinctNextHop bool, avoid []netip.Addr) (l []*RoutingTableEntry, done bool) {
	// First, check if the entry should be avoided.
	if len(add.Path.Hops) < 2 {
		return list, false
	}
	for _, avoidIP := range avoid {
		for _, hop := range add.Path.Hops[1:] {
			if avoidIP == hop.Router {
				// Found an IP that should be avoided, abort adding entry.
				return list, false
			}
		}
	}

	// Then, check for a distinct next hop.
	if distinctNextHop {
		for _, rte := range list {
			if add.NextHop == rte.NextHop {
				// NextHop is already in the list, abort adding entry.
				return list, false
			}
		}
	}

	// Add the entry to the list.
	list = append(list, add)
	return list, len(list) >= maxMatches
}

// findIndex looks up the given dst address in the routing table.
// It always returns the address-nearest next hop, if the table is not empty.
func (rt *RoutingTable) findIndex(dst netip.Addr) (index int, dstMatched bool) {
	// Search for entry, get index where it is or should be.
	index, dstMatched = slices.BinarySearchFunc[[]*RoutingTableEntry, *RoutingTableEntry, netip.Addr](
		rt.entries,
		dst,
		func(rte *RoutingTableEntry, a netip.Addr) int {
			// Compare IPs and return if not equal.
			cmp := rte.DstIP.Compare(a)
			if cmp != 0 {
				return cmp
			}

			// Return exact match when entry is a peer.
			if rte.Source == RouteSourcePeer {
				return 0
			}

			// Otherwise, find the best route by moving to first entry.
			// Routes to the same destination are ordered by best first.
			return 1
		},
	)

	// TODO: We might have multiple entries for the same dst ip but with different paths!

	switch {
	case dstMatched:
		// Destination is a peer, return index as match.
		return index, true

	case index >= len(rt.entries):
		// Index is after last entry, return last possible index.
		// If the table is empty, this will return an index of -1.
		return len(rt.entries) - 1, false

	case rt.entries[index].DstIP == dst:
		// If entry dst matches, return index as match.
		return index, true

	case index <= 0:
		// Index is before or at first entry, return first entry.
		return 0, false

	default:
		// The returned index is where the entry should be. This means that between
		// two IPs, the index will always be at the next IP, not the previous. In
		// case of routing, this means the next IP might be in a different address
		// scope, while the previous might fit better. The best and easiest way is
		// to choose the IP that is closer in regards to the IP distance.
		prevEntry := rt.entries[index-1]
		nextEntry := rt.entries[index]
		prevDistance := IPDistance(prevEntry.DstIP, dst)
		nextDistance := IPDistance(nextEntry.DstIP, dst)
		if prevDistance.Less(nextDistance) {
			return index - 1, false
		}
		return index, false
	}
}

// RemoveNextHop removes all routes with the given next hop IP from the routing table.
func (rt *RoutingTable) RemoveNextHop(ip netip.Addr) (removed int) {
	rt.lock.Lock()
	defer rt.lock.Unlock()

	rt.entries = slices.DeleteFunc[[]*RoutingTableEntry, *RoutingTableEntry](
		rt.entries,
		func(rte *RoutingTableEntry) bool {
			if rte.NextHop == ip {
				removed++
				return true
			}
			return false
		},
	)

	return
}

// RemoveDisconnected removes all routes with the given disconnected peerings.
// If disconnected is empty, all routes including the router are removed.
func (rt *RoutingTable) RemoveDisconnected(router netip.Addr, disconnected []netip.Addr) (removed int) {
	rt.lock.Lock()
	defer rt.lock.Unlock()

	rt.entries = slices.DeleteFunc[[]*RoutingTableEntry, *RoutingTableEntry](
		rt.entries,
		func(rte *RoutingTableEntry) bool {
			// Remove any route with the router in it.
			if len(disconnected) == 0 {
				switch {
				case rte.DstIP == router:
					removed++
					return true
				case rte.NextHop == router:
					removed++
					return true
				default:
					for _, hop := range rte.Path.Hops {
						if hop.Router == router {
							removed++
							return true
						}
					}
					return false
				}
			}

			// Remove specific links only.
			for i, hop := range rte.Path.Hops {
				if hop.Router == router {
					// Found route that includes the router.

					// Check if the previous hop in the path is one of the peerings.
					if i > 0 {
						for _, peer := range disconnected {
							if rte.Path.Hops[i-1].Router == peer {
								removed++
								return true
							}
						}
					}

					// Check if the next hop in the path is one of the peerings.
					if i < len(rte.Path.Hops)-1 {
						for _, peer := range disconnected {
							if rte.Path.Hops[i+1].Router == peer {
								removed++
								return true
							}
						}
					}

					// Router was in route, but not the disconnected peer.
					// Router cannot be in route twice, stop here.
					return false
				}
			}

			return false
		},
	)

	return removed
}

// Clean cleans the routing table from unneeded entries:
// - Removes expired routes.
// - Removes excess routes of identical routing prefixes.
func (rt *RoutingTable) Clean() {
	rt.lock.Lock()
	defer rt.lock.Unlock()

	// Removes expired (non-peer) routes.
	now := time.Now()
	rt.entries = slices.DeleteFunc[[]*RoutingTableEntry, *RoutingTableEntry](
		rt.entries,
		func(rte *RoutingTableEntry) bool {
			return rte.Source != RouteSourcePeer && rte.Expires.Before(now)
		},
	)

	// Sort into buckets for cleaning.
	rt.sortForCleaning()
	defer rt.sortForRouting()

	// Go through the buckets and remove excess entries.
	var (
		currentPrefix    netip.Prefix
		currentPrefixMax int
		seenInPrefix     int
	)
	rt.entries = slices.DeleteFunc[[]*RoutingTableEntry, *RoutingTableEntry](
		rt.entries,
		func(rte *RoutingTableEntry) bool {
			// Count entries in prefix.
			if currentPrefix != rte.RoutingPrefix {
				currentPrefix = rte.RoutingPrefix
				rp, ok := rt.getRoutablePrefixConfig(rte.RoutingPrefix.Addr())
				if ok {
					currentPrefixMax = rp.EntriesPerPrefix
				} else {
					currentPrefixMax = 0
				}
				seenInPrefix = 0
			}
			seenInPrefix++

			// If we already have enough, remove any excess routes learned from gossip. Discovered routes must expire.
			if seenInPrefix > currentPrefixMax {
				return rte.Source == RouteSourceGossip
			}

			return false
		},
	)
}

func (rt *RoutingTable) sortForCleaning() {
	// Sort all routes into their bucket.
	slices.SortFunc[[]*RoutingTableEntry, *RoutingTableEntry](
		rt.entries,
		func(a, b *RoutingTableEntry) int {
			switch {
			case a.RoutingPrefix != b.RoutingPrefix:
				// Group gossip entries by routing prefix.
				return a.RoutingPrefix.Addr().Compare(b.RoutingPrefix.Addr())

			case a.Path.TotalHops != b.Path.TotalHops:
				// Sort by hop distance to dst.
				return int(a.Path.TotalHops) - int(b.Path.TotalHops)

			case a.Path.TotalDelay != b.Path.TotalDelay:
				// Sort by delay to distance.
				return int(a.Path.TotalDelay) - int(b.Path.TotalDelay)
			}

			// When we have the same routing prefix with equal hops and latency,
			// sort by IP distance.
			if rt.cfg.RouterIP.IsValid() {
				aDist := IPDistance(rt.cfg.RouterIP, a.DstIP)
				bDist := IPDistance(rt.cfg.RouterIP, b.DstIP)
				cmp := aDist.Compare(bDist)
				if cmp != 0 {
					return cmp
				}
			}

			// As a final fallback, compare the Dst IPs themselves.
			return a.DstIP.Compare(b.DstIP)
		},
	)
}

func (rt *RoutingTable) stdSort(a, b *RoutingTableEntry) int {
	switch {
	case a.DstIP != b.DstIP:
		// Sort by destination IP.
		return a.DstIP.Compare(b.DstIP)

	case a.Path.TotalHops != b.Path.TotalHops:
		// Sort by hop distance to dst.
		return int(a.Path.TotalHops) - int(b.Path.TotalHops)

	case a.Path.TotalDelay != b.Path.TotalDelay:
		// Sort by latency to dst.
		return int(a.Path.TotalDelay) - int(b.Path.TotalDelay)
	}

	// Then, sort by relay hop IDs.
	for i := 1; i < len(a.Path.Hops)-1; i++ {
		aRelayRouter := a.Path.Hops[i].Router
		bRelayRouter := b.Path.Hops[i].Router
		if aRelayRouter != bRelayRouter {
			return aRelayRouter.Compare(bRelayRouter)
		}
	}

	// Same dst, route, and latency.
	// Note: This does not deduplicate identical routes, as the latency may change.
	return 0
}

// RouteEquals returns whether the routes match.
func (a *RoutingTableEntry) RouteEquals(b *RoutingTableEntry) bool {
	// Check metadata.
	switch {
	case a.DstIP != b.DstIP:
		return false
	case a.Path.TotalHops != b.Path.TotalHops:
		return false
	case len(a.Path.Hops) != len(b.Path.Hops):
		return false
	}

	// Check actual route.
	for i := 1; i < len(a.Path.Hops)-1; i++ {
		if a.Path.Hops[i].Router != b.Path.Hops[i].Router {
			return false
		}
	}

	return true
}

func (rt *RoutingTable) sortForRouting() {
	slices.SortFunc[[]*RoutingTableEntry, *RoutingTableEntry](
		rt.entries,
		rt.stdSort,
	)
}

// Format formats the routing table for printing it.
// Warning: Acquires a write lock!
func (rt *RoutingTable) Format() string {
	rt.lock.Lock()
	defer rt.lock.Unlock()

	var (
		b        = &strings.Builder{}
		previous *RoutingTableEntry
	)
	for i, rte := range rt.entries {
		if previous == nil || rte.RoutingPrefix != previous.RoutingPrefix {
			previous = rte
			fmt.Fprintln(b, formatPrefix(rte.RoutingPrefix))
		}

		cc := "?"
		if cml, _ := LookupCountryMarker(rte.DstIP); cml != nil {
			cc = cml.Country
		}

		switch {
		case rte.Source == RouteSourcePeer:
			fmt.Fprintf(b, "  %d: %s   %s cc=%s hops=%d\n", i+1,
				rte.Source, rte.DstIP.StringExpanded(), cc, rte.Path.TotalHops,
			)
		default:
			fmt.Fprintf(b,
				"  %d: %s %s cc=%s hops=%d lat=%dms next=%x via=%s\n", i+1,
				rte.Source,
				rte.DstIP.StringExpanded(),
				cc,
				rte.Path.TotalHops,
				rte.Path.TotalDelay,
				rte.Path.Hops[0].ForwardLabel,
				formatRelays(rte.Path.Hops),
			)
		}
	}

	return b.String()
}

func formatPrefix(prefix netip.Prefix) string {
	var info string
	switch GetAddressType(prefix.Addr()) {
	case TypeInvalid:
		info = "invalid address range"
	case TypeReserved:
		info = "reserved address range"
	case TypePrivacy:
		info = "private address range"
	case TypeRoaming:
		info = "special range: roaming"
	case TypeOrganization:
		info = "special range: organizations"
	case TypeAnycast:
		info = "special range: anycast"
	case TypeExperiment:
		info = "special range: experiments"
	case TypeInternal:
		info = "internal range"

	case TypeGeoMarked:
		cml, err := LookupCountryMarker(prefix.Addr())
		if err != nil {
			info = "unknown geo marked address range"
		} else {
			switch {
			case prefix.Bits() == ContinentPrefixBits:
				info = "geomarked world region " + cml.Continent
			case prefix.Bits() == RegionPrefixBits:
				info = "geomarked continental region " +
					cml.Continent + " " + regionCodeToDescription[cml.Region]
			default:
				info = "geomarked country " + cml.Country +
					" (" + cml.Continent + " " + regionCodeToDescription[cml.Region] + ")"
			}
		}
	}

	if info != "" {
		return fmt.Sprintf("%s - %s", prefix, info)
	}
	return prefix.String()
}

func formatRelays(hops []SwitchHop) string {
	if len(hops) <= 2 {
		return "none"
	}

	parts := make([]string, 0, len(hops)-2)
	for _, hop := range hops[1 : len(hops)-1] {
		s := hop.Router.StringExpanded()
		parts = append(parts, s[len(s)-4:])
	}
	return strings.Join(parts, ",")
}

func (rt *RoutingTable) getRoutablePrefixConfig(ip netip.Addr) (rp RoutablePrefix, ok bool) {
	for _, rp = range rt.cfg.RoutablePrefixes {
		if rp.BasePrefix.Contains(ip) {
			return rp, true
		}
	}
	return RoutablePrefix{}, false
}

func (s RouteSource) String() string {
	switch s {
	case RouteSourceGossip:
		return "gossip"
	case RouteSourcePeer:
		return "peer"
	case RouteSourceDiscovered:
		return "discovered"
	case RouteSourceUnknown:
		fallthrough
	default:
		return "unknown"
	}
}
