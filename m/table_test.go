package m

import (
	"crypto/rand"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit"
	"github.com/stretchr/testify/assert"
)

var (
	myPrefix = MustPrefix([]byte{0xfd, 0x1f, 0x00}, 18)
	myIP     = makeRandomAddress(myPrefix)
)

func TestTable(t *testing.T) { //nolint:maintidx
	t.Parallel()

	// Make routable prefixes for testing.
	entriesPerPrefix := 5
	rps := []RoutablePrefix{
		{ // Continent Prefixes.
			BasePrefix:       RoutingAddressPrefix,
			RoutingBits:      RegionPrefixBits,
			EntryTTL:         3 * time.Hour,
			EntriesPerPrefix: entriesPerPrefix,
		},
	}
	tbl := NewRoutingTable(RoutingTableConfig{
		RoutablePrefixes: rps,
		RouterIP:         myIP,
	})

	var (
		addRandomGossipPrefixes          = 10
		addRandomGossipEntriesPerPrefix  = 20
		addRandomPeerEntries             = 10
		addRandomDiscoveredEntries       = 10
		expectedSizeAfterRemovingNextHop = ((addRandomGossipPrefixes * (entriesPerPrefix + (entriesPerPrefix / 2))) +
			addRandomPeerEntries +
			addRandomDiscoveredEntries) * 9 / 10
		expectedSizeAfterClean = (addRandomGossipPrefixes * entriesPerPrefix) +
			(addRandomPeerEntries+
				addRandomDiscoveredEntries)*9/10

		testLookups = 10000

		peers    = make([]netip.Addr, 0, addRandomPeerEntries)
		prefixes = make(map[string]struct{})

		disconnectRouters = make([]netip.Addr, 0, 100)
	)

	t.Logf("testing empty lookup...")
	ip := makeRandomAddress(RoutingAddressPrefix)
	entry, _ := tbl.LookupNearestRoute(ip)
	assert.Nil(t, entry, "lookup must not return an entry")

	t.Logf("adding peer entries...")
	for i := range addRandomPeerEntries {
		ip := makeRandomAddress(myPrefix)
		peers = append(peers, ip)
		_, err := tbl.AddRoute(RoutingTableEntry{
			DstIP:   ip,
			NextHop: ip,
			Path:    makeRandomSwitchPath(ip, 0, 0),
			Stub:    i%5 == 0,
			Source:  RouteSourcePeer,
		})
		assert.NoError(t, err, "adding peer entry should succeed")

		// Add some entry for disconnecting later.
		if i%2 == 0 {
			disconnectRouters = append(disconnectRouters, ip)
		}

		// Check if tables is sorted.
		if !slices.IsSortedFunc[[]*RoutingTableEntry, *RoutingTableEntry](tbl.entries, tbl.stdSort) {
			t.Fatal("table is not sorted after adding peer entry")
		}

		// Check lookup.
		entry, isDestination := tbl.LookupNearest(ip)
		assert.Equalf(t, ip.String(), entry.DstIP.String(), "peer table lookup (%d) must match", i)
		assert.Truef(t, isDestination, "peer table lookup (%d) must report dst match", i)
		// Check one-off lookup -1.
		entry, isDestination = tbl.LookupNearest(ip.Prev())
		assert.Equalf(t, ip.String(), entry.DstIP.String(), "one-off (-1) peer table lookup (%d) must still match", i)
		assert.Falsef(t, isDestination, "one-off (-1) peer table lookup (%d) must not report dst match", i)
		// Check one-off lookup +1.
		entry, isDestination = tbl.LookupNearest(ip.Next())
		assert.Equalf(t, ip.String(), entry.DstIP.String(), "one-off (+1) peer table lookup (%d) must still match", i)
		assert.Falsef(t, isDestination, "one-off (+1) peer table lookup (%d) must not report dst match", i)

		// t.Logf("added peer %s", ip)
	}

	t.Logf("adding gossip entries...")
	for range addRandomGossipPrefixes {
		var prefix netip.Prefix
		for {
			prefixIP := makeRandomAddress(RoutingAddressPrefix)
			rp, ok := tbl.getRoutablePrefixConfig(prefixIP)
			if !ok {
				t.Fatalf("failed to get routable prefix config for %s", prefixIP)
				continue
			}
			var err error
			prefix, err = prefixIP.Prefix(rp.RoutingBits)
			if err != nil {
				t.Fatal(err)
				continue
			}
			// Check if prefix is new so that test is reproducible.
			_, ok = prefixes[prefix.String()]
			if !ok {
				prefixes[prefix.String()] = struct{}{}
				break
			}
		}

		// Generate addresses per prefix.
		for i := range addRandomGossipEntriesPerPrefix {

			// Add up to five entries.
			ip := makeRandomAddress(prefix)
			for j := range (i + 1) % 5 {
				rte := RoutingTableEntry{
					DstIP:   ip,
					NextHop: peers[j%len(peers)],
					Path:    makeRandomSwitchPath(peers[j%len(peers)], j+2, j+2),
					Stub:    i%5 == 0,
					Source:  RouteSourceGossip,
				}
				_, err := tbl.AddRoute(rte)
				assert.NoError(t, err, "adding gossip entry should succeed")

				// Add identical route with different delay.
				if j == 4 {
					for k := range len(rte.Path.Hops) {
						rte.Path.Hops[k].Delay = gofakeit.Uint16()
					}
					rte.Path.CalculateTotals()
					_, err := tbl.AddRoute(rte)
					assert.NoError(t, err, "adding gossip entry should succeed")
				}
			}

			// Add some entry for disconnecting later.
			if i%2 == 0 {
				disconnectRouters = append(disconnectRouters, ip)
			}

			// Check if tables is sorted.
			if !slices.IsSortedFunc[[]*RoutingTableEntry, *RoutingTableEntry](tbl.entries, tbl.stdSort) {
				t.Fatal("table is not sorted after adding gossip entry")
			}

			if i < entriesPerPrefix/2 {
				// Check lookup.
				entry, isDestination := tbl.LookupNearestRoute(ip)
				assert.Equalf(t, ip.String(), entry.DstIP.String(), "gossip table lookup (%d) must match exactly", i)
				assert.Truef(t, isDestination, "gossip table lookup (%d) must report dst match", i)
				assert.Equalf(t, uint8(2), entry.Path.TotalHops, "gossip table lookup (%d) must return better route", i)
			}
		}
	}

	t.Logf("adding discovered entries...")
	for i := range addRandomDiscoveredEntries {
		ip := makeRandomAddress(RoutingAddressPrefix)
		_, err := tbl.AddRoute(RoutingTableEntry{
			DstIP:   ip,
			NextHop: peers[i%len(peers)],
			Path:    makeRandomSwitchPath(peers[i%len(peers)], 2, 5),
			Stub:    i%5 == 0,
			Source:  RouteSourceDiscovered,
			Expires: time.Now().Add(1 * time.Hour),
		})
		assert.NoError(t, err, "adding discovered entry should succeed")

		// Add some entry for disconnecting later.
		if i%2 == 0 {
			disconnectRouters = append(disconnectRouters, ip)
		}
	}

	t.Logf("testing lookups...")
	for range testLookups {
		ip := makeRandomAddress(RoutingAddressPrefix)
		entry, _ := tbl.LookupNearestRoute(ip)
		assert.NotNil(t, entry, "lookup must return an entry")
	}

	// DEBUG:
	// fmt.Println(tbl.Format())

	// Remove next hop and check size afterwards.
	tbl.RemoveNextHop(peers[0])
	t.Logf("table size after removing one next hop: %d", len(tbl.entries))
	switch {
	case len(tbl.entries) > expectedSizeAfterRemovingNextHop:
		assert.Equal(t, expectedSizeAfterRemovingNextHop, len(tbl.entries), "unexpected table size after removing hop")
	case len(tbl.entries) < expectedSizeAfterRemovingNextHop*9/10:
		assert.Equal(t, expectedSizeAfterRemovingNextHop, len(tbl.entries), "unexpected table size after removing hop")
	}

	// Clean and check size afterwards.
	tbl.Clean()
	t.Logf("table size after clean: %d", len(tbl.entries))

	// DEBUG:
	// fmt.Println(tbl.Format())

	switch {
	case len(tbl.entries) > expectedSizeAfterClean:
		assert.Equal(t, expectedSizeAfterClean, len(tbl.entries), "unexpected table size after cleaning")
	case len(tbl.entries) < expectedSizeAfterClean*8/10:
		assert.Equal(t, expectedSizeAfterClean, len(tbl.entries), "unexpected table size after cleaning")
	}

	// Randomly remove routes.
	for i, disconnect := range disconnectRouters {
		var removed int
		if i%2 == 0 {
			removed = tbl.RemoveDisconnected(disconnect, nil)
		} else {
			removed = tbl.RemoveDisconnected(disconnect, []netip.Addr{makeRandomAddress(RoutingAddressPrefix)})
		}
		// t.Logf("removed %d with %s", removed, disconnect)
		_ = removed
	}
}

func makeRandomAddress(prefix netip.Prefix) netip.Addr {
	// Get random bytes.
	var buf [16]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		panic(err)
	}

	// Copy prefix to buf.
	prefixBuf := prefix.Addr().AsSlice()
	// Copy full bytes.
	var index int
	for ; index < prefix.Bits()/8; index++ {
		buf[index] = prefixBuf[index]
	}
	// Copy last partial byte.
	remainingBits := prefix.Bits() % 8
	if remainingBits > 0 {
		buf[index] = prefixBuf[index] | (buf[index] >> byte(remainingBits))
	}

	// Create IP and check it.
	ip := netip.AddrFrom16(buf)
	if !prefix.Contains(ip) {
		panic("random ip not in prefix")
	}

	return ip
}

func makeRandomSwitchPath(peer netip.Addr, minHops, maxHops int) SwitchPath {
	sp := SwitchPath{}

	// Generate hops.
	hopCnt := gofakeit.Number(minHops+1, maxHops+1)
	if minHops == 0 {
		hopCnt = 2
	}
	sp.Hops = make([]SwitchHop, hopCnt)
	// First entry
	sp.Hops[0] = SwitchHop{
		Router:       peer,
		Delay:        gofakeit.Uint16(),
		ForwardLabel: SwitchLabel(gofakeit.Uint16()),
		ReturnLabel:  0,
	}
	// Middle entries
	for i := 1; i < hopCnt-1; i++ {
		sp.Hops[i] = SwitchHop{
			Router:       makeRandomAddress(RoutingAddressPrefix),
			Delay:        gofakeit.Uint16(),
			ForwardLabel: SwitchLabel(gofakeit.Uint16()),
			ReturnLabel:  SwitchLabel(gofakeit.Uint16()),
		}
	}
	// Last entry
	sp.Hops[len(sp.Hops)-1] = SwitchHop{
		Router:       makeRandomAddress(RoutingAddressPrefix),
		Delay:        gofakeit.Uint16(),
		ForwardLabel: 0,
		ReturnLabel:  SwitchLabel(gofakeit.Uint16()),
	}

	// Calculate remainging data.
	err := sp.BuildBlocks()
	if err != nil {
		panic(err)
	}
	sp.CalculateTotals()

	return sp
}

func BenchmarkTableLookup(b *testing.B) {
	tbl := NewRoutingTable(RoutingTableConfig{
		RoutablePrefixes: GetRoutablePrefixesFor(myIP, myPrefix),
	})

	var (
		addRandomGossipEntries     = 890
		addRandomPeerEntries       = 10
		addRandomDiscoveredEntries = 100
	)

	b.Logf("adding peer entries...")
	for i := 0; i < addRandomPeerEntries; i++ {
		ip := makeRandomAddress(myPrefix)
		_, _ = tbl.AddRoute(RoutingTableEntry{
			DstIP:  ip,
			Source: RouteSourcePeer,
		})
	}
	b.Logf("adding gossip entries...")
	for i := 0; i < addRandomGossipEntries; i++ {
		ip := makeRandomAddress(RoutingAddressPrefix)
		_, _ = tbl.AddRoute(RoutingTableEntry{
			DstIP:  ip,
			Source: RouteSourceGossip,
		})
	}
	b.Logf("adding discovered entries...")
	for i := 0; i < addRandomDiscoveredEntries; i++ {
		ip := makeRandomAddress(RoutingAddressPrefix)
		_, _ = tbl.AddRoute(RoutingTableEntry{
			DstIP:  ip,
			Source: RouteSourceDiscovered,
		})
	}

	ips := make([]netip.Addr, 1000)
	for i := 0; i < len(ips); i++ {
		ips[i] = makeRandomAddress(RoutingAddressPrefix)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry, _ := tbl.LookupNearestRoute(ips[i%1000])
		if entry == nil {
			b.Fatal("lookup failed")
		}
	}
}

func BenchmarkMapTableLookup(b *testing.B) {
	tbl := make(map[netip.Addr]RoutingTableEntry, 1000)
	ips := make([]netip.Addr, 0, 1000)

	var (
		addRandomGossipEntries     = 890
		addRandomPeerEntries       = 10
		addRandomDiscoveredEntries = 100
	)

	b.Logf("adding peer entries...")
	for i := 0; i < addRandomPeerEntries; i++ {
		ip := makeRandomAddress(myPrefix)
		ips = append(ips, ip)
		tbl[ip] = RoutingTableEntry{
			DstIP:  ip,
			Source: RouteSourcePeer,
		}
	}
	b.Logf("adding gossip entries...")
	for i := 0; i < addRandomGossipEntries; i++ {
		ip := makeRandomAddress(RoutingAddressPrefix)
		ips = append(ips, ip)
		tbl[ip] = RoutingTableEntry{
			DstIP:  ip,
			Source: RouteSourceGossip,
		}
	}
	b.Logf("adding discovered entries...")
	for i := 0; i < addRandomDiscoveredEntries; i++ {
		ip := makeRandomAddress(RoutingAddressPrefix)
		ips = append(ips, ip)
		tbl[ip] = RoutingTableEntry{
			DstIP:  ip,
			Source: RouteSourceDiscovered,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rte := tbl[ips[i%1000]]
		if !rte.DstIP.IsValid() {
			b.Fatal(rte.DstIP)
		}
	}
}

func BenchmarkTableCleaning(b *testing.B) {
	tbl := NewRoutingTable(RoutingTableConfig{
		RoutablePrefixes: GetRoutablePrefixesFor(myIP, myPrefix),
		RouterIP:         myIP,
	})

	var (
		addRandomGossipEntries     = 890
		addRandomPeerEntries       = 10
		addRandomDiscoveredEntries = 100
	)

	b.Logf("adding peer entries...")
	for i := 0; i < addRandomPeerEntries; i++ {
		ip := makeRandomAddress(myPrefix)
		_, err := tbl.AddRoute(RoutingTableEntry{
			DstIP:   ip,
			NextHop: ip,
			Path:    makeRandomSwitchPath(ip, 1, 3),
			Source:  RouteSourcePeer,
			Expires: time.Now().Add(1 * time.Hour),
		})
		if err != nil {
			b.Fatal(err)
		}
	}
	b.Logf("adding gossip entries...")
	for i := 0; i < addRandomGossipEntries; i++ {
		ip := makeRandomAddress(RoutingAddressPrefix)
		_, err := tbl.AddRoute(RoutingTableEntry{
			DstIP:   ip,
			NextHop: ip,
			Path:    makeRandomSwitchPath(ip, 1, 3),
			Source:  RouteSourceGossip,
			Expires: time.Now().Add(1 * time.Hour),
		})
		if err != nil {
			b.Fatal(err)
		}
	}
	b.Logf("adding discovered entries...")
	for i := 0; i < addRandomDiscoveredEntries; i++ {
		ip := makeRandomAddress(RoutingAddressPrefix)
		_, err := tbl.AddRoute(RoutingTableEntry{
			DstIP:   ip,
			NextHop: ip,
			Path:    makeRandomSwitchPath(ip, 1, 3),
			Source:  RouteSourceDiscovered,
			Expires: time.Now().Add(1 * time.Hour),
		})
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tbl.sortForCleaning()
		tbl.sortForRouting()
	}
}
