package m

import (
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit"
	"github.com/stretchr/testify/assert"
)

var (
	myPrefix = MustPrefix([]byte{0xfd, 0x1f, 0x00}, 18)
	myIP     = makeRandomAddress(myPrefix)
)

func TestTable(t *testing.T) {
	t.Skip() // FIXME: test is flaky.

	t.Parallel()

	// Make routable prefixes for testing.
	rps := GetRoutablePrefixesFor(myIP, myPrefix)
	// Set max entries to 5 for all prefixes for testing.
	for i := 0; i < len(rps); i++ {
		rps[i].EntriesPerPrefix = 5
	}

	tbl := NewRoutingTable(RoutingTableConfig{
		RoutablePrefixes: rps,
		RouterIP:         myIP,
	})

	var (
		addRandomGossipPrefixes          = 10
		addRandomGossipEntriesPerPrefix  = 100
		addRandomPeerEntries             = 10
		addRandomDiscoveredEntries       = 10
		expectedSizeAfterRemovingNextHop = ((addRandomGossipPrefixes * addRandomGossipEntriesPerPrefix) +
			addRandomPeerEntries +
			addRandomDiscoveredEntries) * 9 / 10
		expectedSizeAfterClean = (addRandomGossipPrefixes * 5) +
			(addRandomPeerEntries+
				addRandomDiscoveredEntries)*9/10

		testLookups = 10000

		peers    = make([]netip.Addr, 0, addRandomPeerEntries)
		prefixes = make(map[string]struct{})
	)

	t.Logf("testing empty lookup...")
	ip := makeRandomAddress(RoutingAddressPrefix)
	entry, _ := tbl.LookupNearest(ip)
	assert.Nil(t, entry, "lookup must not return an entry")

	t.Logf("adding peer entries...")
	for i := 0; i < addRandomPeerEntries; i++ {
		ip := makeRandomAddress(myPrefix)
		peers = append(peers, ip)
		assert.NoError(t, tbl.AddRoute(RoutingTableEntry{
			DstIP:   ip,
			NextHop: ip,
			Path:    makeRandomSwitchPath(ip, 0),
			Source:  RouteSourcePeer,
		}), "adding peer entry should succeed")
		// t.Logf("added peer %s", ip)
	}

	t.Logf("adding gossip entries...")
	for i := 0; i < addRandomGossipPrefixes; i++ {
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
		for j := 0; j < addRandomGossipEntriesPerPrefix; j++ {
			ip := makeRandomAddress(prefix)
			assert.NoError(t, tbl.AddRoute(RoutingTableEntry{
				DstIP:   ip,
				NextHop: peers[j%len(peers)],
				Path:    makeRandomSwitchPath(peers[i%len(peers)], 2),
				Source:  RouteSourceGossip,
			}), "adding gossip entry should succeed")
			// t.Logf("added gossip %s", ip)
		}
	}

	t.Logf("adding discovered entries...")
	for i := 0; i < addRandomDiscoveredEntries; i++ {
		ip := makeRandomAddress(RoutingAddressPrefix)
		assert.NoError(t, tbl.AddRoute(RoutingTableEntry{
			DstIP:   ip,
			NextHop: peers[i%len(peers)],
			Path:    makeRandomSwitchPath(peers[i%len(peers)], 2),
			Source:  RouteSourceDiscovered,
			Expires: time.Now().Add(1 * time.Hour),
		}), "adding discovered entry should succeed")
	}

	t.Logf("testing lookups...")
	for i := 0; i < testLookups; i++ {
		ip := makeRandomAddress(RoutingAddressPrefix)
		entry, _ := tbl.LookupNearest(ip)
		assert.NotNil(t, entry, "lookup must return an entry")
	}

	// Remove next hop and check size afterwards.
	tbl.RemoveNextHop(peers[0])
	t.Logf("table size after removing one next hop: %d", len(tbl.entries))
	assert.Equal(t, expectedSizeAfterRemovingNextHop, len(tbl.entries), "unexpected table size after removing hop")

	// Clean and check size afterwards.
	tbl.Clean()
	// fmt.Println(tbl.Format())
	t.Logf("table size after clean: %d", len(tbl.entries))
	assert.Equal(t, expectedSizeAfterClean, len(tbl.entries), "unexpected table size after cleaning")
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

func makeRandomSwitchPath(peer netip.Addr, minHops int) SwitchPath {
	sp := SwitchPath{}

	// Generate hops.
	hopCnt := gofakeit.Number(minHops+1, 10)
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
		_ = tbl.AddRoute(RoutingTableEntry{
			DstIP:  ip,
			Source: RouteSourcePeer,
		})
	}
	b.Logf("adding gossip entries...")
	for i := 0; i < addRandomGossipEntries; i++ {
		ip := makeRandomAddress(RoutingAddressPrefix)
		_ = tbl.AddRoute(RoutingTableEntry{
			DstIP:  ip,
			Source: RouteSourceGossip,
		})
	}
	b.Logf("adding discovered entries...")
	for i := 0; i < addRandomDiscoveredEntries; i++ {
		ip := makeRandomAddress(RoutingAddressPrefix)
		_ = tbl.AddRoute(RoutingTableEntry{
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
		entry, _ := tbl.LookupNearest(ips[i%1000])
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
		err := tbl.AddRoute(RoutingTableEntry{
			DstIP:   ip,
			NextHop: ip,
			Path:    makeRandomSwitchPath(ip, 1),
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
		err := tbl.AddRoute(RoutingTableEntry{
			DstIP:   ip,
			NextHop: ip,
			Path:    makeRandomSwitchPath(ip, 1),
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
		err := tbl.AddRoute(RoutingTableEntry{
			DstIP:   ip,
			NextHop: ip,
			Path:    makeRandomSwitchPath(ip, 1),
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
