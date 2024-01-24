package m

import "net/netip"

var (
	// APIAddress is the address used to connect to the local API.
	// It is only accessible from the tun interface.
	APIAddress = netip.MustParseAddr("fd00::1")

	// ServiceAddress is the address used to connect to the public service API.
	// It is available both from the tun interface and the network.
	ServiceAddress = netip.MustParseAddr("fd00::2")

	// RouterAddress is the address used to send multicast messages to other routers.
	RouterAddress = netip.MustParseAddr("fd00::4")
)
