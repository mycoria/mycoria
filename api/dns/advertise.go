package dns

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
)

// SendRouterAdvertisement sends a router advertisement to the tun interface to configure DNS via RDNSS and DNSSL.
func (srv *Server) SendRouterAdvertisement(ifAddr netip.Addr) error {
	// Ignore if tun device is disabled.
	if srv.instance.Config().System.DisableTun {
		return nil
	}

	// RFC4861 & RFC4191
	advert := &ndp.RouterAdvertisement{
		CurrentHopLimit: 64,

		// 1-bit "Managed address configuration" flag.  When
		// set, it indicates that addresses are available via
		// Dynamic Host Configuration Protocol [DHCPv6].
		ManagedConfiguration: false,

		// 1-bit "Other configuration" flag.  When set, it
		// indicates that other configuration information is
		// available via DHCPv6.
		OtherConfiguration: false,

		// TODO: ?
		MobileIPv6HomeAgent: false,

		// Indicates whether to prefer this
		// router over other default routers.  If the Router Lifetime
		// is zero, the preference value MUST be set to (00)
		RouterSelectionPreference: 0,

		// TODO: ?
		NeighborDiscoveryProxy: false,

		// 0 indicates that the router is not a default
		// router and SHOULD NOT appear on the default router list.
		RouterLifetime: 0,

		ReachableTime:   0xFFFFFFFF * time.Second, // Infinity?.
		RetransmitTimer: 0xFFFFFFFF * time.Second, // Infinity?.

		Options: []ndp.Option{
			&ndp.RecursiveDNSServer{
				Lifetime: 0xFFFFFFFF * time.Second, // Infinity.
				Servers:  []netip.Addr{config.DefaultAPIAddress},
			},
			&ndp.DNSSearchList{
				Lifetime:    0xFFFFFFFF * time.Second, // Infinity.
				DomainNames: []string{config.DefaultTLD},
			},
		},
	}
	icmpData, err := ndp.MarshalMessageChecksum(advert, config.DefaultAPIAddress, ifAddr)
	if err != nil {
		return fmt.Errorf("build router advertisement: %w", err)
	}

	// Create full packet and copy ICMP message.
	offset := srv.instance.TunDevice().SendRawOffset()
	packetData := make([]byte, offset+ipv6.HeaderLen+len(icmpData))
	copy(packetData[offset+ipv6.HeaderLen:], icmpData)

	// Set IPv6 header.
	header := packetData[offset : offset+ipv6.HeaderLen]
	header[0] = 6 << 4 // IP Version
	m.PutUint16(header[4:6], uint16(len(icmpData)))
	header[6] = 58 // Next Header
	header[7] = 64 // Hop Limit
	srcData := config.DefaultAPIAddress.As16()
	copy(header[8:24], srcData[:])
	dstData := ifAddr.As16()
	copy(header[24:40], dstData[:])

	// Submit to writer.
	srv.instance.TunDevice().SendRaw <- packetData
	return nil
}
