package api

import (
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/state"
	"github.com/mycoria/mycoria/tun"
)

var apiAddress = netip.MustParseAddr("fd00::b909")

// API is an the API collection connected via a virtual network stack.
type API struct {
	instance instance

	tunDevice *tun.Device
	address   netip.Addr

	netstack   *stack.Stack
	netstackIO *channel.Endpoint

	httpServerListener *gonet.TCPListener
	httpServer         *http.Server

	dnsServerBind *gonet.UDPConn
	dnsServer     *dns.Server
	dnsWorkerCtx  *mgr.WorkerCtx
}

// instance is an interface subset of inst.Ance.
type instance interface {
	Version() string
	Config() *config.Config
	Identity() *m.Address
	State() *state.State
}

// New returns an initialized API connected to the given tun device.
// Input packets must be submitted manually using SubmitPacket().
func New(instance instance, tunDevice *tun.Device) (*API, error) {
	// getMTU := instance.Config().OverlayMTU// FIXME

	const nicID = 1
	api := &API{
		instance:  instance,
		tunDevice: tunDevice,
		address:   apiAddress,
	}

	// Create network stack.
	api.netstack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6},
	})
	// Configure network stack.
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tErr := api.netstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tErr != nil {
		return nil, fmt.Errorf("failed to enable TCP SACK: %v", tErr)
	}
	// Create API endpoint to communicate with stack.
	api.netstackIO = channel.New(128, 1500, "") // FIXME: uint32(getMTU())
	// Add API endpoint to stack.
	tErr = api.netstack.CreateNIC(nicID, api.netstackIO)
	if tErr != nil {
		return nil, fmt.Errorf("failed to create NIC: %v", tErr)
	}

	// Add listen address and default route.
	listenAddress := tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(api.address.AsSlice()).WithPrefix(),
	}
	tErr = api.netstack.AddProtocolAddress(nicID, listenAddress, stack.AddressProperties{})
	if tErr != nil {
		return nil, fmt.Errorf("failed to add API listen address to netstack NIC: %v", tErr)
	}
	api.netstack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})

	// Add HTTP server.
	var err error
	api.httpServerListener, err = gonet.ListenTCP(api.netstack, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(api.address.AsSlice()),
		Port: 80,
	}, ipv6.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to listen with TCP on netstack: %w", err)
	}
	api.httpServer = &http.Server{
		Handler:      api,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}

	// Add DNS server.
	var wq waiter.Queue
	ep, tErr := api.netstack.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if tErr != nil {
		return nil, fmt.Errorf("failed to create packet endpoint for DNS server: %v", tErr)
	}
	tErr = ep.Bind(tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(api.address.AsSlice()),
		Port: 53,
	})
	if tErr != nil {
		return nil, fmt.Errorf("failed to bind packet endpoint for DNS server: %v", tErr)
	}
	api.dnsServerBind = gonet.NewUDPConn(&wq, ep)
	api.dnsServer = &dns.Server{
		PacketConn:   api.dnsServerBind,
		Handler:      api,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}

	return api, nil
}

// Start starts the API stack.
func (api *API) Start(m *mgr.Manager) error {
	m.StartWorker("response packet handler", api.handleResponsePackets)
	m.StartWorker("http server", api.netstackHTTPServer)
	m.StartWorker("dns server", api.netstackDNSServer)

	return nil
}

// Stop stops the API stack.
func (api *API) Stop(m *mgr.Manager) error {
	if err := api.httpServer.Close(); err != nil {
		m.Error("failed to stop http server", "err", err)
	}
	if err := api.dnsServer.Shutdown(); err != nil {
		m.Error("failed to stop dns server", "err", err)
	}
	return nil
}

// SubmitPacket is the send bridge to the API network stack.
func (api *API) SubmitPacket(packet []byte) {
	// DEBUG:
	// fmt.Printf("in:\n%s", hex.Dump(packet))

	api.netstackIO.InjectInbound(
		ipv6.ProtocolNumber,
		stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)}),
	)

	// TODO: Can we return the pooled buffer?
}

// WriteNotify is the recv bridge to the API network stack.
func (api *API) handleResponsePackets(w *mgr.WorkerCtx) error {
	for {
		// Get from network stack.
		pktBuf := api.netstackIO.ReadContext(w.Ctx())
		if pktBuf == nil {
			return nil
		}

		// *tun.Device.Write() wants a 10 byte offset for packet data.
		// Probably because it wants to use some special network stack features,
		// where it needs to some space in front of the packet.
		offset := 10

		// Copy all parts of the packet to one slice.
		pktParts := pktBuf.AsSlices()
		var fullLength int
		for _, part := range pktParts {
			fullLength += len(part)
		}
		pktWithOffset := make([]byte, offset, fullLength+offset)
		for _, part := range pktParts {
			pktWithOffset = append(pktWithOffset, part...)
		}

		// DEBUG:
		// fmt.Printf("out:\n%s", hex.Dump(pktWithOffset[offset:]))

		// TODO: Should we trigger a resource release here?
		// pktBuf.DecRef()

		// Write packet data to tun device.
		dataWritten, err := api.tunDevice.Write([][]byte{pktWithOffset}, offset)
		switch {
		case err != nil:
			w.Error("failed to write packet", "err", err)
		case dataWritten != len(pktWithOffset):
			w.Error(
				"failed to write all packet data",
				"written",
				dataWritten,
				"total",
				fullLength,
			)
		}
	}
}
