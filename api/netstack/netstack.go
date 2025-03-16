package netstack

import (
	"fmt"
	"net"
	"net/netip"

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

	"github.com/mycoria/mycoria/api/dns"
	"github.com/mycoria/mycoria/api/httpapi"
	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/state"
	"github.com/mycoria/mycoria/tun"
)

var apiAddress = netip.MustParseAddr("fd00::b909")

// NetStack is virtual network stack to attach services to.
type NetStack struct {
	mgr      *mgr.Manager
	instance instance

	nicID     tcpip.NICID
	tunDevice *tun.Device
	address   netip.Addr

	stack   *stack.Stack
	stackIO *channel.Endpoint
}

// instance is an interface subset of inst.Ance.
type instance interface {
	Version() string
	Config() *config.Config
	Identity() *m.Address
	State() *state.State
	DNS() *dns.Server
	API() *httpapi.API
}

// New returns an initialized API connected to the given tun device.
// Input packets must be submitted manually using SubmitPacket().
func New(instance instance, tunDevice *tun.Device) (*NetStack, error) {
	ns := &NetStack{
		mgr:       mgr.New("netstack"),
		instance:  instance,
		nicID:     1,
		tunDevice: tunDevice,
		address:   apiAddress,
	}

	// Create network stack.
	ns.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6},
	})
	// Configure network stack.
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tErr := ns.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tErr != nil {
		return nil, fmt.Errorf("failed to enable TCP SACK: %v", tErr)
	}
	// Create API endpoint to communicate with stack.
	ns.stackIO = channel.New(128, uint32(instance.Config().TunMTU()), "")
	// Add API endpoint to stack.
	tErr = ns.stack.CreateNIC(ns.nicID, ns.stackIO)
	if tErr != nil {
		return nil, fmt.Errorf("failed to create NIC: %v", tErr)
	}

	// Add listen address and default route.
	listenAddress := tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(ns.address.AsSlice()).WithPrefix(),
	}
	tErr = ns.stack.AddProtocolAddress(ns.nicID, listenAddress, stack.AddressProperties{})
	if tErr != nil {
		return nil, fmt.Errorf("failed to add API listen address to netstack NIC: %v", tErr)
	}
	ns.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: ns.nicID})

	return ns, nil
}

// Manager returns the module's manager.
func (ns *NetStack) Manager() *mgr.Manager {
	return ns.mgr
}

// Start starts the API stack.
func (ns *NetStack) Start() error {
	ns.mgr.Go("response packet handler", ns.handleResponsePackets)

	return nil
}

// Stop stops the API stack.
func (ns *NetStack) Stop() error {
	return nil
}

// ListenTCP returns a new listener on the given port of the API address.
func (ns *NetStack) ListenTCP(port uint16) (net.Listener, error) {
	ln, err := gonet.ListenTCP(ns.stack, tcpip.FullAddress{
		NIC:  ns.nicID,
		Addr: tcpip.AddrFromSlice(ns.address.AsSlice()),
		Port: port,
	}, ipv6.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to listen with TCP on netstack: %w", err)
	}

	return ln, nil
}

// ListenUDP returns a new listener on the given port of the API address.
func (ns *NetStack) ListenUDP(port uint16) (net.PacketConn, error) {
	var wq waiter.Queue
	ep, err := ns.stack.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if err != nil {
		return nil, fmt.Errorf("failed to create packet endpoint for DNS server: %v", err)
	}
	err = ep.Bind(tcpip.FullAddress{
		NIC:  ns.nicID,
		Addr: tcpip.AddrFromSlice(ns.address.AsSlice()),
		Port: port,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to bind packet endpoint for DNS server: %v", err)
	}
	packetConn := gonet.NewUDPConn(&wq, ep)

	return packetConn, nil
}

// SubmitPacket is the send bridge to the API network stack.
func (ns *NetStack) SubmitPacket(packet []byte) {
	// DEBUG:
	// fmt.Printf("in:\n%s", hex.Dump(packet))

	ns.stackIO.InjectInbound(
		ipv6.ProtocolNumber,
		stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)}),
	)

	// TODO: Can we return the pooled buffer?
}

// WriteNotify is the recv bridge to the API network stack.
func (ns *NetStack) handleResponsePackets(w *mgr.WorkerCtx) error {
	for {
		// Get from network stack.
		pktBuf := ns.stackIO.ReadContext(w.Ctx())
		if pktBuf == nil {
			return nil
		}

		// *tun.Device.Write() wants a 10 byte offset for packet data.
		// Probably because it wants to use some special network stack features,
		// where it needs to some space in front of the packet.
		offset := ns.tunDevice.SendRawOffset()

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

		// Trigger resource release.
		// This will (seemingly) also removed the packet from the queue it was in.
		pktBuf.DecRef()

		// Write packet data to tun device.
		select {
		case ns.tunDevice.SendRaw <- pktWithOffset:
			// Packet submitted to tun writer.
		case <-w.Done():
			return w.Ctx().Err()
		}
	}
}
