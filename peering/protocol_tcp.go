package peering

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/mycoria/mycoria/m"
)

// ProtocolTCP uses plain TCP.
var ProtocolTCP = NewProtocol(
	"tcp",
	tcpPeerWith,
	tcpStartListener,
)

var _ Protocol = ProtocolTCP

func tcpPeerWith(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Link, error) {
	// Build destination address.
	var host string
	switch {
	case ip.IsValid():
		host = ip.String()
	case peeringURL.Domain != "":
		host = peeringURL.Domain
	default:
		return nil, errors.New("host not specified")
	}
	address := net.JoinHostPort(host, strconv.FormatUint(uint64(peeringURL.Port), 10))

	// Connect.
	dialer := &net.Dialer{
		Timeout:       30 * time.Second,
		FallbackDelay: -1, // Disables Fast Fallback from IPv6 to IPv4.
		KeepAlive:     -1, // Disable keep-alive.
	}
	conn, err := dialer.DialContext(peering.mgr.Ctx(), "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", address, err)
	}

	// Start link setup.
	newLink := newLinkBase(
		conn,
		peeringURL,
		true,
		peering,
	)
	return newLink.handleSetup(peering.mgr)
}

func tcpStartListener(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Listener, error) {
	// Build listen address.
	var host string
	switch {
	case ip.IsValid():
		host = ip.String()
	case peeringURL.Domain != "":
		host = peeringURL.Domain
	default:
		host = ""
	}
	address := net.JoinHostPort(host, strconv.FormatUint(uint64(peeringURL.Port), 10))

	// Bind listener.
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	// Start listener.
	newListener := newListenerBase(
		peeringURL.FormatWith(host),
		ln,
		peeringURL,
		peering,
	)
	newListener.startWorkers()

	// Add to peering manager and return.
	peering.AddListener(newListener.id, newListener)
	return newListener, nil
}
