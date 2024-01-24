package frame

import (
	"net"
	"net/netip"

	"github.com/mycoria/mycoria/m"
)

// LinkAccessor is an interface to access links from a frame.
type LinkAccessor interface {
	String() string

	// Peer returns the ID of the connected peer.
	Peer() netip.Addr

	// SwitchLabel returns the switch label of the link.
	SwitchLabel() m.SwitchLabel

	// PeeringURL returns the used peering URL.
	PeeringURL() *m.PeeringURL

	// Outgoing returns whether the connection was initiated by this router.
	Outgoing() bool

	// SendPriority sends a priority frame to the peer.
	SendPriority(f Frame) error

	// Send sends a frame to the peer.
	Send(f Frame) error

	// LocalAddr returns the underlying local net.Addr of the connection.
	LocalAddr() net.Addr

	// RemoteAddr returns the underlying remote net.Addr of the connection.
	RemoteAddr() net.Addr

	// Latency returns the latency of the link in milliseconds.
	Latency() uint16

	// FlowControlIndicator returns a flow control flag that indicates the
	// pressure on the sending queue of this link.
	FlowControlIndicator() FlowControlFlag

	// IsClosing returns whether the link is closing or has closed.
	IsClosing() bool
}
