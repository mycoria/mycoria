package peering

import (
	"net"
	"net/netip"

	"github.com/mycoria/mycoria/m"
)

// NewConnectedPipeStacks returns a new set of net.Pipe based connectivity stacks for testing.
func NewConnectedPipeStacks() (Protocol, Protocol) {
	a := make(chan net.Conn)
	b := make(chan net.Conn)

	return &protocolPipe{
			acceptIn:  a,
			acceptOut: b,
		}, &protocolPipe{
			acceptIn:  b,
			acceptOut: a,
		}
}

type protocolPipe struct {
	acceptIn  chan net.Conn
	acceptOut chan net.Conn
}

func (pipe *protocolPipe) Name() string {
	return "pipe"
}

func (pipe *protocolPipe) PeerWith(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Link, error) {
	// Create (unbuffered) pipes and connected them for some basic async buffering.
	client, a := net.Pipe()
	b, server := net.Pipe()
	go copyPipe(a, b)
	go copyPipe(b, a)

	// Wait until it is accepted by the listener.
	pipe.acceptOut <- server

	// Start link setup.
	newLink := newLinkBase(
		client,
		peeringURL,
		true,
		peering,
	)
	return newLink.handleSetup(peering.mgr)
}

func (pipe *protocolPipe) StartListener(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Listener, error) {
	// Start listener.
	newListener := newListenerBase(
		peeringURL.FormatWith(ip.String()),
		pipe,
		peeringURL,
		peering,
	)
	newListener.startWorkers()

	// Add to peering manager and return.
	peering.AddListener(newListener.id, newListener)
	return newListener, nil
}

// Accept waits for and returns the next connection to the listener.
func (pipe *protocolPipe) Accept() (net.Conn, error) {
	return <-pipe.acceptIn, nil
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (pipe *protocolPipe) Close() error {
	close(pipe.acceptIn)
	return nil
}

// Addr returns the listener's network address.
func (pipe *protocolPipe) Addr() net.Addr {
	return &net.UnixAddr{
		Name: "pipe",
	}
}

func copyPipe(a, b net.Conn) {
	for {
		buf := make([]byte, 1500)
		n, err := a.Read(buf)
		if err != nil {
			_ = b.Close()
			return
		}

		_, err = b.Write(buf[:n])
		if err != nil {
			_ = a.Close()
			return
		}
	}
}
