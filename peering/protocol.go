package peering

import (
	"errors"
	"net/netip"

	"github.com/mycoria/mycoria/m"
)

// Protocol defines how to create a listener or connect to a peer using a certain protocol.
type Protocol interface {
	// Name returns the protocol name/scheme.
	Name() string
	// PeerWith connects to the given router.
	PeerWith(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Link, error)
	// StartListener starts a listener for peering requests.
	StartListener(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Listener, error)
}

// GetProtocol adds a new protocol.
func (p *Peering) GetProtocol(id string) Protocol {
	p.protocolsLock.RLock()
	defer p.protocolsLock.RUnlock()

	return p.protocols[id]
}

// AddProtocol adds a new protocol.
func (p *Peering) AddProtocol(id string, prot Protocol) {
	p.protocolsLock.Lock()
	defer p.protocolsLock.Unlock()

	p.protocols[id] = prot
}

// PeerWith establishes a connection with the given peering URL.
// The IP address is optional, but may be required by different protocols.
// If the peering URL has no IP defined, the IP address is required.
func (p *Peering) PeerWith(peeringURL *m.PeeringURL, ip netip.Addr) (Link, error) {
	prot := p.GetProtocol(peeringURL.Protocol)
	if prot == nil {
		return nil, errors.New("unknown protocol")
	}

	return prot.PeerWith(p, peeringURL, ip)
}

// StartListener starts a new listener with the given peering URL.
// The IP address is optional, but may be required by different protocols.
func (p *Peering) StartListener(peeringURL *m.PeeringURL, ip netip.Addr) (Listener, error) {
	prot := p.GetProtocol(peeringURL.Protocol)
	if prot == nil {
		return nil, errors.New("unknown protocol")
	}

	return prot.StartListener(p, peeringURL, ip)
}

// ProtocolFunctions implements Protocol with saved functions.
type ProtocolFunctions struct {
	name          string
	peerWith      func(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Link, error)
	startListener func(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Listener, error)
}

// NewProtocol returns a new protocol using the given functions.
func NewProtocol(
	name string,
	peerWith func(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Link, error),
	startListener func(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Listener, error),
) *ProtocolFunctions {
	return &ProtocolFunctions{
		name:          name,
		peerWith:      peerWith,
		startListener: startListener,
	}
}

// Name returns the protocol name/scheme.
func (p *ProtocolFunctions) Name() string {
	return p.name
}

// PeerWith connects to the given router.
func (p *ProtocolFunctions) PeerWith(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Link, error) {
	return p.peerWith(peering, peeringURL, ip)
}

// StartListener starts a listener for peering requests.
func (p *ProtocolFunctions) StartListener(peering *Peering, peeringURL *m.PeeringURL, ip netip.Addr) (Listener, error) {
	return p.startListener(peering, peeringURL, ip)
}
