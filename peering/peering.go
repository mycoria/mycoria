package peering

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/state"
	"github.com/mycoria/mycoria/tun"
)

// Peering is a peering manager.
type Peering struct {
	instance       instance
	mgr            *mgr.Manager
	frameHandler   chan frame.Frame
	triggerPeering chan struct{}

	links        map[netip.Addr]Link
	linksByLabel map[m.SwitchLabel]Link
	linksLock    sync.RWMutex

	listeners     map[string]Listener
	listenersLock sync.RWMutex

	protocols     map[string]Protocol
	protocolsLock sync.RWMutex

	PeeringEvents *mgr.EventMgr[*EventPeering]
}

// instance is an interface subset of inst.Ance.
type instance interface {
	Version() string
	Config() *config.Config
	Identity() *m.Address
	FrameBuilder() *frame.Builder

	State() *state.State

	TunDevice() *tun.Device
	RoutingTable() *m.RoutingTable
}

// New returns a new peering manager.
func New(instance instance, frameHandler chan frame.Frame) *Peering {
	p := &Peering{
		instance:       instance,
		frameHandler:   frameHandler,
		triggerPeering: make(chan struct{}, 1),
		links:          make(map[netip.Addr]Link),
		linksByLabel:   make(map[m.SwitchLabel]Link),
		listeners:      make(map[string]Listener),
		protocols:      make(map[string]Protocol),
	}

	return p
}

// Start starts the peering manager. It:
// - Starts configured listeners.
// - Connects to configured peers.
func (p *Peering) Start(m *mgr.Manager) error {
	p.mgr = m
	p.PeeringEvents = mgr.NewEventMgr[*EventPeering]("peering", p.mgr)

	p.mgr.Go("listen manager", p.listenMgr)
	p.mgr.Go("connect manager", p.connectMgr)

	return nil
}

// Stop stops all listeners and links.
func (p *Peering) Stop(mgr *mgr.Manager) error {
	p.mgr.Cancel()

	p.closeAllListeners()
	p.closeAllLinks()

	return nil
}

// LinkCnt returns the current amount of active peering links.
func (p *Peering) LinkCnt() int {
	p.linksLock.RLock()
	defer p.linksLock.RUnlock()

	return len(p.links)
}

// GetLink returns the link to the given peer, if available.
func (p *Peering) GetLink(ip netip.Addr) Link {
	p.linksLock.RLock()
	defer p.linksLock.RUnlock()

	return p.links[ip]
}

// GetLinkByLabel returns the link to the given peer by switch label, if available.
func (p *Peering) GetLinkByLabel(label m.SwitchLabel) Link {
	p.linksLock.RLock()
	defer p.linksLock.RUnlock()

	return p.linksByLabel[label]
}

// GetLinkByRemoteHost returns the link with the given peering host.
func (p *Peering) GetLinkByRemoteHost(peeringHost string) Link {
	p.linksLock.RLock()
	defer p.linksLock.RUnlock()

	for _, link := range p.links {
		if link.PeeringURL() != nil && link.PeeringURL().Domain == peeringHost {
			return link
		}
	}

	return nil
}

// GetLinks returns a list of all links.
func (p *Peering) GetLinks() []Link {
	p.linksLock.RLock()
	defer p.linksLock.RUnlock()

	list := make([]Link, 0, len(p.links))
	for _, link := range p.links {
		list = append(list, link)
	}

	// TODO: Sort by nearest.
	slices.SortFunc[[]Link, Link](list, func(a, b Link) int {
		return a.Peer().Compare(b.Peer())
	})

	return list
}

// AddLink adds the link to the peering list.
func (p *Peering) AddLink(link Link) error {
	p.linksLock.Lock()
	defer p.linksLock.Unlock()

	_, err := p.instance.RoutingTable().AddRoute(m.RoutingTableEntry{
		DstIP:   link.Peer(),
		NextHop: link.Peer(),
		Source:  m.RouteSourcePeer,
	})
	if err != nil {
		return fmt.Errorf("add link to routing table: %w", err)
	}

	p.links[link.Peer()] = link
	p.linksByLabel[link.SwitchLabel()] = link
	return nil
}

// RemoveLink removes the link from the peering list.
// The link is not closed by this function!
func (p *Peering) RemoveLink(link Link) {
	p.linksLock.Lock()
	defer p.linksLock.Unlock()

	delete(p.links, link.Peer())
	delete(p.linksByLabel, link.SwitchLabel())
	p.instance.RoutingTable().RemoveNextHop(link.Peer())

	// If we reach zero links, trigger peering.
	if len(p.links) == 0 && !p.mgr.IsDone() {
		p.TriggerPeering()
	}
}

// CloseLink closes the link to the given peer.
func (p *Peering) CloseLink(ip netip.Addr) {
	var link Link
	func() {
		p.linksLock.Lock()
		defer p.linksLock.Unlock()

		link = p.links[ip]
	}()

	if link != nil {
		link.Close(func() {
			p.mgr.Info(
				"closing link (by manager)",
				"peer", link.Peer(),
				"remote", link.RemoteAddr(),
			)
		})
		p.RemoveLink(link)
	}
}

func (p *Peering) closeAllLinks() {
	for _, l := range p.copyLinksWithLocking() {
		link := l
		link.Close(func() {
			p.mgr.Info(
				"closing link (by manager)",
				"peer", link.Peer(),
				"remote", link.RemoteAddr(),
			)
		})
		p.RemoveLink(link)
	}
}

// IsStub returns whether the router is currently a dead end:
// It only has 1 peer or only lite peers.
func (p *Peering) IsStub() bool {
	p.linksLock.RLock()
	defer p.linksLock.RUnlock()

	// Check if there is only one peer.
	if len(p.links) <= 1 {
		return true
	}

	// Check if there are only lite peers.
	for _, link := range p.links {
		if !link.Lite() {
			return false
		}
	}
	return true
}

// GetListener returns the listener with the given ID.
func (p *Peering) GetListener(id string) Listener {
	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()

	return p.listeners[id]
}

// AddListener adds the listener to the listener list.
func (p *Peering) AddListener(id string, listener Listener) {
	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()

	p.listeners[id] = listener
}

// RemoveListener removes the listener from the listener list.
func (p *Peering) RemoveListener(id string) {
	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()

	delete(p.listeners, id)
}

// CloseListener closes the listener with the given ID.
func (p *Peering) CloseListener(id string) {
	var ln Listener
	func() {
		p.listenersLock.Lock()
		defer p.listenersLock.Unlock()

		ln = p.listeners[id]
	}()

	if ln != nil {
		ln.Close(func() {
			p.mgr.Info(
				"closing listener (by manager)",
				"bind", ln.ID(),
			)
		})
		p.RemoveListener(id)
	}
}

func (p *Peering) closeAllListeners() {
	for id, l := range p.copyListenersWithLocking() {
		ln := l
		ln.Close(func() {
			p.mgr.Info(
				"closing listener (by manager)",
				"bind", ln.ID(),
			)
		})
		p.RemoveListener(id)
	}
}

func (p *Peering) copyLinksWithLocking() map[netip.Addr]Link {
	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()

	return maps.Clone[map[netip.Addr]Link, netip.Addr, Link](p.links)
}

func (p *Peering) copyListenersWithLocking() map[string]Listener {
	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()

	return maps.Clone[map[string]Listener, string, Listener](p.listeners)
}
