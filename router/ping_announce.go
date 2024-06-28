package router

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/peering"
	"github.com/mycoria/mycoria/state"
)

const (
	announcePingType = "announce"
	announceInterval = 5 * time.Minute
)

var errAnnouncementIsLooping = errors.New("announcement is looping")

// AnnouncePingHandler handles announce pings.
type AnnouncePingHandler struct {
	r *Router
}

var _ PingHandler = &AnnouncePingHandler{}

// NewAnnouncePingHandler returns a new announce ping handler.
func NewAnnouncePingHandler(r *Router) *AnnouncePingHandler {
	return &AnnouncePingHandler{
		r: r,
	}
}

// Type returns the ping type.
func (h *AnnouncePingHandler) Type() string {
	return announcePingType
}

// Clean cleans any internal state of the ping handler.
func (h *AnnouncePingHandler) Clean(w *mgr.WorkerCtx) error {
	return nil
}

// AnnouncePingMsg is an announce ping message.
type AnnouncePingMsg struct {
	Info        *m.RouterInfo `cbor:"i,omitempty" json:"i,omitempty"`
	ReturnLabel m.SwitchLabel `cbor:"b,omitempty" json:"b,omitempty"`
	// Stub signifies that the router is a dead end:
	// It only has 1 peer or only lite peers.
	Stub    bool      `cbor:"s,omitempty" json:"s,omitempty"`
	Expires time.Time `cbor:"e,omitempty" json:"e,omitempty"`
}

// AnnouncePingAttachment is an announce ping attachment.
type AnnouncePingAttachment struct {
	Router       m.PublicAddress `cbor:"r"           json:"r"`
	Delay        uint16          `cbor:"d,omitempty" json:"d,omitempty"`
	ForwardLabel m.SwitchLabel   `cbor:"f,omitempty" json:"f,omitempty"`
	ReturnLabel  m.SwitchLabel   `cbor:"b,omitempty" json:"b,omitempty"`

	NextAttachment []byte `cbor:"n,omitempty" json:"n,omitempty"`
}

// Send sends a hello message to the given destination.
func (h *AnnouncePingHandler) Send(peer netip.Addr) error {
	// Get link of peer where to send announcement to.
	link := h.r.instance.Peering().GetLink(peer)
	if link == nil {
		return errors.New("peer link not found")
	}

	// Get info to announce and marshal.
	msg := AnnouncePingMsg{}
	msg.Info = h.r.instance.Config().GetRouterInfo()
	msg.Info.Version = h.r.instance.Version()
	msg.ReturnLabel = link.SwitchLabel()
	msg.Expires = time.Now().Add(announceInterval*2 + 10*time.Second)
	msg.Stub = h.r.instance.Config().Router.Stub || h.r.instance.Peering().IsStub()
	data, err := cbor.Marshal(&msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// Send announcement.
	err = h.r.sendPingMsg(sendPingOpts{
		dst:      m.RouterAddress,
		msgType:  frame.RouterHopPingDeprecated,
		pingType: announcePingType,
		pingData: data,
	})
	if err != nil {
		return fmt.Errorf("send ping: %w", err)
	}

	return nil
}

// Handle handles incoming ping frames.
func (h *AnnouncePingHandler) Handle(w *mgr.WorkerCtx, f frame.Frame, hdr *PingHeader, data []byte) error {
	// Get recv link.
	recvLink := f.RecvLink()
	if recvLink == nil {
		return errors.New("announce ping requires recv link for handling")
	}

	// Parse announement ping, including appendix data.
	msg, hops, err := h.parseAnnouncePing(f, data)
	if err != nil {
		// If the announcement is looping, ignore it.
		if errors.Is(err, errAnnouncementIsLooping) {
			return nil
		}

		return fmt.Errorf("parse announce ping: %w", err)
	}

	// If there are no hops, check if the source matches the peer.
	if len(hops) == 0 && f.SrcIP() != recvLink.Peer() {
		return errors.New("announce ping has no appendix, but source does not match peer")
	}

	// If there are hops, the last hop must match the peer.
	if len(hops) > 0 && hops[0].Router != recvLink.Peer() {
		return errors.New("last announce ping attachment does not match peer")
	}

	// Add router info to state.
	err = h.r.instance.State().AddPublicRouterInfo(f.SrcIP(), msg.Info)
	if err != nil {
		w.Error(
			"failed to save public router info",
			"router", f.SrcIP(),
			"err", err,
		)
	}

	// Add route to routing table.
	switchPath := m.SwitchPath{
		Hops: make([]m.SwitchHop, 0, len(hops)+2),
	}
	// Add own entry as first.
	switchPath.Hops = append(switchPath.Hops, m.SwitchHop{
		Router:       h.r.instance.Identity().IP,
		Delay:        recvLink.Latency(),
		ForwardLabel: recvLink.SwitchLabel(),
		ReturnLabel:  0,
	})
	// Add stacked hops in reverse order.
	for _, hop := range hops {
		switchPath.Hops = append(switchPath.Hops, m.SwitchHop{
			Router:       hop.Router,
			Delay:        hop.Delay,
			ForwardLabel: hop.ForwardLabel,
			ReturnLabel:  hop.ReturnLabel,
		})
	}
	// Add announcing router as last.
	switchPath.Hops = append(switchPath.Hops, m.SwitchHop{
		Router:       f.SrcIP(),
		Delay:        0,
		ForwardLabel: 0,
		ReturnLabel:  msg.ReturnLabel,
	})
	switchPath.CalculateTotals()
	// Create table entry.
	rte := m.RoutingTableEntry{
		DstIP:   f.SrcIP(),
		NextHop: recvLink.Peer(),
		Path:    switchPath,
		Stub:    msg.Stub,
		Source:  m.RouteSourcePeer,
	}
	if len(hops) > 0 {
		rte.Source = m.RouteSourceGossip
		rte.Expires = msg.Expires
	}
	// Add to table.
	added, err := h.r.table.AddRoute(rte)
	switch {
	case err != nil:
		w.Warn(
			"failed to add entry to routing table",
			"dst", f.SrcIP(),
			"err", err,
		)
	case added:
		w.Info(
			"updated routing entry",
			"router", f.SrcIP(),
			"nexthop", recvLink.Peer(),
			"hops", switchPath.TotalHops,
		)
	default:
		// Not added to routing table.
		// Do not forward.
		return nil
	}

	// Never forward if router is a stub.
	if h.r.instance.Config().Router.Stub {
		return nil
	}

	// Select peers to forward to.
	var forwardTo []peering.Link
	if f.DstIP() == m.RouterAddress {
		// If announcement is destined for all routers, forward to all links.
		forwardTo = h.r.instance.Peering().GetLinks()
	} else {
		// Otherwise, only forward to best next hop.
		rte, _ := h.r.table.LookupNearestRoute(f.DstIP())
		if rte == nil {
			return errors.New("not routing: table empty")
		}
		forwardTo = []peering.Link{h.r.instance.Peering().GetLink(rte.NextHop)}
	}

	// Forward to all peers, except where it came from.
	apx := f.AppendixData()
	signingContext := h.signingContext(f)
forwardToPeers:
	for _, sendLink := range forwardTo {
		// Check if the announcement should be forwarded to this link.
		switch {
		case sendLink == nil:
			// Check if link is valid.
			continue forwardToPeers

		case sendLink.Lite() &&
			!h.r.instance.Config().Router.Lite:
			// Do not send announcement to lite mode routers.
			// Except, when this router is in lite mode too.
			continue forwardToPeers

		case sendLink.Peer() == f.SrcIP():
			// Do not send to announcing router.
			continue forwardToPeers

		case sendLink.Peer() == recvLink.Peer():
			// Do not send back to link where it came from.
			continue forwardToPeers

		default:
			// Do not send to peers which are already in the hops.
			for _, hop := range hops {
				if sendLink.Peer() == hop.Router {
					continue forwardToPeers
				}
			}
		}

		// Clone frame.
		fwd := f.Clone()

		// Marshal attachment.
		attach := AnnouncePingAttachment{
			Router:         h.r.instance.Identity().PublicAddress,
			Delay:          recvLink.Latency(),
			ForwardLabel:   recvLink.SwitchLabel(),
			ReturnLabel:    sendLink.SwitchLabel(),
			NextAttachment: apx,
		}
		attachData, err := cbor.Marshal(attach)
		if err != nil {
			return fmt.Errorf("forward: marshal attachment: %w", err)
		}

		// Sign attachment.
		sig, err := h.r.instance.Identity().SignWithContext(attachData, signingContext)
		if err != nil {
			return fmt.Errorf("forward: sign with context: %w", err)
		}
		attachData = append(attachData, sig...)

		// Set new appendix and forward frame to peer.
		err = fwd.SetAppendixData(attachData)
		if err != nil {
			return fmt.Errorf("forward: set new appendix: %w", err)
		}
		err = h.r.instance.Switch().ForwardByPeer(fwd, sendLink.Peer())
		if err != nil {
			w.Warn(
				"failed to route forwarded announce ping",
				"src", f.SrcIP(),
				"err", err,
			)
		}
	}

	return nil
}

func (h *AnnouncePingHandler) signingContext(f frame.Frame) []byte {
	context := make([]byte,
		16+ // Source IP
			8+ // Ping Timestamp
			64) // Ed25519 Signature

	// Copy all context data.
	copy(context[:16], f.SrcIP().AsSlice())
	m.PutUint64(context[16:24], uint64(f.SequenceTime().UnixMilli()))
	copy(context[24:], f.AuthData())

	return context
}

func (h *AnnouncePingHandler) parseAnnouncePing(f frame.Frame, pingData []byte) (*AnnouncePingMsg, []m.SwitchHop, error) {
	// Parse announce msg.
	msg := &AnnouncePingMsg{}
	err := cbor.Unmarshal(pingData, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal message data: %w", err)
	}

	// Parse switch path.
	hops := make([]m.SwitchHop, 0, 10) // TODO: Can we estimate this better?
	apx := f.AppendixData()
	signingContext := h.signingContext(f)
	for i := 1; i <= 100; i++ {
		// Check if there is data left.
		if len(apx) == 0 {
			break
		}

		// Stop at some point.
		if i == 100 {
			return nil, nil, errors.New("max recursion of 100 reached")
		}

		// Check size of appendix data.
		if len(apx) < 65 {
			return nil, nil, errors.New("appendix too small for announce attachment")
		}

		// Parse attachment.
		attached := AnnouncePingAttachment{}
		err := cbor.Unmarshal(apx[:len(apx)-64], &attached)
		if err != nil {
			return nil, nil, fmt.Errorf("unmarshal announce attachment at layer %d: %w", i, err)
		}

		// Check if this us.
		if attached.Router.IP == h.r.instance.Identity().IP {
			return nil, nil, errAnnouncementIsLooping
		}

		// Get (or create) session.
		session, err := h.sessionFromAnnouncePingAttachment(&attached)
		if err != nil {
			return nil, nil, fmt.Errorf("get session for %s at layer %d: %w", attached.Router.IP, i, err)
		}

		// Verify signature.
		sigStart := len(apx) - 64
		err = session.Address().VerifySigWithContext(apx[:sigStart], apx[sigStart:], signingContext)
		if err != nil {
			return nil, nil, fmt.Errorf("verify attachment of %s at layer %d: %w", attached.Router.IP, i, err)
		}

		// Add hop to list.
		hops = append(hops, m.SwitchHop{
			Router:       attached.Router.IP,
			Delay:        attached.Delay,
			ForwardLabel: attached.ForwardLabel,
			ReturnLabel:  attached.ReturnLabel,
		})

		// Set apx to next attachment.
		apx = attached.NextAttachment
	}

	return msg, hops, nil
}

func (h *AnnouncePingHandler) sessionFromAnnouncePingAttachment(a *AnnouncePingAttachment) (*state.Session, error) {
	// Get (or create) session.
	session := h.r.instance.State().GetSession(a.Router.IP)
	if session != nil {
		return session, nil
	}

	// Check and add router address.
	if err := a.Router.VerifyAddress(); err != nil {
		return nil, fmt.Errorf("announce ping attachment address data invalid: %w", err)
	}
	if err := h.r.instance.State().AddRouter(&a.Router); err != nil {
		return nil, fmt.Errorf("add router to state: %w", err)
	}

	// Get session for newly added router.
	session = h.r.instance.State().GetSession(a.Router.IP)
	if session == nil {
		return nil, errors.New("internal state failure")
	}

	return session, nil
}

func (r *Router) announceWorker(w *mgr.WorkerCtx) error {
	// Try to announce first time 5 seconds after start.
	time.Sleep(5 * time.Second)
	r.announceRouter(w)

	ticker := time.NewTicker(announceInterval)
	for {
		select {
		case <-w.Done():
			return nil
		case <-ticker.C:
			r.announceRouter(w)
		}
	}
}

func (r *Router) announceRouter(w *mgr.WorkerCtx) {
	for _, link := range r.instance.Peering().GetLinks() {
		if err := r.AnnouncePing.Send(link.Peer()); err != nil {
			w.Warn(
				"failed to announce to peer",
				"router", link.Peer(),
				"err", err,
			)
		}
	}
}
