package router

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/fxamacker/cbor/v2"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/peering"
)

const disconnectPingType = "disconnect"

// DisconnectPingHandler handles announce pings.
type DisconnectPingHandler struct {
	r *Router
}

var _ PingHandler = &DisconnectPingHandler{}

// NewDisconnectPingHandler returns a new announce ping handler.
func NewDisconnectPingHandler(r *Router) *DisconnectPingHandler {
	return &DisconnectPingHandler{
		r: r,
	}
}

// Type returns the ping type.
func (h *DisconnectPingHandler) Type() string {
	return disconnectPingType
}

// Clean cleans any internal state of the ping handler.
func (h *DisconnectPingHandler) Clean(w *mgr.WorkerCtx) error {
	return nil
}

// DisconnectPingMsg is a disconnect ping message.
type DisconnectPingMsg struct {
	// GoingDown signifies that the router is about to go offline.
	GoingDown bool `cbor:"off,omitempty" json:"off,omitempty"`

	// Disconnected holds a list of routers that are no longer connected to the announcing router.
	// Ignored when GoingDown is set.
	Disconnected []netip.Addr `cbor:"d,omitempty" json:"d,omitempty"`
}

// Send sends a hello message to the given destination.
func (h *DisconnectPingHandler) Send(goingDown bool, disconnected []netip.Addr) error {
	// Create msg.
	msg := DisconnectPingMsg{
		GoingDown: goingDown,
	}
	if !goingDown {
		msg.Disconnected = disconnected
	}
	data, err := cbor.Marshal(&msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// Send announcement.
	err = h.r.sendPingMsg(sendPingOpts{
		dst:      m.RouterAddress,
		msgType:  frame.RouterPing,
		pingType: disconnectPingType,
		pingData: data,
	})
	if err != nil {
		return fmt.Errorf("send ping: %w", err)
	}

	if goingDown {
		h.r.mgr.Info(
			"sent disconnect ping",
			"disconnect", "all",
		)
	} else {
		h.r.mgr.Info(
			"sent disconnect ping",
			"disconnect", len(disconnected),
		)
	}

	return nil
}

// Handle handles incoming ping frames.
func (h *DisconnectPingHandler) Handle(w *mgr.WorkerCtx, f frame.Frame, hdr *PingHeader, data []byte) error {
	// Parse announce msg.
	msg := &DisconnectPingMsg{}
	err := cbor.Unmarshal(data, msg)
	if err != nil {
		return fmt.Errorf("unmarshal message data: %w", err)
	}

	// Mark router as offline in state/storage.
	if msg.GoingDown {
		if err := h.r.instance.State().MarkRouterOffline(f.SrcIP()); err != nil {
			w.Warn(
				"failed to mark router as offline",
				"router", f.SrcIP(),
				"err", err,
			)
		}
		msg.Disconnected = nil
	}

	// Remove any applicable routes.
	removed := h.r.table.RemoveDisconnected(f.SrcIP(), nil)

	// If nothing was removed, do not process further.
	if removed == 0 {
		return nil
	}

	// Log route removal.
	w.Debug(
		"removed disconnected routes",
		"router", f.SrcIP(),
		"count", removed,
	)

	// Never forward if router is a stub.
	if h.r.instance.Config().Router.Stub {
		return nil
	}

	// Get recv link.
	recvLink := f.RecvLink()
	if recvLink == nil {
		return errors.New("disconnect ping requires recv link for handling")
	}

	// Forward to peers.
	links := h.r.instance.Peering().GetLinks()
forwardToPeers:
	for i, forwardLink := range links {
		// Check if the announcement should be forwarded to this link.
		switch {
		case forwardLink == nil:
			// Check if link is valid.
			continue forwardToPeers

		case forwardLink.Lite() &&
			!h.r.instance.Config().Router.Lite:
			// Do not send announcement to lite mode routers.
			// Except, when this router is in lite mode too.
			continue forwardToPeers

		case forwardLink.Peer() == f.SrcIP():
			// Do not send to announcing router.
			continue forwardToPeers

		case forwardLink.Peer() == recvLink.Peer():
			// Do not send back to link where it came from.
			continue forwardToPeers
		}

		// Clone frame for all but last link.
		var sendFrame frame.Frame
		if i < len(links)-1 {
			sendFrame = f.Clone()
		} else {
			sendFrame = f
		}

		// Forward to link.
		err := h.r.instance.Switch().ForwardByPeer(sendFrame, forwardLink.Peer())
		if err != nil {
			w.Warn(
				"failed to forward disconnect ping",
				"err", err,
			)
		}
	}

	return nil
}

func (r *Router) disconnectWorker(w *mgr.WorkerCtx) error {
	// Subscribe to peering events.
	sub := r.instance.Peering().PeeringEvents.Subscribe("send disconnect pings", 10)
	defer sub.Cancel()

	for {
		select {
		case event := <-sub.Events():
			if event.State == peering.EventStateDown {
				if err := r.DisconnectPing.Send(false, []netip.Addr{event.Peer}); err != nil {
					w.Warn(
						"failed to send disconnect ping",
						"err", err,
					)
				}
			}
		case <-w.Done():
			return nil
		}
	}
}
