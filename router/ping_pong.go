package router

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/mgr"
)

const pingPongPingType = "pong"

// PingPongHandler handles pong pings.
type PingPongHandler struct {
	r *Router

	active     map[uint64]*pingPongState
	activeLock sync.Mutex
}

// pingPongState is pong ping state.
type pingPongState struct {
	started time.Time

	notify  chan struct{}
	expires time.Time
}

var _ PingHandler = &PingPongHandler{}

// NewPingPongHandler returns a new pong ping handler.
func NewPingPongHandler(r *Router) *PingPongHandler {
	return &PingPongHandler{
		r:      r,
		active: make(map[uint64]*pingPongState),
	}
}

// Type returns the ping type.
func (h *PingPongHandler) Type() string {
	return pingPongPingType
}

func (h *PingPongHandler) setActive(pingID uint64, pongState *pingPongState) {
	h.activeLock.Lock()
	defer h.activeLock.Unlock()

	pongState.expires = time.Now().Add(30 * time.Second)
	h.active[pingID] = pongState
}

func (h *PingPongHandler) getActive(pingID uint64) *pingPongState {
	h.activeLock.Lock()
	defer h.activeLock.Unlock()

	return h.active[pingID]
}

func (h *PingPongHandler) pluckActive(pingID uint64) *pingPongState {
	h.activeLock.Lock()
	defer h.activeLock.Unlock()

	state, ok := h.active[pingID]
	if !ok {
		return nil
	}

	delete(h.active, pingID)
	return state
}

// Clean cleans any internal state of the ping handler.
func (h *PingPongHandler) Clean(w *mgr.WorkerCtx) error {
	h.activeLock.Lock()
	defer h.activeLock.Unlock()

	now := time.Now()
	for pingID, pongState := range h.active {
		if now.After(pongState.expires) {
			delete(h.active, pingID)
		}
	}

	return nil
}

// pingPongMsg is a ping pong message.
type pingPongMsg struct {
	Msg string `cbor:"msg,omitempty" json:"msg,omitempty"`
}

// Send sends a pong message to the given destination.
func (h *PingPongHandler) Send(dstIP netip.Addr, peer bool, retryPingID uint64) (notify <-chan struct{}, pingID uint64, err error) {
	pingID = retryPingID

	// Create message and marshal it.
	msg := pingPongMsg{
		Msg: "ping",
	}
	data, err := cbor.Marshal(&msg)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal: %w", err)
	}

	// Get or create state.
	var pingState *pingPongState
	if pingID != 0 {
		pingState = h.getActive(pingID)
	}
	if pingState == nil {
		pingState = &pingPongState{
			started: time.Now(),
			notify:  make(chan struct{}),
		}
	}

	// Send ping.
	if pingID == 0 {
		pingID = newPingID()
	}
	opts := sendPingOpts{
		msgType:  frame.RouterPing,
		pingID:   pingID,
		pingType: pingPongPingType,
		pingData: data,
	}
	if peer {
		opts.peer = dstIP
	} else {
		opts.dst = dstIP
	}
	err = h.r.sendPingMsg(opts)
	if err != nil {
		return nil, 0, fmt.Errorf("send ping: %w", err)
	}

	// Ping is sent, save to state.
	h.setActive(pingID, pingState)
	return pingState.notify, pingID, nil
}

// Handle handles incoming ping frames.
func (h *PingPongHandler) Handle(w *mgr.WorkerCtx, f frame.Frame, hdr *PingHeader, data []byte) error {
	if hdr.FollowUp {
		return h.handleResponse(w, f, hdr, data)
	}
	return h.handleRequest(w, f, hdr, data)
}

func (h *PingPongHandler) handleRequest(_ *mgr.WorkerCtx, f frame.Frame, hdr *PingHeader, data []byte) error { //nolint:unparam
	// Parse request.
	msg := pingPongMsg{}
	if err := cbor.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("unmarshal msg: %w", err)
	}
	if msg.Msg != "ping" {
		return errors.New("invalid ping pong request")
	}

	// Create response and send it.
	msg = pingPongMsg{
		Msg: "pong",
	}
	data, err := cbor.Marshal(&msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	err = h.r.sendPingMsg(sendPingOpts{
		dst:      f.SrcIP(),
		msgType:  frame.RouterPing,
		pingID:   hdr.PingID,
		pingType: pingPongPingType,
		pingData: data,
		followUp: true,
	})
	if err != nil {
		return fmt.Errorf("send ping pong response: %w", err)
	}

	// DEBUG:
	// w.Debug(
	// 	"ping pong (server) successful",
	// 	"router", f.SrcIP(),
	// )
	return nil
}

func (h *PingPongHandler) handleResponse(_ *mgr.WorkerCtx, _ frame.Frame, hdr *PingHeader, data []byte) error { //nolint:unparam
	// Get ping state.
	pingState := h.pluckActive(hdr.PingID)
	if pingState == nil {
		return errors.New("no state")
	}

	// Parse and check response.
	response := pingPongMsg{}
	if err := cbor.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	if response.Msg != "pong" {
		return errors.New("invalid ping pong response")
	}

	// Notify waiters and set state again to block too quick requests.
	close(pingState.notify)

	// DEBUG:
	// w.Debug(
	// 	"ping pong (client) successful",
	// 	"router", f.SrcIP(),
	// )
	return nil
}
