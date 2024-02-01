package router

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/mgr"
)

const (
	errorPingType     = "error"
	errorSendCooldown = 10 * time.Second
	errorRecvCooldown = 10 * time.Second
	errorCleanup      = 10 * time.Minute
)

// Error IDs.
const (
	PingErrorNoRoute          = "no route"
	PingErrorNoEncryptionKeys = "no encryption keys"
)

// ErrorPingHandler handles announce pings.
type ErrorPingHandler struct {
	r *Router

	routerStates     map[netip.Addr]*routerErrorState
	routerStatesLock sync.Mutex
}

// routerErrorState is router error state.
type routerErrorState struct {
	sync.Mutex

	sent map[string]time.Time
	rcvd map[string]time.Time

	lastActivity time.Time
}

var _ PingHandler = &ErrorPingHandler{}

// NewErrorPingHandler returns a new announce ping handler.
func NewErrorPingHandler(r *Router) *ErrorPingHandler {
	return &ErrorPingHandler{
		r:            r,
		routerStates: make(map[netip.Addr]*routerErrorState),
	}
}

// Type returns the ping type.
func (h *ErrorPingHandler) Type() string {
	return errorPingType
}

func (h *ErrorPingHandler) getOrCreateState(remote netip.Addr) *routerErrorState {
	h.routerStatesLock.Lock()
	defer h.routerStatesLock.Unlock()

	// Check if we already have a state.
	state, ok := h.routerStates[remote]
	if ok {
		// Update last activity and return.
		state.lastActivity = time.Now()
		return state
	}

	// Create new state, save and return.
	state = &routerErrorState{
		sent:         make(map[string]time.Time),
		rcvd:         make(map[string]time.Time),
		lastActivity: time.Now(),
	}
	h.routerStates[remote] = state
	return state
}

func (h *ErrorPingHandler) maySend(errID string, remote netip.Addr) bool {
	state := h.getOrCreateState(remote)
	state.Lock()
	defer state.Unlock()

	// Check if we have a record for this error.
	lastSent, ok := state.sent[errID]
	if ok && time.Since(lastSent) < errorSendCooldown {
		// If within cooldown, don't send again.
		return false
	}

	// If not sent or outside of cooldown, update timestamp and allow sending.
	state.sent[errID] = time.Now()
	return true
}

func (h *ErrorPingHandler) mayRecv(errID string, remote netip.Addr) bool {
	state := h.getOrCreateState(remote)
	state.Lock()
	defer state.Unlock()

	// Check if we have a record for this error.
	lastRcvd, ok := state.rcvd[errID]
	if ok && time.Since(lastRcvd) < errorRecvCooldown {
		// If within cooldown, don't receive again.
		return false
	}

	// If not received or outside of cooldown, update timestamp and allow sending.
	state.rcvd[errID] = time.Now()
	return true
}

// Clean cleans any internal state of the ping handler.
func (h *ErrorPingHandler) Clean(w *mgr.WorkerCtx) error {
	h.routerStatesLock.Lock()
	defer h.routerStatesLock.Unlock()

	deleteOlderThan := time.Now().Add(-errorCleanup)
	for remote, state := range h.routerStates {
		if state.lastActivity.Before(deleteOlderThan) {
			delete(h.routerStates, remote)
		}
	}

	return nil
}

// ErrorPingMsg is an error ping message.
type ErrorPingMsg struct {
	ID  string `cbor:"e,omitempty" json:"e,omitempty"`
	Msg string `cbor:"m,omitempty" json:"m,omitempty"`
}

// Send sends a hello message to the given destination.
func (h *ErrorPingHandler) Send(errID, msg string, to netip.Addr) error {
	// Check if we may send.
	if !h.maySend(errID, to) {
		// Ignore.
		return nil
	}

	// Marshal error message.
	data, err := cbor.Marshal(&ErrorPingMsg{
		ID:  errID,
		Msg: msg,
	})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// Send error.
	err = h.r.sendPingMsg(to, 0, errorPingType, data, false, false)
	if err != nil {
		return fmt.Errorf("send ping: %w", err)
	}

	return nil
}

// Handle handles incoming ping frames.
func (h *ErrorPingHandler) Handle(w *mgr.WorkerCtx, f frame.Frame, hdr *PingHeader, data []byte) error {
	// Parse error message.
	msg := &ErrorPingMsg{}
	err := cbor.Unmarshal(data, msg)
	if err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	// Check if we may receive.
	if !h.mayRecv(msg.ID, f.SrcIP()) {
		// Ignore.
		return nil
	}

	switch msg.ID {
	case PingErrorNoRoute:
		// TODO: Mark in session as non-existent router?

	case PingErrorNoEncryptionKeys:
		// Removing the encryption setting will trigger the next packet to that
		// router to setup up new encryption keys.
		// Error is only returned when router has no session.
		_ = h.r.instance.State().SetEncryptionSession(f.SrcIP(), nil)

	default:
		w.Debug(
			"received unknown error ping",
			"id", msg.ID,
			"msg", msg.Msg,
			"router", f.SrcIP(),
		)
		return nil
	}

	w.Debug(
		"received error ping",
		"id", msg.ID,
		"msg", msg.Msg,
		"router", f.SrcIP(),
	)

	return nil
}
