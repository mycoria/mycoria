package router

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
)

const (
	errorPingType     = "error"
	errorSendCooldown = 10 * time.Second
	errorRecvCooldown = 10 * time.Second
	errorCleanup      = 10 * time.Minute
)

// ErrorPingHandler handles announce pings.
type ErrorPingHandler struct {
	r *Router

	routerStates     map[netip.Addr]*routerErrorState
	routerStatesLock sync.Mutex
}

type errCode uint8

// routerErrorState is router error state.
type routerErrorState struct {
	sync.Mutex

	sent map[errCode]time.Time
	rcvd map[errCode]time.Time

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
		sent:         make(map[errCode]time.Time),
		rcvd:         make(map[errCode]time.Time),
		lastActivity: time.Now(),
	}
	h.routerStates[remote] = state
	return state
}

func (h *ErrorPingHandler) maySend(errCode errCode, remote netip.Addr) bool {
	state := h.getOrCreateState(remote)
	state.Lock()
	defer state.Unlock()

	// Check if we have a record for this error.
	lastSent, ok := state.sent[errCode]
	if ok && time.Since(lastSent) < errorSendCooldown {
		// If within cooldown, don't send again.
		return false
	}

	// If not sent or outside of cooldown, update timestamp and allow sending.
	state.sent[errCode] = time.Now()
	return true
}

func (h *ErrorPingHandler) mayRecv(errCode errCode, remote netip.Addr) bool {
	state := h.getOrCreateState(remote)
	state.Lock()
	defer state.Unlock()

	// Check if we have a record for this error.
	lastRcvd, ok := state.rcvd[errCode]
	if ok && time.Since(lastRcvd) < errorRecvCooldown {
		// If within cooldown, don't receive again.
		return false
	}

	// If not received or outside of cooldown, update timestamp and allow sending.
	state.rcvd[errCode] = time.Now()
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

// Error Ping Codes.
const (
	pingCodeErrorGeneric          errCode = 0
	pingCodeErrorUnreachable      errCode = 1
	pingCodeErrorNoEncryptionKeys errCode = 2
	pingCodeErrorAccessDenied     errCode = 3
)

type unreachableMsg struct {
	Unreachable netip.Addr `cbor:"u,omitempty" json:"u,omitempty"`
}

type accessDeniedMsg struct {
	DstIP    netip.Addr `cbor:"d,omitempty" json:"d,omitempty"`
	Protocol uint8      `cbor:"t,omitempty" json:"t,omitempty"`
	DstPort  uint16     `cbor:"p,omitempty" json:"p,omitempty"`
}

// SendGeneric sends a generic error.
func (h *ErrorPingHandler) SendGeneric(to netip.Addr, text string) error {
	return h.sendError(to, frame.RouterPing, pingCodeErrorGeneric, text)
}

// SendUnreachable sends an unreachable error.
func (h *ErrorPingHandler) SendUnreachable(to, unreachable netip.Addr) error {
	return h.sendError(to, frame.RouterPing, pingCodeErrorUnreachable, &unreachableMsg{
		Unreachable: unreachable,
	})
}

// SendNoEncryptionKeys sends a "no encryption keys" error.
func (h *ErrorPingHandler) SendNoEncryptionKeys(to netip.Addr) error {
	return h.sendError(to, frame.RouterPing, pingCodeErrorNoEncryptionKeys, nil)
}

// SendAccessDenied sends an access denied error.
func (h *ErrorPingHandler) SendAccessDenied(to netip.Addr, dstIP netip.Addr, protocol uint8, dstPort uint16) error {
	return h.sendError(to, frame.RouterCtrl, pingCodeErrorAccessDenied, &accessDeniedMsg{
		DstIP:    dstIP,
		Protocol: protocol,
		DstPort:  dstPort,
	})
}

// Send sends a hello message to the given destination.
func (h *ErrorPingHandler) sendError(to netip.Addr, msgType frame.MessageType, errCode errCode, data any) error {
	// Check if we may send.
	if !h.maySend(errCode, to) {
		// Ignore.
		return nil
	}

	// Marshal error message.
	pingData, err := cbor.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// Send error.
	err = h.r.sendPingMsg(to, msgType, 0, errorPingType, uint8(errCode), pingData, false)
	if err != nil {
		return fmt.Errorf("send ping: %w", err)
	}

	return nil
}

// Handle handles incoming ping frames.
func (h *ErrorPingHandler) Handle(w *mgr.WorkerCtx, f frame.Frame, hdr *PingHeader, data []byte) error {
	// Check if we may receive.
	if !h.mayRecv(errCode(hdr.PingCode), f.SrcIP()) {
		// Ignore.
		return nil
	}

	// Handle depending on error code.
	switch errCode(hdr.PingCode) {
	case pingCodeErrorGeneric:
		w.Warn(
			"received generic error ping",
			"router", f.SrcIP(),
			"err", m.SafeString(string(data)),
		)

	case pingCodeErrorUnreachable:
		// Parse error message.
		msg := &unreachableMsg{}
		err := cbor.Unmarshal(data, msg)
		if err != nil {
			return fmt.Errorf("unmarshal: %w", err)
		}
		h.r.markUnreachable(msg.Unreachable)

	case pingCodeErrorNoEncryptionKeys:
		// Removing the encryption setting will trigger the next packet to that
		// router to setup up new encryption keys.
		// Error is only returned when router has no session.
		_ = h.r.instance.State().SetEncryptionSession(f.SrcIP(), nil)

	case pingCodeErrorAccessDenied:
		// Parse error message.
		msg := &accessDeniedMsg{}
		err := cbor.Unmarshal(data, msg)
		if err != nil {
			return fmt.Errorf("unmarshal: %w", err)
		}
		h.r.markAccessDenied(msg.DstIP, msg.Protocol, msg.DstPort)

	default:
		w.Debug(
			"received unknown error ping",
			"router", f.SrcIP(),
			"code", hdr.PingCode,
			"err", m.SafeString(string(data)),
		)
	}

	return nil
}
