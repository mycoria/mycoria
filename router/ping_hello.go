package router

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/state"
)

const helloPingType = "hello"

// HelloPingHandler handles hello pings.
type HelloPingHandler struct {
	r *Router

	sendLock sync.Mutex

	active     map[netip.Addr]*helloPingState
	activeLock sync.Mutex
}

// helloPingState is hello ping state.
type helloPingState struct {
	pingID     uint64
	encSession *state.EncryptionSession

	done    atomic.Bool
	notify  chan struct{}
	expires time.Time
}

var _ PingHandler = &HelloPingHandler{}

// NewHelloPingHandler returns a new hello ping handler.
func NewHelloPingHandler(r *Router) *HelloPingHandler {
	return &HelloPingHandler{
		r:      r,
		active: make(map[netip.Addr]*helloPingState),
	}
}

// Type returns the ping type.
func (h *HelloPingHandler) Type() string {
	return helloPingType
}

func (h *HelloPingHandler) getActive(remote netip.Addr) *helloPingState {
	h.activeLock.Lock()
	defer h.activeLock.Unlock()

	state := h.active[remote]
	if state != nil && time.Now().Before(state.expires) {
		return state
	}

	return nil
}

func (h *HelloPingHandler) setActive(remote netip.Addr, helloState *helloPingState) {
	h.activeLock.Lock()
	defer h.activeLock.Unlock()

	h.active[remote] = helloState
}

// Clean cleans any internal state of the ping handler.
func (h *HelloPingHandler) Clean(w *mgr.WorkerCtx) error {
	h.activeLock.Lock()
	defer h.activeLock.Unlock()

	now := time.Now()
	for remote, helloState := range h.active {
		if now.After(helloState.expires) {
			delete(h.active, remote)
		}
	}

	return nil
}

// HelloPingRequest is a hello ping request.
type HelloPingRequest struct {
	KeyExchange     []byte `cbor:"kx,omitempty"  json:"kx,omitempty"`
	KeyExchangeType string `cbor:"kxt,omitempty" json:"kxt,omitempty"`

	MTU int `cbor:"mtu,omitempty" json:"mtu,omitempty"`
}

// HelloPingResponse is a hello ping response.
type HelloPingResponse struct {
	KeyExchange     []byte `cbor:"kx,omitempty"  json:"kx,omitempty"`
	KeyExchangeType string `cbor:"kxt,omitempty" json:"kxt,omitempty"`

	MTU int `cbor:"mtu,omitempty" json:"mtu,omitempty"`

	Err string `cbor:"err,omitempty" json:"err,omitempty"`
}

// Send sends a hello message to the given destination.
func (h *HelloPingHandler) Send(dstIP netip.Addr) (notify <-chan struct{}, err error) {
	// Make sure we don't sent a hello ping twice.
	h.sendLock.Lock()
	defer h.sendLock.Unlock()

	// Check if we already have an active hello ping.
	if pingState := h.getActive(dstIP); pingState != nil {
		return pingState.notify, ErrAlreadyActive
	}
	pingState := &helloPingState{
		pingID: newPingID(),
		notify: make(chan struct{}),
	}

	// Initialize encryption session decoupled, as destination may not be known.
	pingState.encSession = state.NewEncryptionSession()
	kxKey, kxType, err := pingState.encSession.InitKeyClientStart()
	if err != nil {
		return nil, fmt.Errorf("init key exchange: %w", err)
	}

	// Create request and send it.
	request := HelloPingRequest{
		KeyExchange:     kxKey,
		KeyExchangeType: kxType,
		MTU:             h.r.instance.Config().TunMTU(),
	}
	data, err := cbor.Marshal(&request)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	// Send new ping.
	err = h.r.sendPingMsg(sendPingOpts{
		dst:      dstIP,
		msgType:  frame.RouterPing,
		pingID:   pingState.pingID,
		pingType: helloPingType,
		pingData: data,
	})
	if err != nil {
		return nil, fmt.Errorf("send ping: %w", err)
	}

	h.r.mgr.Debug(
		"sent hello ping",
		"router", dstIP,
	)

	// Ping is sent, add expiry and save to state.
	pingState.expires = time.Now().Add(30 * time.Second)
	h.setActive(dstIP, pingState)
	return pingState.notify, nil
}

// Handle handles incoming ping frames.
func (h *HelloPingHandler) Handle(w *mgr.WorkerCtx, f frame.Frame, hdr *PingHeader, data []byte) error {
	if hdr.FollowUp {
		return h.handlePingHelloResponse(w, f, hdr, data)
	}
	return h.handlePingHelloRequest(w, f, hdr, data)
}

func (h *HelloPingHandler) handlePingHelloRequest(w *mgr.WorkerCtx, f frame.Frame, hdr *PingHeader, data []byte) error {
	// Parse request.
	request := HelloPingRequest{}
	if err := cbor.Unmarshal(data, &request); err != nil {
		return fmt.Errorf("unmarshal request: %w", err)
	}

	// Do key exchange.
	session := h.r.instance.State().GetSession(f.SrcIP())
	if session == nil {
		return fmt.Errorf("internal error: router %s unknown", f.SrcIP())
	}
	kxKey, kxType, err := session.Encryption().InitKeyServer(request.KeyExchange, request.KeyExchangeType)
	if err != nil {
		return fmt.Errorf("server key exchange: %w", err)
	}
	if request.MTU > 0 {
		session.SetTunMTU(request.MTU)
	}

	// Create response and send it.
	response := HelloPingResponse{
		KeyExchange:     kxKey,
		KeyExchangeType: kxType,
		MTU:             h.r.instance.Config().TunMTU(),
	}
	data, err = cbor.Marshal(&response)
	if err != nil {
		return fmt.Errorf("init client key exchange: %w", err)
	}
	err = h.r.sendPingMsg(sendPingOpts{
		dst:      f.SrcIP(),
		msgType:  frame.RouterPing,
		pingID:   hdr.PingID,
		pingType: helloPingType,
		pingData: data,
		followUp: true,
	})
	if err != nil {
		return fmt.Errorf("send hello response: %w", err)
	}

	w.Debug(
		"hello ping successful (server)",
		"router", f.SrcIP(),
	)
	return nil
}

func (h *HelloPingHandler) handlePingHelloResponse(w *mgr.WorkerCtx, f frame.Frame, hdr *PingHeader, data []byte) error {
	// Parse response.
	response := HelloPingResponse{}
	if err := cbor.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	// Get ping state.
	pingState := h.getActive(f.SrcIP())
	if pingState == nil {
		return errors.New("no state")
	}
	// Check ping ID.
	if pingState.pingID != hdr.PingID {
		return errors.New("ping ID mismatch")
	}

	// Check if the already received a response for this ID.
	if !pingState.done.CompareAndSwap(false, true) {
		return errors.New("hello response already processed")
	}

	// Finalize key exchange and set it.
	err := pingState.encSession.InitKeyClientComplete(response.KeyExchange, response.KeyExchangeType)
	if err != nil {
		return fmt.Errorf("complete client key exchange: %w", err)
	}
	pingState.encSession.InitCleanup()

	// Save to session.
	session := h.r.instance.State().GetSession(f.SrcIP())
	if session == nil {
		return fmt.Errorf("internal error: router %s unknown", f.SrcIP())
	}
	session.SetEncryptionSession(pingState.encSession)
	if response.MTU > 0 {
		session.SetTunMTU(response.MTU)
	}

	// Notify waiters, set cooldown (to block too quick requests) and save.
	close(pingState.notify)
	pingState.expires = time.Now().Add(5 * time.Second)
	h.setActive(f.SrcIP(), pingState)

	w.Debug(
		"hello ping successful (client)",
		"router", f.SrcIP(),
	)
	return nil
}
