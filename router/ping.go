package router

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/state"
)

// Ping Msg Format V1:
// - Version (uint8)
// - Length of PingHeader (uint8)
// - PingHeader ([]byte)
// - PingBody ([]byte)

// Errors.
var (
	ErrAlreadyActive = errors.New("already active")
)

var pingTypeRegex = regexp.MustCompile(`^[a-z0-9\.]+$`)

// PingHeader is the header used for every ping message.
type PingHeader struct {
	PingID    uint64            `cbor:"i,omitempty" json:"i,omitempty"`
	PingType  string            `cbor:"t,omitempty" json:"t,omitempty"`
	PingCode  uint8             `cbor:"c,omitempty" json:"c,omitempty"`
	FollowUp  bool              `cbor:"f,omitempty" json:"f,omitempty"`
	AddrHash  m.Hash            `cbor:"h,omitempty" json:"h,omitempty"`
	KeyType   string            `cbor:"a,omitempty" json:"a,omitempty"`
	PublicKey ed25519.PublicKey `cbor:"k,omitempty" json:"k,omitempty"`
}

// PingHandler handles ping messages of a type.
type PingHandler interface {
	Type() string
	Handle(w *mgr.WorkerCtx, f frame.Frame, pingHdr *PingHeader, pingData []byte) error
	Clean(w *mgr.WorkerCtx) error
}

// RegisterPingHandler registers the given ping handler in the router.
func (r *Router) RegisterPingHandler(handler PingHandler) error {
	r.pingHandlersLock.Lock()
	defer r.pingHandlersLock.Unlock()

	// Check if ping type matches format.
	pingType := handler.Type()
	if !pingTypeRegex.MatchString(pingType) {
		return fmt.Errorf("invalid ping type %q", pingType)
	}

	// Check if there is already a handler with this ping type.
	_, ok := r.pingHandlers[pingType]
	if ok {
		return fmt.Errorf("ping handler %q already registered", pingType)
	}

	// Add handler.
	r.pingHandlers[pingType] = handler
	return nil
}

// GetPingHandler returns the ping handler of the given ping type.
func (r *Router) GetPingHandler(pingType string) PingHandler {
	r.pingHandlersLock.RLock()
	defer r.pingHandlersLock.RUnlock()

	return r.pingHandlers[pingType]
}

func (r *Router) handlePing(w *mgr.WorkerCtx, f frame.Frame) error {
	// Parse ping header.
	hdr, data, err := r.parsePingMsg(f)
	if err != nil {
		return err
	}

	// Get handler for ping type.
	handler := r.GetPingHandler(hdr.PingType)
	if handler == nil {
		return fmt.Errorf("unknown ping type %s", hdr.PingType)
	}

	// Handle ping.
	return handler.Handle(w, f, hdr, data)
}

type sendPingOpts struct { //nolint:maligned
	// Route to destination.
	dst netip.Addr
	// Send to peer.
	peer netip.Addr
	// Use message type.
	msgType frame.MessageType
	// Define ping ID to use.
	// A new will be generated if 0.
	pingID uint64
	// Define ping type.
	// Mandatory.
	pingType string
	// Define ping code.
	// Optional and only valid for some ping types.
	pingCode uint8
	// Ping data to send.
	// Mandatory.
	pingData []byte
	// Define this message is a response or follow up.
	followUp bool
}

func (opts sendPingOpts) validate() error {
	switch {
	case opts.dst.IsValid() == opts.peer.IsValid():
		return errors.New("(only) dst or peer must be set")
	case opts.msgType != frame.RouterHopPingDeprecated &&
		opts.msgType != frame.RouterPing &&
		opts.msgType != frame.RouterCtrl &&
		opts.msgType != frame.RouterHopPing:
		return fmt.Errorf("%s is not a valid ping message type", opts.msgType)
	case opts.pingType == "":
		return errors.New("ping type is mandatory")
	case len(opts.pingData) == 0:
		return errors.New("ping data is mandatory")
	default:
		return nil
	}
}

func (r *Router) sendPingMsg(opts sendPingOpts) error {
	// Validate options.
	if err := opts.validate(); err != nil {
		return fmt.Errorf("internal error: invalid ping options: %w", err)
	}

	// Get ping ID, if not set.
	if opts.pingID == 0 {
		opts.pingID = newPingID()
	}

	// Build and marshal header.
	hdr := PingHeader{
		PingID:    opts.pingID,
		PingType:  opts.pingType,
		PingCode:  opts.pingCode,
		FollowUp:  opts.followUp,
		AddrHash:  r.instance.Identity().Hash,
		KeyType:   r.instance.Identity().Type,
		PublicKey: r.instance.Identity().PublicKey,
	}
	hdrData, err := cbor.Marshal(&hdr)
	if err != nil {
		return fmt.Errorf("marshal ping header: %w", err)
	}
	if len(hdrData) > 0xFF {
		return fmt.Errorf("ping header too big: %d bytes", len(hdrData))
	}

	// Build complete frame data.
	requiredSize := 2 + len(hdrData) + len(opts.pingData)
	frameData := make([]byte, requiredSize)
	frameData[0] = 1
	frameData[1] = uint8(len(hdrData))
	copy(frameData[2:], hdrData)
	copy(frameData[2+len(hdrData):], opts.pingData)

	// Make frame.
	dst := opts.dst
	sendToPeer := false
	if !dst.IsValid() {
		dst = opts.peer
		sendToPeer = true
	}
	f, err := r.instance.FrameBuilder().NewFrameV1(
		r.instance.Identity().IP, dst, opts.msgType,
		nil, frameData, nil,
	)
	if err != nil {
		return fmt.Errorf("build frame: %w", err)
	}

	// Sign frame.
	session := r.instance.State().GetSession(dst)
	switch {
	case session != nil:
		// Sign or encrypt with the existing session.
		if err := f.Seal(session); err != nil {
			return fmt.Errorf("sign frame: %w", err)
		}

	case opts.msgType.IsEncrypted():
		// If there is no session and the message type is encrypted,
		// abort with error.
		return errors.New("encryption is not set up")

	default:
		// Destination router is not known, sign raw.
		f.SetTTL(0)
		f.SetSequenceTime(time.Now().Round(state.DefaultPrecision).Add(-state.DefaultPrecision))
		if err := f.SignRaw(r.instance.Identity().PrivateKey); err != nil {
			return fmt.Errorf("sign frame: %w", err)
		}
		f.SetTTL(32)
	}

	// Send frame on all links.
	if f.DstIP() == m.RouterAddress {
		links := r.instance.Peering().GetLinks()
		for i, link := range links {
			// Clone frame for all but last link.
			var sendFrame frame.Frame
			if i < len(links)-1 {
				sendFrame = f.Clone()
			} else {
				sendFrame = f
			}

			// Forward to link.
			err := r.instance.Switch().ForwardByPeer(sendFrame, link.Peer())
			if err != nil {
				// TODO: Continue sending if one fails.
				return fmt.Errorf("send ping frame to %s: %w", link.Peer(), err)
			}
		}
		return nil
	}

	// Send frame.
	// Send to peer.
	if sendToPeer {
		if err := r.instance.Switch().ForwardByPeer(f, opts.peer); err != nil {
			return fmt.Errorf("send ping frame to peer: %w", err)
		}
		return nil
	}
	// Route to destination.
	if err := r.RouteFrame(f); err != nil {
		return fmt.Errorf("send ping frame: %w", err)
	}
	return nil
}

func (r *Router) parsePingMsg(f frame.Frame) (hdr *PingHeader, body []byte, err error) {
	// Get (or create) session.
	session := r.instance.State().GetSession(f.SrcIP())
	if session == nil {
		// Add address frm
		session, err = r.sessionFromPingHeader(f)
		if err != nil {
			return nil, nil, fmt.Errorf("session from ping: %w", err)
		}
	}

	// Unseal ping message.
	if err := f.Unseal(session); err != nil {
		switch {
		case f.MessageType() == frame.RouterHopPingDeprecated &&
			errors.Is(err, state.ErrImmediateDuplicateFrame):
			fallthrough
		case f.MessageType() == frame.RouterHopPing &&
			errors.Is(err, state.ErrImmediateDuplicateFrame):
			// Hop pings may have immediate duplicate frames, as the pings hop and
			// spread and we might receive variants of the same message from different
			// peers - eg. router announcements.
		default:
			return nil, nil, fmt.Errorf("unseal: %w", err)
		}
	}

	// Get header.
	hdr, dataOffset, err := parsePingHeader(f)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ping header: %w", err)
	}

	return hdr, f.MessageData()[dataOffset:], nil
}

func (r *Router) sessionFromPingHeader(f frame.Frame) (*state.Session, error) {
	// Get header.
	hdr, _, err := parsePingHeader(f)
	if err != nil {
		return nil, fmt.Errorf("parse ping header: %w", err)
	}

	// Create public address from header, verify and add it.
	addr := &m.PublicAddress{
		IP:        f.SrcIP(),
		Hash:      hdr.AddrHash,
		Type:      hdr.KeyType,
		PublicKey: hdr.PublicKey,
	}
	if err := addr.VerifyAddress(); err != nil {
		return nil, fmt.Errorf("ping header address data invalid: %w", err)
	}
	if err := r.instance.State().AddRouter(addr); err != nil {
		return nil, fmt.Errorf("add router to state: %w", err)
	}

	// Get session for newly added router.
	session := r.instance.State().GetSession(f.SrcIP())
	if session == nil {
		return nil, errors.New("internal state failure")
	}
	return session, nil
}

func parsePingHeader(f frame.Frame) (hdr *PingHeader, dataOffset int, err error) {
	// Get header data.
	data := f.MessageData()
	if len(data) < 3 {
		return nil, 0, errors.New("not enough data")
	}
	hdrLen := int(data[1])
	if len(data) < 2+hdrLen {
		return nil, 0, errors.New("not enough data")
	}
	hdrData := data[2 : hdrLen+2]

	// Parse header.
	hdr = &PingHeader{}
	if err := cbor.Unmarshal(hdrData, hdr); err != nil {
		return nil, 0, fmt.Errorf("unmarshal: %w", err)
	}

	// Check ping type format.
	if !pingTypeRegex.MatchString(hdr.PingType) {
		return nil, 0, errors.New("invalid ping type")
	}

	return hdr, hdrLen + 2, nil
}

func newPingID() uint64 {
	var pingID uint64
	err := binary.Read(rand.Reader, binary.BigEndian, &pingID)
	if err != nil || pingID == 0 {
		slog.Error("failed to generate random ping ID", "err", err)
		// Fall back to nanoseconds.
		pingID = uint64(time.Now().Nanosecond())
	}
	return pingID
}

func (r *Router) cleanPingHandlersWorker(w *mgr.WorkerCtx) error {
	ticker := time.NewTicker(1 * time.Minute)

	for {
		select {
		case <-w.Done():
			return nil
		case <-ticker.C:
			r.cleanPingHandlers(w)
		}
	}
}

func (r *Router) cleanPingHandlers(w *mgr.WorkerCtx) {
	r.pingHandlersLock.RLock()
	defer r.pingHandlersLock.RUnlock()

	for _, handler := range r.pingHandlers {
		if err := handler.Clean(w); err != nil {
			w.Warn(
				"ping clean failed",
				"type", handler.Type(),
				"err", err,
			)
		}
	}
}
