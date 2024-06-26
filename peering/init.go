package peering

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/state"
)

// Peering Errors.
var (
	ErrUnsupportedVersion  = errors.New("unsupported version")
	ErrRemoteDeniedPeering = errors.New("remote denied peering")
)

const (
	challengeSize    = 32
	minChallengeSize = 16
)

type peeringRequestState struct { //nolint:maligned
	peering *Peering

	// step designates the current peering step:
	// 0: waiting for request
	// 1: waiting for response
	// 2: waiting for ack
	// 3: finished
	step int

	client  bool
	session *state.Session

	remoteIP      netip.Addr
	remoteVersion string
	remoteLite    bool
	challenge     []byte
}

type peeringRequest struct {
	RouterVersion string `cbor:"v,omitempty"  json:"v,omitempty"`
	Universe      string `cbor:"u,omitempty"  json:"u,omitempty"`
	LiteMode      bool   `cbor:"lm,omitempty" json:"lm,omitempty"`

	Address   m.PublicAddress `cbor:"a,omitempty" json:"a,omitempty"`
	Challenge []byte          `cbor:"c,omitempty" json:"c,omitempty"`

	LinkVersion int `cbor:"lv,omitempty"   json:"lv,omitempty"`
	TunMTU      int `cbor:"tmtu,omitempty" json:"tmtu,omitempty"`
}

type peeringResponse struct {
	Challenge       []byte `cbor:"c,omitempty"   json:"c,omitempty"`
	UniverseAuth    []byte `cbor:"ua,omitempty"  json:"ua,omitempty"`
	KeyExchange     []byte `cbor:"kx,omitempty"  json:"kx,omitempty"`
	KeyExchangeType string `cbor:"kxt,omitempty" json:"kxt,omitempty"`

	Err string `cbor:"err,omitempty" json:"err,omitempty"`
}

type peeringAck struct {
	Ack             bool   `cbor:"ack,omitempty" json:"ack,omitempty"`
	KeyExchange     []byte `cbor:"kx,omitempty"  json:"kx,omitempty"`
	KeyExchangeType string `cbor:"kxt,omitempty" json:"kxt,omitempty"`

	Err string `cbor:"err,omitempty" json:"err,omitempty"`
}

type peeringErr struct {
	Err string `cbor:"err,omitempty" json:"err,omitempty"`
}

func (p *Peering) createPeeringRequest(client bool) (*peeringRequestState, frame.Frame, error) {
	challenge := make([]byte, challengeSize)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Create request.
	r := &peeringRequest{
		RouterVersion: p.instance.Version(),
		Universe:      p.instance.Config().Router.Universe,
		LiteMode:      p.instance.Config().Router.Lite,
		Address:       p.instance.Identity().PublicAddress,
		Challenge:     challenge,
		LinkVersion:   1,
		TunMTU:        p.instance.Config().TunMTU(),
	}
	msg, err := cbor.Marshal(r)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal peering request: %w", err)
	}

	// Make and sign frame.
	f, err := p.instance.FrameBuilder().NewFrameV1(
		p.instance.Identity().IP,
		m.RouterAddress,
		frame.RouterPing,
		nil,
		msg,
		nil,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("build frame: %w", err)
	}
	f.SetTTL(0)
	f.SetSequenceTime(time.Now().Round(state.DefaultPrecision).Add(-state.DefaultPrecision))
	if err := f.SignRaw(p.instance.Identity().PrivateKey); err != nil {
		return nil, nil, fmt.Errorf("sign frame: %w", err)
	}
	f.SetTTL(1)

	return &peeringRequestState{
		peering:   p,
		challenge: challenge,
		client:    client,
		step:      1,
	}, f, nil
}

func (state *peeringRequestState) handle(in frame.Frame) (response frame.Frame, err error) {
	switch state.step {
	case 1: // waiting for request
		response, err = state.handlePeeringRequest(in)
	case 2: // waiting for response
		response, err = state.handlePeeringResponse(in)
	case 3: // waiting for ack
		err = state.handlePeeringAck(in)
	default:
		return nil, errors.New("invalid peering state")
	}

	// Create default error response.
	if err != nil && response == nil && !errors.Is(err, ErrRemoteDeniedPeering) {
		data, respErr := cbor.Marshal(&peeringErr{Err: err.Error()})
		if respErr != nil {
			goto done
		}
		respErr = in.Reply(nil, data, nil)
		if respErr != nil {
			goto done
		}
		response = in
	}

done:
	if err != nil {
		return response, fmt.Errorf("peering step %d: %w", state.step, err)
	}
	state.step++
	return response, nil
}

func (state *peeringRequestState) handlePeeringRequest(in frame.Frame) (frame.Frame, error) {
	if state.step != 1 {
		return nil, fmt.Errorf("wrong step for receiving peering request: %d", state.step)
	}

	// Check if we are connecting to self.
	if in.SrcIP() == state.peering.instance.Identity().IP {
		return nil, errors.New("received peering request from myself")
	}

	// Unmarshal request.
	r := new(peeringRequest)
	err := cbor.Unmarshal(in.MessageData(), r)
	if err != nil {
		return nil, fmt.Errorf("unmarshal peering request: %w", err)
	}
	if in.MessageType() != frame.RouterPing {
		return nil, fmt.Errorf("unexpected frame message type: %s", in.MessageType())
	}
	if in.SrcIP() != r.Address.IP {
		return nil, fmt.Errorf("peering request IP (%s) does not match frame source (%s)", r.Address.IP, in.SrcIP())
	}

	// Check address integrity.
	remoteAddr := &r.Address
	if err := remoteAddr.VerifyAddress(); err != nil {
		return nil, fmt.Errorf("verify address: %w", err)
	}

	// Check if we already have a connection to this router.
	if state.peering.GetLink(r.Address.IP) != nil {
		return nil, errors.New("already connected to this router")
	}

	// Get session and add router if necessary.
	session := state.peering.instance.State().GetSession(remoteAddr.IP)
	if session == nil {
		if err := state.peering.instance.State().AddRouter(remoteAddr); err != nil {
			return nil, fmt.Errorf("add router to state: %w", err)
		}
		session = state.peering.instance.State().GetSession(remoteAddr.IP)
		if session == nil {
			return nil, errors.New("session manager failure")
		}
	}
	state.session = session

	// Check signature.
	if err := in.Unseal(state.session); err != nil {
		return nil, fmt.Errorf("integrity violated: %w", err)
	}

	// Check link version.
	if r.LinkVersion != 1 {
		return nil, errors.New("unsupported link version")
	}

	// Apply metadata.
	if r.TunMTU > 0 {
		session.SetTunMTU(r.TunMTU)
	}

	// Populate state.
	state.remoteIP = r.Address.IP
	state.remoteVersion = r.RouterVersion
	state.remoteLite = r.LiteMode

	// Start building response.
	resp := &peeringResponse{}

	// Check universe.
	if r.Universe != state.peering.instance.Config().Router.Universe {
		return nil, errors.New("universe mismatch")
	}
	// Add universe auth, if set.
	if r.Universe != "" && state.peering.instance.Config().Router.UniverseSecret != "" {
		resp.UniverseAuth = makeUniverseAuth(
			r.Universe,
			state.peering.instance.Config().Router.UniverseSecret,
			r.Challenge,
			state.remoteIP,
			state.peering.instance.Identity().IP,
		)
	}

	// Check and compute challenge.
	if len(r.Challenge) < minChallengeSize {
		return nil, errors.New("invalid challenge")
	}
	// Copy challenge to response.
	// Sign it with the frame later.
	resp.Challenge = r.Challenge

	// Generate key exchange.
	if state.client {
		kxKey, kxType, err := state.session.Encryption().InitKeyClientStart()
		if err != nil {
			return nil, fmt.Errorf("init key exchange: %w", err)
		}
		resp.KeyExchange = kxKey
		resp.KeyExchangeType = kxType
	}

	// Create response frame.
	msg, err := cbor.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	if err := in.ReplyTo(state.peering.instance.Identity().IP, state.remoteIP, nil, msg, nil); err != nil {
		return nil, fmt.Errorf("frame reply: %w", err)
	}
	response := in

	// Sign and return.
	if err := response.Seal(state.session); err != nil {
		return nil, err
	}
	return response, nil
}

func (state *peeringRequestState) handlePeeringResponse(in frame.Frame) (frame.Frame, error) {
	if state.step != 2 {
		return nil, fmt.Errorf("wrong step for receiving peering response: %d", state.step)
	}

	// Verify integrity and check IPs.
	if err := in.Unseal(state.session); err != nil {
		return nil, fmt.Errorf("unseal: %w", err)
	}
	if in.MessageType() != frame.RouterPing {
		return nil, fmt.Errorf("unexpected frame type: %s", in.MessageType())
	}
	if in.SrcIP() != state.remoteIP {
		return nil, errors.New("peering response src IP does not match session")
	}
	if in.DstIP() != state.peering.instance.Identity().IP {
		return nil, errors.New("peering response dst IP does not match session")
	}

	// Unmarshal request.
	r := new(peeringResponse)
	err := cbor.Unmarshal(in.MessageData(), r)
	if err != nil {
		return nil, fmt.Errorf("unmarshal peering response: %w", err)
	}

	// Check for error.
	if r.Err != "" {
		return nil, fmt.Errorf("%w: %s", ErrRemoteDeniedPeering, r.Err)
	}

	// Check challenge value.
	if subtle.ConstantTimeCompare(state.challenge, r.Challenge) == 0 {
		return nil, errors.New("challenge mismatch")
	}

	// Check universe auth.
	if state.peering.instance.Config().Router.UniverseSecret != "" {
		if len(r.UniverseAuth) == 0 {
			return nil, errors.New("universe auth missing")
		}
		universeCheckAuth := makeUniverseAuth(
			state.peering.instance.Config().Router.Universe,
			state.peering.instance.Config().Router.UniverseSecret,
			state.challenge,
			state.peering.instance.Identity().IP,
			state.remoteIP,
		)
		if subtle.ConstantTimeCompare(r.UniverseAuth, universeCheckAuth) == 0 {
			return nil, errors.New("universe auth failed")
		}
	}

	// Start building response.
	resp := &peeringAck{}

	// Process key exchange.
	if !state.client {
		if len(r.KeyExchange) == 0 || r.KeyExchangeType == "" {
			return nil, errors.New("key exchange missing")
		}
		kxKey, kxType, err := state.session.Encryption().InitKeyServer(r.KeyExchange, r.KeyExchangeType)
		if err != nil {
			return nil, fmt.Errorf("process key exchange: %w", err)
		}
		resp.KeyExchange = kxKey
		resp.KeyExchangeType = kxType
	}

	// Create response frame.
	msg, err := cbor.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal ack: %w", err)
	}
	if err := in.Reply(nil, msg, nil); err != nil {
		return nil, fmt.Errorf("frame reply: %w", err)
	}
	response := in

	// Sign and return.
	if err := response.Seal(state.session); err != nil {
		return nil, err
	}
	return response, nil
}

func (state *peeringRequestState) handlePeeringAck(in frame.Frame) error {
	if state.step != 3 {
		return fmt.Errorf("wrong step for receiving peering ack: %d", state.step)
	}

	// Verify integrity and check IPs.
	if err := in.Unseal(state.session); err != nil {
		return err
	}
	if in.MessageType() != frame.RouterPing {
		return fmt.Errorf("unexpected frame type: %s", in.MessageType())
	}
	if in.SrcIP() != state.remoteIP {
		return errors.New("peering response src IP does not match session")
	}
	if in.DstIP() != state.peering.instance.Identity().IP {
		return errors.New("peering response dst IP does not match session")
	}

	// Unmarshal request.
	r := new(peeringAck)
	err := cbor.Unmarshal(in.MessageData(), r)
	if err != nil {
		return fmt.Errorf("unmarshal peering ack: %w", err)
	}

	// Check for error.
	if r.Err != "" {
		return fmt.Errorf("%w: %s", ErrRemoteDeniedPeering, r.Err)
	}

	// Complete key exchange, if on client.
	if state.client {
		if len(r.KeyExchange) == 0 || r.KeyExchangeType == "" {
			return errors.New("key exchange missing")
		}
		if err := state.session.Encryption().InitKeyClientComplete(r.KeyExchange, r.KeyExchangeType); err != nil {
			return fmt.Errorf("complete key exchange: %w", err)
		}
	}

	return nil
}

func (state *peeringRequestState) finalize() (*state.EncryptionSession, error) {
	// Clean up exchange keys when done.
	defer state.session.Encryption().InitCleanup()
	// Derive link layer encryption session.
	return state.session.Encryption().DeriveSessionFromKX(state.client, "link layer crypt")
}

func makeUniverseAuth(universe, secret string, challenge []byte, remoteIP, idIP netip.Addr) []byte {
	// Convert to slices.
	universeData := []byte(universe)
	secretData := []byte(secret)

	// Put all data together.
	authData := make([]byte, 0, len(universeData)+len(challenge)+len(secretData)+32)
	authData = append(authData, universeData...)
	authData = append(authData, challenge...)
	authData = append(authData, secretData...)
	authData = append(authData, remoteIP.AsSlice()...)
	authData = append(authData, idIP.AsSlice()...)

	// Hash and return.
	return m.BLAKE3.Digest(authData)
}
