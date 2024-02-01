package state

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"math/bits"
	"sync"
	"sync/atomic"

	"github.com/zeebo/blake3"
	_ "golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	defaultKXType = "ECDH-X25519/BLAKE3"

	rolloverLowerBound = 0x0000_00FF // 255
	rolloverUpperBound = 0xFFFF_FF00 // 255 below max
)

// EncryptionSession holds all necessary information for encrypting a duplex packet stream.
type EncryptionSession struct {
	lock sync.Mutex

	// Key exchange and keys.
	kxRouterPrivate *ecdh.PrivateKey
	kxRemotePublic  *ecdh.PublicKey
	inKey           []byte
	outKey          []byte

	// Active ciphers.
	inCipher  cipher.AEAD
	outCipher cipher.AEAD

	// Replay Attack Mitigation
	prioSeqHandler *SequenceHandler
	reglSeqHandler *SequenceHandler
}

// NewEncryptionSession returns a new encryption session.
// It does not hold any keys.
func NewEncryptionSession() *EncryptionSession {
	return &EncryptionSession{
		prioSeqHandler: new(SequenceHandler),
		reglSeqHandler: new(SequenceHandler),
	}
}

// IsSetUp returns whether the encryption is set up and ready to use.
func (s *EncryptionSession) IsSetUp() bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.inCipher != nil && s.outCipher != nil
}

// InitKeyClientStart generates exchange keys on the client.
func (s *EncryptionSession) InitKeyClientStart() (kxKey []byte, kxType string, err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Generate new private key.
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate key: %w", err)
	}

	// Set and return public key.
	s.kxRouterPrivate = private
	return s.kxRouterPrivate.PublicKey().Bytes(), defaultKXType, nil
}

// InitKeyServer takes the exchange key of the client and generates exchange keys on the server.
// It already uses that information to finalize the encryption keys.
// Call InitCleanup() when done with key setup.
func (s *EncryptionSession) InitKeyServer(kxKey []byte, kxType string) (returnKxKey []byte, returnKxType string, err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check kx type.
	if kxType != defaultKXType {
		return nil, "", fmt.Errorf("kx type %q not supported", kxType)
	}

	// Parse given public key.
	public, err := ecdh.X25519().NewPublicKey(kxKey)
	if err != nil {
		return nil, "", fmt.Errorf("parse remote public key: %w", err)
	}
	s.kxRemotePublic = public

	// Generate new private key.
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate key: %w", err)
	}
	s.kxRouterPrivate = private

	// Make keys and ciphers from new shared secret.
	if err := s.initFinalize(false, kxSetupContext); err != nil {
		return nil, "", fmt.Errorf("finalize keys: %w", err)
	}

	return s.kxRouterPrivate.PublicKey().Bytes(), kxType, nil
}

// InitKeyClientComplete takes the exchange key of the server to finalize the encryption keys.
// Call InitCleanup() when done with key setup.
func (s *EncryptionSession) InitKeyClientComplete(kxKey []byte, kxType string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check kx type.
	if kxType != defaultKXType {
		return fmt.Errorf("kx type %q not supported", kxType)
	}

	// Parse given public key.
	public, err := ecdh.X25519().NewPublicKey(kxKey)
	if err != nil {
		return fmt.Errorf("parse remote public key: %w", err)
	}
	s.kxRemotePublic = public

	// Make keys and ciphers from new shared secret.
	if err := s.initFinalize(true, kxSetupContext); err != nil {
		return fmt.Errorf("finalize keys: %w", err)
	}
	return nil
}

const (
	kxBaseContext     = "mycoria key exch"
	kxSetupContext    = " - initial setup"
	kxExtraContext    = " - extra keys - "
	kxRolloverContext = " - key rollover "
)

func (s *EncryptionSession) initFinalize(reverse bool, keyContext string) error {
	if keyContext == "" {
		return errors.New("invalid key context")
	}

	// Compute shared key.
	sharedKey, err := s.kxRouterPrivate.ECDH(s.kxRemotePublic)
	if err != nil {
		return fmt.Errorf("compute shared key: %w", err)
	}

	// Derive keys.
	keys := make([]byte, chacha20poly1305.KeySize*2)
	blake3.DeriveKey(kxBaseContext+keyContext, sharedKey, keys)
	key1 := keys[:chacha20poly1305.KeySize]
	key2 := keys[chacha20poly1305.KeySize:]
	keys = nil //nolint:wastedassign // Maintainability.
	if len(key1) != chacha20poly1305.KeySize ||
		len(key2) != chacha20poly1305.KeySize ||
		bytes.Equal(key1, key2) {
		return errors.New("derived keys are faulty")
	}

	// Create ciphers.
	c1, err := chacha20poly1305.New(key1)
	if err != nil {
		return fmt.Errorf("create first cipher: %w", err)
	}
	c2, err := chacha20poly1305.New(key2)
	if err != nil {
		return fmt.Errorf("create second cipher: %w", err)
	}

	// Assign to session.
	if reverse {
		s.inKey = key1
		s.inCipher = c1
		s.outKey = key2
		s.outCipher = c2
	} else {
		s.inKey = key2
		s.inCipher = c2
		s.outKey = key1
		s.outCipher = c1
	}
	return nil
}

// InitCleanup cleans up the exchange keys after the initial setup.
func (s *EncryptionSession) InitCleanup() {
	s.kxRemotePublic = nil
	s.kxRouterPrivate = nil
}

// DeriveSessionFromKX derives a new encryption session with the current key
// exchange keys and a different context.
func (s *EncryptionSession) DeriveSessionFromKX(reverse bool, purpose string) (*EncryptionSession, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check if we have the keys.
	if s.kxRemotePublic == nil || s.kxRouterPrivate == nil {
		return nil, errors.New("can only derive session if kx keys are present")
	}
	// Check if a purpose is given.
	if purpose == "" {
		return nil, errors.New("invalid purpose")
	}

	// Create new session, but copy the keys.
	newS := NewEncryptionSession()
	newS.kxRemotePublic = s.kxRemotePublic
	newS.kxRouterPrivate = s.kxRouterPrivate
	// Finalize with different context.
	if err := newS.initFinalize(reverse, kxExtraContext+purpose); err != nil {
		return nil, fmt.Errorf("finalize keys: %w", err)
	}
	newS.InitCleanup()

	return newS, nil
}

// In returns the cipher to decrypt an incoming frame.
func (s *EncryptionSession) In(seqNum uint32, prio bool) (
	c cipher.AEAD,
	err error,
) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check if encryption is set up.
	if s.inCipher == nil {
		return nil, ErrEncryptionNotSetUp
	}

	// Get correct sequence handler.
	sh := s.reglSeqHandler
	if prio {
		sh = s.prioSeqHandler
	}

	// Check if we need to rollover key.
	if sh.RolloverRequired(seqNum) {
		if prio {
			return nil, errors.New("prio sequence handler requested key rollover")
		}
		s.prioSeqHandler.Reset()
		if err := s.rolloverInKey(); err != nil {
			return nil, fmt.Errorf("rollover in key: %w", err)
		}
	}

	return s.inCipher, nil
}

// Out returns all data to set on the outgoing frame and the cipher to encrypt it.
func (s *EncryptionSession) Out(prio bool) (
	seqNum uint32,
	ack uint32,
	recvRate uint8,
	c cipher.AEAD,
	err error,
) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check if encryption is set up.
	if s.outCipher == nil {
		return 0, 0, 0, nil, errors.New("encryption is not set up")
	}

	// Get correct sequence handler.
	sh := s.reglSeqHandler
	if prio {
		sh = s.prioSeqHandler
	}

	// Get sequence number and check if we need to do a key rollover.
	seqNum, rollover := sh.NextOut()
	if rollover {
		if prio {
			return 0, 0, 0, nil, errors.New("prio sequence handler requested key rollover")
		}
		s.prioSeqHandler.Reset()
		if err := s.rolloverOutKey(); err != nil {
			return 0, 0, 0, nil, fmt.Errorf("rollover in key: %w", err)
		}
	}

	ack, recvRate = sh.Ack()
	return seqNum, ack, recvRate, s.outCipher, nil
}

// rolloverInKey rolls over the incoming encryption key.
func (s *EncryptionSession) rolloverInKey() error {
	newKey, newCipher, err := rolloverKey(s.inKey)
	if err != nil {
		return err
	}

	s.inKey = newKey
	s.inCipher = newCipher
	return nil
}

// rolloverOutKey rolls over the outgoing encryption key.
func (s *EncryptionSession) rolloverOutKey() error {
	newKey, newCipher, err := rolloverKey(s.outKey)
	if err != nil {
		return err
	}

	s.outKey = newKey
	s.outCipher = newCipher
	return nil
}

// Check checks the given sequence number and returns an error if there is an issue.
func (s *EncryptionSession) Check(seqNum uint32, prio bool) error {
	if prio {
		return s.prioSeqHandler.Check(seqNum)
	}
	return s.reglSeqHandler.Check(seqNum)
}

func rolloverKey(oldKey []byte) (newKey []byte, newCipher cipher.AEAD, err error) {
	// Roll over key.
	newKey = make([]byte, chacha20poly1305.KeySize)
	blake3.DeriveKey(kxBaseContext+kxRolloverContext, oldKey, newKey)

	// Create new ciper.
	newCipher, err = chacha20poly1305.New(newKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	return newKey, newCipher, nil
}

// SequenceHandler checks sequence numbers to detect duplicate messages.
type SequenceHandler struct {
	lock    sync.Mutex
	bitMap  uint64
	highest uint32

	outSeq atomic.Uint32
}

const fullBitMap = 0xFFFF_FFFF_FFFF_FFFF

// NewSequenceHandler returns a new sequence handler.
func NewSequenceHandler() *SequenceHandler {
	return &SequenceHandler{
		bitMap: fullBitMap, // Start with full bit map.
	}
}

// NextOut returns the next outgoing sequence number and if a key rollover is required.
// It makes sure rollover only returns true once per key rollover.
// Therefore, the rollover must be executed.
func (sh *SequenceHandler) NextOut() (seqNum uint32, rollover bool) {
	seqNum = sh.outSeq.Add(1)

	if seqNum == 0 {
		// Zero is only used as a rollover indicator and safeguard.
		seqNum = sh.outSeq.Add(1)
		rollover = true
	}

	return
}

// RolloverRequired returns whether the current sequence number allows
// for a key rollover.
// It makes sure to only return true once per key rollover.
// Therefore, the rollover must be executed.
func (sh *SequenceHandler) RolloverRequired(seqNum uint32) bool {
	sh.lock.Lock()
	defer sh.lock.Unlock()

	switch {
	case sh.highest < rolloverUpperBound:
		return false
	case seqNum > rolloverLowerBound:
		return false
	default:
		// Zero is only used as a rollover indicator and safeguard.
		sh.highest = 0
		return true
	}
}

// Reset resets the sequence counters to zero.
// This is only used for resetting the priority sequence,
// when the regular triggered a key rollover.
func (sh *SequenceHandler) Reset() {
	sh.lock.Lock()
	defer sh.lock.Unlock()

	sh.highest = 0
	sh.outSeq.Store(0)
}

// Ack returns the highest sequence number received so far,
// as well as the current frame recv rate.
func (sh *SequenceHandler) Ack() (seqNum uint32, recvRate uint8) {
	sh.lock.Lock()
	defer sh.lock.Unlock()

	return sh.highest, sh.recvRate()
}

const oneCountToPercentRate = 1.5625

func (sh *SequenceHandler) recvRate() uint8 {
	return uint8(float32(bits.OnesCount64(sh.bitMap)) * oneCountToPercentRate)
}

// Check checks the given sequence number and returns an error if there is an issue.
func (sh *SequenceHandler) Check(seqNum uint32) error {
	sh.lock.Lock()
	defer sh.lock.Unlock()

	switch {
	case seqNum == sh.highest:
		// This is the same as the highest sequence number we already received.
		// Must be a duplicate.
		return ErrImmediateDuplicateFrame

	case seqNum > sh.highest:
		// The received sequence number is higher the previous highest sequence number.
		// Update view bitmap and highest sequence number.
		diff := seqNum - sh.highest
		// Shift bitmap by diff
		sh.bitMap <<= diff
		// Update highest value
		sh.highest = seqNum
		return nil

	case seqNum < sh.highest:
		// The received sequence number is lower the previous highest sequence number.
		// This means this is either a duplicate or late packet.
		// Check the view bitmap.
		diff := sh.highest - seqNum
		// Return if the position would be out of view.
		if diff > 64 {
			return ErrDelayedFrame
		}
		// Calculate position in view bitmap.
		var bitMapPosition uint64 = 1 << (diff - 1)
		// Check if received flag is set in vie bitmap.
		if sh.bitMap&bitMapPosition > 0 {
			// Received flag is set, this must be a duplicate.
			return ErrDelayedDuplicateFrame
		}
		// Otherwise, set the received flag.
		sh.bitMap |= bitMapPosition
		return nil
	}

	// In case something goes wrong, don't accept the packet.
	return ErrUnknownDelayedFrame
}

// EncryptionSessionTestHelper is test helper.
type EncryptionSessionTestHelper struct {
	*EncryptionSession
}

// PrioSeq returns the priority sequence handler.
func (h *EncryptionSessionTestHelper) PrioSeq() *SequenceHandler {
	return h.prioSeqHandler
}

// ReglSeq returns the regular sequence handler.
func (h *EncryptionSessionTestHelper) ReglSeq() *SequenceHandler {
	return h.reglSeqHandler
}

// ReglSetOut sets the regular outgoing sequence number.
func (h *EncryptionSessionTestHelper) ReglSetOut(seq uint32) {
	h.reglSeqHandler.outSeq.Store(seq)
}

// PrioSetOut sets the priority outgoing sequence number.
func (h *EncryptionSessionTestHelper) PrioSetOut(seq uint32) {
	h.prioSeqHandler.outSeq.Store(seq)
}

// InKey returns the in key.
func (h *EncryptionSessionTestHelper) InKey() []byte {
	return h.inKey
}

// OutKey returns the out key.
func (h *EncryptionSessionTestHelper) OutKey() []byte {
	return h.outKey
}
