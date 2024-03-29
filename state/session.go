package state

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mycoria/mycoria/m"
)

// Sequence Errors.
var (
	ErrImmediateDuplicateFrame = errors.New("immediate duplicate frame")
	ErrDelayedDuplicateFrame   = errors.New("delayed duplicate frame")
	ErrUnknownDelayedFrame     = errors.New("unknown delayed frame")
	ErrDelayedFrame            = errors.New("delayed frame")
	ErrTooOldFrame             = errors.New("too old frame")
	ErrTooNewFrame             = errors.New("too new frame")
)

// Encryption Errors.
var (
	ErrEncryptionNotSetUp = errors.New("encryption is not set up")
)

// Session is a logical session with another router.
type Session struct {
	id      netip.Addr
	address *m.PublicAddress

	lastActivity time.Time

	signing    *SigningSession
	encryption *EncryptionSession
	mtu        atomic.Int32

	lock  sync.Mutex
	state *State
}

// For returns who this session is for.
func (s *Session) For() netip.Addr {
	return s.id
}

// Address returns the public address of the router this session is for.
func (s *Session) Address() *m.PublicAddress {
	return s.address
}

// Signing returns the signing session.
func (s *Session) Signing() *SigningSession {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Create a new signing session, if it does not exist yet.
	if s.signing == nil {
		s.signing = NewSigningSession(
			s.state.instance.Identity().PrivateKey,
			s.address.PublicKey,
		)
	}

	return s.signing
}

// SetEncryptionSession sets the encryption session.
func (s *Session) SetEncryptionSession(encSession *EncryptionSession) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.encryption = encSession
}

// Encryption returns the encryption session.
func (s *Session) Encryption() *EncryptionSession {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Create a new encryption session, if it does not exist yet.
	if s.encryption == nil {
		s.encryption = NewEncryptionSession()
	}

	return s.encryption
}

// SetTunMTU sets the reported tun device MTU of that router.
func (s *Session) SetTunMTU(mtu int) {
	// Raise to minimum 1280 mtu.
	if mtu > 0 && mtu < 1280 {
		mtu = 1280
	}

	s.mtu.Store(int32(mtu))
}

// TunMTU returns the tun device MTU of that router.
func (s *Session) TunMTU() int {
	return int(s.mtu.Load())
}

// inUse marks the session as in use.
func (s *Session) inUse() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.lastActivity = time.Now()
}

// killable checks if the session may be destroyed.
func (s *Session) killable() bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check if the session is old enough to kill.
	ttl := time.Hour
	if s.encryption == nil {
		// If no encryption is set up, clear faster.
		ttl = time.Minute
	}
	return time.Since(s.lastActivity) > ttl
}
