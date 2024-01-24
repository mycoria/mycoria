package state

import (
	"crypto/ed25519"
	"sync"
	"time"
)

// DefaultPrecision is the default precision for time sequences.
const DefaultPrecision = time.Millisecond

// SigningSession holds all necessary information for signing (unreliable) packets.
type SigningSession struct {
	routerPrivKey ed25519.PrivateKey
	remotePubKey  ed25519.PublicKey

	// Replay Attack Mitigation
	seqHandler *TimeSequenceHandler
}

// NewSigningSession returns a new signing session.
func NewSigningSession(routerPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey) *SigningSession {
	return &SigningSession{
		routerPrivKey: routerPrivKey,
		remotePubKey:  remotePubKey,
		seqHandler:    NewTimeSequenceHandler(0),
	}
}

// RouterPrivKey returns the private key of the router.
func (s *SigningSession) RouterPrivKey() ed25519.PrivateKey {
	return s.routerPrivKey
}

// RemotePubKey returns the public key of the remote peer.
func (s *SigningSession) RemotePubKey() ed25519.PublicKey {
	return s.remotePubKey
}

// Seq returns the sequence handler.
func (s *SigningSession) Seq() *TimeSequenceHandler {
	return s.seqHandler
}

// TimeSequenceHandler is a simple timestamp based sequence handler.
type TimeSequenceHandler struct {
	lock   sync.Mutex
	latest time.Time
	out    time.Time

	precision time.Duration
}

// NewTimeSequenceHandler returns a new TimeSequenceHandler.
func NewTimeSequenceHandler(precision time.Duration) *TimeSequenceHandler {
	// Apply defaults.
	if precision == 0 {
		precision = DefaultPrecision
	}

	return &TimeSequenceHandler{
		precision: precision,
	}
}

// Next returns the next sequence time.
func (sh *TimeSequenceHandler) Next() time.Time {
	sh.lock.Lock()
	defer sh.lock.Unlock()

	// Round current time and increase until newer than last.
	next := time.Now().Round(sh.precision)
	for !next.After(sh.out) {
		next = next.Add(sh.precision)
	}

	// Save next as last outgoing sequence time.
	sh.out = next
	return next
}

// Check checks if the given sequence time should be accepted.
func (sh *TimeSequenceHandler) Check(seqTime time.Time) error {
	sh.lock.Lock()
	defer sh.lock.Unlock()

	switch {
	case seqTime.Equal(sh.latest):
		return ErrImmediateDuplicateFrame

	case seqTime.Before(sh.latest):
		return ErrDelayedFrame

	default:
		sh.latest = seqTime
		return nil
	}
}
