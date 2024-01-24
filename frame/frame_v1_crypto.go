package frame

import (
	"bytes"
	"crypto/cipher"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/mycoria/mycoria/state"
)

// Crypto means Cryptography.

var (
	zero16 = make([]byte, 16)
	zero64 = make([]byte, 64)
)

// Seal signs or encrypts the frame using the given session.
func (f *FrameV1) Seal(s *state.Session) error {
	msgClass := f.MessageType().Class()

	// Prepare frame.
	done := f.putFieldsIntoCryptoState()
	defer done()

	// Check if the auth space is not cleared, indicating an already used packet.
	switch msgClass {
	case MessageClassSigned:
		// Check for reuse.
		if !bytes.Equal(f.authData(), zero64) {
			return errors.New("frame is already (or was previosly) signed")
		}

		// Set fields and sign.
		f.SetSequenceTime(s.Signing().Seq().Next())
		if err := f.SignRaw(s.Signing().RouterPrivKey()); err != nil {
			return fmt.Errorf("sign: %w", err)
		}

	case MessageClassPriorityEncrypted, MessageClassEncrypted:
		// Check for reuse.
		if !bytes.Equal(f.authData(), zero16) {
			return errors.New("frame is already (or was previosly) encrypted")
		}

		// Set fields and encrypt.
		seqNum, ack, recvRate, c, err := s.Encryption().Out(
			msgClass == MessageClassPriorityEncrypted,
		)
		if err != nil {
			return err
		}
		f.SetSequenceNum(seqNum)
		f.SetSequenceAck(ack)
		f.SetRecvRate(recvRate)
		f.encryptFrame(c)

	case MessageClassUnknown:
		fallthrough
	default:
		return errors.New("unknown message class")
	}

	return nil
}

// Unseal verifies or decrypts the frame using the given session.
func (f *FrameV1) Unseal(s *state.Session) error {
	msgClass := f.MessageType().Class()

	// Prepare frame.
	done := f.putFieldsIntoCryptoState()
	defer done()

	// Verify or decrypt.
	switch msgClass {
	case MessageClassSigned:
		if err := f.VerifyRaw(s.Signing().RemotePubKey()); err != nil {
			return fmt.Errorf("verify: %w", err)
		}
		return s.Signing().Seq().Check(f.SequenceTime())

	case MessageClassPriorityEncrypted, MessageClassEncrypted:
		seqNum := f.SequenceNum()
		c, err := s.Encryption().In(seqNum, msgClass == MessageClassPriorityEncrypted)
		if err != nil {
			return err
		}

		// Decrypt.
		if err := f.decryptFrame(c); err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		return s.Encryption().Check(seqNum, msgClass == MessageClassPriorityEncrypted)

	case MessageClassUnknown:
		fallthrough
	default:
		return errors.New("unknown message class")
	}
}

// SignRaw signs the raw frame, with any special handling.
func (f *FrameV1) SignRaw(key ed25519.PrivateKey) error {
	sig := ed25519.Sign(key, f.data[:f.authIndex])
	n := copy(f.authData(), sig)
	if n != len(sig) {
		return fmt.Errorf("copy sig to frame: copied %d/%d bytes", n, len(sig))
	}
	return nil
}

// VerifyRaw verifies the raw frame, with any special handling.
func (f *FrameV1) VerifyRaw(key ed25519.PublicKey) error {
	if !ed25519.Verify(key, f.data[:f.authIndex], f.authData()) {
		return ErrVerificationFailed
	}
	return nil
}

func (f *FrameV1) encryptFrame(c cipher.AEAD) {
	// Encrypt and authenticate data.
	toEncrypt := f.MessageData()
	c.Seal(toEncrypt[:0], f.nonce(), toEncrypt, f.associatedData())
}

func (f *FrameV1) decryptFrame(c cipher.AEAD) error {
	// Decrypt and authenticate data.
	toDecrypt := f.MessageDataWithAuth()
	_, err := c.Open(toDecrypt[:0], f.nonce(), toDecrypt, f.associatedData())
	return err
}

func (f *FrameV1) putFieldsIntoCryptoState() (done func()) {
	// Save current values.
	ttl := f.TTL()
	flowC := f.FlowControl()
	// Set values to zero for cryptographic operations.
	f.SetTTL(0)
	f.SetFlowControl(0)
	// Return done function to set data back to what it was.
	return func() {
		f.SetTTL(ttl)
		f.SetFlowControl(flowC)
	}
}

func (f *FrameV1) nonce() []byte {
	return f.data[frameV1FullNonceIndex : frameV1FullNonceIndex+12]
}

func (f *FrameV1) associatedData() []byte {
	return f.data[:f.messageIndex+frameV1MessageLengthSize]
}

func (f *FrameV1) authData() []byte {
	return f.data[f.authIndex:f.appendixIndex]
}
