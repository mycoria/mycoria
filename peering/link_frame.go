package peering

import (
	"fmt"

	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/state"
)

// Link Frame V1:
// --- 12B
// - Length (uint16)
// - Version (uint8)
// - Recv Rate (uint8) [0-100; in percent; 100% == received all link frames)]
// - SequenceNum uint32 (4 Bytes)
// - SequenceAck uint32 (4 Bytes)
// --- ~B
// - Link Data []byte
// --- 16B
// - MAC [16]byte

// Chacha20-Poly1305:
// Nonce Size: 12
// Overhead: 16

// Required Frame Margins.
const (
	FrameOffset   = 12
	FrameOverhead = 16
)

// LinkFrame is a minimal frame used to protect links.
type LinkFrame []byte

// Length returns the full frame length.
func (f LinkFrame) Length() uint16 {
	return m.GetUint16(f[:2])
}

// SetLength sets the full frame length.
func (f LinkFrame) SetLength(n uint16) {
	m.PutUint16(f[0:2], n)
}

// Version returns the frame version.
func (f LinkFrame) Version() uint8 {
	return f[2]
}

// SetVersion sets the frame version.
func (f LinkFrame) SetVersion(v uint8) {
	f[2] = v
}

// RecvRate returns the recv rate.
func (f LinkFrame) RecvRate() uint8 {
	return f[3]
}

// SetRecvRate sets the recv rate.
func (f LinkFrame) SetRecvRate(percent uint8) {
	f[3] = percent
}

// Nonce returns the slice of data used as the nonce.
func (f LinkFrame) Nonce() []byte {
	return f[:12]
}

// SequenceNum returns the sequence number.
func (f LinkFrame) SequenceNum() uint32 {
	return m.GetUint32(f[4:8])
}

// SetSequenceNum sets the sequence number.
func (f LinkFrame) SetSequenceNum(n uint32) {
	m.PutUint32(f[4:8], n)
}

// SequenceAck returns the acknowledge sequence number.
func (f LinkFrame) SequenceAck() uint32 {
	return m.GetUint32(f[8:12])
}

// SetSequenceAck sets the acknowledge sequence number.
func (f LinkFrame) SetSequenceAck(n uint32) {
	m.PutUint32(f[8:12], n)
}

// LinkData returns the data for the next layer.
func (f LinkFrame) LinkData() []byte {
	return f[FrameOffset : len(f)-FrameOverhead]
}

// LinkDataWithAuth the link data and the authentication data.
func (f LinkFrame) LinkDataWithAuth() []byte {
	return f[FrameOffset:]
}

// Seal sets the link frame metadata and encrypts everything.
func (f LinkFrame) Seal(encrypt *state.EncryptionSession) error {
	// Prepare.
	if len(f) > 0xFFFF {
		return fmt.Errorf("link frame is too big (%d bytes)", len(f))
	}
	seqNum, ack, recvRate, c, err := encrypt.Out(false)
	if err != nil {
		return err
	}
	f.SetLength(uint16(len(f)))
	f.SetVersion(1)
	f.SetRecvRate(recvRate)
	f.SetSequenceNum(seqNum)
	f.SetSequenceAck(ack)

	// Encrypt.
	toEncrypt := f.LinkData()
	c.Seal(toEncrypt[:0], f.Nonce(), toEncrypt, nil)

	return nil
}

// Unseal decrypts the link frame.
func (f LinkFrame) Unseal(encrypt *state.EncryptionSession) error {
	// Prepare.
	seqNum := f.SequenceNum()
	c, err := encrypt.In(seqNum, false)
	if err != nil {
		return err
	}

	// Decrypt and authenticate data.
	toDecrypt := f.LinkDataWithAuth()
	if _, err := c.Open(toDecrypt[:0], f.Nonce(), toDecrypt, nil); err != nil {
		return err
	}

	// Check sequence.
	return encrypt.Check(seqNum, false)
}
