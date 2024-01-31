package frame

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/tevino/abool"

	"github.com/mycoria/mycoria/m"
)

// Frame V1:
// --- 16B
// - Version (uint8)
// - TTL (uint8) [set to zero for cryptographic ops]
// - Flow Control Flags (uint8) [set by switch hops, set to zero for cryptographic ops]
// - Frame Recv Rate (uint8) [0-100; in percent; 100% == received all frames)]
// - Message Type (uint8) [types are prio/lossy and signed/encrypted]
// - Random Nonce [3]byte
// - Sequencing: (8 Bytes)
//   - Encryption:
//     - SequenceNum uint32 (4 Bytes) [per message type priority]
//     - SequenceAck uint32 (4 Bytes) [per message type priority]
//   - Signing:
//     - SequenceTime uint64/time.Time (8 Bytes) [per message type priority]
// --- 32B
// - SrcIPData [16]byte
// - DstIPData [16]byte
// --- ~B
// - Switch Block Length (uint8; zero for no switching)
// - Switch Block ([]byte; if any) [signed/MAC'd in the final format the receiving node sees]
// --- ~B
// - Message Data Length (uint16)
// - Message Data []byte (signed or encrypted envelope)
// --- 16B or 64B
// - MAC [16]byte or Signature [64]byte
// ----
// - Message Appendix Data [not AEAD encrypted or signed]
//   - Only for Router Messages for router to tack on their data, which may be signed or encrypted.

// Chacha20-Poly1305:
// Nonce Size: 12
// Overhead: 16

// Ed25519:
// Sig Size: 64

// FrameV1 is a frame in version 1.
type FrameV1 struct { //nolint:golint
	// Raw frame - a subslice of pooledSlice.
	data []byte

	// Data block indexes
	messageIndex  int
	authIndex     int
	appendixIndex int

	// Parsed data
	src netip.Addr
	dst netip.Addr

	// Link
	recvLink LinkAccessor

	// Pooling
	builder        *Builder
	pooledSlice    []byte
	psDataOffset   int
	dblReturnCheck abool.AtomicBool
}

const (
	frameV1MinSize = 40 + // Header
		1 + // Switch Block Length
		2 + // Message Data Length
		1 + // At least 1 byte of Message Data
		16 // Smallest Auth

	frameV1BaseSize = 40 + // Header
		1 + // Switch Block Length
		2 // Message Data Length

	frameV1MessageLimit  = 10000
	frameV1AppendixLimit = 10000

	frameV1SwitchBlockLengthSize = 1
	frameV1MessageLengthSize     = 2

	frameV1FullNonceIndex   = 4
	frameV1SwitchBlockIndex = 48

	frameV1MACSize = 16
	frameV1SigSize = 64
)

// NewFrameV1 returns a new frame (v1) with the given data set.
func (b *Builder) NewFrameV1(
	src, dst netip.Addr,
	msgType MessageType,
	switchLabels, data, appendixData []byte,
) (*FrameV1, error) {
	// Create and initialize frame.
	f := b.frameV1Pool.Get().(*FrameV1) //nolint:forcetypeassert
	f.dblReturnCheck.UnSet()
	if err := f.initFrame(
		src, dst,
		msgType,
		switchLabels, data, appendixData,
	); err != nil {
		return nil, err
	}

	return f, nil
}

// Reply transforms the frame into a reply.
func (f *FrameV1) Reply(switchLabels, data, appendixData []byte) error {
	return f.initFrame(
		f.dst, f.src,
		f.MessageType(),
		switchLabels, data, appendixData,
	)
}

// ReplyTo transforms the frame into a reply with the given src and dst addresses.
func (f *FrameV1) ReplyTo(src, dst netip.Addr, switchLabels, data, appendixData []byte) error {
	return f.initFrame(
		src, dst,
		f.MessageType(),
		switchLabels, data, appendixData,
	)
}

func (f *FrameV1) initFrame(
	src, dst netip.Addr,
	msgType MessageType,
	switchLabels, data, appendixData []byte,
) error {
	// Determine sizes.
	offset, overhead := f.builder.FrameMargins()
	authSize := frameV1SigSize
	if msgType.IsEncrypted() {
		authSize = frameV1MACSize
	}
	requiredSize := offset + frameV1BaseSize + len(switchLabels) +
		len(data) + authSize + len(appendixData) + overhead

	// Get new pooled slice if not big enough.
	if len(f.pooledSlice) < requiredSize {
		// Get new pooled slice.
		if f.builder == nil {
			return errors.New("frame has no builder")
		}
		ps := f.builder.GetPooledSlice(requiredSize)

		// Return pooled slice to pool.
		if f.pooledSlice != nil {
			f.builder.ReturnPooledSlice(f.pooledSlice)
		}
		f.pooledSlice = ps
	}

	// Set offset and overhead.
	f.data = f.pooledSlice[offset : len(f.pooledSlice)-overhead]
	f.psDataOffset = offset

	// Set all data.
	if err := f.initHeader(src, dst, msgType); err != nil {
		return err
	}
	if err := f.setData(switchLabels, data, appendixData); err != nil {
		return err
	}

	// Reset link.
	f.recvLink = nil

	return nil
}

func (f *FrameV1) initHeader(src, dst netip.Addr, msgType MessageType) error {
	// Version
	f.data[0] = V1
	// TTL
	f.data[1] = 32
	// Flow Control Flags
	f.data[2] = 0
	// Receive Rate
	f.SetRecvRate(0)

	// Message Type
	f.SetMessageType(msgType)
	// Random Nonce [3]byte
	_, err := rand.Read(f.data[5:8])
	if err != nil {
		return err
	}

	// SequenceNum
	// SequenceAck
	clear(f.data[8:16])

	// SrcIPData
	f.src = src
	srcData := src.As16()
	copy(f.data[16:32], srcData[:])
	// DstIPData
	f.dst = dst
	dstData := dst.As16()
	copy(f.data[32:48], dstData[:])

	return nil
}

func (f *FrameV1) setData(switchBlock, message, appendix []byte) error {
	// Expand data to full size.
	f.data = f.data[0:cap(f.data)]

	// Add switch label data.
	switch {
	case len(switchBlock) == 0:
		f.data[frameV1SwitchBlockIndex] = 0
		f.messageIndex = frameV1SwitchBlockIndex + frameV1SwitchBlockLengthSize
	case len(switchBlock) > 255:
		return errors.New("switch labels too big")
	default:
		f.data[frameV1SwitchBlockIndex] = uint8(len(switchBlock))
		switchBlockEndIndex := frameV1SwitchBlockIndex + frameV1SwitchBlockLengthSize + len(switchBlock)
		copy(f.data[frameV1SwitchBlockIndex+frameV1SwitchBlockLengthSize:switchBlockEndIndex], switchBlock)
		f.messageIndex = switchBlockEndIndex
	}

	// Add message data.
	switch {
	case len(message) == 0:
		return errors.New("message data may not be empty")
	case len(message) > frameV1MessageLimit:
		return errors.New("message data too big")
	default:
		m.PutUint16(f.data[f.messageIndex:f.messageIndex+frameV1MessageLengthSize], uint16(len(message)))
		messageEndIndex := f.messageIndex + frameV1MessageLengthSize + len(message)
		copy(f.data[f.messageIndex+frameV1MessageLengthSize:messageEndIndex], message)
		f.authIndex = messageEndIndex
	}

	// Calculate auth size.
	authSize := frameV1SigSize
	if f.MessageType().IsEncrypted() {
		authSize = frameV1MACSize
	}
	f.appendixIndex = f.authIndex + authSize

	// Add appendix data.
	var endIndex int
	switch {
	case len(appendix) == 0:
		endIndex = f.appendixIndex
	case len(appendix) > frameV1AppendixLimit:
		return errors.New("appendix data too big")
	default:
		endIndex = f.appendixIndex + len(appendix)
		copy(f.data[f.appendixIndex:endIndex], appendix)
	}

	// Set end of frame.
	f.data = f.data[:endIndex]

	// Clear auth data.
	clear(f.authData())

	return nil
}

// ParseFrameV1 parses a version 1 frame.
func (b *Builder) ParseFrameV1(data, pooledSlice []byte, dataOffset int) (*FrameV1, error) {
	// Check minimum length.
	if len(data) < frameV1MinSize {
		return nil, ErrInsufficientFrameData
	}

	// Build frame.
	f := b.frameV1Pool.Get().(*FrameV1) //nolint:forcetypeassert
	f.dblReturnCheck.UnSet()
	f.builder = b
	f.data = data
	f.pooledSlice = pooledSlice
	f.psDataOffset = dataOffset

	// Check all length attributes and save the ranges.

	// Get switch label size.
	switchBlockEndIndex := frameV1SwitchBlockIndex + frameV1SwitchBlockLengthSize + int(f.data[frameV1SwitchBlockIndex])

	// Get message data size.
	f.messageIndex = switchBlockEndIndex
	if len(f.data) < f.messageIndex+19 {
		return nil, fmt.Errorf(
			"%w: not enough space for message (%d<%d)",
			ErrInsufficientFrameData,
			len(f.data),
			f.messageIndex+19,
		)
	}
	messageSize := int(m.GetUint16(f.data[switchBlockEndIndex : switchBlockEndIndex+2]))
	messageDataEndIndex := f.messageIndex + frameV1MessageLengthSize + messageSize

	// Calculate auth size.
	f.authIndex = messageDataEndIndex
	authSize := frameV1SigSize
	if f.MessageType().IsEncrypted() {
		authSize = frameV1MACSize
	}
	authEndIndex := f.authIndex + authSize

	// Get appendix data size.
	f.appendixIndex = authEndIndex
	appendixDataEndIndex := len(f.data)

	// Check final size.
	if f.appendixIndex > appendixDataEndIndex {
		return nil, fmt.Errorf(
			"%w: not enough space after evaluating data, auth and appendix size (%d>%d)",
			ErrInsufficientFrameData,
			f.appendixIndex,
			appendixDataEndIndex,
		)
	}

	return f, nil
}

// Version returns the frame version.
func (f *FrameV1) Version() uint8 {
	return f.data[0]
}

// TTL returns the TTL.
func (f *FrameV1) TTL() uint8 {
	return f.data[1]
}

// SetTTL sets the TTL.
func (f *FrameV1) SetTTL(ttl uint8) {
	f.data[1] = ttl
}

// ReduceTTL reduces the ttl by the given amount.
// Will not drop below zero.
func (f *FrameV1) ReduceTTL(by uint8) {
	if by < f.data[1] {
		f.data[1] -= by
	} else {
		f.data[1] = 0
	}
}

// FlowControl returns the flow control flag set.
func (f *FrameV1) FlowControl() uint8 {
	return f.data[2]
}

// SetFlowControl sets the flow control flag set to the given value.
func (f *FrameV1) SetFlowControl(fc uint8) {
	f.data[2] = fc
}

// HasFlowFlag returns whether the given flow control flag is set.
func (f *FrameV1) HasFlowFlag(flag FlowControlFlag) bool {
	return FlowControlFlag(f.data[2])&flag == flag
}

// SetFlowFlag sets the given flow control flag.
func (f *FrameV1) SetFlowFlag(flag FlowControlFlag) {
	f.data[2] |= uint8(flag)
}

// RecvRate returns the recv rate.
func (f *FrameV1) RecvRate() uint8 {
	return f.data[3]
}

// SetRecvRate sets the recv rate.
func (f *FrameV1) SetRecvRate(percent uint8) {
	f.data[3] = percent
}

// MessageType returns the message type.
func (f *FrameV1) MessageType() MessageType {
	return MessageType(f.data[4])
}

// SetMessageType sets the message type.
func (f *FrameV1) SetMessageType(msgType MessageType) {
	f.data[4] = uint8(msgType)
}

// SequenceNum returns the sequence number.
func (f *FrameV1) SequenceNum() uint32 {
	return m.GetUint32(f.data[8:12])
}

// SetSequenceNum sets the sequence number.
func (f *FrameV1) SetSequenceNum(n uint32) {
	m.PutUint32(f.data[8:12], n)
}

// SequenceAck returns the sequence ack number.
func (f *FrameV1) SequenceAck() uint32 {
	return m.GetUint32(f.data[12:16])
}

// SetSequenceAck sets the sequence ack number.
func (f *FrameV1) SetSequenceAck(n uint32) {
	m.PutUint32(f.data[12:16], n)
}

// SequenceTime returns the sequence time.
func (f *FrameV1) SequenceTime() time.Time {
	return time.UnixMilli(int64(m.GetUint64(f.data[8:16])))
}

// SetSequenceTime sets the sequence time.
func (f *FrameV1) SetSequenceTime(t time.Time) {
	m.PutUint64(f.data[8:16], uint64(t.UnixMilli()))
}

// SrcIP returns the frame source IP.
func (f *FrameV1) SrcIP() netip.Addr {
	if f.src.IsValid() {
		return f.src
	}
	f.src = netip.AddrFrom16([16]byte(f.data[16:32]))
	return f.src
}

// DstIP returns the frame destination IP.
func (f *FrameV1) DstIP() netip.Addr {
	if f.dst.IsValid() {
		return f.dst
	}
	f.dst = netip.AddrFrom16([16]byte(f.data[32:48]))
	return f.dst
}

// SwitchBlock returns the switch block.
func (f *FrameV1) SwitchBlock() []byte {
	return f.data[frameV1SwitchBlockIndex+frameV1SwitchBlockLengthSize : f.messageIndex]
}

// SetSwitchBlock sets the switch block.
// It must be the same size as the existing block.
func (f *FrameV1) SetSwitchBlock(update []byte) error {
	if len(update) != f.messageIndex-(frameV1SwitchBlockIndex+frameV1SwitchBlockLengthSize) {
		return errors.New("switch label update must be the same size")
	}

	copy(f.data[frameV1SwitchBlockIndex+frameV1SwitchBlockLengthSize:f.messageIndex], update)
	return nil
}

// MessageData returns the message data.
func (f *FrameV1) MessageData() []byte {
	return f.data[f.messageIndex+frameV1MessageLengthSize : f.authIndex]
}

// MessageDataWithAuth returns the message data, including the auth data.
func (f *FrameV1) MessageDataWithAuth() []byte {
	return f.data[f.messageIndex+frameV1MessageLengthSize : f.appendixIndex]
}

// MessageDataWithOffset returns the message data with the given offset.
// If you change any of the data, consider the frame invalid.
func (f *FrameV1) MessageDataWithOffset(offset int) ([]byte, error) {
	start := (f.messageIndex + frameV1MessageLengthSize) - offset
	if start < 0 {
		return nil, fmt.Errorf(
			"margins out of bound: request offset of %d, but only %d is available",
			offset,
			f.messageIndex+frameV1MessageLengthSize,
		)
	}
	return f.data[start:f.authIndex], nil
}

// AuthData returns the authentication data.
func (f *FrameV1) AuthData() []byte {
	return f.data[f.authIndex:f.appendixIndex]
}

// AppendixData returns the appendix data.
func (f *FrameV1) AppendixData() []byte {
	return f.data[f.appendixIndex:]
}

// SetAppendixData sets the appendix data.
func (f *FrameV1) SetAppendixData(appendix []byte) error {
	origDataSize := len(f.data)

	// Expand data so we have enough space.
	f.data = f.data[:cap(f.data)]

	// Add appendix data.
	var endIndex int
	switch {
	case f.appendixIndex <= 0:
		f.data = f.data[:origDataSize]
		return errors.New("frame is not initialized")

	case len(appendix) == 0:
		// Remove appendix.
		f.data = f.data[:f.appendixIndex]
		return nil

	case len(appendix) > frameV1AppendixLimit:
		f.data = f.data[:origDataSize]
		return errors.New("appendix data too big")

	case len(appendix) > len(f.data)-f.appendixIndex:
		f.data = f.data[:origDataSize]
		return errors.New("not enough space for appendix")

	default:
		// Write new appendix.
		endIndex = f.appendixIndex + len(appendix)
		copy(f.data[f.appendixIndex:endIndex], appendix)

		// Set end of frame.
		f.data = f.data[:endIndex]

		return nil
	}
}

// FrameDataWithMargins returns the whole frame, including the given offset and overhead.
func (f *FrameV1) FrameDataWithMargins(offset, overhead int) ([]byte, error) {
	start := f.psDataOffset - offset
	end := f.psDataOffset + len(f.data) + overhead
	if start < 0 {
		return nil, fmt.Errorf("margins out of bound: request offset of %d, but only %d is available", offset, f.psDataOffset)
	}
	if end > len(f.pooledSlice) {
		return nil, fmt.Errorf("margins out of bound: request overhead of %d, but only %d is available", overhead,
			len(f.pooledSlice)-(f.psDataOffset+len(f.data)))
	}

	return f.pooledSlice[start:end], nil
}

// Clone return an exact copy of the frame.
func (f *FrameV1) Clone() Frame {
	c := f.builder.frameV1Pool.Get().(*FrameV1) //nolint:forcetypeassert
	c.dblReturnCheck.UnSet()

	// Copy metadata.
	c.messageIndex = f.messageIndex
	c.authIndex = f.authIndex
	c.appendixIndex = f.appendixIndex
	c.src = f.src
	c.dst = f.dst
	c.recvLink = f.recvLink
	c.builder = f.builder
	c.psDataOffset = f.psDataOffset

	// Copy pooled slice to new pooled slice.
	c.pooledSlice = f.builder.GetPooledSlice(len(c.pooledSlice))
	copy(c.pooledSlice, f.pooledSlice)

	// Recreate correct data slice.
	c.data = c.pooledSlice[c.psDataOffset : c.psDataOffset+len(f.data)]

	return c
}

// RecvLink returns the receive link.
func (f *FrameV1) RecvLink() LinkAccessor {
	return f.recvLink
}

// SetRecvLink sets the receive link.
func (f *FrameV1) SetRecvLink(link LinkAccessor) {
	f.recvLink = link
}

// ReturnToPool returns the frame and the included pooled slice to the pool.
func (f *FrameV1) ReturnToPool() {
	// Do nothing if no builder is referenced.
	if f.builder == nil {
		return
	}

	// Check if frame was already returned.
	if !f.dblReturnCheck.SetToIf(false, true) {
		panic("double return to pool!")
	}

	// Return pooled slice to pool.
	if f.pooledSlice != nil {
		f.builder.ReturnPooledSlice(f.pooledSlice)
	}

	// Clear frame data.
	f.data = nil
	f.messageIndex = 0
	f.authIndex = 0
	f.appendixIndex = 0
	f.src = netip.Addr{}
	f.dst = netip.Addr{}
	f.pooledSlice = nil
	f.psDataOffset = 0
	// Return frame to pool.
	f.builder.frameV1Pool.Put(f)
}
