package frame

import (
	"errors"
	"net/netip"
	"time"

	"github.com/mycoria/mycoria/state"
)

const (
	// V1 is frame version 1.
	V1 = 1
)

// Errors.
var (
	ErrInsufficientFrameData   = errors.New("insufficient frame data")
	ErrIncorrectLength         = errors.New("incorrect length")
	ErrUnsupportedFrameVersion = errors.New("unsupported frame version")
	ErrVerificationFailed      = errors.New("verification failed")
)

// Frame is a common interface to different frame versions.
type Frame interface {
	// Header

	// Version returns the frame version.
	Version() uint8
	// TTL returns the TTL.
	TTL() uint8
	// SetTTL sets the TTL.
	SetTTL(ttl uint8)
	// ReduceTTL reduces the ttl by the given amount.
	// Will not drop below zero.
	ReduceTTL(by uint8)
	// HasFlowFlag returns whether the given flow control flag is set.
	HasFlowFlag(FlowControlFlag) bool
	// SetFlowFlag sets the given flow control flag.
	SetFlowFlag(FlowControlFlag)
	// RecvRate returns the recv rate.
	RecvRate() uint8
	// SetRecvRate sets the recv rate.
	SetRecvRate(uint8)

	// ---

	// MessageType returns the message type.
	MessageType() MessageType
	// SetMessageType sets the message type.
	SetMessageType(MessageType)
	// SequenceNum returns the sequence number.
	SequenceNum() uint32
	// SetSequenceNum sets the sequence number.
	SetSequenceNum(uint32)
	// SequenceAck returns the sequence ack number.
	SequenceAck() uint32
	// SetSequenceAck sets the sequence ack number.
	SetSequenceAck(uint32)
	// SequenceTime returns the sequence time.
	SequenceTime() time.Time
	// SetSequenceTime sets the sequence time.
	SetSequenceTime(time.Time)

	// Src/Dst

	// SrcIP returns the frame source IP.
	SrcIP() netip.Addr
	// DstIP returns the frame destination IP.
	DstIP() netip.Addr

	// SwitchBlock returns the switch block.
	SwitchBlock() []byte
	// SetSwitchBlock sets the switch block.
	// It must be the same size as the existing block.
	SetSwitchBlock(update []byte) error
	// MessageData returns the message data.
	MessageData() []byte

	// MessageDataWithAuth returns the message data, including the auth data.
	MessageDataWithAuth() []byte
	// MessageDataWithOffset returns the message data with the given offset.
	// If you change any of the data, consider the frame invalid.
	MessageDataWithOffset(offset int) ([]byte, error)
	// AuthData returns the authentication data.
	AuthData() []byte
	// AppendixData returns the appendix data.
	AppendixData() []byte
	// SetAppendixData sets the appendix data.
	SetAppendixData(appendix []byte) error
	// FrameDataWithMargins returns the whole frame, including the given offset and overhead.
	FrameDataWithMargins(offset, overhead int) ([]byte, error)
	// Clone return an exact copy of the frame.
	Clone() Frame

	// Cryptography Handlers

	// Seal signs or encrypts the frame using the given session.
	Seal(s *state.Session) error
	// Unseal verifies or decrypts the frame using the given session.
	Unseal(s *state.Session) error

	// Received From Link

	// RecvLink returns the receive link.
	RecvLink() LinkAccessor
	// SetRecvLink sets the receive link.
	SetRecvLink(LinkAccessor)

	// Other

	// Reply transforms the frame into a reply.
	Reply(switchLabels, data, appendixData []byte) error
	// ReplyTo transforms the frame into a reply with the given src and dst addresses.
	ReplyTo(src, dst netip.Addr, switchLabels, data, appendixData []byte) error
	// ReturnToPool returns the frame and the included pooled slice to the pool.
	ReturnToPool()
}

// FlowControlFlag is a set of flow control flags.
type FlowControlFlag uint8

// Flow Control Flags.
const (
	FlowControlFlagDecreaseFlow FlowControlFlag = iota + 1
	FlowControlFlagHoldFlow
	FlowControlFlagIncreaseFlow
)

// ParseFrame parses a frame.
func (b *Builder) ParseFrame(data, pooledSlice []byte, dataOffset int) (Frame, error) {
	if len(data) < 1 {
		return nil, ErrInsufficientFrameData
	}
	switch data[0] {
	case V1:
		return b.ParseFrameV1(data, pooledSlice, dataOffset)
	default:
		return nil, ErrUnsupportedFrameVersion
	}
}
