package frame

// MessageType designates the message type of a frame.
type MessageType uint8

// Message Types.
const (
	RouterHopPingDeprecated MessageType = 0 // multicast, priority, signed
	RouterPing              MessageType = 1 // unicast, priority, signed
	RouterCtrl              MessageType = 2 // unicast, priority, encrypted
	RouterHopPing           MessageType = 3 // multicast, priority, signed

	NetworkTraffic MessageType = 8 // encrypted

	SessionCtrl MessageType = 16 // priority, encrypted
	SessionData MessageType = 17 // encrypted
)

// MessageClass is a class of messages with shared attributes.
type MessageClass uint8

// Message Classes.
const (
	MessageClassUnknown MessageClass = iota
	MessageClassSigned  MessageClass = iota
	MessageClassPriorityEncrypted
	MessageClassEncrypted
)

// Class returns whether the message class.
func (mt MessageType) Class() MessageClass {
	switch mt {
	case RouterHopPing, RouterHopPingDeprecated, RouterPing:
		return MessageClassSigned

	case RouterCtrl, SessionCtrl:
		return MessageClassPriorityEncrypted

	case NetworkTraffic, SessionData:
		return MessageClassEncrypted

	default:
		return MessageClassUnknown
	}
}

// IsPriority returns whether the message type is prioritized.
func (mt MessageType) IsPriority() bool {
	switch mt {
	case RouterHopPing, RouterHopPingDeprecated, RouterPing, RouterCtrl, SessionCtrl:
		return true
	case NetworkTraffic, SessionData:
		return false
	default:
		return false
	}
}

// IsEncrypted returns whether the message type is encrypted (instead of signing).
func (mt MessageType) IsEncrypted() bool {
	switch mt {
	case RouterCtrl, NetworkTraffic, SessionCtrl, SessionData:
		return true
	case RouterHopPing, RouterHopPingDeprecated, RouterPing:
		return false
	default:
		return false
	}
}

func (mt MessageType) String() string {
	switch mt {
	case RouterHopPing, RouterHopPingDeprecated:
		return "RouterHopPing"
	case RouterPing:
		return "RouterPing"
	case RouterCtrl:
		return "RouterCtrl"
	case SessionCtrl:
		return "SessionCtrl"
	case NetworkTraffic:
		return "NetworkTraffic"
	case SessionData:
		return "SessionData"
	default:
		return "Unknown"
	}
}
