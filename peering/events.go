package peering

import "net/netip"

// EventPeering is a peering event.
type EventPeering struct {
	Peer  netip.Addr
	State EventState
}

// EventState describes a peering event state.
type EventState string

// Peering Event States.
const (
	EventStateUp   = "up"
	EventStateDown = "down"
)
