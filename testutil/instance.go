package testutil

import (
	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/state"
)

// Instance is a testing helper instance.
// Most functions return a zero or default value.
// Inherit and just replace the parts you need.
// Some fields are of type "any", you will need
// to assert them in the return function.
type Instance struct {
	VersionStub  string
	ConfigStub   *config.Config
	IdentityStub *m.Address
	StateStub    *state.State

	TunDeviceStub any
	APIStub       any

	FrameBuilderStub any
	PeeringStub      any
	SwitchStub       any
	RouterStub       any

	RoutingTableStub *m.RoutingTable
}

// Version returns the version.
func (i *Instance) Version() string {
	return i.VersionStub
}

// Config returns the config.
func (i *Instance) Config() *config.Config {
	return i.ConfigStub
}

// Identity returns the identity.
func (i *Instance) Identity() *m.Address {
	return i.IdentityStub
}

// State returns the state manager.
func (i *Instance) State() *state.State {
	return i.StateStub
}

// TunDevice returns the tun device.
func (i *Instance) TunDevice() any {
	return nil
}

// API returns the api.
func (i *Instance) API() any {
	return nil
}

// FrameBuilder returns the frame builder.
func (i *Instance) FrameBuilder() any {
	return nil
}

// Peering returns the peering manager.
func (i *Instance) Peering() any {
	return nil
}

// Switch returns the switch.
func (i *Instance) Switch() any {
	return nil
}

// Router returns the router.
func (i *Instance) Router() any {
	return nil
}

// RoutingTable returns the routing table.
func (i *Instance) RoutingTable() *m.RoutingTable {
	return i.RoutingTableStub
}
