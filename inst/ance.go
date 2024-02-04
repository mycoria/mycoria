package inst

import (
	"github.com/mycoria/mycoria/api/dns"
	"github.com/mycoria/mycoria/api/httpapi"
	"github.com/mycoria/mycoria/api/netstack"
	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/peering"
	"github.com/mycoria/mycoria/router"
	"github.com/mycoria/mycoria/state"
	"github.com/mycoria/mycoria/switchr"
	"github.com/mycoria/mycoria/tun"
)

// Ance (inst.Ance) is an interface to access global attributes of a router instance.
type Ance interface {
	Version() string
	Config() *config.Config
	Identity() *m.Address
	FrameBuilder() *frame.Builder

	State() *state.State
	TunDevice() *tun.Device
	NetStack() *netstack.NetStack
	API() *httpapi.API
	DNS() *dns.Server

	Peering() *peering.Peering
	Switch() *switchr.Switch
	Router() *router.Router
}

// AnceStub (inst.AnceStub) is a stub to easily create an inst.Ance.
type AnceStub struct {
	VersionStub      string
	ConfigStub       *config.Config
	IdentityStub     *m.Address
	FrameBuilderStub *frame.Builder

	StateStub     *state.State
	TunDeviceStub *tun.Device
	NetStackStub  *netstack.NetStack
	APIStub       *httpapi.API
	DNSStub       *dns.Server

	PeeringStub *peering.Peering
	SwitchStub  *switchr.Switch
	RouterStub  *router.Router
}

var _ Ance = &AnceStub{}

// Version returns the version.
func (stub *AnceStub) Version() string {
	return stub.VersionStub
}

// Config returns the config.
func (stub *AnceStub) Config() *config.Config {
	return stub.ConfigStub
}

// Identity returns the identity.
func (stub *AnceStub) Identity() *m.Address {
	return stub.IdentityStub
}

// FrameBuilder returns the frame builder.
func (stub *AnceStub) FrameBuilder() *frame.Builder {
	return stub.FrameBuilderStub
}

/////

// State returns the state manager.
func (stub *AnceStub) State() *state.State {
	return stub.StateStub
}

// TunDevice returns the tun device.
func (stub *AnceStub) TunDevice() *tun.Device {
	return stub.TunDeviceStub
}

// NetStack returns the local API netstack.
func (stub *AnceStub) NetStack() *netstack.NetStack {
	return stub.NetStackStub
}

// API returns the local http API.
func (stub *AnceStub) API() *httpapi.API {
	return stub.APIStub
}

// DNS returns the local DNS server.
func (stub *AnceStub) DNS() *dns.Server {
	return stub.DNSStub
}

/////

// Peering returns the peering manager.
func (stub *AnceStub) Peering() *peering.Peering {
	return stub.PeeringStub
}

// Switch returns the switch.
func (stub *AnceStub) Switch() *switchr.Switch {
	return stub.SwitchStub
}

// Router returns the router.
func (stub *AnceStub) Router() *router.Router {
	return stub.RouterStub
}
