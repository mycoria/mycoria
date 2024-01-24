package mycoria

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mycoria/mycoria/api"
	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/peering"
	"github.com/mycoria/mycoria/router"
	"github.com/mycoria/mycoria/state"
	"github.com/mycoria/mycoria/switchr"
	"github.com/mycoria/mycoria/tun"
)

// Instance is an instance of a mycoria router.
type Instance struct {
	*mgr.Group

	version      string
	config       *config.Config
	identity     *m.Address
	frameBuilder *frame.Builder

	state     *state.State
	tunDevice *tun.Device
	api       *api.API

	peering *peering.Peering
	swtch   *switchr.Switch
	router  *router.Router
}

// New returns a new mycoria router instance.
func New(version string, c *config.Config) (*Instance, error) {
	identity, err := m.AddressFromStorage(c.Router.Address)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	// Create instance to pass it to modules.
	instance := &Instance{
		version:  version,
		config:   c,
		identity: identity,
	}

	// Create frame builder.
	builder := frame.NewFrameBuilder()
	builder.SetFrameMargins(peering.FrameOffset, peering.FrameOverhead)
	instance.frameBuilder = builder

	// Load state and create state manager.
	var stateStorage state.Storage
	switch {
	case c.System.StatePath == "":
		stateStorage = state.NewMemStorage()
	case strings.HasSuffix(c.System.StatePath, ".json"):
		var err error
		stateStorage, err = state.NewJSONFileStorage(c.System.StatePath)
		if err != nil {
			return nil, fmt.Errorf("load state: %w", err)
		}
	default:
		return nil, errors.New("unknown state file type")
	}
	stateMgr := state.New(instance, stateStorage)
	instance.state = stateMgr

	// Create tunnel interface and add router IP.
	tunDev, err := tun.Create(instance)
	if err != nil {
		return nil, fmt.Errorf("create tun device: %w", err)
	}
	instance.tunDevice = tunDev

	// Create API.
	apiI, err := api.New(instance, tunDev)
	if err != nil {
		return nil, fmt.Errorf("create api endpoint: %w", err)
	}
	instance.api = apiI

	// Create router.
	routerI, err := router.New(instance, router.Config{})
	if err != nil {
		return nil, fmt.Errorf("create router: %w", err)
	}
	instance.router = routerI

	// Create switch.
	switchI := switchr.New(instance, routerI.Input())
	instance.swtch = switchI

	// Create peering.
	peeringI := peering.New(instance, switchI.Input())
	instance.peering = peeringI

	// Add protocols.
	peeringI.AddProtocol("tcp", peering.ProtocolTCP)

	// Add all modules to instance group.
	instance.Group = mgr.NewGroup(
		stateMgr,
		tunDev,
		apiI,

		peeringI,
		switchI,
		routerI,
	)

	return instance, nil
}

// Version returns the version.
func (i *Instance) Version() string {
	return i.version
}

// Config returns the config.
func (i *Instance) Config() *config.Config {
	return i.config
}

// Identity returns the identity.
func (i *Instance) Identity() *m.Address {
	return i.identity
}

// State returns the state manager.
func (i *Instance) State() *state.State {
	return i.state
}

// TunDevice returns the tun device.
func (i *Instance) TunDevice() *tun.Device {
	return i.tunDevice
}

// API returns the api.
func (i *Instance) API() *api.API {
	return i.api
}

// FrameBuilder returns the frame builder.
func (i *Instance) FrameBuilder() *frame.Builder {
	return i.frameBuilder
}

// Peering returns the peering manager.
func (i *Instance) Peering() *peering.Peering {
	return i.peering
}

// Switch returns the switch.
func (i *Instance) Switch() *switchr.Switch {
	return i.swtch
}

// Router returns the router.
func (i *Instance) Router() *router.Router {
	return i.router
}

// RoutingTable returns the routing table.
func (i *Instance) RoutingTable() *m.RoutingTable {
	return i.router.Table()
}
