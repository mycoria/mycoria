package mycoria

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mycoria/mycoria/api/dns"
	"github.com/mycoria/mycoria/api/httpapi"
	"github.com/mycoria/mycoria/api/netstack"
	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/dashboard"
	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/peering"
	"github.com/mycoria/mycoria/router"
	"github.com/mycoria/mycoria/state"
	"github.com/mycoria/mycoria/storage"
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

	storage   storage.Storage
	state     *state.State
	tunDevice *tun.Device
	netstack  *netstack.NetStack
	api       *httpapi.API
	dns       *dns.Server

	peering *peering.Peering
	switchr *switchr.Switch
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
	instance.frameBuilder = frame.NewFrameBuilder()
	instance.frameBuilder.SetFrameMargins(peering.FrameOffset, peering.FrameOverhead)

	// Load storage and create state manager.
	switch {
	case c.System.StatePath == "":
		instance.storage = storage.NewMemStorage()
	case strings.HasSuffix(c.System.StatePath, ".json"):
		var err error
		instance.storage, err = storage.NewJSONFileStorage(c.System.StatePath)
		if err != nil {
			return nil, fmt.Errorf("load state: %w", err)
		}
	default:
		return nil, errors.New("unknown state file type")
	}
	instance.state = state.New(instance, instance.storage)

	// Create tunnel interface and add router IP.
	if !c.System.DisableTun {
		instance.tunDevice, err = tun.Create(instance)
		if err != nil {
			return nil, fmt.Errorf("create tun device: %w", err)
		}
	}

	// Create API.
	instance.netstack, err = netstack.New(instance, instance.tunDevice)
	if err != nil {
		return nil, fmt.Errorf("create local API netstack: %w", err)
	}
	ln, err := instance.netstack.ListenTCP(80)
	if err != nil {
		return nil, fmt.Errorf("listen on API netstack: %w", err)
	}
	instance.api, err = httpapi.New(instance, ln)
	if err != nil {
		return nil, fmt.Errorf("create local http API: %w", err)
	}
	packetConn, err := instance.netstack.ListenUDP(53)
	if err != nil {
		return nil, fmt.Errorf("listen on API netstack: %w", err)
	}
	instance.dns, err = dns.New(instance, packetConn, instance.storage)
	if err != nil {
		return nil, fmt.Errorf("create local http API: %w", err)
	}

	// Create router.
	instance.router, err = router.New(instance, router.Config{})
	if err != nil {
		return nil, fmt.Errorf("create router: %w", err)
	}

	// Create switch.
	instance.switchr = switchr.New(instance, instance.router.Input())

	// Create peering.
	instance.peering = peering.New(instance, instance.switchr.Input())

	// Add protocols.
	instance.peering.AddProtocol("tcp", peering.ProtocolTCP)

	// Create dashboard.
	dashboard, err := dashboard.New(instance)
	if err != nil {
		return nil, fmt.Errorf("create dashboard: %w", err)
	}

	// Add all modules to instance group.
	instance.Group = mgr.NewGroup(
		instance.storage,

		instance.state,
		instance.tunDevice,
		instance.netstack,
		instance.api,
		instance.dns,

		instance.peering,
		instance.switchr,
		instance.router,

		dashboard,
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

// FrameBuilder returns the frame builder.
func (i *Instance) FrameBuilder() *frame.Builder {
	return i.frameBuilder
}

/////

// Storage returns the storage.
func (i *Instance) Storage() storage.Storage {
	return i.storage
}

// State returns the state manager.
func (i *Instance) State() *state.State {
	return i.state
}

// TunDevice returns the tun device.
func (i *Instance) TunDevice() *tun.Device {
	return i.tunDevice
}

// NetStack returns the local API netstack.
func (i *Instance) NetStack() *netstack.NetStack {
	return i.netstack
}

// API returns the local http API.
func (i *Instance) API() *httpapi.API {
	return i.api
}

// DNS returns the local DNS server.
func (i *Instance) DNS() *dns.Server {
	return i.dns
}

/////

// Peering returns the peering manager.
func (i *Instance) Peering() *peering.Peering {
	return i.peering
}

// Switch returns the switch.
func (i *Instance) Switch() *switchr.Switch {
	return i.switchr
}

// Router returns the router.
func (i *Instance) Router() *router.Router {
	return i.router
}

// RoutingTable returns the routing table.
func (i *Instance) RoutingTable() *m.RoutingTable {
	return i.router.Table()
}
