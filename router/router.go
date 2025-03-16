package router

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mycoria/mycoria/api/httpapi"
	"github.com/mycoria/mycoria/api/netstack"
	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/peering"
	"github.com/mycoria/mycoria/state"
	"github.com/mycoria/mycoria/switchr"
	"github.com/mycoria/mycoria/tun"
)

// Router is the primary handler for frames.
type Router struct {
	mgr *mgr.Manager

	routerConfig  Config
	input         chan frame.Frame
	handleTraffic atomic.Bool

	table *m.RoutingTable

	pingHandlers     map[string]PingHandler
	pingHandlersLock sync.RWMutex

	connStates     map[connStateKey]*connStateEntry
	connStatesLock sync.RWMutex

	HelloPing      *HelloPingHandler
	PingPong       *PingPongHandler
	ErrorPing      *ErrorPingHandler
	AnnouncePing   *AnnouncePingHandler
	DisconnectPing *DisconnectPingHandler

	instance instance
}

// instance is an interface subset of inst.Ance.
type instance interface {
	Version() string
	Config() *config.Config
	Identity() *m.Address
	FrameBuilder() *frame.Builder

	State() *state.State
	NetStack() *netstack.NetStack
	API() *httpapi.API

	TunDevice() *tun.Device
	Switch() *switchr.Switch
	Peering() *peering.Peering
}

// Config configures the router.
type Config struct {
	Table m.RoutingTableConfig
}

// New returns a new router.
func New(instance instance, routerConfig Config) (*Router, error) {
	// Setup routing table.
	// Get router IP and default prefix.
	routerIP := instance.Identity().IP
	routerPrefix := netip.PrefixFrom(routerIP, m.RegionPrefixBits)
	// Make prefix more precise by looking up the country marker.
	marker, err := m.LookupCountryMarker(routerIP)
	if err == nil {
		routerPrefix = marker.Prefix
	}
	if !routerPrefix.Contains(routerIP) {
		return nil, errors.New("internal error: failed to derive router IP prefix")
	}
	// Create routing table.
	tbl := m.NewRoutingTable(m.RoutingTableConfig{
		RoutablePrefixes: m.GetRoutablePrefixesFor(routerIP, routerPrefix),
		RouterIP:         routerIP,
	})

	// Create router.
	r := &Router{
		mgr:          mgr.New("router"),
		routerConfig: routerConfig,
		input:        make(chan frame.Frame),
		table:        tbl,
		pingHandlers: make(map[string]PingHandler),
		connStates:   make(map[connStateKey]*connStateEntry),
		instance:     instance,
	}
	if r.instance.Config().System.DisableTun {
		r.handleTraffic.Store(false)
	} else {
		r.handleTraffic.Store(true)
	}

	// Set and register ping handlers.
	r.HelloPing = NewHelloPingHandler(r)
	if err := r.RegisterPingHandler(r.HelloPing); err != nil {
		return nil, err
	}
	r.PingPong = NewPingPongHandler(r)
	if err := r.RegisterPingHandler(r.PingPong); err != nil {
		return nil, err
	}
	r.ErrorPing = NewErrorPingHandler(r)
	if err := r.RegisterPingHandler(r.ErrorPing); err != nil {
		return nil, err
	}
	r.AnnouncePing = NewAnnouncePingHandler(r)
	if err := r.RegisterPingHandler(r.AnnouncePing); err != nil {
		return nil, err
	}
	r.DisconnectPing = NewDisconnectPingHandler(r)
	if err := r.RegisterPingHandler(r.DisconnectPing); err != nil {
		return nil, err
	}

	return r, nil
}

// Manager returns the module's manager.
func (r *Router) Manager() *mgr.Manager {
	return r.mgr
}

// Start starts the router.
func (r *Router) Start() error {
	r.mgr.Go("announce router", r.announceWorker)
	r.mgr.Go("accounce disconnects", r.disconnectWorker)
	r.mgr.Go("keep-alive peers", r.keepAliveWorker)

	r.mgr.Go("clean conn states", r.cleanConnStatesWorker)
	r.mgr.Go("clean ping handlers", r.cleanPingHandlersWorker)
	r.mgr.Go("clean routing table", r.cleanRoutingTableWorker)

	for i := 0; i < runtime.NumCPU(); i++ {
		r.mgr.Go("router", r.frameHandler)

		if !r.instance.Config().System.DisableTun {
			r.mgr.Go("tun handler", r.handleTun)
		}
	}

	return nil
}

// Stop stops the router.
func (r *Router) Stop() error {
	// Disable traffic handling.
	r.handleTraffic.Store(false)

	// Send disconnect message to tell others we are going offline.
	if err := r.DisconnectPing.Send(true, nil); err != nil {
		r.mgr.Warn(
			"failed to send disconnect ping",
			"err", err,
		)
	}

	// Wait for 100ms for disconnect ping to be sent.
	// TODO: Can we improve this?
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Input returns the router input channel.
func (r *Router) Input() chan frame.Frame {
	return r.input
}

// Table returns the routing table.
func (r *Router) Table() *m.RoutingTable {
	return r.table
}

func (r *Router) frameHandler(w *mgr.WorkerCtx) error {
	for {
		select {
		case f := <-r.input:
			if err := r.handleFrame(w, f); err != nil {
				w.Debug(
					"failed to handle frame",
					"router", f.SrcIP(),
					"dst", f.DstIP(),
					"msgtype", f.MessageType(),
					"err", err,
				)
				f.ReturnToPool()
			}
		case <-w.Done():
			return nil
		}
	}
}

func (r *Router) handleFrame(w *mgr.WorkerCtx, f frame.Frame) error {
	switch {
	case f.DstIP() == r.instance.Identity().IP:
		// If the frame is destined to us, handle as incoming frame.
		return r.handleIncomingFrame(w, f)

	case f.MessageType() == frame.RouterHopPingDeprecated:
		fallthrough
	case f.MessageType() == frame.RouterHopPing:
		// If the frame is a hop ping, handle as incoming frame.
		return r.handleIncomingFrame(w, f)

	default:
		// Otherwise, handle as unsolicited frame.
		return r.handleUnsolicitedFrame(f)
	}
}

func (r *Router) handleIncomingFrame(w *mgr.WorkerCtx, f frame.Frame) error {
	switch f.MessageType() {
	case frame.RouterPing, frame.RouterCtrl, frame.RouterHopPing, frame.RouterHopPingDeprecated:
		return r.handlePing(w, f)

	case frame.NetworkTraffic:
		return r.handleIncomingTraffic(w, f)

	case frame.SessionCtrl:
		return errors.New("not yet supported")

	case frame.SessionData:
		return errors.New("not yet supported")

	default:
		return fmt.Errorf("unknown message type: %d", f.MessageType())
	}
}

func (r *Router) handleUnsolicitedFrame(f frame.Frame) error {
	// For now, just forward.
	err := r.RouteFrame(f)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrWouldLoop):
		if err := r.ErrorPing.SendUnreachable(f.SrcIP(), f.DstIP()); err != nil {
			return fmt.Errorf("send unreachable ping: %w", err)
		}
		return nil
	default:
		return err
	}
}
