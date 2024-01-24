package tun

import (
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/state"
)

// DefaultTunName is the default interface name for the tunnel interface.
const DefaultTunName = "mycoria"

// Device represents a tun device.
type Device struct {
	linkName  string
	linkIndex int

	tun tun.Device

	primaryAddress netip.Prefix
	secondaryIPs   []netip.Prefix

	RecvRaw   chan []byte
	SendRaw   chan []byte
	SendFrame chan frame.Frame

	instance instance
}

// instance is an interface subset of inst.Ance.
type instance interface {
	Version() string
	Config() *config.Config
	Identity() *m.Address
	State() *state.State
	FrameBuilder() *frame.Builder
}

// Create creates a tun device and returns it.
func Create(instance instance) (*Device, error) {
	// Get parameters.
	linkName := instance.Config().System.TunName
	if linkName == "" {
		linkName = DefaultTunName
	}
	primaryAddress := netip.PrefixFrom(instance.Identity().IP, 8)
	if !primaryAddress.IsValid() {
		return nil, fmt.Errorf("primary interface IP %v is invalid", primaryAddress)
	}

	// Create tun device.
	t, err := tun.CreateTUN(linkName, instance.Config().TunMTU()) // TODO: Calculate MTU as needed.
	if err != nil {
		return nil, err
	}

	// Create device struct.
	d := &Device{
		linkName:       linkName,
		tun:            t,
		primaryAddress: primaryAddress,
		secondaryIPs:   make([]netip.Prefix, 0, 2),
		RecvRaw:        make(chan []byte, 1000),
		SendRaw:        make(chan []byte, 1000),
		SendFrame:      make(chan frame.Frame, 1000),
		instance:       instance,
	}

	// Add primary address to interface.
	if err := d.InitInterface(primaryAddress); err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("failed to add primary address %v: %w", primaryAddress, err)
	}

	return d, nil
}

// Start starts brings the device online and starts workers.
func (d *Device) Start(m *mgr.Manager) error {
	if err := d.StartInterface(); err != nil {
		return err
	}

	m.StartWorker("read packets", d.tunReader)
	m.StartWorker("write packets", d.tunWriter)
	m.StartWorker("handle tun events", d.handleTunEvents)
	return nil
}

// Stop closes the interface and stops workers.
func (d *Device) Stop(m *mgr.Manager) error {
	m.Cancel()
	return d.Close()
}

// Read one or more packets from the Device (without any additional headers).
// On a successful read it returns the number of packets read, and sets
// packet lengths within the sizes slice. len(sizes) must be >= len(bufs).
// A nonzero offset can be used to instruct the Device on where to begin
// reading into each element of the bufs slice.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	return d.tun.Read(bufs, sizes, offset)
}

// Write one or more packets to the device (without any additional headers).
// On a successful write it returns the number of packets written. A nonzero
// offset can be used to instruct the Device on where to begin writing from
// each packet contained within the bufs slice.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	return d.tun.Write(bufs, offset)
}

// TunEvents returns a channel of type Event, which is fed Device events.
func (d *Device) TunEvents() <-chan tun.Event {
	return d.tun.Events()
}

// Close stops the Device and closes the Event channel.
func (d *Device) Close() error {
	return d.tun.Close()
}

// BatchSize returns the preferred/max number of packets that can be read or
// written in a single read/write call. BatchSize must not change over the
// lifetime of a Device.
func (d *Device) BatchSize() int {
	return d.tun.BatchSize()
}

func (d *Device) handleTunEvents(w *mgr.WorkerCtx) error {
	for {
		select {
		case event := <-d.TunEvents():
			switch event {
			case 0:
				w.Info("tun interface event", "event", "closed", "eventID", event)
				return nil
			case tun.EventUp:
				w.Info("tun interface event", "event", "EventUp", "eventID", event)
			case tun.EventDown:
				w.Info("tun interface event", "event", "EventDown", "eventID", event)
			case tun.EventMTUUpdate:
				// TODO: What is being updated here? How can we use this information?
				mtu, err := d.tun.MTU()
				if err != nil {
					w.Warn("failed to get tun mtu", "err", err)
				} else {
					w.Info("tun interface event", "event", "EventMTUUpdate", "eventID", event, "mtu", mtu)
				}
			default:
				w.Info("tun interface event", "event", "unknown", "eventID", event)
			}
		case <-w.Done():
			return nil
		}
	}
}
