package tun

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

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
	linkIndex int //nolint:structcheck,unused // Used on linux.

	tun tun.Device

	primaryAddress netip.Prefix
	secondaryIPs   []netip.Prefix

	RecvRaw   chan []byte
	SendRaw   chan []byte
	SendFrame chan frame.Frame

	sendRawOffset int

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

	// Create device struct.
	d := &Device{
		linkName:       linkName,
		primaryAddress: primaryAddress,
		secondaryIPs:   make([]netip.Prefix, 0, 2),
		RecvRaw:        make(chan []byte, 1000),
		SendRaw:        make(chan []byte, 1000),
		SendFrame:      make(chan frame.Frame, 1000),
		sendRawOffset:  10,
		instance:       instance,
	}

	// Prep.
	d.PrepTUN()

	// Create tun device.
	t, err := tun.CreateTUN(linkName, instance.Config().TunMTU()) // TODO: Calculate MTU as needed.
	if err != nil {
		return nil, err
	}
	d.tun = t

	// Add primary address to interface.
	if err := d.InitInterface(primaryAddress); err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("failed to add primary address %v: %w", primaryAddress, err)
	}

	return d, nil
}

// Start starts brings the device online and starts workers.
func (d *Device) Start(mgr *mgr.Manager) error {
	if err := d.StartInterface(); err != nil {
		return err
	}

	if err := d.applyChromiumWorkaround(mgr); err != nil {
		mgr.Warn(
			"chromium workaround failed",
			"err", err,
		)
	}

	mgr.Go("read packets", d.tunReader)
	mgr.Go("write packets", d.tunWriter)
	mgr.Go("handle tun events", d.handleTunEvents)
	return nil
}

// Stop closes the interface and stops workers.
func (d *Device) Stop(mgr *mgr.Manager) error {
	mgr.Cancel()
	return d.Close()
}

// applyChromiumWorkaround applies a workaround to enable Chromium to query AAAA records.
func (d *Device) applyChromiumWorkaround(mgr *mgr.Manager) error {
	// Chromium Workaround.
	// Workaround to get Chromium based browsers to resolve IPv6/AAAA even when
	// no global IPv6 connectivity is available.
	// Chromium Docs:
	// https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/dns/README.md#IPv6-and-connectivity
	// TL;DR: `ip -6 route get 2001:4860:4860::8888` must succeed.

	// Check if disabled.
	if d.instance.Config().System.DisableChromiumWorkaround {
		return nil
	}

	// Parse IP address (+net) that Chromium checks.
	workaroundNet := netip.MustParsePrefix("2001:4860:4860::8888/128")

	// Check if the OS has a route to the IP.
	conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{
		IP:   net.IP(workaroundNet.Addr().AsSlice()),
		Port: 53,
	})
	switch {
	case err == nil:
		// Global IPv6 connectivity seems to be available.
		_ = conn.Close()
	case strings.Contains(err.Error(), "unreachable"):
		// If not route exists, fake it.
		if err := d.AddRoute(workaroundNet, false); err != nil {
			return fmt.Errorf("add route: %w", err)
		}
		mgr.Debug(
			"chromium workaround applied",
			"workaround-check", err,
		)
	default:
		// Another error occurred.
		mgr.Warn(
			"chromium workaround check failed",
			"err", err,
		)
	}

	return nil
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

// SendRawOffset returns the required offset of packets submitted via SendRaw.
func (d *Device) SendRawOffset() int {
	return d.sendRawOffset
}

// AddSendRawOffset returns the given data with the required offset of packets
// submitted via SendRaw.
func (d *Device) AddSendRawOffset(data []byte) (withOffset []byte, copied bool) {
	// Don't do anything if there is no required offset.
	if d.sendRawOffset == 0 {
		return data, false
	}

	// Create new slice with offset and copy data.
	withOffset = make([]byte, len(data)+d.sendRawOffset)
	copy(withOffset[d.sendRawOffset:], data)
	return withOffset, true
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
