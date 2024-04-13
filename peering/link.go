package peering

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/state"
)

// Errors.
var (
	ErrNetworkReadError  = errors.New("read i/o error")
	ErrNetworkWriteError = errors.New("write i/o error")
)

// Link represents a network connection to another router.
type Link interface {
	String() string

	// Peer returns the ID of the connected peer.
	Peer() netip.Addr

	// SwitchLabel returns the switch label of the link.
	SwitchLabel() m.SwitchLabel

	// GeoMark returns geo location of the peer, based on the router address.
	GeoMark() string

	// PeeringURL returns the used peering URL.
	PeeringURL() *m.PeeringURL

	// Outgoing returns whether the connection was initiated by this router.
	Outgoing() bool

	// Lite returns whether the connected router is in lite mode.
	Lite() bool

	// SendPriority sends a priority frame to the peer.
	SendPriority(f frame.Frame) error

	// Send sends a frame to the peer.
	Send(f frame.Frame) error

	// LocalAddr returns the underlying local net.Addr of the connection.
	LocalAddr() net.Addr

	// RemoteAddr returns the underlying remote net.Addr of the connection.
	RemoteAddr() net.Addr

	// Started returns when the link was created.
	Started() time.Time

	// Uptime returns how long the link has been up.
	Uptime() time.Duration

	// Latency returns the latency of the link in milliseconds.
	Latency() uint16

	// AddMeasuredLatency adds the given latency to the measured latencies and
	// calculates and sets the new average.
	AddMeasuredLatency(latency time.Duration)

	// BytesIn returns the total amount of bytes received via the link.
	BytesIn() uint64

	// BytesOut returns the total amount of bytes sent via the link.
	BytesOut() uint64

	// FlowControlIndicator returns a flow control flag that indicates the
	// pressure on the sending queue of this link.
	FlowControlIndicator() frame.FlowControlFlag

	// IsClosing returns whether the link is closing or has closed.
	IsClosing() bool

	// Close closes the link.
	Close(log func())
}

// LinkBase implements common functions to comply with the Link interface.
type LinkBase struct { //nolint:maligned
	// conn is the actual underlying connection.
	conn net.Conn
	// encSession is the encryption session.
	encSession *state.EncryptionSession

	// sendQueuePrio is the send queue for priority messages.
	sendQueuePrio chan frame.Frame
	// sendQueueRegl is the send queue for regular messages.
	sendQueueRegl chan frame.Frame

	// peer is the mycoria identity IP of the peer.
	peer netip.Addr
	// switchLabel is the switch ID for this link.
	switchLabel m.SwitchLabel
	// geoMark holds geo location info based on the geo geomarked router address.
	geoMark string

	// peeringURL holds the used peering URL.
	peeringURL *m.PeeringURL
	// outgoing specifies whether the link was initiated by this router.
	outgoing bool
	// lite specifies whether the connected router is in lite mode.
	lite bool

	// started holds the time when the link was created.
	started time.Time

	// closing specifies if the link is being closed
	closing atomic.Bool

	// peering references back to the peering manager.
	peering *Peering

	// Locked fields

	// lock locks the locked fields.
	lock sync.RWMutex

	// latency is the latency of the link in ms (one direction).
	latency uint16
	// measuredLatencies holds the measured latencies.
	measuredLatencies [10]time.Duration
	// measuredLatenciesNext holds the next index to use of measuredLatencies.
	measuredLatenciesNext int

	// bytesIn records the total amount of bytes received via this connection.
	bytesIn atomic.Uint64
	// bytesOut records the total amount of bytes sent via this connection.
	bytesOut atomic.Uint64
}

var _ Link = &LinkBase{}

func newLinkBase(
	conn net.Conn,
	peeringURL *m.PeeringURL,
	outgoing bool,
	peering *Peering,
) *LinkBase {
	link := &LinkBase{
		conn:          conn,
		sendQueuePrio: make(chan frame.Frame, 100),
		sendQueueRegl: make(chan frame.Frame, 1000),
		peeringURL:    peeringURL,
		outgoing:      outgoing,
		started:       time.Now(),
		peering:       peering,
	}
	link.latency = link.getFallbackLatency()

	return link
}

func (link *LinkBase) startWorkers() {
	link.peering.mgr.Go("link reader", link.reader)
	link.peering.mgr.Go("link writer", link.writer)
}

// String returns a human readable summary.
func (link *LinkBase) String() string {
	if link.outgoing {
		return fmt.Sprintf("link to %s @ %s using %s", link.peer, link.RemoteAddr(), link.peeringURL)
	}
	return fmt.Sprintf("link from %s @ %s using %s", link.peer, link.RemoteAddr(), link.peeringURL)
}

// Peer returns the ID of the connected peer.
func (link *LinkBase) Peer() netip.Addr {
	return link.peer
}

// SwitchLabel returns the switch label of the link.
func (link *LinkBase) SwitchLabel() m.SwitchLabel {
	if link == nil {
		return 0
	}
	return link.switchLabel
}

// GeoMark returns geo location of the peer, based on the router address.
func (link *LinkBase) GeoMark() string {
	return link.geoMark
}

// PeeringURL returns the used peering URL.
func (link *LinkBase) PeeringURL() *m.PeeringURL {
	return link.peeringURL
}

// Outgoing returns whether the connection was initiated by this router.
func (link *LinkBase) Outgoing() bool {
	return link.outgoing
}

// Lite returns whether the connected router is in lite mode.
func (link *LinkBase) Lite() bool {
	return link.lite
}

// Started returns when the link was created.
func (link *LinkBase) Started() time.Time {
	return link.started
}

// Uptime returns how long the link has been up.
func (link *LinkBase) Uptime() time.Duration {
	return time.Since(link.started)
}

// SendPriority sends a priority frame to the peer.
func (link *LinkBase) SendPriority(f frame.Frame) error {
	select {
	case link.sendQueuePrio <- f:
	default:
	}
	return nil
}

// Send sends a frame to the peer.
func (link *LinkBase) Send(f frame.Frame) error {
	select {
	case link.sendQueueRegl <- f:
	default:
	}
	return nil
}

// LocalAddr returns the underlying local net.Addr of the connection.
func (link *LinkBase) LocalAddr() net.Addr {
	return link.conn.LocalAddr()
}

// RemoteAddr returns the underlying remote net.Addr of the connection.
func (link *LinkBase) RemoteAddr() net.Addr {
	return link.conn.RemoteAddr()
}

// Latency returns the latency of the link in milliseconds.
func (link *LinkBase) Latency() uint16 {
	link.lock.RLock()
	defer link.lock.RUnlock()

	return link.latency
}

// AddMeasuredLatency adds the given latency to the measured latencies and
// calculates and sets the new average.
func (link *LinkBase) AddMeasuredLatency(latency time.Duration) {
	link.lock.Lock()
	defer link.lock.Unlock()

	// Add latency to measured latencies.
	link.measuredLatencies[link.measuredLatenciesNext] = latency
	link.measuredLatenciesNext = (link.measuredLatenciesNext + 1) % 10

	// Calculate new average.
	var (
		set   int64
		total time.Duration
	)
	for _, ml := range link.measuredLatencies {
		if ml > 0 {
			set++
			total += ml
		}
	}
	avgLatency := (total / time.Duration(set)).Round(time.Millisecond)
	link.latency = uint16(avgLatency / time.Millisecond)

	// Force to at least 1ms.
	if link.latency == 0 {
		link.latency = 1
	}
}

// BytesIn returns the total amount of bytes received via the link.
func (link *LinkBase) BytesIn() uint64 {
	return link.bytesIn.Load()
}

// BytesOut returns the total amount of bytes sent via the link.
func (link *LinkBase) BytesOut() uint64 {
	return link.bytesOut.Load()
}

// FlowControlIndicator returns a flow control flag that indicates the
// pressure on the sending queue of this link.
func (link *LinkBase) FlowControlIndicator() frame.FlowControlFlag {
	percent := len(link.sendQueueRegl) * 100 / cap(link.sendQueueRegl)
	switch {
	case percent >= 70: // Send queue is over 70% full.
		return frame.FlowControlFlagDecreaseFlow
	case percent >= 30: // Send queue is over 30% full.
		return frame.FlowControlFlagHoldFlow
	default:
		return frame.FlowControlFlagIncreaseFlow
	}
}

// IsClosing returns whether the link is closing or has closed.
func (link *LinkBase) IsClosing() bool {
	return link.closing.Load()
}

// Close closes the link.
func (link *LinkBase) Close(log func()) {
	if link == nil {
		return
	}

	if link.closing.CompareAndSwap(false, true) {
		if log != nil {
			log()
		}

		link.peering.RemoveLink(link)
		_ = link.conn.Close()
	}
}

func (link *LinkBase) reader(w *mgr.WorkerCtx) error {
	defer link.Close(func() {
		w.Info(
			"closing link (by reader)",
			"router", link.peer,
			"address", link.RemoteAddr(),
		)
	})

	var (
		builder           = link.peering.instance.FrameBuilder()
		upstream          = link.peering.frameHandler
		consecutiveErrors int
	)
	for {
		f, err := link.readFrame(builder)
		if err == nil {
			consecutiveErrors = 0
			select {
			case upstream <- f:
			case <-w.Done():
				return nil
			}
			continue
		}

		// Close link in case of a network error.
		if errors.Is(err, ErrNetworkReadError) {
			if errors.Is(err, io.EOF) {
				link.Close(func() {
					w.Info(
						"closing link (by remote)",
						"router", link.peer,
						"address", link.RemoteAddr(),
					)
				})
				return nil
			}

			link.Close(func() {
				w.Warn(
					"read i/o error, closing link",
					"router", link.peer,
					"address", link.RemoteAddr(),
					"err", err,
				)
			})
			return nil
		}

		// Log read error, close after 100 consecutive errors.
		consecutiveErrors++
		if consecutiveErrors >= 100 {
			link.Close(func() {
				w.Warn(
					"closing link after 100 consecutive read errors",
					"router", link.peer,
					"address", link.RemoteAddr(),
					"err", err,
				)
			})
			return nil
		}

		w.Debug(
			"failed to read frame (non-fatal)",
			"router", link.peer,
			"address", link.RemoteAddr(),
			"err", err,
		)
	}
}

func (link *LinkBase) writer(w *mgr.WorkerCtx) error {
	defer link.Close(func() {
		w.Info(
			"closing link (by writer)",
			"router", link.peer,
			"address", link.RemoteAddr(),
		)
	})

	var (
		f                 frame.Frame
		consecutiveErrors int
	)
	for {
		// Get next frame to write.
		select {
		case f = <-link.sendQueuePrio:
		default:
			select {
			case f = <-link.sendQueuePrio:
			case f = <-link.sendQueueRegl:
			case <-w.Done():
				return nil
			}
		}
		if f == nil {
			return nil
		}

		// Write frame.
		err := link.writeFrame(f)
		if err == nil {
			consecutiveErrors = 0
			continue
		}

		// Close link in case of a network error.
		if errors.Is(err, ErrNetworkWriteError) {
			link.Close(func() {
				w.Warn(
					"write i/o error, closing link",
					"router", link.peer,
					"address", link.RemoteAddr(),
					"err", err,
				)
			})
			return nil
		}

		// Log write error, close after 100 consecutive errors.
		consecutiveErrors++
		if consecutiveErrors >= 100 {
			link.Close(func() {
				w.Warn(
					"closing link after 100 consecutive write errors",
					"router", link.peer,
					"address", link.RemoteAddr(),
					"err", err,
				)
			})
			return nil
		}

		w.Debug(
			"failed to write frame (non-fatal)",
			"router", link.peer,
			"address", link.RemoteAddr(),
			"err", err,
		)
	}
}

func (link *LinkBase) readFrame(b *frame.Builder) (frame.Frame, error) {
	data, err := link.readLengthAndData()
	if err != nil {
		return nil, fmt.Errorf("read frame: %w", err)
	}
	link.bytesIn.Add(uint64(len(data)))

	// Parse LinkFrame.
	if link.encSession != nil {
		// Unseal linked frame.
		lf := LinkFrame(data)
		if err := lf.Unseal(link.encSession); err != nil {
			return nil, fmt.Errorf("unseal link frame: %w", err)
		}
		// Parse Frame.
		f, err := b.ParseFrame(lf.LinkData(), data[:cap(data)], FrameOffset)
		if err != nil {
			return nil, fmt.Errorf("parse frame (from link frame): %w", err)
		}
		f.SetRecvLink(link)
		return f, nil
	}

	// Parse Frame directly.
	f, err := b.ParseFrame(data[2:], data[:cap(data)], 2)
	if err != nil {
		return nil, fmt.Errorf("parse frame: %w", err)
	}
	f.SetRecvLink(link)
	return f, nil
}

func (link *LinkBase) writeFrame(f frame.Frame) error {
	// Return frame to pool when done writing.
	defer f.ReturnToPool()

	// If link encryption is enabled, wrap the frame in a link frame.
	if link.encSession != nil {
		data, err := f.FrameDataWithMargins(FrameOffset, FrameOverhead)
		if err != nil {
			return fmt.Errorf("frame with margins %d,%d: %w", FrameOffset, FrameOverhead, err)
		}
		lf := LinkFrame(data)
		if err := lf.Seal(link.encSession); err != nil {
			return fmt.Errorf("seal link frame: %w", err)
		}
		if err := link.writeData(data); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		return nil
	}

	// Otherwise, just write the frame directly.
	data, err := f.FrameDataWithMargins(2, 0)
	if err != nil {
		return fmt.Errorf("frame with margins 2,0: %w", err)
	}
	if len(data) > 0xFFFF {
		return fmt.Errorf("frame is too big (%d bytes)", len(data))
	}
	m.PutUint16(data[:2], uint16(len(data)))
	if err := link.writeData(data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

func (link *LinkBase) readLengthAndData() ([]byte, error) {
	var read int
	var lengthBytes [2]byte

	// Read length.
	for read < 2 {
		n, err := link.conn.Read(lengthBytes[read:])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNetworkReadError, err)
		}
		read += n
	}
	dataLen := int(m.GetUint16(lengthBytes[:]))
	if dataLen <= 3 {
		return nil, fmt.Errorf("invalid data length of %d", dataLen)
	}

	// Get pooled slice and check size.
	pooledSlice := link.peering.instance.FrameBuilder().GetPooledSlice(dataLen)
	if len(pooledSlice) < dataLen {
		// Data length is longer than byte slice.
		// Read and discard data, so we can continue with next packet.
		link.peering.mgr.Warn("pooled slice (%d) too small for data (%d)", len(pooledSlice), dataLen)

		for read < dataLen {
			n, err := link.conn.Read(pooledSlice[:min(len(pooledSlice), dataLen-read)])
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrNetworkReadError, err)
			}
			read += n
		}
		return nil, errors.New("frame too big for slice")
	}

	// Copy length bytes.
	copy(pooledSlice, lengthBytes[:])

	// Read data.
	for read < dataLen {
		n, err := link.conn.Read(pooledSlice[read:dataLen])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNetworkReadError, err)
		}
		read += n
	}

	return pooledSlice[:dataLen], nil
}

func (link *LinkBase) writeData(data []byte) error {
	var written int

	for written < len(data) {
		n, err := link.conn.Write(data[written:])
		if err != nil {
			return fmt.Errorf("%w: %w", ErrNetworkWriteError, err)
		}
		written += n
	}

	link.bytesOut.Add(uint64(written))
	return nil
}

func (link *LinkBase) setupWorker(w *mgr.WorkerCtx) error {
	peeringState, err := link.handleSetupMessages(link.outgoing)
	// TODO: Improve error handling here.
	if err == nil {
		link.encSession, err = peeringState.finalize()
	}
	if err == nil {
		// Assign peer and geomarked country.
		link.peer = peeringState.session.Address().IP
		link.lite = peeringState.remoteLite
		cml, cmlErr := m.LookupCountryMarker(link.peer)
		if cmlErr == nil && cml != nil {
			link.geoMark = fmt.Sprintf("%s (%s)", cml.Country, cml.Continent)
		}
		// Assign switch label.
		err = link.assignSwitchLabel()
	}
	if err == nil {
		// Add link to peerings.
		err = link.peering.AddLink(link)
	}
	if err != nil {
		link.Close(func() {
			w.Warn(
				"link setup failed",
				"remote", link.RemoteAddr(),
				"peeringURL", link.peeringURL,
				"err", err,
			)
		})
		return nil //nolint:nilerr // Worker has no error.
	}

	w.Info(
		"new link",
		"router", link.peer,
		"address", link.RemoteAddr(),
		"label", link.SwitchLabel(),
		"peeringURL", link.peeringURL,
		"outgoing", link.outgoing,
	)
	link.startWorkers()
	return nil
}

func (link *LinkBase) handleSetup(mgr *mgr.Manager) (*LinkBase, error) {
	peeringState, err := link.handleSetupMessages(link.outgoing)
	if err == nil {
		link.encSession, err = peeringState.finalize()
	}
	if err == nil {
		// Assign peer and geomarked country.
		link.peer = peeringState.session.Address().IP
		link.lite = peeringState.remoteLite
		cml, cmlErr := m.LookupCountryMarker(link.peer)
		if cmlErr == nil && cml != nil {
			link.geoMark = fmt.Sprintf("%s (%s)", cml.Country, cml.Continent)
		}
		// Assign switch label.
		err = link.assignSwitchLabel()
	}
	if err == nil {
		// Add link to peerings.
		err = link.peering.AddLink(link)
	}
	if err != nil {
		link.Close(nil)
		return nil, err
	}

	mgr.Info(
		"new link",
		"router", link.peer,
		"address", link.RemoteAddr(),
		"label", link.SwitchLabel(),
		"peeringURL", link.peeringURL,
		"outgoing", link.outgoing,
	)
	link.startWorkers()
	return link, nil
}

func (link *LinkBase) handleSetupMessages(client bool) (*peeringRequestState, error) {
	builder := link.peering.instance.FrameBuilder()

	// Initialize connection.
	state, f, err := link.peering.createPeeringRequest(client)
	if err != nil {
		return nil, fmt.Errorf("create peering request (1): %w", err)
	}
	err = link.writeFrame(f)
	if err != nil {
		return nil, fmt.Errorf("write peering request (1): %w", err)
	}

	// Handle setup messages.
	for i := 1; i <= 3; i++ {
		// Read next setup msg.
		f, err := link.readFrame(builder)
		if err != nil {
			return nil, fmt.Errorf("read peering msg %d: %w", i, err)
		}
		// Handle it.
		f, err = state.handle(f)
		if err != nil {
			// If the error also has a response, try to write it as best effort.
			if f != nil {
				_ = link.writeFrame(f)
			}
			return nil, fmt.Errorf("handle peering msg %d: %w", i, err)
		}

		// If there is no respose, we are done with the setup.
		if f == nil {
			return state, nil
		}

		// Return response.
		err = link.writeFrame(f)
		if err != nil {
			return nil, fmt.Errorf("write peering msg response %d: %w", i+1, err)
		}
	}
	return nil, errors.New("too much setup")
}

func (link *LinkBase) assignSwitchLabel() error {
	// Derive label from address.
	label, ok := m.DeriveSwitchLabelFromIP(link.peer)
	if ok && label != 0 && link.peering.GetLinkByLabel(label) == nil {
		link.switchLabel = label
		return nil
	}

	// Try 100 times to generate a random short label for routable addresses.
	if m.RoutingAddressPrefix.Contains(link.peer) {
		for i := 0; i < 100; i++ {
			label, ok := m.GetRandomSwitchLabel(true)
			if ok && label != 0 && link.peering.GetLinkByLabel(label) == nil {
				link.switchLabel = label
				return nil
			}
		}
	}

	// Then try 1000 time for a longer one.
	for i := 0; i < 1000; i++ {
		label, ok := m.GetRandomSwitchLabel(false)
		if ok && label != 0 && link.peering.GetLinkByLabel(label) == nil {
			link.switchLabel = label
			return nil
		}
	}

	return errors.New("no suitable switch label found")
}

func (link *LinkBase) getFallbackLatency() uint16 {
	var remoteIP net.IP
	switch v := link.RemoteAddr().(type) {
	case *net.TCPAddr:
		remoteIP = v.IP
	case *net.UDPAddr:
		remoteIP = v.IP
	case *net.IPAddr:
		remoteIP = v.IP
	default:
		return 50
	}

	switch {
	case remoteIP.IsGlobalUnicast():
		return 100
	case remoteIP.IsPrivate():
		return 5
	default:
		return 50
	}
}
