package router

import (
	"net/netip"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/mycoria/mycoria/mgr"
)

type connStateKey struct {
	localIP    netip.Addr
	remoteIP   netip.Addr
	protocol   uint8
	localPort  uint16
	remotePort uint16
}

type connStateEntry struct {
	firstSeen int64
	lastSeen  atomic.Int64

	inbound    bool
	shortLived bool
	status     atomic.Uint32
	notify     chan connStatus

	dataIn  atomic.Uint64
	dataOut atomic.Uint64
}

type connStatus uint32

const (
	connStatusUnknown connStatus = iota
	connStatusAllowed
	connStatusUnreachable // No route to dst.
	connStatusProhibited  // Denied locally.
	connStatusDenied      // Denied by remote.
	connStatusRejected    // Technical or operational issue.
)

func (r *Router) getConnState(key connStateKey) (*connStateEntry, bool) {
	r.connStatesLock.RLock()
	defer r.connStatesLock.RUnlock()

	state, ok := r.connStates[key]
	return state, ok
}

func (r *Router) setConnState(key connStateKey, entry *connStateEntry) {
	r.connStatesLock.Lock()
	defer r.connStatesLock.Unlock()

	r.connStates[key] = entry
}

func (r *Router) checkPolicy(w *mgr.WorkerCtx, inbound bool, connKey connStateKey, dataLength int) (status connStatus, statusUpdate chan connStatus) {
	// Check if we have seen this connection before.
	connState, ok := r.getConnState(connKey)
	if ok {
		// Update last seen.
		connState.lastSeen.Store(time.Now().Unix())
		// Update traffic stats.
		if inbound {
			connState.dataIn.Add(uint64(dataLength))
		} else {
			connState.dataOut.Add(uint64(dataLength))
		}
		// Return status and status update channel.
		return connStatus(connState.status.Load()), connState.notify
	}

	// If not, set up state record.

	// Check if the protocol is short-lived.
	var shortLived bool
	switch connKey.protocol {
	case 1: // ICMP
		shortLived = true
	case 58: // ICMPv6
		shortLived = true
	}
	// Create state entry.
	connState = &connStateEntry{
		inbound:    inbound,
		shortLived: shortLived,
		firstSeen:  time.Now().Unix(),
		notify:     make(chan connStatus),
	}
	// Update last seen.
	connState.lastSeen.Store(time.Now().Unix())
	// Update traffic stats.
	if inbound {
		connState.dataIn.Add(uint64(dataLength))
	} else {
		connState.dataOut.Add(uint64(dataLength))
	}

	// Only save after decided on connection.
	defer r.setConnState(connKey, connState)

	if inbound {
		// Check inbound policy.
		if r.instance.Config().CheckInboundTrafficPolicy(connKey.protocol, connKey.localPort, connKey.remoteIP) {
			connState.status.Store(uint32(connStatusAllowed))
			w.Debug(
				"incoming connection allowed",
				"router", connKey.remoteIP,
				"protocol", connKey.protocol,
				"port", connKey.localPort,
			)
		} else {
			connState.status.Store(uint32(connStatusDenied))
			w.Warn(
				"incoming connection denied",
				"router", connKey.remoteIP,
				"protocol", connKey.protocol,
				"port", connKey.localPort,
			)
		}
	} else {
		// Check outbound policy.
		if r.outboundAllowedTo(connKey.remoteIP) {
			connState.status.Store(uint32(connStatusAllowed))
			w.Debug(
				"outgoing connection allowed",
				"router", connKey.remoteIP,
				"protocol", connKey.protocol,
				"port", connKey.remotePort,
			)
		} else {
			connState.status.Store(uint32(connStatusProhibited))
			w.Warn(
				"outgoing connection prohibited",
				"router", connKey.remoteIP,
				"protocol", connKey.protocol,
				"port", connKey.remotePort,
			)
		}
	}

	return connStatus(connState.status.Load()), connState.notify
}

func (r *Router) checkSimilarOutboundStatus(w *mgr.WorkerCtx, connKey connStateKey) (status connStatus) {
	connState, ok := r.getConnState(connKey)
	if !ok {
		return connStatusUnknown
	}

	r.connStatesLock.RLock()
	defer r.connStatesLock.RUnlock()

	mustBeNewerThan := time.Now().Add(-errorRecvCooldown).Unix()
stateSearch:
	for key, state := range r.connStates {
		switch {
		case state.inbound:
			// Skip inbound.
			// This is especially important as leftovers from a previous outgoing
			// connction may be recognized as an incoming connection after a restart.
		case key == connKey:
			// Skip own entry.
		case state.lastSeen.Load() < mustBeNewerThan:
		// Entry too old to take into account.
		case key.remoteIP == connKey.remoteIP &&
			connStatus(state.status.Load()) == connStatusUnreachable:
			// Router seems to be unreachable.
			connState.status.Store(uint32(connStatusUnreachable))
			w.Debug(
				"outgoing connection auto-blocked due to unreachable router",
				"router", connKey.remoteIP,
				"protocol", connKey.protocol,
				"port", connKey.remoteIP,
			)
			break stateSearch

		case key.remoteIP == connKey.remoteIP &&
			key.protocol == connKey.protocol &&
			key.remotePort == connKey.remotePort:
			// Router cannot handle connection.
			switch connStatus(state.status.Load()) { //nolint:exhaustive
			case connStatusDenied:
				connState.status.Store(uint32(connStatusDenied))
				w.Debug(
					"outgoing connection auto-denied due to recent similar connection",
					"router", connKey.remoteIP,
					"protocol", connKey.protocol,
					"port", connKey.remoteIP,
				)
				break stateSearch

			case connStatusRejected:
				connState.status.Store(uint32(connStatusRejected))
				w.Debug(
					"outgoing connection auto-rejected due to recent similar connection",
					"router", connKey.remoteIP,
					"protocol", connKey.protocol,
					"port", connKey.remoteIP,
				)
				break stateSearch
			}
		}
	}

	return connStatus(connState.status.Load())
}

func (r *Router) outboundAllowedTo(dst netip.Addr) bool {
	// Check if router is isolated.
	if !r.instance.Config().Router.Isolate {
		return true
	}

	// Check if dst is a friend.
	_, ok := r.instance.Config().FriendsByIP[dst]
	return ok
}

func (r *Router) markRouter(status connStatus, dst netip.Addr) {
	r.connStatesLock.RLock()
	defer r.connStatesLock.RUnlock()

states:
	for key, entry := range r.connStates {
		if key.remoteIP == dst {
			// Mark router as unreachable.
			entry.status.Store(uint32(status))
			// Notify waiting workers.
			for {
				select {
				case entry.notify <- status:
				default:
					continue states
				}
			}
		}
	}
}

func (r *Router) markConnectionDst(status connStatus, dst netip.Addr, protocol uint8, port uint16) {
	r.connStatesLock.RLock()
	defer r.connStatesLock.RUnlock()

states:
	for key, entry := range r.connStates {
		if key.remoteIP == dst &&
			key.protocol == protocol &&
			key.remotePort == port {
			// Mark destination service as denied.
			entry.status.Store(uint32(status))
			// Notify waiting workers.
			for {
				select {
				case entry.notify <- status:
				default:
					continue states
				}
			}
		}
	}
}

// ExportedConnection is an exported version of a connection.
type ExportedConnection struct {
	LocalIP    netip.Addr
	RemoteIP   netip.Addr
	Protocol   uint8
	LocalPort  uint16
	RemotePort uint16

	Inbound     bool
	StatusName  string
	StatusColor string
	FirstSeen   time.Time
	LastSeen    time.Time

	DataIn  uint64
	DataOut uint64
}

// ExportConnections returns an exported version of the connections.
func (r *Router) ExportConnections(maxAge time.Duration) []ExportedConnection {
	// Export connections.
	export := r.exportConnsRaw(maxAge)

	// Sort.
	slices.SortFunc[[]ExportedConnection, ExportedConnection](export, func(a, b ExportedConnection) int {
		if diff := a.LastSeen.Compare(b.LastSeen); diff != 0 {
			return -diff // Newer first.
		}
		if diff := a.FirstSeen.Compare(b.FirstSeen); diff != 0 {
			return -diff // Newer first.
		}
		return 0
	})

	return export
}

func (r *Router) exportConnsRaw(maxAge time.Duration) []ExportedConnection {
	r.connStatesLock.RLock()
	defer r.connStatesLock.RUnlock()

	export := make([]ExportedConnection, 0, len(r.connStates))
	ignoreOlderThan := time.Now().Add(-maxAge).Unix()

	for key, entry := range r.connStates {
		if entry.lastSeen.Load() < ignoreOlderThan {
			continue
		}

		status := connStatus(entry.status.Load())
		export = append(export, ExportedConnection{
			LocalIP:    key.localIP,
			RemoteIP:   key.remoteIP,
			Protocol:   key.protocol,
			LocalPort:  key.localPort,
			RemotePort: key.remotePort,

			Inbound:     entry.inbound,
			StatusName:  status.Name(),
			StatusColor: status.ColorName(),
			FirstSeen:   time.Unix(entry.firstSeen, 0),
			LastSeen:    time.Unix(entry.lastSeen.Load(), 0),

			DataIn:  entry.dataIn.Load(),
			DataOut: entry.dataOut.Load(),
		})
	}

	return export
}

// HasPorts returns whether the connection has ports.
func (e *ExportedConnection) HasPorts() bool {
	switch e.Protocol {
	case 6: // TCP
		return true
	case 17: // UDP
		return true
	case 27: // RDP
		return true
	case 33: // DCCP
		return true
	case 136: // UDP-LITE
		return true
	default:
		return false
	}
}

// ProtocolName returns the protocol name, if available.
// Otherwise a string representation of the protocol number is returned.
func (e *ExportedConnection) ProtocolName() string {
	switch e.Protocol {
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 27:
		return "RDP"
	case 58:
		return "ICMP6"
	case 33:
		return "DCCP"
	case 136:
		return "UDP-LITE"
	default:
		return strconv.FormatUint(uint64(e.Protocol), 10)
	}
}

// TimeDescription returns a simplified and readable description of the first
// and last seen timestamps.
func (e *ExportedConnection) TimeDescription() string {
	switch {
	case time.Since(e.FirstSeen) < 4500*time.Millisecond:
		return "now"

	case time.Since(e.LastSeen) < 4500*time.Millisecond:
		// 1m23s ago - now
		return time.Since(e.FirstSeen).Round(time.Second).String() + " ago - now"

	case e.LastSeen.Sub(e.FirstSeen) < 4500*time.Millisecond:
		// 1m23s ago
		return time.Since(e.LastSeen).Round(time.Second).String() + " ago"

	default:
		// 1m23s - 5s ago
		return time.Since(e.FirstSeen).Round(time.Second).String() + " - " +
			time.Since(e.LastSeen).Round(time.Second).String() + " ago"
	}
}

// Name returns the status name/description.
func (status connStatus) Name() string {
	switch status {
	case connStatusAllowed:
		return "allowed"
	case connStatusUnreachable:
		return "unreachable"
	case connStatusProhibited:
		return "prohibited"
	case connStatusDenied:
		return "access denied"
	case connStatusRejected:
		return "rejected"
	case connStatusUnknown:
		fallthrough
	default:
		return "unknown"
	}
}

// ColorName returns the color name.
// Eg. success, warning, danger, etc.
func (status connStatus) ColorName() string {
	switch status {
	case connStatusAllowed:
		return "success"
	case connStatusUnreachable:
		return "warning"
	case connStatusProhibited:
		return "danger"
	case connStatusDenied:
		return "danger"
	case connStatusRejected:
		return "warning"
	case connStatusUnknown:
		fallthrough
	default:
		return "secondary"
	}
}
