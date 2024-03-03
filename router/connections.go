package router

import (
	"net/netip"
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

	inbound bool
	status  atomic.Uint32
	notify  chan connStatus
}

type connStatus uint32

const (
	connStatusUnknown connStatus = iota
	connStatusAllowed
	connStatusUnreachable
	connStatusProhibited // Denied locally.
	connStatusDenied     // Denied by remote.
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

func (r *Router) checkPolicy(w *mgr.WorkerCtx, inbound bool, connKey connStateKey) (status connStatus, statusUpdate chan connStatus) {
	// Check if we have seen this connection before.
	connState, ok := r.getConnState(connKey)
	if ok {
		// Update last seen.
		connState.lastSeen.Store(time.Now().Unix())
		// Return status and status update channel.
		return connStatus(connState.status.Load()), connState.notify
	}

	// If not, set up state record.
	connState = &connStateEntry{
		inbound:   true,
		firstSeen: time.Now().Unix(),
		notify:    make(chan connStatus),
	}
	// Update last seen.
	connState.lastSeen.Store(time.Now().Unix())

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
				"port", connKey.localIP,
			)
		} else {
			connState.status.Store(uint32(connStatusDenied))
			w.Warn(
				"incoming connection denied",
				"router", connKey.remoteIP,
				"protocol", connKey.protocol,
				"port", connKey.localIP,
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
				"port", connKey.remoteIP,
			)
		} else {
			connState.status.Store(uint32(connStatusProhibited))
			w.Warn(
				"outgoing connection prohibited",
				"router", connKey.remoteIP,
				"protocol", connKey.protocol,
				"port", connKey.remoteIP,
			)
		}
	}

	return connStatus(connState.status.Load()), connState.notify
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

func (r *Router) markUnreachable(dst netip.Addr) {
	r.connStatesLock.RLock()
	defer r.connStatesLock.RUnlock()

states:
	for key, entry := range r.connStates {
		if key.remoteIP == dst {
			// Mark router as unreachable.
			entry.status.Store(uint32(connStatusUnreachable))
			// Notify waiting workers.
			for {
				select {
				case entry.notify <- connStatusUnreachable:
				default:
					continue states
				}
			}
		}
	}
}

func (r *Router) markAccessDenied(dst netip.Addr, protocol uint8, port uint16) {
	r.connStatesLock.RLock()
	defer r.connStatesLock.RUnlock()

states:
	for key, entry := range r.connStates {
		if key.remoteIP == dst &&
			key.protocol == protocol &&
			key.remotePort == port {
			// Mark destination service as denied.
			entry.status.Store(uint32(connStatusDenied))
			// Notify waiting workers.
			for {
				select {
				case entry.notify <- connStatusDenied:
				default:
					continue states
				}
			}
		}
	}
}
