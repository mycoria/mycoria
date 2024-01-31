package router

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
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
	lastSeen atomic.Int64
	inbound  bool
}

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

func (r *Router) handleIncomingTraffic(f frame.Frame) error {
	// Get session.
	session := r.instance.State().GetSession(f.SrcIP())
	if session == nil {
		return fmt.Errorf("unknown src router: %s", f.SrcIP())
	}

	// Unseal.
	if err := f.Unseal(session); err != nil {
		return fmt.Errorf("unseal: %w", err)
	}

	// Get packet metadata.
	packetData := f.MessageData()
	if len(packetData) < 44 {
		return fmt.Errorf("packet too small: %d bytes", len(packetData))
	}
	src := netip.AddrFrom16([16]byte(packetData[8:24]))
	dst := netip.AddrFrom16([16]byte(packetData[24:40]))
	var (
		srcPort uint16
		dstPort uint16
	)
	protocol := packetData[6]
	if protocol == 6 || protocol == 17 {
		// TODO: Handle additional IPv6 headers.
		srcPort = m.GetUint16(packetData[40:42])
		dstPort = m.GetUint16(packetData[42:44])
	}

	// Check integrity and policy
	switch {
	case src != f.SrcIP():
		return errors.New("invalid packet: src IPs do not match")
	case dst != f.DstIP():
		return errors.New("invalid packet: dst IPs do not match")
	case m.InternalPrefix.Contains(f.DstIP()):
		return errors.New("invalid packet: dst IP is internal range")
	}

	// Check if we have seen this connection before.
	connKey := connStateKey{
		localIP:    dst,
		remoteIP:   src,
		protocol:   protocol,
		localPort:  dstPort,
		remotePort: srcPort,
	}
	connState, ok := r.getConnState(connKey)
	switch {
	case ok:
		// Connection was seen and allowed previously.
		connState.lastSeen.Store(time.Now().Unix())

	case r.instance.Config().CheckInboundTrafficPolicy(protocol, dstPort, f.SrcIP()):
		// New inbound connection is allowed by policy.
		entry := &connStateEntry{
			inbound: true,
		}
		entry.lastSeen.Store(time.Now().Unix())
		r.setConnState(connKey, entry)

	default:
		return fmt.Errorf("packet from %s to %d-%d not allowed", f.SrcIP(), protocol, dstPort)
	}

	// Hand frame to tun device.
	select {
	case r.instance.TunDevice().SendFrame <- f:
	default:
		select {
		case r.instance.TunDevice().SendFrame <- f:
		case <-time.After(time.Second):
			return errors.New("submitting to tun timed out")
		}
	}
	return nil
}

func (r *Router) cleanConnStatesWorker(w *mgr.WorkerCtx) error {
	ticker := time.NewTicker(1 * time.Minute)
	for {
		select {
		case <-w.Done():
			return nil
		case <-ticker.C:
			r.cleanConnStates()
		}
	}
}

func (r *Router) cleanConnStates() {
	removeThreshold := time.Now().Add(-10 * time.Minute).Unix()

	r.connStatesLock.Lock()
	defer r.connStatesLock.Unlock()

	for key, entry := range r.connStates {
		if entry.lastSeen.Load() < removeThreshold {
			delete(r.connStates, key)
		}
	}
}
