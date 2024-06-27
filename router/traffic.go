package router

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/state"
)

func (r *Router) handleIncomingTraffic(w *mgr.WorkerCtx, f frame.Frame) error {
	// Get session.
	session := r.instance.State().GetSession(f.SrcIP())
	if session == nil {
		return fmt.Errorf("unknown src router: %s", f.SrcIP())
	}

	// Unseal.
	if err := f.Unseal(session); err != nil {
		// Send error ping if encryption is not set up.
		if errors.Is(err, state.ErrEncryptionNotSetUp) {
			if err := r.ErrorPing.SendNoEncryptionKeys(f.SrcIP()); err != nil {
				return fmt.Errorf("send error ping no encryption keys: %w", err)
			}
			return nil // TODO: Do we need to return the frame to pool here?
		}
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

	// Check if handling is enabled or
	if !r.handleTraffic.Load() {
		if err := r.ErrorPing.SendRejected(src, dst, protocol, dstPort); err != nil {
			return fmt.Errorf("send rejected ping: %w", err)
		}
		return nil
	}

	// Check integrity.
	switch {
	case src != f.SrcIP():
		f.ReturnToPool()
		return errors.New("invalid packet: src IPs do not match")

	case dst != f.DstIP():
		f.ReturnToPool()
		return errors.New("invalid packet: dst IPs do not match")

	case m.InternalPrefix.Contains(f.DstIP()):
		f.ReturnToPool()
		return errors.New("invalid packet: dst IP is internal range")
	}
	// Check policy.
	status, _ := r.checkPolicy(w, true, connStateKey{
		localIP:    dst,
		remoteIP:   src,
		protocol:   protocol,
		localPort:  dstPort,
		remotePort: srcPort,
	}, len(packetData))
	if status != connStatusAllowed {
		// Packet may not be received.
		f.ReturnToPool()
		if err := r.ErrorPing.SendAccessDenied(src, dst, protocol, dstPort); err != nil {
			return fmt.Errorf("send access denied ping: %w", err)
		}

		return nil
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
	ticker := time.NewTicker(10 * time.Second)
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
	shortRemoveThreshold := time.Now().Add(-10 * time.Second).Unix()

	r.connStatesLock.Lock()
	defer r.connStatesLock.Unlock()

	for key, entry := range r.connStates {
		switch {
		case entry.shortLived:
			if entry.lastSeen.Load() < shortRemoveThreshold {
				delete(r.connStates, key)
			}
		default:
			if entry.lastSeen.Load() < removeThreshold {
				delete(r.connStates, key)
			}
		}
	}
}
