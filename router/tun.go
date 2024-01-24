package router

import (
	"errors"
	"net/netip"
	"time"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
)

func (r *Router) handleTun(w *mgr.WorkerCtx) error {
	nic := r.instance.TunDevice()

	for {
		select {
		case packetData := <-nic.RecvRaw:
			r.handleTunPacket(w, packetData)

		case <-w.Done():
			return nil
		}
	}
}

var multicastPrefix = netip.MustParsePrefix("ff00::/12")

func (r *Router) handleTunPacket(w *mgr.WorkerCtx, packetData []byte) {
	routerIP := r.instance.Identity().IP

	// Check packet and parse important fields.
	if len(packetData) < 44 {
		w.Warn("packet too small for header", "packetSize", len(packetData))
		return
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

	// DEBUG:
	// prot := packetData[6]
	// fmt.Printf("packet: %s %s %d\n", src, dst, prot)

	// Raw packet handling.
	if dst == config.DefaultAPIAddress {
		// Submit packet to API if going to API IP.
		r.instance.API().SubmitPacket(packetData)
		return
	}

	// Return packet data to pool after here.
	// Note: The data is currently copied for the frame.
	defer r.instance.FrameBuilder().ReturnPooledSlice(packetData)

	// Check addresses.
	switch {
	case multicastPrefix.Contains(dst):
		// Ignore multicast packets.
		return

	case !m.BaseNetPrefix.Contains(dst):
		// Drop packet if outside mycoria range.
		w.Debug(
			"dropping packet with dst outside of mycoria",
			"dst", dst,
		)
		return

	case src != routerIP:
		// Drop packet if source does not match router IP.
		w.Debug(
			"dropping packet with src that does not match router IP",
			"src", src,
		)
		return
	}

	// Check if we have seen this connection before.
	connKey := connStateKey{
		localIP:    src,
		remoteIP:   dst,
		protocol:   protocol,
		localPort:  srcPort,
		remotePort: dstPort,
	}
	connState, ok := r.getConnState(connKey)
	switch {
	case ok:
		// Connection was seen previously.
		connState.lastSeen.Store(time.Now().Unix())

	case r.outboundAllowedTo(dst):
		// New outbound connection is allowed.
		entry := &connStateEntry{
			inbound: false,
		}
		entry.lastSeen.Store(time.Now().Unix())
		r.setConnState(connKey, entry)

	default:
		w.Debug(
			"dropping non-friend packet in isolation mode",
			"router", dst,
		)
		return
	}

	// Get session.
	session := r.instance.State().GetSession(dst)
	if session == nil || !session.Encryption().IsSetUp() {
		// Setup encryption with hello ping.
		notify, err := r.HelloPing.Send(dst)
		if err != nil {
			if errors.Is(err, ErrAlreadyActive) {
				w.Debug(
					"hello ping already active, dropping additional packet",
					"dst", dst,
				)
				return
			}

			w.Warn(
				"hello ping failed",
				"dst", dst,
				"err", err,
			)
			return
		}

		// Wait for hello ping to finish.
		select {
		case <-notify:
			// Continue
		case <-time.After(1 * time.Second):
			// Wait for 1 second in hot path, blocking one worker.
			// TODO: Is this a good idea?
		case <-w.Done():
			return
		}

		session = r.instance.State().GetSession(dst)
		if session == nil {
			w.Warn(
				"internal error: no session after hello ping",
				"router", dst,
				"dst", dst,
			)
			return
		}
	}

	// Make new frame from data.
	// TODO: Stop copying data. (Don't forget about the ReturnPooledSlice above!)
	f, err := r.instance.FrameBuilder().NewFrameV1(
		r.instance.Identity().IP, dst,
		frame.NetworkTraffic,
		nil, packetData, nil,
	)
	if err != nil {
		w.Warn(
			"failed to build frame",
			"router", dst,
			"err", err,
		)
		return
	}

	// Seal.
	if err := f.Seal(session); err != nil {
		w.Warn(
			"failed to seal frame",
			"router", dst,
			"err", err,
		)
		f.ReturnToPool()
		return
	}

	// Send the frame along its way!
	if err := r.RouteFrame(f); err != nil {
		w.Warn(
			"failed to route frame ",
			"dst", dst,
			"err", err,
		)
		f.ReturnToPool()
		return
	}
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
