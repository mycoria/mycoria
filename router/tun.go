package router

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"

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

func (r *Router) handleTunPacket(w *mgr.WorkerCtx, packetData []byte) { //nolint:maintidx
	routerIP := r.instance.Identity().IP

	// Check if packet is empty.
	if len(packetData) == 0 {
		w.Warn("ignoring empty packet")
		return
	}

	// Basic packet checks.
	ipVersion := packetData[0] >> 4
	switch {
	case ipVersion == 4:
		w.Debug("ignoring IPv4 packet")
		return
	case ipVersion != 6:
		w.Warn("ignoring packet with unknown IP version")
		return
	case len(packetData) < 44:
		w.Warn("ignoring too small packet", "packetSize", len(packetData))
		return
	}

	// Parse important fields.
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
		r.instance.NetStack().SubmitPacket(packetData)
		return
	}

	// Return packet data to pool after here.
	// Note: The data is currently copied for the frame.
	defer r.instance.FrameBuilder().ReturnPooledSlice(packetData)

	// Check integrity and addresses.
	switch {
	case !r.handleTraffic.Load():
		// Traffic handling is disabled.
		return

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
	// Check policy.
	key := connStateKey{
		localIP:    src,
		remoteIP:   dst,
		protocol:   protocol,
		localPort:  srcPort,
		remotePort: dstPort,
	}
	status, statusUpdate := r.checkPolicy(w, false, key, len(packetData))
	// Check for similar status to reduce network clutter.
	// Also, error pings are heavily rate limited.
	// This ensure more reliable and stable network response.
	if similarStatus := r.checkSimilarOutboundStatus(w, key); similarStatus != connStatusUnknown {
		status = similarStatus
	}
	// Return network response if not allowed.
	if status != connStatusAllowed {
		if err := r.respondWithError(src, packetData, status); err != nil {
			w.Debug(
				"failed to send icmp error",
				"err", err,
			)
		}
		return
	}

	// Get session.
	session := r.instance.State().GetSession(dst)
	if session == nil || !session.Encryption().IsSetUp() {
		// Setup encryption with hello ping.
		notify, err := r.HelloPing.Send(dst)
		if err != nil {
			switch {
			case errors.Is(err, ErrTableEmpty):
				// Ignore packets if we can't route them.
			case errors.Is(err, ErrAlreadyActive):
				w.Debug(
					"hello ping already active, dropping additional packet",
					"dst", dst,
				)
			default:
				w.Warn(
					"hello ping failed",
					"dst", dst,
					"err", err,
				)
			}
			return
		}

		// Wait for hello ping to finish.
		select {
		case <-notify:
			// Continue

		case status = <-statusUpdate:
			// Connection status changed.
			if err := r.respondWithError(src, packetData, status); err != nil {
				w.Debug(
					"failed to send icmp error",
					"err", err,
				)
			}
			return

		case <-time.After(200 * time.Millisecond):
			// Wait for 200ms in hot path, blocking one worker.
			// TODO: Is this a good idea?
			return

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

	// Check MTU.
	dstMTU := session.TunMTU()
	if dstMTU != 0 && len(packetData) > dstMTU {
		// Packet is too big for MTU, notify OS.
		if err := r.sendICMP6PacketTooBig(src, dstMTU, packetData); err != nil {
			w.Debug(
				"failed to send icmp6 packet too big error",
				"err", err,
			)
		}
		return
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

func (r *Router) respondWithError(to netip.Addr, packetData []byte, status connStatus) error {
	// Note: packetData must be copied!

	switch status {
	case connStatusUnreachable:
		// Reply with ICMP error 1.3: "address unreachable".
		// r.mgr.Debug("sent icmp error 1.3 address unreachable")
		return r.sendICMP6Unreachable(to, 3, packetData)

	case connStatusProhibited:
		// Denied locally.
		// Reply with ICMP error 1.1: "communication with destination administratively prohibited".
		// r.mgr.Debug("sent icmp error 1.1 administratively prohibited")
		return r.sendICMP6Unreachable(to, 1, packetData)

	case connStatusDenied:
		// Denied by remote.
		// Reply with ICMP error 1.5: "source address failed ingress/egress policy".
		// r.mgr.Debug("sent icmp error 1.5 denied: failed policy")
		return r.sendICMP6Unreachable(to, 5, packetData)

	case connStatusRejected:
		// Rejected for technical or operational reason.
		// Reply with ICMP error 1.6: "reject route to destination".
		// r.mgr.Debug("sent icmp error 1.6 reject route")
		return r.sendICMP6Unreachable(to, 6, packetData)

	case connStatusUnknown, connStatusAllowed:
		fallthrough
	default:
		// Drop packet.
		return nil
	}
}

func (r *Router) sendICMP6Unreachable(to netip.Addr, code int, packetData []byte) error {
	packetBody := packetData
	if len(packetBody) > 48 {
		packetBody = packetBody[:48]
	}

	return r.sendICMP6(to, icmp.Message{
		Type: ipv6.ICMPTypeDestinationUnreachable,
		Code: code,
		Body: &icmp.DstUnreach{
			Data: packetBody,
		},
	})
}

func (r *Router) sendICMP6PacketTooBig(to netip.Addr, mtu int, packetData []byte) error {
	packetBody := packetData
	if len(packetBody) > 48 {
		packetBody = packetBody[:48]
	}

	return r.sendICMP6(to, icmp.Message{
		Type: ipv6.ICMPTypePacketTooBig,
		Body: &icmp.PacketTooBig{
			MTU:  mtu,
			Data: packetBody,
		},
	})
}

func (r *Router) sendICMP6(to netip.Addr, icmpMsg icmp.Message) error {
	// Build ICMP packet.
	icmpData, err := icmpMsg.Marshal(
		icmp.IPv6PseudoHeader(config.DefaultAPIAddress.AsSlice(), to.AsSlice()),
	)
	if err != nil {
		return fmt.Errorf("failed to build icmp error packet: %w", err)
	}

	// Create full packet and copy ICMP message.
	offset := r.instance.TunDevice().SendRawOffset()
	packetData := make([]byte, offset+ipv6.HeaderLen+len(icmpData))
	copy(packetData[offset+ipv6.HeaderLen:], icmpData)

	// Set IPv6 header.
	header := packetData[offset : offset+ipv6.HeaderLen]
	header[0] = 6 << 4 // IP Version
	m.PutUint16(header[4:6], uint16(len(icmpData)))
	header[6] = 58 // Next Header
	header[7] = 64 // Hop Limit
	srcData := config.DefaultAPIAddress.As16()
	copy(header[8:24], srcData[:])
	dstData := to.As16()
	copy(header[24:40], dstData[:])

	// Submit to writer.
	r.instance.TunDevice().SendRaw <- packetData
	return nil
}
