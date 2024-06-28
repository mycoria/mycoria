package router

import (
	"errors"
	"fmt"
	"time"

	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
)

// Routing options:
// - build: add own switch hop and forward to best next hop, use max distance to prevent loops
//   - response: switch path (each step sign by origin router), router public key
// - sweep: add own switch hop and forward to best three next hops, avoid all previous hops
//   - response: switch path (each step sign by origin router), router public key
// - query: return list of best next hops to given destination, avoid previous hop only
//   - response: list of hops

// Finding a route:
// - build with TTL of 16 and 1s timeout
// - build with TTL of 64 and 5s timeout
// - sweep with TTL of 64 and 10s timeout
// - query: hop by hop discovery with direct messages only

var (
	// ErrWouldLoop is returned when a packet cannot be routed because it would
	// be sent back where it was received from.
	ErrWouldLoop = errors.New("not routing: would loop")

	// ErrTableEmpty is returned when a packet cannot be routed because the
	// routing table is empty.
	ErrTableEmpty = errors.New("not routing: table empty")
)

// RouteFrame forwards the given frame to the next hop based on the destination IP.
func (r *Router) RouteFrame(f frame.Frame) error {
	// Check if destination is routable.
	if !m.RoutingAddressPrefix.Contains(f.DstIP()) {
		return fmt.Errorf("dst IP %s is not routable", f.DstIP())
	}

	// Lookup routing table for best next hop.
	rte, _ := r.table.LookupNearestRoute(f.DstIP())
	if rte == nil {
		return ErrTableEmpty
	}

	// Check if this returns the frame back to where it came from.
	if f.RecvLink() != nil && rte.NextHop == f.RecvLink().Peer() {
		return ErrWouldLoop
	}

	// Forward to peer.
	if err := r.instance.Switch().ForwardByPeer(f, rte.NextHop); err != nil {
		return fmt.Errorf("forward: %w", err)
	}
	return nil
}

func (r *Router) cleanRoutingTableWorker(w *mgr.WorkerCtx) error {
	ticker := time.NewTicker(10 * time.Minute)
	for {
		select {
		case <-w.Done():
			return nil
		case <-ticker.C:
			r.table.Clean()
		}
	}
}
