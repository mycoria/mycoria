package router

import (
	"time"

	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/peering"
)

func (r *Router) keepAliveWorker(w *mgr.WorkerCtx) error {
	ticker := time.NewTicker(15 * time.Second)
	for {
		select {
		case <-w.Done():
			return nil
		case <-ticker.C:
			r.keepAlivePeers(w)
		}
	}
}

func (r *Router) keepAlivePeers(w *mgr.WorkerCtx) {
	for _, link := range r.instance.Peering().GetLinks() {
		// Skip incoming and closing connections.
		if !link.Outgoing() || link.IsClosing() {
			continue
		}

		// Keep alive peer.
		r.keepAlivePeer(w, link)

		// Check if worker is canceled.
		if w.IsDone() {
			return
		}
	}
}

func (r *Router) keepAlivePeer(w *mgr.WorkerCtx, link peering.Link) {
	var (
		fails  int
		notify <-chan struct{}
		pingID uint64
		err    error
	)

	for {
		// Close if ping fails persistently.
		if fails >= 5 { // 15 seconds.
			link.Close(func() {
				w.Warn(
					"link seems down, closing",
					"router", link.Peer(),
				)
			})
			return
		}

		// Send keep-alive.
		notify, pingID, err = r.PingPong.Send(link.Peer(), pingID)
		if err != nil {
			w.Warn(
				"failed to send keep-alive ping",
				"router", link.Peer(),
				"err", err,
			)

			fails++
			time.Sleep(3 * time.Second)
			continue
		}

		// Wait for response.
		select {
		case <-w.Done():
			return
		case <-notify:
			return
		case <-time.After(3 * time.Second):
			fails++
			w.Warn(
				"keep-alive timed out",
				"router", link.Peer(),
			)
		}
	}
}
