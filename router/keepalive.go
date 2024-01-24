package router

import (
	"time"

	"github.com/mycoria/mycoria/mgr"
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
		// Only send keep-alive to outgoing connection.
		if !link.Outgoing() {
			continue
		}

		// Send keep-alive.
		notify, err := r.PingPong.Send(link.Peer())
		if err != nil {
			w.Warn(
				"failed to send keep-alive ping",
				"router", link.Peer(),
				"err", err,
			)
			continue
		}

		// Wait for response.
		select {
		case <-w.Done():
			return
		case <-notify:
			// Continue
		case <-time.After(10 * time.Second):
			w.Warn(
				"keep-alive timed out",
				"router", link.Peer(),
			)
		}
	}
}
