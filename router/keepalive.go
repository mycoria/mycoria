package router

import (
	"time"

	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/peering"
)

func (r *Router) keepAliveWorker(w *mgr.WorkerCtx) error {
	lastCheck := time.Now()
	ticker := time.NewTicker(time.Second)
	var ticks uint64

	for {
		select {
		case <-w.Done():
			return nil
		case <-ticker.C:
			ticks++
			switch {
			case clockTimeSince(lastCheck) > 5*time.Minute:
				// Check with fast fail when last check is more than 5 minutes ago.
				// This will usually happen when device was sleeping.
				lastCheck = time.Now()
				r.keepAlivePeers(w, true)

			case ticks%15 == 0:
				// Check every 15 ticks / 15 sec.
				lastCheck = time.Now()
				r.keepAlivePeers(w, false)
			}
		}
	}
}

// clockTimeSince returns the elapsed non-monotic time since t.
// This can have weird results when the system clock changes.
func clockTimeSince(t time.Time) time.Duration {
	return time.Duration(time.Now().Unix()-t.Unix()) * time.Second
}

func (r *Router) keepAlivePeers(w *mgr.WorkerCtx, fastCheck bool) {
	for _, link := range r.instance.Peering().GetLinks() {
		// Skip closing connections.
		if link.IsClosing() {
			continue
		}

		// Keep alive peer.
		r.keepAlivePeer(w, link, fastCheck)

		// Check if worker is canceled.
		if w.IsDone() {
			return
		}
	}
}

func (r *Router) keepAlivePeer(w *mgr.WorkerCtx, link peering.Link, fastCheck bool) {
	var (
		fails       int
		notify      <-chan struct{}
		pingID      uint64
		err         error
		sentFirstAt = time.Now()
	)

	for {
		// Abort if the link is closing.
		if link.IsClosing() {
			return
		}

		// Close if ping fails persistently.
		if fails >= 5 || (fastCheck && fails >= 1) {
			link.Close(func() {
				w.Warn(
					"link seems down, closing",
					"router", link.Peer(),
					"fast-check", fastCheck,
				)
			})
			return
		}

		// Send keep-alive.
		notify, pingID, err = r.PingPong.Send(link.Peer(), true, pingID)
		if err != nil {
			// Abort silently if the link is closing.
			if link.IsClosing() {
				return
			}
			fails++

			w.Warn(
				"failed to send keep-alive ping",
				"router", link.Peer(),
				"err", err,
			)

			// Try again after some time.
			if fastCheck {
				continue
			}
			select {
			case <-w.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}

		// Wait for response.
		select {
		case <-w.Done():
			return

		case <-notify:
			// We re-use ping IDs, so we always measure from the first ping we sent.
			// High reported latency is not too bad when we have obvious packet loss.
			// Impact is also quite low though, as we use 10x avg.
			link.AddMeasuredLatency(time.Since(sentFirstAt) / 2)

			// Update status if we printed a warning.
			if fails >= 1 {
				w.Info(
					"keep-alive succeeded",
					"router", link.Peer(),
				)
			}
			return

		case <-time.After(time.Second):
			fails++
			w.Warn(
				"keep-alive timed out",
				"router", link.Peer(),
			)
		}
	}
}
