package peering

import (
	"net/netip"
	"time"

	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
)

func (p *Peering) listenMgr(w *mgr.WorkerCtx) error {
	listening := make(map[string]string)
	p.checkListen(w, listening)

	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-w.Done():
			return nil
		case <-ticker.C:
			p.checkListen(w, listening)
		}
	}
}

func (p *Peering) checkListen(w *mgr.WorkerCtx, listening map[string]string) {
	// Start listeners.
	for _, listenURL := range p.instance.Config().Router.Listen {
		// Check if we are already connected.
		if id, ok := listening[listenURL]; ok && p.GetListener(id) != nil {
			continue
		}

		// Parse peering URL to connect.
		u, err := m.ParsePeeringURL(listenURL)
		if err != nil {
			w.Warn(
				"invalid listen peering URL",
				"peeringURL", listenURL,
				"err", err,
			)
			continue
		}

		// Start listener.
		ln, err := p.StartListener(u, netip.Addr{})
		if err != nil {
			w.Warn(
				"failed to listen",
				"listenURL", ln.ID(),
				"err", err,
			)
			continue
		}

		w.Info(
			"listener started",
			"listenURL", ln.ID(),
		)
		listening[listenURL] = ln.ID()
	}
}
