package peering

import (
	"net/netip"
	"time"

	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
)

func (p *Peering) connectMgr(w *mgr.WorkerCtx) error {
	connected := make(map[string]netip.Addr)
	p.checkConnect(w, connected)

	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-w.Done():
			return nil
		case <-ticker.C:
			p.checkConnect(w, connected)
		}
	}
}

func (p *Peering) checkConnect(w *mgr.WorkerCtx, connected map[string]netip.Addr) {
	for _, peeringURL := range p.instance.Config().Router.Connect {
		// Check if we are already connected.
		if ip, ok := connected[peeringURL]; ok && p.GetLink(ip) != nil {
			continue
		}

		// Parse peering URL to connect.
		u, err := m.ParsePeeringURL(peeringURL)
		if err != nil {
			w.Warn(
				"invalid peering URL",
				"peeringURL", peeringURL,
				"err", err,
			)
			continue
		}

		// Connect to router.
		_, err = p.PeerWith(u, netip.Addr{})
		if err != nil {
			w.Warn(
				"failed to connect",
				"peeringURL", peeringURL,
				"err", err,
			)
			continue
		}
	}

	// Bootstrap if we have no link.
	if p.LinkCnt() == 0 {
		for _, peeringURL := range p.instance.Config().Router.Bootstrap {
			// Parse peering URL to connect.
			u, err := m.ParsePeeringURL(peeringURL)
			if err != nil {
				w.Warn(
					"invalid bootstrap peering URL",
					"peeringURL", peeringURL,
					"err", err,
				)
				continue
			}

			// Connect to router.
			_, err = p.PeerWith(u, netip.Addr{})
			if err != nil {
				w.Warn(
					"failed to bootstrap",
					"peeringURL", peeringURL,
					"err", err,
				)
				continue
			}

			// Bootstrapping with one router is enough.
			return
		}
	}
}
