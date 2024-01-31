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
	// Connect
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

	// Connect to the two nearest routers in the address space.
	if p.instance.Config().Router.AutoConnect {
		nearest, err := p.instance.State().QueryNearestRouters(p.instance.Identity().IP, 100)
		if err != nil {
			w.Warn(
				"failed to query nearest routers",
				"err", err,
			)
		} else {
			var connected int
		connectToNearest:
			for _, near := range nearest {
				// Connect to the two nearest reachable routers.
				if connected >= 2 {
					break
				}

				// Check if we are already connected.
				if p.GetLink(near.Address.IP) != nil {
					// Aleady connected!
					connected++
					continue
				}

				// Skip if we don't have any public addresses.
				if near.PublicInfo == nil || len(near.PublicInfo.IANA) == 0 || len(near.PublicInfo.Listeners) == 0 {
					continue
				}

				// Attempt to connect.
				for _, listener := range near.PublicInfo.Listeners {
					u, err := m.ParsePeeringURL(listener)
					if err != nil {
						w.Warn(
							"invalid listener",
							"router", near.Address.IP,
							"value", listener,
							"err", err,
						)
						continue
					}

					// Try to connect on all available Domains/IPs.
					for _, iana := range near.PublicInfo.IANA {
						u.Domain = iana
						_, err = p.PeerWith(u, netip.Addr{})
						if err != nil {
							w.Warn(
								"failed to auto connect",
								"router", near.Address.IP,
								"peeringURL", u.String(),
								"err", err,
							)
						} else {
							// Connected!
							connected++
							continue connectToNearest
						}
					}
				}
			}
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
