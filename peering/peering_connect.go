package peering

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
)

// TriggerPeering triggers checking peers and connecting to new peers if needed.
func (p *Peering) TriggerPeering() {
	select {
	case p.triggerPeering <- struct{}{}:
	default:
	}
}

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
		case <-p.triggerPeering:
			p.checkConnect(w, connected)
		}
	}
}

func (p *Peering) checkConnect(w *mgr.WorkerCtx, connected map[string]netip.Addr) {
	// Check if worker is done.
	if w.IsDone() {
		return
	}

	// Check network workaround if we lost all links.
	if p.LinkCnt() == 0 {
		p.instance.TunDevice().CheckWorkarounds()
	}

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
		newLink, err := p.PeerWith(u, netip.Addr{})
		if err != nil {
			w.Warn(
				"failed to connect",
				"peeringURL", peeringURL,
				"err", err,
			)
			continue
		}

		// Add connection to state map.
		connected[peeringURL] = newLink.Peer()
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
			var connectedCnt int
		connectToNearest:
			for _, near := range nearest {
				// Connect to the two nearest reachable routers.
				if connectedCnt >= 2 {
					break
				}

				// Skip if router does not have any public addresses or listeners.
				if near.PublicInfo == nil || len(near.PublicInfo.IANA) == 0 || len(near.PublicInfo.Listeners) == 0 {
					continue connectToNearest
				}

				// Check if we are already connected.
				if p.GetLink(near.Address.IP) != nil {
					// Aleady connected!
					connectedCnt++
					continue connectToNearest
				}

				// Check if we are already connected to a peer with any of the advertised IANA IPs.
				for _, iana := range near.PublicInfo.IANA {
					if p.GetLinkByRemoteHost(iana) != nil {
						// Aleady connected to this host, but to another router.
						// This is common when a Mycoria router changes ID.
						continue connectToNearest
					}
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
						continue connectToNearest
					}

					// Try to connect on all available Domains/IPs.
					for _, iana := range near.PublicInfo.IANA {
						u.Domain = iana
						_, err = p.PeerWith(u, netip.Addr{})
						if err == nil {
							// Connected!
							connectedCnt++
							continue connectToNearest
						}

						// Log error according to source.
						logLevel := slog.LevelWarn
						var opError *net.OpError
						if errors.As(err, &opError) {
							// Log network errors only on debug, as they are common.
							logLevel = slog.LevelDebug
						}
						w.Log(
							logLevel,
							"failed to auto connect",
							"router", near.Address.IP,
							"peeringURL", u.String(),
							"err", err,
						)
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
