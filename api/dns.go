package api

import (
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/mycoria/mycoria/mgr"
)

func (api *API) netstackDNSServer(w *mgr.WorkerCtx) error {
	// Configure server.
	api.dnsWorkerCtx = w

	// Start serving.
	err := api.dnsServer.ActivateAndServe()
	if err != nil {
		return err
	}

	return nil
}

// ServeDNS implements the DNS server handler.
func (api *API) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	wkr := api.dnsWorkerCtx
	q := r.Question[0]
	queryName := strings.ToLower(q.Name)

	started := time.Now()
	defer func() {
		wkr.Debug(
			"request",
			"name", queryName,
			"time", time.Since(started),
		)
	}()

	// Source 1: config.resolve
	resolveToIP, ok := api.instance.Config().Resolve[queryName]
	if ok {
		replyAAAA(wkr, w, r, resolveToIP)
		return
	}

	// Source 2: config.friends
	if friendName, cut := strings.CutSuffix(queryName, ".myco."); cut {
		friend, ok := api.instance.Config().FriendsByName[friendName]
		if ok {
			replyAAAA(wkr, w, r, friend.IP)
			return
		}
	}

	replyNotFound(wkr, w, r)
}

func replyAAAA(wkr *mgr.WorkerCtx, w dns.ResponseWriter, r *dns.Msg, ip netip.Addr) {
	reply := new(dns.Msg)

	// Create answer record.
	q := r.Question[0]
	rr, err := dns.NewRR(q.Name + " 1 IN AAAA " + ip.String())
	if err != nil {
		wkr.Error(
			"failed to create answre record",
			"name", q.Name,
			"answer", ip.String(),
			"err", err,
		)
		return
	}

	reply.Answer = []dns.RR{rr}
	reply.SetRcode(r, dns.RcodeSuccess)
	replyMsg(wkr, w, reply)
}

func replyNotFound(wkr *mgr.WorkerCtx, w dns.ResponseWriter, r *dns.Msg) {
	replyMsg(wkr, w, new(dns.Msg).SetRcode(r, dns.RcodeNameError))
}

func replyMsg(wkr *mgr.WorkerCtx, w dns.ResponseWriter, reply *dns.Msg) {
	err := w.WriteMsg(reply)
	if err != nil {
		wkr.Error(
			"failed to write dns response",
			"name", reply.Question[0].Name,
			"rcode", reply.Rcode,
			"err", err,
		)
	}
}
