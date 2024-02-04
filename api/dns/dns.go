package dns

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/state"
	"github.com/mycoria/mycoria/tun"
)

// Server is DNS Server.
type Server struct {
	instance instance
	mgr      *mgr.Manager

	dnsServer     *dns.Server
	dnsServerBind net.PacketConn

	apiNames []string
}

// instance is an interface subset of inst.Ance.
type instance interface {
	Version() string
	Config() *config.Config
	Identity() *m.Address
	State() *state.State
	TunDevice() *tun.Device
}

// New returns a new HTTP API.
func New(instance instance, ln net.PacketConn) (*Server, error) {
	// Create HTTP server.
	srv := &Server{
		instance:      instance,
		dnsServerBind: ln,
		apiNames: []string{
			"status", // Human interface.
			"api",    // Computer interface.
			"open",   // For TOFU Names.
		},
	}
	srv.dnsServer = &dns.Server{
		PacketConn:   ln,
		Handler:      srv,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}

	return srv, nil
}

// Start starts the API.
func (srv *Server) Start(m *mgr.Manager) error {
	srv.mgr = m

	// Start DNS server worker.
	m.Go("dns server", srv.dnsServerWorker)

	// Advertise DNS server via RA.
	err := srv.SendRouterAdvertisement(srv.instance.Identity().IP)
	if err != nil {
		m.Error(
			"failed to send router advertisement to announce DNS server",
			"err", err,
		)
	}

	return nil
}

// Stop stops the API.
func (srv *Server) Stop(m *mgr.Manager) error {
	if err := srv.dnsServer.Shutdown(); err != nil {
		m.Error("failed to stop dns server", "err", err)
	}
	return nil
}

func (srv *Server) dnsServerWorker(w *mgr.WorkerCtx) error {
	// Start serving.
	err := srv.dnsServer.ActivateAndServe()
	if err != nil {
		return err
	}

	return nil
}

// ServeDNS implements the DNS server handler.
func (srv *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	_ = srv.mgr.Do("request", func(wkr *mgr.WorkerCtx) error {
		srv.handleRequest(wkr, w, r)
		return nil
	})
}

func (srv *Server) handleRequest(wkr *mgr.WorkerCtx, w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	queryName := strings.ToLower(q.Name)

	// Check TLD.
	mycoName, cut := strings.CutSuffix(queryName, config.DefaultTLDBetweenDots)
	if !cut {
		// Ignore all queries outside of .myco
		replyNotFound(wkr, w, r)
		return
	}

	// Check query type.
	switch q.Qtype {
	case dns.TypeA, dns.TypeAAAA, dns.TypeANY:
		// Allow A, AAAA, ANY.
		// But we always reply with AAAA.
	default:
		// Ignore other types.
		replyNotFound(wkr, w, r)
		return
	}

	// Check query class.
	switch q.Qclass {
	case dns.ClassINET, dns.ClassANY:
		// Allow INET, ANY.
	default:
		// Ignore other classes.
		replyNotFound(wkr, w, r)
		return
	}

	// Log query.
	started := time.Now()
	defer func() {
		wkr.Debug(
			"request",
			"name", queryName,
			"type", dns.Type(q.Qtype),
			"time", time.Since(started),
		)
	}()

	// Source 0: API
	if slices.Contains[[]string, string](srv.apiNames, mycoName) {
		replyAAAA(wkr, w, r, config.DefaultAPIAddress)
		return
	}

	// Source 1: config.resolve
	resolveToIP, ok := srv.instance.Config().Resolve[mycoName]
	if ok {
		replyAAAA(wkr, w, r, resolveToIP)
		return
	}

	// Source 2: config.friends
	friend, ok := srv.instance.Config().FriendsByName[mycoName]
	if ok {
		replyAAAA(wkr, w, r, friend.IP)
		return
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
			"failed to create AAAA answer record",
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
