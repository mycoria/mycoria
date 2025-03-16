package dns

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/state"
	"github.com/mycoria/mycoria/storage"
	"github.com/mycoria/mycoria/tun"
)

// Server is DNS Server.
type Server struct {
	mgr      *mgr.Manager
	instance instance
	mappings storage.DomainMappingStorage

	dnsServer     *dns.Server
	dnsServerBind net.PacketConn
	replyLock     sync.Mutex

	apiNames       []string
	forbiddenNames []string
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
func New(instance instance, ln net.PacketConn, mappings storage.DomainMappingStorage) (*Server, error) {
	// Create HTTP server.
	srv := &Server{
		mgr:           mgr.New("dns"),
		instance:      instance,
		mappings:      mappings,
		dnsServerBind: ln,
		apiNames: []string{
			"router.myco", // Main UI domain.
			"open.myco",   // For TOFU Names.
		},
		forbiddenNames: []string{
			"wpad.myco", // Windows proxy auto detect.
			"myco.myco", // Queried by Windows for unknown reason.
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

// Manager returns the module's manager.
func (srv *Server) Manager() *mgr.Manager {
	return srv.mgr
}

// Start starts the API.
func (srv *Server) Start() error {
	// Start DNS server worker.
	srv.mgr.Go("dns server", srv.dnsServerWorker)

	// Advertise DNS server via RA.
	err := srv.SendRouterAdvertisement(srv.instance.Identity().IP)
	if err != nil {
		srv.mgr.Error(
			"failed to send router advertisement to announce DNS server",
			"err", err,
		)
	}

	return nil
}

// Stop stops the API.
func (srv *Server) Stop() error {
	if err := srv.dnsServer.Shutdown(); err != nil {
		srv.mgr.Error("failed to stop dns server", "err", err)
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
	if !strings.HasSuffix(queryName, config.DefaultTLDBetweenDots) {
		// Ignore all queries outside of .myco
		srv.replyNotFound(wkr, w, r)
		return
	}
	// Domain names are internally handle without the trailing dot.
	mycoName := strings.TrimSuffix(queryName, ".")

	// Check query type.
	switch q.Qtype {
	case dns.TypeA, dns.TypeAAAA, dns.TypeSVCB, dns.TypeHTTPS, dns.TypeANY:
		// Handle A, AAAA, SVCB, HTTPS and ANY.
	default:
		// Ignore other types.
		srv.replyNotFound(wkr, w, r)
		return
	}

	// Check query class.
	switch q.Qclass {
	case dns.ClassINET, dns.ClassANY:
		// Allow INET, ANY.
	default:
		// Ignore other classes.
		srv.replyNotFound(wkr, w, r)
		return
	}

	// Log query.
	started := time.Now()
	defer func() {
		wkr.Debug(
			"request",
			"name", mycoName,
			"type", dns.Type(q.Qtype),
			"time", time.Since(started),
		)
	}()

	// Lookup and reply.
	resolveToIP, source := srv.Lookup(mycoName)
	switch source {
	case SourceInternal, SourceResolveConfig,
		SourceFriend, SourceMapping:
		srv.reply(wkr, w, r, resolveToIP, source)

	case SourceNone, SourceForbidden:
		srv.replyNotFound(wkr, w, r)

	default:
		srv.replyNotFound(wkr, w, r)
	}
}

// Lookup looks up a name.
func (srv *Server) Lookup(domain string) (netip.Addr, Source) {
	// Source 0: Internal API
	if slices.Contains[[]string, string](srv.apiNames, domain) {
		return config.DefaultAPIAddress, SourceInternal
	}

	// Source 1: config.resolve
	resolveToIP, ok := srv.instance.Config().Resolve[domain]
	if ok {
		return resolveToIP, SourceResolveConfig
	}

	// Source 2: Forbidden
	if slices.Contains[[]string, string](srv.forbiddenNames, domain) {
		return netip.Addr{}, SourceForbidden
	}

	// Source 3: config.friends
	friendName, cut := strings.CutSuffix(domain, config.DefaultDotTLD)
	if cut {
		friend, ok := srv.instance.Config().FriendsByName[friendName]
		if ok {
			return friend.IP, SourceFriend
		}
	}

	// Source 4: domain mappings
	if srv.mappings != nil {
		resolveToIP, err := srv.mappings.GetMapping(domain)
		if err == nil {
			// TODO: How should we handle a database failure here?
			return resolveToIP, SourceMapping
		}
	}

	return netip.Addr{}, SourceNone
}

func (srv *Server) reply(wkr *mgr.WorkerCtx, w dns.ResponseWriter, r *dns.Msg, ip netip.Addr, source Source) {
	reply := new(dns.Msg)

	// Create answers.
	q := r.Question[0]
	aaaa, err := dns.NewRR(q.Name + " 1 IN AAAA " + ip.String())
	if err != nil {
		wkr.Error(
			"failed to create AAAA answer record",
			"name", q.Name,
			"answer", ip.String(),
			"err", err,
		)
		return
	}
	svcb, err := dns.NewRR(q.Name + " 1 IN SVCB 1 . ipv6hint=" + ip.String())
	if err != nil {
		wkr.Error(
			"failed to create SVCB answer record",
			"name", q.Name,
			"answer", ip.String(),
			"err", err,
		)
		return
	}

	// Assign answers to sections.
	switch q.Qtype {
	case dns.TypeAAAA:
		reply.Answer = []dns.RR{aaaa}
		reply.Extra = []dns.RR{svcb}

	case dns.TypeSVCB:
		reply.Answer = []dns.RR{svcb}
		reply.Extra = []dns.RR{aaaa}

	case dns.TypeANY:
		reply.Answer = []dns.RR{aaaa, svcb}

	default:
		reply.Extra = []dns.RR{aaaa, svcb}
	}

	// Add info record to signify answer source.
	infoTxt, err := dns.NewRR(`info.myco. 0 IN TXT "answer source: ` + string(source) + `"`)
	if err == nil {
		reply.Extra = append(reply.Extra, infoTxt)
	}

	// Finalize and reply.
	reply.SetRcode(r, dns.RcodeSuccess)
	srv.replyMsg(wkr, w, reply)
}

func (srv *Server) replyNotFound(wkr *mgr.WorkerCtx, w dns.ResponseWriter, r *dns.Msg) {
	srv.replyMsg(wkr, w, new(dns.Msg).SetRcode(r, dns.RcodeNameError))
}

func (srv *Server) replyMsg(wkr *mgr.WorkerCtx, w dns.ResponseWriter, reply *dns.Msg) {
	// The gVisor netstack hangs at
	//   tcpip/adapters/gonet.(*UDPConn).WriteTo+0x6b0
	//   tcpip/adapters/gonet/gonet.go:680
	// This breaks DNS resolution and leads to massive goroutine leak.
	// This is an attempt to workaround this and stabilize responses.
	// TODO: Evaluate other options
	srv.replyLock.Lock()
	defer srv.replyLock.Unlock()
	err := srv.dnsServer.PacketConn.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if err != nil {
		wkr.Error(
			"failed to set write deadline for dns response",
			"name", reply.Question[0].Name,
			"rcode", reply.Rcode,
			"err", err,
		)
		return
	}

	err = w.WriteMsg(reply)
	if err != nil {
		wkr.Error(
			"failed to write dns response",
			"name", reply.Question[0].Name,
			"rcode", reply.Rcode,
			"err", err,
		)
	}
}
