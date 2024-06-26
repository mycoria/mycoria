package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"

	"github.com/mycoria/mycoria/m"
)

// Config holds initialized configuration.
type Config struct {
	Store

	APIListen netip.AddrPort

	Friends       []Friend
	FriendsByName map[string]Friend
	FriendsByIP   map[netip.Addr]Friend

	Services []Service
	Resolve  map[string]netip.Addr

	inPolicy map[string]map[netip.Addr]struct{}

	tunMTU atomic.Int32

	devMode atomic.Bool
	started time.Time
}

// Friend is a trusted router in the network.
type Friend struct {
	Name string
	IP   netip.Addr
}

// Service defines an endpoint other routers can send traffic to.
type Service struct { //nolint:maligned
	Name        string
	Description string
	Domain      string
	URL         string

	Public  bool
	Friends bool
	For     []netip.Addr

	Advertise bool
}

var (
	tunNameRegex = regexp.MustCompile(`^[A-z0-9]+$`)
	domainRegex  = regexp.MustCompile(
		`^` + // match beginning
			`(` + // start subdomain group
			`(xn--)?` + // idn prefix
			`[a-z0-9_-]{1,63}` + // main chunk
			`\.` + // ending with a dot
			`)*` + // end subdomain group, allow any number of subdomains
			`(xn--)?` + // TLD idn prefix
			`[a-z0-9_-]{1,63}` + // TLD main chunk with at least one character
			`$`, // match end
	)
)

// Parse parses a config definition and return an initialized config.
func (s Store) Parse() (*Config, error) {
	return s.parse(false)
}

// MakeTestConfig parses and returns the given config store with loosened checks.
// If anything fails, it panics.
func MakeTestConfig(s Store) *Config {
	c, err := s.parse(true)
	if err != nil {
		panic("test config invalid: " + err.Error())
	}
	return c
}

func (s Store) parse(test bool) (*Config, error) { //nolint:maintidx // Function has sections.
	c := &Config{
		Store:    s,
		inPolicy: make(map[string]map[netip.Addr]struct{}),
		started:  time.Now(),
	}
	c.SetTunMTU(DefaultTunMTU)

	// Basic field checks.
	if c.System.TunName != "" &&
		!tunNameRegex.MatchString(c.System.TunName) {
		return nil, fmt.Errorf("system.tunName %q is invalid - it may only contain A-z and 0-9", c.System.TunName)
	}
	if c.System.TunMTU != 0 {
		c.SetTunMTU(c.System.TunMTU)
	}
	if !test && c.System.StatePath != "" && !filepath.IsAbs(c.System.StatePath) {
		return nil, errors.New("system.statePath must be an absolute path")
	}
	if c.System.APIListen != "" {
		var err error
		c.APIListen, err = netip.ParseAddrPort(c.System.APIListen)
		if err != nil {
			return nil, errors.New("system.apiListen ist not a valid IP and port")
		}
	}

	// Check if there is any way to connect.
	if !test {
		if len(c.Router.Listen) == 0 && len(c.Router.Connect) == 0 && len(c.Router.Bootstrap) == 0 {
			return nil, errors.New(
				`router has no way to connect or accept connections and will die forever alone
Configure at least one of these settings:
- router.listen
- router.connect
- router.bootstrap`)
		}
	}

	// Check peering URLs.
	for i, peeringURL := range c.Router.Listen {
		if _, err := m.ParsePeeringURL(peeringURL); err != nil {
			return nil, fmt.Errorf("router.listen.#%d is invalid: %w", i+1, err)
		}
	}
	for i, peeringURL := range c.Router.Connect {
		if _, err := m.ParsePeeringURL(peeringURL); err != nil {
			return nil, fmt.Errorf("router.connect.#%d is invalid: %w", i+1, err)
		}
	}
	for i, peeringURL := range c.Router.Bootstrap {
		if _, err := m.ParsePeeringURL(peeringURL); err != nil {
			return nil, fmt.Errorf("router.bootstrap.#%d is invalid: %w", i+1, err)
		}
	}

	// Parse friends.
	c.Friends = make([]Friend, 0, len(c.FriendConfigs))
	c.FriendsByName = make(map[string]Friend, len(c.FriendConfigs))
	c.FriendsByIP = make(map[netip.Addr]Friend, len(c.FriendConfigs))
	for i, friendConfig := range c.FriendConfigs {
		ip, err := netip.ParseAddr(friendConfig.IP)
		if err != nil {
			return nil, fmt.Errorf("IP address of friend %s (#%d) is invalid: %w", friendConfig.Name, i+1, err)
		}
		switch m.GetAddressType(ip) { //nolint:exhaustive
		case m.TypeGeoMarked,
			m.TypeRoaming,
			m.TypeOrganization,
			m.TypeAnycast,
			m.TypeExperiment:
			// Address in accepted range.
		default:
			return nil, fmt.Errorf("IP address of friend %s (#%d) is invalid: must be in acceptable routable range", friendConfig.Name, i+1)
		}

		friend := Friend{
			Name: friendConfig.Name,
			IP:   ip,
		}
		c.Friends = append(c.Friends, friend)
		c.FriendsByName[friend.Name] = friend
		c.FriendsByIP[friend.IP] = friend
	}

	// Parse services.
	c.Services = make([]Service, 0, len(c.ServiceConfigs))
	for i, svc := range c.ServiceConfigs {
		// Check if a name is defined.
		if svc.Name == "" {
			return nil, fmt.Errorf(`service #%d has no name`, i+1)
		}

		// Check if anyone is allowed to access.
		if !svc.Public && !svc.Friends && len(svc.For) == 0 {
			return nil, fmt.Errorf(`service %s (#%d): nobody is allowed to access service`, svc.Name, i+1)
		}

		// Make list of allowed IPs.
		forIPs := make([]netip.Addr, 0, len(svc.For))
		for j, forIP := range svc.For {
			// Check if entry is friend name.
			friend, ok := c.FriendsByName[forIP]
			if ok {
				forIPs = append(forIPs, friend.IP)
				continue
			}

			// Check if entry is IP.
			ip, err := netip.ParseAddr(forIP)
			if err != nil {
				return nil, fmt.Errorf(`service %s (#%d): "for" entry #%d is neither friend name nor IP: %w`, svc.Name, i+1, j+1, err)
			}
			// Check if IP is in scope.
			if !m.RoutingAddressPrefix.Contains(ip) {
				return nil, fmt.Errorf(`service %s (#%d): "for" entry #%d IP is not a valid mycoria address`, svc.Name, i+1, j+1)
			}
			forIPs = append(forIPs, ip)
		}

		// Parse service URL to get policy key and domain.
		svcDomain := svc.Domain
		policyKeys, domain, err := getInfoFromURL(svc.URL)
		if err != nil {
			return nil, fmt.Errorf(`service %s (#%d): %w`, svc.Name, i+1, err)
		}
		if svcDomain == "" {
			svcDomain = domain
		}
		if svcDomain != "" {
			var valid bool
			svcDomain, valid = CleanDomain(svcDomain)
			if !valid {
				return nil, fmt.Errorf(`service %s (#%d): domain %q is invalid`, svc.Name, i+1, domain)
			}
		}

		// Create and add service.
		service := Service{
			Name:        svc.Name,
			Description: svc.Description,
			Domain:      svcDomain,
			URL:         svc.URL,
			Public:      svc.Public,
			Friends:     svc.Friends,
			For:         forIPs,
			Advertise:   svc.Advertise,
		}
		c.Services = append(c.Services, service)

		// Add service to in policy.
		if service.Public && (service.Friends || len(service.For) > 0) {
			return nil, fmt.Errorf(`service %s (#%d): public service may not also define friends or "for"`, svc.Name, i+1)
		}
		for _, policyKey := range policyKeys {
			if err := c.addInPolicyKey(policyKey, service.Public, service.Friends, service.For); err != nil {
				return nil, fmt.Errorf(`service %s (#%d): create service policy: %w`, svc.Name, i+1, err)
			}
		}
	}

	// Parse resolving.
	c.Resolve = make(map[string]netip.Addr, len(c.ResolveConfig))
	for domain, ip := range c.ResolveConfig {
		// Check if domain is valid.
		cleaned, valid := CleanDomain(domain)
		if !valid {
			return nil, fmt.Errorf("resolve domain %q is invalid", domain)
		}

		// Check if entry is IP.
		resolveIP, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("resolve domain %q has an invalid IP (%s): %w", domain, ip, err)
		}
		// Check if IP is in scope.
		if !m.RoutingAddressPrefix.Contains(resolveIP) {
			return nil, fmt.Errorf("resolve domain %q has an invalid IP (%s): not a valid mycoria address", domain, ip)
		}

		// Add to resolve map.
		c.Resolve[cleaned] = resolveIP
	}

	return c, nil
}

// CleanDomain cleans the given domain and also returns if it is valid.
func CleanDomain(domain string) (cleaned string, valid bool) {
	// Clean domain.
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")

	// Check if domain ends in ".myco".
	if !strings.HasSuffix(domain, DefaultDotTLD) {
		return domain, false
	}

	// Check max length.
	if len(domain) > 256 {
		return domain, false
	}

	// Check domain with regex.
	if !domainRegex.MatchString(domain) {
		// Check if this is an IDN domain.
		punyDomain, err := idna.ToASCII(domain)
		if err == nil && domainRegex.MatchString(punyDomain) {
			domain = punyDomain
		} else {
			return domain, false
		}
	}

	return domain, true
}

func (c *Config) addInPolicyKey(policyKey string, public bool, friends bool, forIPs []netip.Addr) error {
	// Check for existing policy.
	_, ok := c.inPolicy[policyKey]
	if ok {
		return fmt.Errorf("duplicate policy for protocol-port %q detected, please check for duplicate services", policyKey)
	}

	// Check parameters.
	if public && (friends || len(forIPs) > 0) {
		return errors.New(`public policy may not also define friends or "for"`)
	}

	// Add public policy.
	if public {
		c.inPolicy[policyKey] = nil
		return nil
	}

	// Add IP based policy.
	ipPolicy := make(map[netip.Addr]struct{}, len(c.Friends)+len(forIPs))
	if friends {
		for _, friend := range c.Friends {
			ipPolicy[friend.IP] = struct{}{}
		}
	}
	for _, forIP := range forIPs {
		ipPolicy[forIP] = struct{}{}
	}
	c.inPolicy[policyKey] = ipPolicy

	return nil
}

// CheckInboundTrafficPolicy checks if the given inbound traffic is allowed.
func (c *Config) CheckInboundTrafficPolicy(protocol uint8, dstPort uint16, src netip.Addr) (allowed bool) {
	// Check protocol/port.
	servicePolicy, ok := c.inPolicy[makePolicyKey(protocol, dstPort)]
	if !ok {
		return false
	}

	// Check if service is public.
	if servicePolicy == nil {
		return true
	}

	// Check for allowed sources.
	_, ok = servicePolicy[src]
	return ok
}

func makePolicyKey(protocol uint8, dstPort uint16) string {
	return strconv.FormatInt(int64(protocol), 10) + "-" + strconv.FormatInt(int64(dstPort), 10)
}

func getInfoFromURL(svcURL string) (policyKeys []string, domain string, err error) {
	u, err := url.Parse(svcURL)
	if err != nil {
		return nil, "", fmt.Errorf("invalid url: %w", err)
	}

	// Extract domain from URL.
	domain = u.Hostname()
	if _, err := netip.ParseAddr(domain); err == nil {
		domain = ""
	}

	// Derive protocols and port from scheme.
	var (
		protocols []uint8
		port      int = -1
	)
	switch u.Scheme {
	case "tcp":
		protocols = []uint8{6}
	case "http":
		protocols = []uint8{6, 17} // TCP + UDP
		port = 80
	case "https":
		protocols = []uint8{6, 17} // TCP + UDP
		port = 443
	case "udp":
		protocols = []uint8{6}
	case "icmp6", "ping6":
		protocols = []uint8{58}
		port = 0
	default:
		return nil, "", fmt.Errorf("unknown or unsupported protocol/scheme: %s", u.Scheme)
	}

	// Parse port from URL.
	if port != 0 {
		uPort := u.Port()
		if uPort != "" {
			uPortNum, err := strconv.ParseUint(uPort, 10, 16)
			if err != nil {
				return nil, "", fmt.Errorf("invalid port: %w", err)
			}
			port = int(uPortNum)
		}
	}

	// Check if port is set.
	if port < 0 {
		return nil, "", errors.New("port required, but not specified")
	}

	policyKeys = make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		policyKeys = append(policyKeys, makePolicyKey(protocol, uint16(port)))
	}

	return policyKeys, domain, nil
}

// GetRouterInfo retruns a new router info derived from config.
func (c *Config) GetRouterInfo() *m.RouterInfo {
	// Create router info.
	info := &m.RouterInfo{
		Listeners: c.Router.Listen,
		IANA:      c.Router.IANA,
	}

	// Collect public services.
	srv := make([]m.RouterService, 0, len(c.Services))
	for _, service := range c.Services {
		if service.Public && service.Advertise {
			srv = append(srv, m.RouterService{
				Name:        service.Name,
				Description: service.Description,
				Domain:      service.Domain,
				URL:         service.URL,
			})
		}
	}

	// Set and return.
	info.PublicServices = srv
	return info
}

// DevMode returns if the development mode is enabled.
func (c *Config) DevMode() bool {
	return c.devMode.Load()
}

// SetDevMode sets the development mode.
func (c *Config) SetDevMode(mode bool) {
	c.devMode.Store(mode)
}

// Started returns the time when the router was started.
// Measured by when the config was created.
func (c *Config) Started() time.Time {
	return c.started
}

// Uptime returns the time since the router was started.
// Measured by when the config was created.
func (c *Config) Uptime() time.Duration {
	return time.Since(c.started)
}
