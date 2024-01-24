package m

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

// PeeringURL represents a peering point that others can connect to.
type PeeringURL struct {
	Protocol string
	Domain   string
	Port     uint16
	Path     string
	Option   string
}

// ParsePeeringURLs returns a list of parsed peering URLs and errors from parsing.
func ParsePeeringURLs(definitions []string) (urls []*PeeringURL, errs []error) {
	urls = make([]*PeeringURL, 0, len(definitions))
	for _, definition := range definitions {
		parsed, err := ParsePeeringURL(definition)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"unknown or invalid peering URL %q: %w", definition, err,
			))
		} else {
			urls = append(urls, parsed)
		}
	}

	SortPeeringURLs(urls)
	return urls, errs
}

// ParsePeeringURL parses a peering URL.
func ParsePeeringURL(definition string) (*PeeringURL, error) {
	u, err := url.Parse(definition)
	if err != nil {
		return nil, err
	}

	// Check for invalid parts.
	if u.User != nil {
		return nil, errors.New("user/pass is not allowed")
	}

	// Create Peering URL.
	p := &PeeringURL{
		Protocol: u.Scheme,
		Domain:   u.Hostname(),
		Path:     u.RequestURI(),
		Option:   u.Fragment,
	}

	// Check if protocol is set.
	if p.Protocol == "" {
		return nil, errors.New("missing scheme/protocol")
	}

	// Parse port.
	portData := u.Port()
	if portData == "" && u.Opaque != "" {
		// For URLs without "//", the port is part of u.Opaque.
		// The path might also be part of u.Opaque
		splitted := strings.SplitN(u.Opaque, "/", 2)
		portData = splitted[0]
		// Save path, if it exists.
		if len(splitted) == 2 {
			p.Path = splitted[1]
		} else {
			p.Path = ""
		}
	}
	if portData != "" {
		port, err := strconv.ParseUint(portData, 10, 16)
		if err != nil {
			return nil, errors.New("invalid port")
		}
		p.Port = uint16(port)
	}

	// Check if port is set.
	if p.Port == 0 {
		// Fallback to default ports.
		switch p.Protocol {
		case "http", "ws":
			p.Port = 80
		case "https", "wss":
			p.Port = 443
		case "tcp", "kcp", "udp":
			p.Port = 47369 // config.DefaultPortNumber
		}
		return nil, errors.New("missing port")
	}

	// Remove root paths.
	if p.Path == "/" {
		p.Path = ""
	}

	return p, nil
}

// String returns the definition form of the peering URL.
func (p *PeeringURL) String() string {
	switch {
	case p.Option != "":
		return fmt.Sprintf("%s://%s:%d%s#%s", p.Protocol, p.Domain, p.Port, p.Path, p.Option)
	case p.Domain != "":
		return fmt.Sprintf("%s://%s:%d%s", p.Protocol, p.Domain, p.Port, p.Path)
	default:
		return fmt.Sprintf("%s:%d%s", p.Protocol, p.Port, p.Path)
	}
}

// FormatWith formats the peering URL with the given host.
func (p *PeeringURL) FormatWith(host string) string {
	if host == "" {
		host = p.Domain
	}

	return fmt.Sprintf(
		"%s://%s%s",
		p.Protocol,
		net.JoinHostPort(host, strconv.FormatUint(uint64(p.Port), 10)),
		p.Path,
	)
}

// SortPeeringURLs sorts the peering URls to emphasize certain protocols
// and get a stable representation.
func SortPeeringURLs(urls []*PeeringURL) {
	slices.SortStableFunc[[]*PeeringURL, *PeeringURL](urls, func(a, b *PeeringURL) int {
		aOrder := a.protocolOrder()
		bOrder := b.protocolOrder()

		switch {
		case aOrder != bOrder:
			return aOrder - bOrder
		case a.Port != b.Port:
			return int(a.Port) - int(b.Port)
		case a.Domain != b.Domain:
			return strings.Compare(a.Domain, b.Domain)
		case a.Path != b.Path:
			return strings.Compare(a.Path, b.Path)
		case a.Option != b.Option:
			return strings.Compare(a.Option, b.Option)
		default:
			return 0
		}
	})
}

func (p *PeeringURL) protocolOrder() int {
	switch p.Protocol {
	case "tcp":
		return 1
	case "http":
		return 2
	default:
		return 0xFFFF
	}
}
