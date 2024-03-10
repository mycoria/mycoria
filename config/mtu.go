package config

import "net"

const (
	// DefaultTunMTU is used for tun devices.
	DefaultTunMTU = 9000

	// DefaultFrameSize is the default expected frame size based on the default tun mtu.
	DefaultFrameSize = DefaultTunMTU - IPv6HeaderMTUSize - TCPHeaderMTUSize - LinkFrameSize - FrameSizeEncrypted
)

// MTU Calculation Configuration.
const (
	BaseMTU           = 1480 // 1500 with 20 bytes a little extra space for special cases.
	IPv4HeaderMTUSize = 20   // Without options, as not common.
	IPv6HeaderMTUSize = 40   // Without options, as not common.
	TCPHeaderMTUSize  = 20   // Base size with no options.
	UDPHeaderMTUSize  = 8    // Has no options.

	FrameSizeEncrypted = 80 // With 12 byte switch block. TODO: Source better.
	LinkFrameSize      = 32 // TODO: Source better.
)

// CalculateExpectedFrameSize calculates the overlay MTU based on the given address.
func CalculateExpectedFrameSize(addr net.Addr) int {
	tunMTU := DefaultTunMTU

	// Get remote IP from remote address.
	// Subtract transport header size.
	var remoteIP net.IP
	switch v := addr.(type) {
	case *net.TCPAddr:
		remoteIP = v.IP
		tunMTU -= TCPHeaderMTUSize

	case *net.UDPAddr:
		remoteIP = v.IP
		tunMTU -= UDPHeaderMTUSize

	case *net.IPAddr:
		remoteIP = v.IP
		// Unknown other protocol?
		// Default to subtracting the TCP header.
		tunMTU -= TCPHeaderMTUSize

	default:
		// Unknown other protocol?
		// Default to subtracting the TCP header.
		tunMTU -= TCPHeaderMTUSize
	}

	// Subtract IP Header, if IP is available.
	if ip4 := remoteIP.To4(); ip4 != nil {
		tunMTU -= IPv4HeaderMTUSize
	} else {
		tunMTU -= IPv6HeaderMTUSize
	}

	return tunMTU
}

// TunMTU returns the MTU to be used for tun devices.
func (c *Config) TunMTU() int {
	return int(c.tunMTU.Load())
}

// SetTunMTU sets the MTU to be used for tun devices.
func (c *Config) SetTunMTU(mtu int) {
	c.tunMTU.Store(int32(mtu))
}

// OverlayFrameSize returns the expected maximum frame size for overlay network links.
func (c *Config) OverlayFrameSize() int {
	return int(c.frameSize.Load())
}

// SetOverlayFrameSize sets the expected maximum frame size for overlay network links.
func (c *Config) SetOverlayFrameSize(mtu int) {
	c.frameSize.Store(int32(mtu))
}
