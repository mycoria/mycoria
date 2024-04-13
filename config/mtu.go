package config

// DefaultTunMTU is used for tun devices.
const DefaultTunMTU = 9000

// TunMTU returns the MTU to be used for tun devices.
func (c *Config) TunMTU() int {
	return int(c.tunMTU.Load())
}

// SetTunMTU sets the MTU to be used for tun devices.
func (c *Config) SetTunMTU(mtu int) {
	c.tunMTU.Store(int32(mtu))
}
