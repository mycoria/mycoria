package tun

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/mycoria/mycoria/config"
)

// MycoriaInterfaceGUID is the interface GUID.
var MycoriaInterfaceGUID = windows.GUID{
	Data1: 0xbddbdc60,
	Data2: 0x55fd,
	Data3: 0xb909,
	Data4: [8]byte{0x47, 0x62, 0x9b, 0xc7, 0x0c, 0x07, 0x06, 0xaa},
}

func init() {
	tun.WintunTunnelType = "Mycoria"
	tun.WintunStaticRequestedGUID = &MycoriaInterfaceGUID
}

// PrepTUN prepares the creation of the TUN device.
func (d *Device) PrepTUN() {
	tun.WintunStaticRequestedGUID = &MycoriaInterfaceGUID
}

// LUID returns the tun interface LUID.
func (d *Device) LUID() (winipcfg.LUID, error) {
	return winipcfg.LUIDFromGUID(&MycoriaInterfaceGUID)
}

// InitInterface initializes the interface.
func (d *Device) InitInterface(prefix netip.Prefix) error {
	luid, err := d.LUID()
	if err != nil {
		return err
	}

	// Set primary address.
	err = luid.AddIPAddress(prefix)
	if err != nil {
		return fmt.Errorf("set primary address: %w", err)
	}

	// Set interface DNS.
	err = luid.SetDNS(
		windows.AF_INET6,
		[]netip.Addr{config.DefaultAPIAddress},
		[]string{config.DefaultTLD},
	)
	if err != nil {
		return fmt.Errorf("set interface DNS: %w", err)
	}

	return nil
}

// StartInterface starts the interface and brings it online.
func (d *Device) StartInterface() error {
	return nil
}

// AddAddress adds an address to the interface.
func (d *Device) AddAddress(prefix netip.Prefix) error {
	luid, err := d.LUID()
	if err != nil {
		return err
	}

	return luid.AddIPAddress(prefix)
}

// RemoveAddress removes an address from the interface.
func (d *Device) RemoveAddress(prefix netip.Prefix) error {
	luid, err := d.LUID()
	if err != nil {
		return err
	}

	return luid.DeleteIPAddress(prefix)
}

// AddRoute adds a route to the interface.
func (d *Device) AddRoute(prefix netip.Prefix, highPrio bool) error {
	luid, err := d.LUID()
	if err != nil {
		return err
	}

	var metric uint32 = 0xFFFF_FFFF
	if highPrio {
		metric = 1
	}

	return luid.AddRoute(prefix, config.DefaultAPIAddress, metric)
}

// RemoveRoute removes a route to the interface.
func (d *Device) RemoveRoute(prefix netip.Prefix) error {
	luid, err := d.LUID()
	if err != nil {
		return err
	}

	return luid.DeleteRoute(prefix, config.DefaultAPIAddress)
}
