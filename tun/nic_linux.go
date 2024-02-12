package tun

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"go4.org/netipx"
)

func (d *Device) netLink() (netlink.Link, error) {
	// Get link by index and check if the name matches.
	nl, err := netlink.LinkByIndex(d.linkIndex)
	if err == nil && nl.Attrs().Name == d.linkName {
		return nl, nil
	}

	// Otherwise, get link by name and save the index.
	nl, err = netlink.LinkByName(d.linkName)
	if err != nil {
		return nil, fmt.Errorf("get link %q by name: %w", d.linkName, err)
	}
	d.linkIndex = nl.Attrs().Index

	return nl, nil
}

// PrepTUN prepares the creation of the TUN device.
func (d *Device) PrepTUN() {}

// InitInterface initializes the interface.
func (d *Device) InitInterface(prefix netip.Prefix) error {
	nl, err := d.netLink()
	if err != nil {
		return err
	}

	// Set primary address.
	err = netlink.AddrReplace(nl, &netlink.Addr{
		IPNet: netipx.PrefixIPNet(prefix),
	})
	if err != nil {
		return fmt.Errorf("set primary address: %w", err)
	}

	// Set interface flags.
	err = netlink.LinkSetARPOff(nl)
	if err != nil {
		return fmt.Errorf("disable ARP: %w", err)
	}
	err = netlink.LinkSetAllmulticastOff(nl)
	if err != nil {
		return fmt.Errorf("disable multicast: %w", err)
	}

	return nil
}

// StartInterface starts the interface and brings it online.
func (d *Device) StartInterface() error {
	nl, err := d.netLink()
	if err != nil {
		return err
	}

	// Take the interface online.
	err = netlink.LinkSetUp(nl)
	if err != nil {
		return fmt.Errorf("set link to up: %w", err)
	}

	return nil
}

// AddAddress adds an address to the interface.
func (d *Device) AddAddress(prefix netip.Prefix) error {
	nl, err := d.netLink()
	if err != nil {
		return err
	}

	return netlink.AddrReplace(nl, &netlink.Addr{
		IPNet: netipx.PrefixIPNet(prefix),
	})
}

// RemoveAddress removes an address from the interface.
func (d *Device) RemoveAddress(prefix netip.Prefix) error {
	nl, err := d.netLink()
	if err != nil {
		return err
	}

	return netlink.AddrDel(nl, &netlink.Addr{
		IPNet: netipx.PrefixIPNet(prefix),
	})
}

// AddRoute adds a route to the interface.
func (d *Device) AddRoute(prefix netip.Prefix, highPrio bool) error {
	metric := 0x7FFF_FFFF
	if highPrio {
		metric = 1
	}

	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: d.linkIndex,
		Dst:       netipx.PrefixIPNet(prefix),
		Priority:  metric,
		Family:    netlink.FAMILY_V6,
	})
}

// RemoveRoute removes a route to the interface.
func (d *Device) RemoveRoute(prefix netip.Prefix) error {
	return netlink.RouteDel(&netlink.Route{
		LinkIndex: d.linkIndex,
		Dst:       netipx.PrefixIPNet(prefix),
		Priority:  0,
		Family:    netlink.FAMILY_V6,
	})
}
