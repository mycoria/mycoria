package tun

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

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

// InitInterface initializes the interface.
func (d *Device) InitInterface(prefix netip.Prefix) error {
	nl, err := d.netLink()
	if err != nil {
		return err
	}

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

	// Chromium Workaround.
	if !d.instance.Config().System.DisableChromiumWorkaround {
		// Workaround to get Chromium based browsers to resolve IPv6/AAAA even when
		// no global IPv6 connectivity is available.
		// Chromium Docs:
		// https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/dns/README.md#IPv6-and-connectivity
		// TL;DR: `ip -6 route get 2001:4860:4860::8888` must succeed.

		// Parse IP address (+net) that Chromium checks.
		workaroundIP, workaroundNet, err := net.ParseCIDR("2001:4860:4860::8888/128")
		if err != nil {
			return fmt.Errorf("parse chromium workaround network: %w", err)
		}
		// Check if the OS has a route to the IP.
		_, err = netlink.RouteGet(workaroundIP)
		if err != nil && strings.Contains(err.Error(), "unreachable") {
			// If not route exists, fake it.
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: d.linkIndex,
				Dst:       workaroundNet,
				Priority:  0x7FFF_FFFF, // Set to maximum so that any other route will be used instead.
				Family:    netlink.FAMILY_V6,
			})
			if err != nil {
				return fmt.Errorf("set chromium workaround route: %w", err)
			}
		}
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
