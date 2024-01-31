package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/geomarker"
	"github.com/mycoria/mycoria/m"
)

func init() {
	configCmd.AddCommand(generateCmd)
}

var generateCmd = &cobra.Command{
	Use:  "generate",
	Args: cobra.ExactArgs(1),
	RunE: generate,
}

func generate(cmd *cobra.Command, args []string) error {
	// Get country prefix.
	prefix, err := geomarker.GetCountryPrefix(args[0])
	if err != nil {
		if args[0] == "US" {
			return fmt.Errorf("invalid country code: in case of the US, please specify the state as US-XX")
		}
		return fmt.Errorf("invalid country code: %w", err)
	}

	// Generate address.
	addr, _, err := m.GenerateRoutableAddress(cmd.Context(), []netip.Prefix{prefix})
	if err != nil {
		return fmt.Errorf("failed to generate address: %w", err)
	}

	// Output default config.
	c := makeDefaultConfig(addr)
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	fmt.Println(string(data)) // CLI output.
	return nil
}

func makeDefaultConfig(id *m.Address) config.Store {
	// Find state path.
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = os.TempDir()
	}
	_ = os.Mkdir(filepath.Join(homeDir, ".mycoria"), 0o0750)
	statePath := filepath.Join(homeDir, ".mycoria", "state.json")

	// Get public IPs.
	var iana []string
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			netAddr, ok := addr.(*net.IPNet)
			if ok && netAddr.IP.IsGlobalUnicast() {
				iana = append(iana, netAddr.IP.String())
			}
		}
	}

	return config.Store{
		Router: config.Router{
			Address:     id.Store(),
			Listen:      []string{"tcp:47369"},
			IANA:        iana,
			AutoConnect: true,
			Bootstrap:   []string{"tcp://bootstrap.mycoria.org:47369"},
		},
		System: config.System{
			StatePath: statePath,
		},
		ServiceConfigs: []config.ServiceConfig{{
			Name:   "ping",
			URL:    "icmp6:",
			Public: true,
		}},
		ResolveConfig: map[string]string{
			"status.myco": "fd00::b909",
		},
	}
}
