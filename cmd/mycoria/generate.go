package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
)

func init() {
	configCmd.AddCommand(generateCmd)
}

var generateCmd = &cobra.Command{
	Use:  "generate [2-letter country code; US needs state: US-DC; omit to ask reallyfreegeoip.org]",
	Long: "Generate a new identity and configuration. If your (2-letter) country code cannot be automatically detected using reallyfreegeoip.org, you will need to provide it yourself as the first argument. For the US, you also need to provide your state like US-DC.",
	RunE: generate,
}

func generate(cmd *cobra.Command, args []string) error {
	var (
		geoMark   string
		usedGeoIP bool
	)

	if len(args) >= 1 {
		geoMark = args[0]
	}
	if geoMark == "" {
		geoIPMark, err := getGeoMarkFromGeoIP()
		if err != nil {
			return fmt.Errorf("failed to auto-detect country code: %w", err)
		}
		geoMark = geoIPMark
		usedGeoIP = true

		// Log result.
		fmt.Fprintf(os.Stderr, "Got country code from geoip: %s\n\n", geoMark)
	}

	// Get country prefix.
	prefix, err := m.GetCountryPrefix(geoMark)
	if err != nil {
		if usedGeoIP {
			return fmt.Errorf("country code from geoip is invalid (%q), please set as argument", geoMark)
		}
		if geoMark == "US" {
			return errors.New("invalid country code: in case of the US, please specify the state like US-DC")
		}
		return fmt.Errorf("invalid country code %q: %w", geoMark, err)
	}

	// Generate address.
	addr, _, err := m.GenerateRoutableAddress(cmd.Context(), []netip.Prefix{prefix}, m.CommonConflictingPrefixes)
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
			if ok &&
				netAddr.IP.IsGlobalUnicast() &&
				!netAddr.IP.IsPrivate() &&
				!netAddr.IP.IsLinkLocalUnicast() {
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
	}
}

type reallyFreeGeoIPResponse struct {
	CountryCode string `json:"country_code"`
	RegionCode  string `json:"region_code"`
}

var usRegionCodeRegex = regexp.MustCompile("^[A-Z]{2}$")

func getGeoMarkFromGeoIP() (string, error) {
	// Get geoip data.
	resp, err := http.Get("https://reallyfreegeoip.org/json/")
	if err != nil {
		return "", fmt.Errorf("fetch geoip data: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Read body.
	bodyData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read geoip response data: %w", err)
	}

	// Parse response.
	geoipResponse := &reallyFreeGeoIPResponse{}
	err = json.Unmarshal(bodyData, geoipResponse)
	if err != nil {
		return "", fmt.Errorf("parse geoip response: %w", err)
	}

	// Return geo marking code.
	if geoipResponse.CountryCode == "US" {
		if geoipResponse.RegionCode == "" || !usRegionCodeRegex.MatchString(geoipResponse.RegionCode) {
			return "", errors.New("geoip data does not specify US state")
		}
		return geoipResponse.CountryCode + "-" + geoipResponse.RegionCode, nil
	}
	return geoipResponse.CountryCode, nil
}
