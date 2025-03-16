package m

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

var prefixTestData = map[string]netip.Prefix{
	"AT": MustPrefix([]byte{0xfd, 0x1f, 0x00}, 18),
	"NZ": MustPrefix([]byte{0xfd, 0x66}, 16),
}

func TestGeoMarkerCreation(t *testing.T) {
	t.Parallel()

	for cc, testPrefix := range prefixTestData {
		// Test 1: prefix generation
		prefix, err := GetCountryPrefix(cc)
		if err != nil {
			assert.NoError(t, err, "must not fail")
			continue
		}
		assert.Equal(t, testPrefix, prefix, "prefixes must match")

		// Test 2: random address generation
		randIP := makeRandomAddress(prefix)

		// Test 3: check the prefix index in lookup table
		var prefixIndex int
		for i, cml := range countryMarkerLookup {
			if cml.Prefix == prefix {
				prefixIndex = i
				break
			}
		}
		index, _ := slices.BinarySearchFunc[countryMarkerLookupTable, CountryMarkerLookup, netip.Prefix](
			countryMarkerLookup,
			prefix,
			func(a CountryMarkerLookup, b netip.Prefix) int {
				return a.Prefix.Addr().Compare(b.Addr())
			},
		)
		assert.Equal(t, prefixIndex, index, "prefix should be at index")

		// Test 4: check the random IP index in lookup table
		index, _ = slices.BinarySearchFunc[countryMarkerLookupTable, CountryMarkerLookup, netip.Addr](
			countryMarkerLookup,
			randIP,
			func(a CountryMarkerLookup, b netip.Addr) int {
				return a.BaseIP.Compare(b)
			},
		)
		index-- // Reduce index by one, as the random IP would be inserted after the prefix.
		assert.Equal(t, prefixIndex, index, "prefix should be at index")

		// Test 5: lookup country
		cml, err := LookupCountryMarker(randIP)
		if err != nil {
			assert.NoError(t, err, "country marker lookup must succeed")
			continue
		}
		assert.Equal(t, cc, cml.Country, "country code must match test case")
	}
}

func TestGeoMarkerLookup(t *testing.T) {
	t.Parallel()

	for cc := range countryGeoMarkers {
		// Step 1: get country marker info.
		prefix, err := GetCountryPrefix(cc)
		if err != nil {
			t.Fatal(err)
		}

		// Step 2: generate random address with marker.
		ip := makeRandomAddress(prefix)

		// Step 3: check random ip
		if GetAddressType(ip) != TypeGeoMarked {
			t.Errorf("ip %s (%s) should be of type geomarked", ip, cc)
		}

		// Step 4: check if we can get the country back.
		cml, err := LookupCountryMarker(ip)
		if err != nil {
			t.Errorf("failed to lookup country marker for ip %s (%s): %s", ip, cc, err)
			continue
		}
		if cml.Country != cc {
			t.Errorf("country mismatch for %s: expected %s, got %s", ip, cc, cml.Country)
		}
	}
}

func TestRandomGeoMarkerLookups(t *testing.T) {
	t.Parallel()

	var (
		iterations = 1000
		required   = iterations / 2
		success    int
	)
	for i := 0; i < iterations; i++ {
		ip := makeRandomAddress(RoutingAddressPrefix)
		cml, err := LookupCountryMarker(ip)
		if err != nil {
			// Continue with next if not found.
			if errors.Is(err, ErrNotFound) {
				continue
			}
			// Otherwise, fail hard.
			t.Fatal(err)
		}
		if cml.Prefix.Contains(ip) {
			success++
		} else {
			t.Errorf("CML prefix %s does not contain IP %s", cml.Prefix, ip)
		}
	}
	if success < required {
		t.Errorf("only %d out of %d iterations were successful", success, iterations)
	} else {
		t.Logf("%d out of %d iterations were successful", success, iterations)
	}
}

func TestCommonConflictingPrefixes(t *testing.T) {
	t.Parallel()

	for _, prefix := range CommonConflictingPrefixes {
		cml, err := LookupCountryMarker(prefix.Addr())
		if err != nil {
			// Continue with next if not found.
			if errors.Is(err, ErrNotFound) {
				t.Logf("prefix %s is not assigned a geo marker", prefix)
				continue
			}
			// Otherwise, fail hard.
			t.Fatal(err)
		}
		t.Logf(
			"prefix %s is part of %s, which is assigned to %s %s %s",
			prefix,
			cml.Prefix,
			cml.Continent,
			cml.Region,
			cml.Country,
		)
	}
}
