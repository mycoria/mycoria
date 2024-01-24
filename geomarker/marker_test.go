package geomarker

import (
	"crypto/rand"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mycoria/mycoria/m"
)

var prefixTestData = map[string]netip.Prefix{
	"AT": m.MustPrefix([]byte{0xfd, 0x1f, 0x00}, 18),
	"NZ": m.MustPrefix([]byte{0xfd, 0x66}, 16),
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
		if m.GetAddressType(ip) != m.TypeGeoMarked {
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
		ip := makeRandomAddress(m.RoutingAddressPrefix)
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

func makeRandomAddress(prefix netip.Prefix) netip.Addr {
	// Get random bytes.
	var buf [16]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		panic(err)
	}

	// Copy prefix to buf.
	prefixBuf := prefix.Addr().AsSlice()
	// Copy full bytes.
	var index int
	for ; index < prefix.Bits()/8; index++ {
		buf[index] = prefixBuf[index]
	}
	// Copy last partial byte.
	remainingBits := prefix.Bits() % 8
	if remainingBits > 0 {
		buf[index] = prefixBuf[index] | (buf[index] >> byte(remainingBits))
	}

	// Create IP and check it.
	ip := netip.AddrFrom16(buf)
	if !prefix.Contains(ip) {
		panic("random ip not in prefix")
	}

	return ip
}
