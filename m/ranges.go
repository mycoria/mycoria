package m

import (
	"net/netip"
	"slices"
	"time"
)

// Base Masks.
const (
	// First Byte in IP.

	// BaseNet is the required prefix base for all addresses.
	// The used address space is fd00/8.
	// It is for unique local addresses that are self-assigned.
	BaseNet = 0xfd

	// Second Byte in IP.

	TypeMask      = 0b1000_0000 // 1 Bit
	ContinentMask = 0b0111_0000 // 3 Bits
	RegionMask    = 0b0000_1111 // 4 Bits

	// Third Byte in IP.

	// CountryBaseMask is the maximum mask used for country IDs.
	CountryBaseMask = 0b1111_0000 // 4 Bits (up to)

	// Further Prefix Bit Sizes.
	ContinentPrefixBits = 12
	RegionPrefixBits    = 16
)

// BaseNetPrefix is the base prefix for all addresses.
var BaseNetPrefix = MustPrefix([]byte{BaseNet}, 8)

// Address Type Markers (1 Bit).
const (
	TypeRoutingAddress = 0b0000_0000
	TypePrivacyAddress = 0b1000_0000
)

// Address Type Prefixes (1 Bit).
var (
	RoutingAddressPrefix = MustPrefix([]byte{BaseNet, TypeRoutingAddress}, 9)
	PrivacyAddressPrefix = MustPrefix([]byte{BaseNet, TypePrivacyAddress}, 9)
)

// Continent Markers (3 Bits).
const (
	// Eurafria.
	ContinentSpecial = 0b000_0000
	ContinentEurope  = 0b001_0000 // EU
	// --.
	ContinentAfrica   = 0b010_0000 // AF
	ContinentWestAsia = 0b011_0000 // WA

	// Pacific.
	ContinentNorthAmerica = 0b100_0000 // NA
	ContinentSouthAmerica = 0b101_0000 // SA
	// --.
	ContinentOceania  = 0b110_0000 // OC
	ContinentEastAsia = 0b111_0000 // EA
)

// Special "Region" Markers (4 Bits).
const (
	// RoamingMarker may be used if the location is unknown or is expected to change.
	// Bad routing performance is expected.
	RoamingMarker = 0b0000_0000

	// OrganizationMarker designates an organizational network.
	OrganizationMarker = 0b0000_0001
	// OrganizationBits is the org ID length in bits that addresses of the same organisation should share.
	// A full Organization Prefix would then be /32.
	OrganizationBits = 16

	// AnycastMarker designates an anycast network.
	AnycastMarker = 0b0000_1110
	// AnycastBits is the anycast network ID length in bits that addresses of the same anycast network should share.
	// A full Anycast Prefix would then be /32.
	AnycastBits = 16

	// ExperimentsMarker is a address marker for testing.
	// May not be handled well by production routers.
	ExperimentsMarker = 0b0000_1111
)

// Special "Region" Prefixes.
var (
	SpecialPrefix      = MustPrefix([]byte{BaseNet, TypeRoutingAddress | ContinentSpecial}, 12)
	RoamingPrefix      = MustPrefix([]byte{BaseNet, TypeRoutingAddress | ContinentSpecial | RoamingMarker}, 16)
	OrganizationPrefix = MustPrefix([]byte{BaseNet, TypeRoutingAddress | ContinentSpecial | OrganizationMarker}, 16)
	AnycastPrefix      = MustPrefix([]byte{BaseNet, TypeRoutingAddress | ContinentSpecial | AnycastMarker}, 16)
	ExperimentsPrefix  = MustPrefix([]byte{BaseNet, TypeRoutingAddress | ContinentSpecial | ExperimentsMarker}, 16)
	InternalPrefix     = MustPrefix([]byte{BaseNet, TypeRoutingAddress}, 112)
)

// GetRoutablePrefixesFor returns the routable prefix for the given own IP as
// well as the own prefix.
func GetRoutablePrefixesFor(myIP netip.Addr, myPrefix netip.Prefix) []RoutablePrefix {
	prefixes := []RoutablePrefix{
		{ // Continent Prefixes.
			BasePrefix:       RoutingAddressPrefix,
			RoutingBits:      ContinentPrefixBits,
			EntryTTL:         3 * time.Hour,
			EntriesPerPrefix: 32, // 16 * 2³ = 256 total max entries
		},
		{ // Special Region Prefixes.
			BasePrefix:       SpecialPrefix,
			RoutingBits:      16,
			EntryTTL:         3 * time.Hour,
			EntriesPerPrefix: 32, // 16 * 2⁴ = 512 total max entries
		},
	}

	// Save region prefixes for own continent, if geo marked.
	if GetAddressType(myIP) == TypeGeoMarked {
		myContinentPrefix, err := myIP.Prefix(ContinentPrefixBits)
		if err == nil {
			prefixes = append(prefixes, RoutablePrefix{
				BasePrefix:       myContinentPrefix,
				RoutingBits:      RegionPrefixBits,
				EntryTTL:         3 * time.Hour,
				EntriesPerPrefix: 64, // 64 * 2⁴ = 1024 total max entries
			})
		}
	}

	// Save more extensive information for own prefix.
	if myPrefix.IsValid() {
		prefixes = append(prefixes, RoutablePrefix{
			BasePrefix:       myPrefix,
			RoutingBits:      myPrefix.Bits(),
			EntryTTL:         24 * time.Hour,
			EntriesPerPrefix: 1024,
		})
	}

	// Reverse for correct lookup priority.
	slices.Reverse[[]RoutablePrefix, RoutablePrefix](prefixes)
	return prefixes
}
