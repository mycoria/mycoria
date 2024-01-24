package m

import "net/netip"

// AddressType represents an address type.
type AddressType uint8

// Address Types.
const (
	TypeInvalid AddressType = iota
	TypeReserved
	TypePrivacy
	TypeGeoMarked
	TypeRoaming
	TypeOrganization
	TypeAnycast
	TypeExperiment
	TypeInternal
)

// GetAddressType returns the address type of the IP.
func GetAddressType(ip netip.Addr) AddressType {
	switch {
	case !BaseNetPrefix.Contains(ip):
		return TypeInvalid
	case PrivacyAddressPrefix.Contains(ip):
		return TypePrivacy
	case !SpecialPrefix.Contains(ip):
		return TypeGeoMarked
	case InternalPrefix.Contains(ip):
		return TypeInternal
	case RoamingPrefix.Contains(ip):
		return TypeRoaming
	case OrganizationPrefix.Contains(ip):
		return TypeOrganization
	case AnycastPrefix.Contains(ip):
		return TypeAnycast
	case ExperimentsPrefix.Contains(ip):
		return TypeExperiment
	default:
		return TypeReserved
	}
}

// RoutingPrefixLength returns the base routing prefix length of the address type.
func (at AddressType) RoutingPrefixLength() int {
	switch at {
	case TypeInvalid:
		return 0 // No Routing.
	case TypeReserved:
		return 16 // Safe default for future compatibility.
	case TypePrivacy:
		return 0 // No Routing.
	case TypeGeoMarked:
		return 12 // At Minimum.
	case TypeRoaming:
		return 16
	case TypeOrganization:
		return 32
	case TypeAnycast:
		return 32
	case TypeExperiment:
		return 16
	case TypeInternal:
		return 0 // No Routing.
	default:
		return 0 // No Routing.
	}
}

func (at AddressType) String() string {
	switch at {
	case TypeInvalid:
		return "Invalid"
	case TypeReserved:
		return "Reserved"
	case TypePrivacy:
		return "Privacy"
	case TypeGeoMarked:
		return "GeoMarked"
	case TypeRoaming:
		return "Roaming"
	case TypeOrganization:
		return "Organization"
	case TypeAnycast:
		return "Anycast"
	case TypeExperiment:
		return "Experiment"
	case TypeInternal:
		return "Internal"
	default:
		return "Unknown"
	}
}
