package geomarker

import (
	"net/netip"
	"slices"
)

// CountryMarkerLookup holds country geo marker information.
type CountryMarkerLookup struct {
	BaseIP    netip.Addr
	Prefix    netip.Prefix
	Continent string
	Country   string
}

type countryMarkerLookupTable []CountryMarkerLookup

var countryMarkerLookup countryMarkerLookupTable

func init() {
	countryMarkerLookup = make([]CountryMarkerLookup, 0, len(countryGeoMarkers))
	for cc, cgm := range countryGeoMarkers {
		baseIP := cgm.BaseIP()
		prefix, err := baseIP.Prefix(int(16 + cgm.CountryMarkerBits))
		if err != nil {
			panic(err)
		}
		countryMarkerLookup = append(countryMarkerLookup, CountryMarkerLookup{
			BaseIP:    baseIP,
			Prefix:    prefix,
			Continent: cgm.ContinentCode,
			Country:   cc,
		})
	}
	slices.SortFunc[countryMarkerLookupTable, CountryMarkerLookup](
		countryMarkerLookup,
		func(a CountryMarkerLookup, b CountryMarkerLookup) int {
			return a.BaseIP.Compare(b.BaseIP)
		},
	)
}

// LookupCountryMarker return the country geo marker information of the given IP.
func LookupCountryMarker(ip netip.Addr) (*CountryMarkerLookup, error) {
	index, ok := slices.BinarySearchFunc[countryMarkerLookupTable, CountryMarkerLookup, netip.Addr](
		countryMarkerLookup,
		ip,
		func(a CountryMarkerLookup, b netip.Addr) int {
			return a.BaseIP.Compare(b)
		},
	)

	// Get closest matching entry.
	var cml CountryMarkerLookup
	switch {
	case ok:
		cml = countryMarkerLookup[index]
	case index > 0:
		cml = countryMarkerLookup[index-1]
	default:
		return nil, ErrNotFound
	}

	// Check if the markers match.
	if !cml.Prefix.Contains(ip) {
		return nil, ErrNotFound
	}

	return &cml, nil
}
