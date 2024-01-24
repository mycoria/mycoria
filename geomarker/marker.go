package geomarker

import (
	"errors"
	"net/netip"

	"github.com/mycoria/mycoria/m"
)

// ErrNotFound is return when a country is not found.
var ErrNotFound = errors.New("not found")

// Continent Markers.
var continentCodeToMarker = map[string]byte{
	"EU": m.ContinentEurope,
	"AF": m.ContinentAfrica,
	"WA": m.ContinentWestAsia,
	"NA": m.ContinentNorthAmerica,
	"SA": m.ContinentSouthAmerica,
	"OC": m.ContinentOceania,
	"EA": m.ContinentEastAsia,
}

// Region Markers.
var (
	// Region Geo Codes:
	//          N
	//      NWN   NEN
	//   NWW    CN   NEE
	// W    CW     CE    E
	//   SWW    CS   SEE
	//      SWS   SES
	//          S

	// Region Geo Markers:
	//          0
	//       1     2
	//    5     3     10
	// 4     7     11     8
	//    6     15     9
	//       14    13
	//          12

	regionCodeToMarker = map[string]byte{
		"N":   0,
		"NWN": 1,
		"NEN": 2,
		"CN":  3,
		"W":   4,
		"NWW": 5,
		"SWW": 6,
		"CW":  7,
		"E":   8,
		"SEE": 9,
		"NEE": 10,
		"CE":  11,
		"S":   12,
		"SES": 13,
		"SWS": 14,
		"CS":  15,
	}
)

// Country Markers.

// GetCountryPrefix returns a prefix with a country geo marker for the given country code.
// The US country code requires the US state code to appended, splitted by a dash.
func GetCountryPrefix(countryCode string) (prefix netip.Prefix, err error) {
	cgm, ok := countryGeoMarkers[countryCode]
	if !ok {
		return netip.Prefix{}, ErrNotFound
	}

	return cgm.Prefix()
}

// CountryGeoMarking defines the geo marker for a country.
type CountryGeoMarking struct {
	ContinentCode string
	RegionCode    string

	CountryMarker     uint8
	CountryMarkerBits uint8
}

// Prefix returns the prefix of the country marker.
func (cgm CountryGeoMarking) Prefix() (netip.Prefix, error) {
	return cgm.BaseIP().Prefix(int(16 + cgm.CountryMarkerBits))
}

// BaseIP returns the base IP of the country marker.
func (cgm CountryGeoMarking) BaseIP() netip.Addr {
	// If there is no separate country marker, take the quick route.
	if cgm.CountryMarkerBits == 0 {
		return m.MakeBaseIP([]byte{
			m.BaseNet,
			m.TypeRoutingAddress |
				continentCodeToMarker[cgm.ContinentCode] |
				regionCodeToMarker[cgm.RegionCode],
		})
	}

	// Make prefix with additional country marker.
	return m.MakeBaseIP([]byte{
		m.BaseNet,
		m.TypeRoutingAddress |
			continentCodeToMarker[cgm.ContinentCode] |
			regionCodeToMarker[cgm.RegionCode],
		// Shift country bits into correct location.
		cgm.CountryMarker << (8 - cgm.CountryMarkerBits),
	})
}

// Tips for planning:
// - Try something like scribblemaps.com for quickly laying a grid over a continent.
// - Check out submarine maps to see where good connectivity is among islands.

var countryGeoMarkers = map[string]CountryGeoMarking{
	// Africa

	// North Block (N, NWN, NEN, CN)

	"LY": {"AF", "N", 0, 1}, // Libya
	"TN": {"AF", "N", 1, 1}, // Tunisia

	"DZ": {"AF", "NWN", 0, 1}, // Algeria
	"MA": {"AF", "NWN", 1, 1}, // Morocco

	"EG": {"AF", "NEN", 0, 0}, // Egypt

	"NE": {"AF", "CN", 0, 1}, // Niger
	"TD": {"AF", "CN", 1, 1}, // Chad

	// West Block (W, NWW, SWW, CW)

	"CV": {"AF", "W", 0, 2}, // Cabo Verde
	"GM": {"AF", "W", 1, 2}, // Gambia
	"GW": {"AF", "W", 2, 2}, // Guinea-Bissau
	"SN": {"AF", "W", 3, 2}, // Senegal

	"BF": {"AF", "NWW", 0, 2}, // Burkina Faso
	"EH": {"AF", "NWW", 1, 2}, // Western Sahara
	"ML": {"AF", "NWW", 2, 2}, // Mali
	"MR": {"AF", "NWW", 3, 2}, // Mauritania

	"CI": {"AF", "SWW", 0, 2}, // Côte d'Ivoire
	"GN": {"AF", "SWW", 1, 2}, // Guinea
	"LR": {"AF", "SWW", 2, 2}, // Liberia
	"SL": {"AF", "SWW", 3, 2}, // Sierra Leone

	"BJ": {"AF", "CW", 0, 2}, // Benin
	"GH": {"AF", "CW", 1, 2}, // Ghana
	"NG": {"AF", "CW", 2, 2}, // Nigeria
	"TG": {"AF", "CW", 3, 2}, // Togo

	// East Block (E, SEE, NEE, CE)

	"DJ": {"AF", "E", 0, 2}, // Djibouti
	"ER": {"AF", "E", 1, 2}, // Eritrea
	"ET": {"AF", "E", 2, 2}, // Ethiopia
	"SO": {"AF", "E", 3, 2}, // Somalia

	"BI": {"AF", "SEE", 0, 3}, // Burundi
	"KE": {"AF", "SEE", 1, 3}, // Kenya
	"RW": {"AF", "SEE", 2, 3}, // Rwanda
	"TZ": {"AF", "SEE", 3, 3}, // Tanzania
	"UG": {"AF", "SEE", 4, 3}, // Uganda

	"SD": {"AF", "NEE", 0, 1}, // Sudan
	"SS": {"AF", "NEE", 1, 1}, // South Sudan

	"CD": {"AF", "CE", 0, 3}, // DR Congo
	"CF": {"AF", "CE", 1, 3}, // Central African Republic
	"CG": {"AF", "CE", 2, 3}, // Congo
	"CM": {"AF", "CE", 3, 3}, // Cameroon
	"GA": {"AF", "CE", 4, 3}, // Gabon
	"GQ": {"AF", "CE", 5, 3}, // Equatorial Guinea
	"ST": {"AF", "CE", 6, 3}, // Sao Tome and Principe

	// South Block (S, SES, SWS, CS)

	"BW": {"AF", "S", 0, 2}, // Botswana
	"LS": {"AF", "S", 1, 2}, // Lesotho
	"SZ": {"AF", "S", 2, 2}, // Eswatini
	"ZA": {"AF", "S", 3, 2}, // South Africa

	"IO": {"AF", "SES", 0, 3}, // British Indian Ocean Territory
	"KM": {"AF", "SES", 1, 3}, // Comoros
	"MG": {"AF", "SES", 2, 3}, // Madagascar
	"MU": {"AF", "SES", 3, 3}, // Mauritius
	"RE": {"AF", "SES", 4, 3}, // Réunion
	"SC": {"AF", "SES", 5, 3}, // Seychelles
	"TF": {"AF", "SES", 6, 3}, // French Southern Territories
	"YT": {"AF", "SES", 7, 3}, // Mayotte

	"AO": {"AF", "SWS", 0, 2}, // Angola
	"NA": {"AF", "SWS", 1, 2}, // Namibia
	"SH": {"AF", "SWS", 2, 2}, // Saint Helena

	"MW": {"AF", "CS", 0, 3}, // Malawi
	"MZ": {"AF", "CS", 1, 3}, // Mozambique
	"ZM": {"AF", "CS", 2, 3}, // Zambia
	"ZW": {"AF", "CS", 3, 3}, // Zimbabwe

	////////////
	// East Asia

	// North Block (N, NWN, NEN, CN)

	"JP": {"EA", "N", 0, 1}, // Japan
	"KR": {"EA", "N", 1, 1}, // South Korea

	"CN": {"EA", "NWN", 0, 2}, // China
	"KP": {"EA", "NWN", 1, 2}, // North Korea (DPRK)
	"MN": {"EA", "NWN", 2, 2}, // Mongolia

	"TW": {"EA", "NEN", 0, 0}, // Taiwan

	"MO": {"EA", "CN", 0, 1}, // Macao
	"HK": {"EA", "CN", 1, 1}, // Hong Kong

	// West Block (W, NWW, SWW, CW)

	"LK": {"EA", "W", 0, 1}, // Sri Lanka
	"MV": {"EA", "W", 1, 1}, // Maldives

	"IN": {"EA", "NWW", 0, 0}, // India

	"BT": {"EA", "SWW", 0, 1}, // Bhutan
	"NP": {"EA", "SWW", 1, 1}, // Nepal

	"BD": {"EA", "CW", 0, 1}, // Bangladesh
	"MM": {"EA", "CW", 1, 1}, // Myanmar

	// South Block (S, SES, SWS, CS)

	"MY": {"EA", "S", 0, 1}, // Malaysia
	"SG": {"EA", "S", 1, 1}, // Singapore

	"BN": {"EA", "SES", 0, 0}, // Brunei Darussalam

	"KH": {"EA", "SWS", 0, 1}, // Cambodia
	"TH": {"EA", "SWS", 1, 1}, // Thailand

	"LA": {"EA", "CS", 0, 1}, // Lao
	"VN": {"EA", "CS", 1, 1}, // Viet Nam

	// East Block (E, SEE, NEE, CE)

	"TL": {"EA", "SEE", 0, 0}, // Timor-Leste
	"PH": {"EA", "NEE", 0, 0}, // Philippines
	"ID": {"EA", "CE", 0, 0},  // Indonesia
	// Info: One spot left.

	/////////
	// Europe

	// North Block (N, NWN, NEN, CN)

	"EE": {"EU", "N", 0, 1}, // Estonia
	"FI": {"EU", "N", 1, 1}, // Finland

	"DK": {"EU", "NWN", 0, 2}, // Denmark
	"NO": {"EU", "NWN", 1, 2}, // Norway
	"SE": {"EU", "NWN", 2, 2}, // Sweden
	"SJ": {"EU", "NWN", 3, 2}, // Svalbard and Jan Mayen

	"LT": {"EU", "NEN", 0, 1}, // Lithuania
	"LV": {"EU", "NEN", 1, 1}, // Latvia

	"BE": {"EU", "CN", 0, 2}, // Belgium
	"DE": {"EU", "CN", 1, 2}, // Germany
	"LU": {"EU", "CN", 2, 2}, // Luxembourg
	"NL": {"EU", "CN", 3, 2}, // Netherlands

	// West Block (W, NWW, SWW, CW)

	"IS": {"EU", "W", 0, 1}, // Iceland
	"FO": {"EU", "W", 1, 1}, // Faroe Islands

	"GB": {"EU", "NWW", 0, 3}, // United Kingdom
	"IE": {"EU", "NWW", 1, 3}, // Ireland
	"GG": {"EU", "NWW", 2, 3}, // Guernsey
	"IM": {"EU", "NWW", 3, 3}, // Isle of Man
	"JE": {"EU", "NWW", 4, 3}, // Jersey

	"AD": {"EU", "SWW", 0, 2}, // Andorra
	"ES": {"EU", "SWW", 1, 2}, // Spain
	"GI": {"EU", "SWW", 2, 2}, // Gibraltar
	"PT": {"EU", "SWW", 3, 2}, // Portugal

	"CH": {"EU", "CW", 0, 2}, // Switzerland
	"FR": {"EU", "CW", 1, 2}, // France
	"LI": {"EU", "CW", 2, 2}, // Liechtenstein
	// FYI: Spot left

	// East Block (E, SEE, NEE, CE)

	"BY": {"EU", "E", 0, 1}, // Belarus
	"RU": {"EU", "E", 1, 1}, // Russia // Assuming mostly Moscow Area

	"AL": {"EU", "SEE", 0, 2}, // Albania
	"BG": {"EU", "SEE", 1, 2}, // Bulgaria
	"GR": {"EU", "SEE", 2, 2}, // Greece
	"MK": {"EU", "SEE", 3, 2}, // North Macedonia

	"MD": {"EU", "NEE", 0, 2}, // Moldova
	"PL": {"EU", "NEE", 1, 2}, // Poland
	"RO": {"EU", "NEE", 2, 2}, // Romania
	"UA": {"EU", "NEE", 3, 2}, // Ukraine

	"CZ": {"EU", "CE", 0, 1}, // Czechia
	"SK": {"EU", "CE", 1, 1}, // Slovakia

	// South Block (S, SES, SWS, CS)

	"MT": {"EU", "S", 0, 0}, // Malta

	"BA": {"EU", "SES", 0, 2}, // Bosnia and Herzegovina
	"ME": {"EU", "SES", 1, 2}, // Montenegro
	"RS": {"EU", "SES", 2, 2}, // Serbia
	"XK": {"EU", "SES", 3, 2}, // Kosovo

	"IT": {"EU", "SWS", 0, 2}, // Italy
	"MC": {"EU", "SWS", 1, 2}, // Monaco
	"SM": {"EU", "SWS", 2, 2}, // San Marino
	"VA": {"EU", "SWS", 3, 2}, // Holy See

	"AT": {"EU", "CS", 0, 2}, // Austria
	"HR": {"EU", "CS", 1, 2}, // Croatia
	"HU": {"EU", "CS", 2, 2}, // Hungary
	"SI": {"EU", "CS", 3, 2}, // Slovenia

	////////////////
	// North America

	// North Block (N, NWN, NEN, CN)

	"CA": {"NA", "N", 0, 2}, // Canada
	"GL": {"NA", "N", 2, 2}, // Greenland
	"PM": {"NA", "N", 3, 2}, // Saint Pierre and Miquelon

	// US North East
	"US-CT": {"NA", "NEN", 0, 4},  // US - Connecticut
	"US-DE": {"NA", "NEN", 1, 4},  // US - Delaware
	"US-MA": {"NA", "NEN", 2, 4},  // US - Massachusetts
	"US-ME": {"NA", "NEN", 3, 4},  // US - Maine
	"US-NH": {"NA", "NEN", 4, 4},  // US - New Hampshire
	"US-NJ": {"NA", "NEN", 5, 4},  // US - New Jersey
	"US-NY": {"NA", "NEN", 6, 4},  // US - New York
	"US-OH": {"NA", "NEN", 7, 4},  // US - Ohio
	"US-PA": {"NA", "NEN", 8, 4},  // US - Pennsylvania
	"US-RI": {"NA", "NEN", 9, 4},  // US - Rhode Island
	"US-VT": {"NA", "NEN", 10, 4}, // US - Vermont
	"BM":    {"NA", "NEN", 15, 4}, // Bermuda

	// US South East
	"US-DC": {"NA", "CN", 0, 3}, // US - Washington DC
	"US-FL": {"NA", "CN", 1, 3}, // US - Florida
	"US-GA": {"NA", "CN", 2, 3}, // US - Georgia
	"US-MD": {"NA", "CN", 3, 3}, // US - Maryland
	"US-NC": {"NA", "CN", 4, 3}, // US - North Carolina
	"US-SC": {"NA", "CN", 5, 3}, // US - South Carolina
	"US-VA": {"NA", "CN", 6, 3}, // US - Virginia
	"US-WV": {"NA", "CN", 7, 3}, // US - West Virginia

	// US Central North
	"US-IA": {"NA", "NWN", 0, 4},  // US - Iowa
	"US-IL": {"NA", "NWN", 1, 4},  // US - Illinois
	"US-IN": {"NA", "NWN", 2, 4},  // US - Indiana
	"US-KS": {"NA", "NWN", 3, 4},  // US - Kansas
	"US-KY": {"NA", "NWN", 4, 4},  // US - Kentucky
	"US-MI": {"NA", "NWN", 5, 4},  // US - Michigan
	"US-MN": {"NA", "NWN", 6, 4},  // US - Minnesota
	"US-MO": {"NA", "NWN", 7, 4},  // US - Missouri
	"US-ND": {"NA", "NWN", 8, 4},  // US - North Dakota
	"US-NE": {"NA", "NWN", 9, 4},  // US - Nebraska
	"US-SD": {"NA", "NWN", 11, 4}, // US - South Dakota
	"US-WI": {"NA", "NWN", 12, 4}, // US - Wisconsin

	// West Block (W, NWW, SWW, CW)

	"US-AK": {"NA", "W", 0, 1}, // US - Alaska
	"US-HI": {"NA", "W", 1, 1}, // US - Hawaii

	// US West North
	"US-ID": {"NA", "NWW", 0, 3}, // US - Idaho
	"US-MT": {"NA", "NWW", 1, 3}, // US - Montana
	"US-OR": {"NA", "NWW", 2, 3}, // US - Oregon
	"US-WA": {"NA", "NWW", 3, 3}, // US - Washington
	"US-WY": {"NA", "NWW", 4, 3}, // US - Wyoming

	// US West South
	"US-AZ": {"NA", "SWW", 0, 3}, // US - Arizona
	"US-CA": {"NA", "SWW", 1, 3}, // US - Kalifornien
	"US-CO": {"NA", "SWW", 2, 3}, // US - Colorado
	"US-NM": {"NA", "SWW", 3, 3}, // US - New Mexico
	"US-NV": {"NA", "SWW", 4, 3}, // US - Nevada
	"US-UT": {"NA", "SWW", 5, 3}, // US - Utah

	// US Central South
	"US-AL": {"NA", "CW", 0, 3}, // US - Alabama
	"US-AR": {"NA", "CW", 1, 3}, // US - Arkansas
	"US-LA": {"NA", "CW", 2, 3}, // US - Louisiana
	"US-MS": {"NA", "CW", 3, 3}, // US - Mississippi
	"US-OK": {"NA", "CW", 4, 3}, // US - Oklahoma
	"US-TN": {"NA", "CW", 5, 3}, // US - Tennessee
	"US-TX": {"NA", "CW", 6, 3}, // US - Texas

	// East Block (E, SEE, NEE, CE)

	"BB": {"NA", "E", 0, 3}, // Barbados
	"DM": {"NA", "E", 1, 3}, // Dominica
	"GD": {"NA", "E", 2, 3}, // Grenada
	"LC": {"NA", "E", 3, 3}, // Saint Lucia
	"MQ": {"NA", "E", 4, 3}, // Martinique
	"TT": {"NA", "E", 5, 3}, // Trinidad and Tobago
	"VC": {"NA", "E", 6, 3}, // Saint Vincent and the Grenadines

	"AG": {"NA", "SEE", 0, 3}, // Antigua and Barbuda
	"AI": {"NA", "SEE", 1, 3}, // Anguilla
	"BL": {"NA", "SEE", 2, 3}, // Saint Barthélemy
	"GP": {"NA", "SEE", 3, 3}, // Guadeloupe
	"KN": {"NA", "SEE", 4, 3}, // Saint Kitts and Nevis
	"MF": {"NA", "SEE", 5, 3}, // Saint Martin
	"MS": {"NA", "SEE", 6, 3}, // Montserrat
	"SX": {"NA", "SEE", 7, 3}, // Sint Maarten

	"AW": {"NA", "NEE", 0, 3}, // Aruba
	"CW": {"NA", "NEE", 1, 3}, // Curaçao
	"DO": {"NA", "NEE", 2, 3}, // Dominican Republic
	"HT": {"NA", "NEE", 3, 3}, // Haiti
	"PR": {"NA", "NEE", 4, 3}, // Puerto Rico
	"VG": {"NA", "NEE", 5, 3}, // Virgin Islands (British)
	"VI": {"NA", "NEE", 6, 3}, // Virgin Islands (U.S.)

	"BS": {"NA", "CE", 0, 3}, // Bahamas
	"CU": {"NA", "CE", 1, 3}, // Cuba
	"JM": {"NA", "CE", 2, 3}, // Jamaica
	"KY": {"NA", "CE", 3, 3}, // Cayman Islands
	"TC": {"NA", "CE", 4, 3}, // Turks and Caicos Islands

	// South Block (S, SES, SWS, CS)

	"CR": {"NA", "S", 0, 2}, // Costa Rica
	"NI": {"NA", "S", 1, 2}, // Nicaragua
	"PA": {"NA", "S", 2, 2}, // Panama

	"HN": {"NA", "SES", 0, 1}, // Honduras
	"SV": {"NA", "SES", 1, 1}, // El Salvador

	"BZ": {"NA", "SWS", 0, 1}, // Belize
	"GT": {"NA", "SWS", 1, 1}, // Guatemala

	"MX": {"NA", "CS", 0, 0}, // Mexico

	//////////
	// Oceania
	// Note: This is split pretty weird. The main guidance here were submarine
	// cables and how islands are connected to eachother.

	// North Block (N, NWN, NEN, CN)

	"GU": {"OC", "N", 0, 1}, // Guam
	"MP": {"OC", "N", 1, 1}, // Northern Mariana Islands

	"PW": {"OC", "NWN", 0, 0}, // Palau

	"FM": {"OC", "NEN", 0, 2}, // Micronesia
	"MH": {"OC", "NEN", 1, 2}, // Marshall Islands
	"NR": {"OC", "NEN", 2, 2}, // Nauru

	"PG": {"OC", "CN", 0, 1}, // Papua New Guinea
	"SB": {"OC", "CN", 1, 1}, // Solomon Islands

	// West Block (W, NWW, SWW, CW)

	"CC": {"OC", "W", 0, 2}, // Cocos (Keeling) Islands
	"CX": {"OC", "W", 1, 2}, // Christmas Island
	"HM": {"OC", "W", 2, 2}, // Heard Island and McDonald Islands

	"AU": {"OC", "NWW", 0, 0}, // Australia

	"NZ": {"OC", "SWW", 0, 0}, // New Zealand

	"NC": {"OC", "CW", 0, 1}, // New Caledonia
	"NF": {"OC", "CW", 1, 1}, // Norfolk Island

	// South Block (S, SES, SWS, CS)

	"VU": {"OC", "S", 0, 0}, // Vanuatu

	"FJ": {"OC", "SES", 0, 1}, // Fiji
	"TO": {"OC", "SES", 1, 1}, // Tonga

	"WF": {"OC", "SWS", 0, 1}, // Wallis and Futuna
	"WS": {"OC", "SWS", 1, 1}, // Samoa

	"KI": {"OC", "CS", 0, 2}, // Kiribati
	"TK": {"OC", "CS", 1, 2}, // Tokelau
	"TV": {"OC", "CS", 2, 2}, // Tuvalu

	// East Block (E, SEE, NEE, CE)

	"PN": {"OC", "E", 0, 0}, // Pitcairn

	"PF": {"OC", "SEE", 0, 0}, // French Polynesia

	"CK": {"OC", "NEE", 0, 2}, // Cook Islands
	"NU": {"OC", "NEE", 1, 2}, // Niue

	"AS": {"OC", "CE", 0, 0}, // American Samoa

	////////////////
	// South America

	// West Block (W, NWW, SWW, CW)
	"CO": {"SA", "W", 0, 0},   // Colombia
	"EC": {"SA", "NWW", 0, 0}, // Ecuador
	"PE": {"SA", "SWW", 0, 0}, // Peru
	"CL": {"SA", "CW", 0, 0},  // Chile

	// North Block (N, NWN, NEN, CN)
	"VE": {"SA", "N", 0, 0},   // Venezuela
	"GY": {"SA", "NWN", 0, 0}, // Guyana
	"SR": {"SA", "NEN", 0, 0}, // Suriname
	"GF": {"SA", "CN", 0, 0},  // French Guiana

	// East Block (E, SEE, NEE, CE)
	"BR": {"SA", "E", 0, 0},   // Brazil
	"UY": {"SA", "SEE", 0, 0}, // Uruguay
	"BO": {"SA", "NEE", 0, 0}, // Bolivia
	"PY": {"SA", "CE", 0, 0},  // Paraguay

	// South Block (S, SES, SWS, CS)
	"GS": {"SA", "S", 0, 0},   // South Georgia and the South Sandwich Islands
	"BV": {"SA", "SES", 0, 0}, // Bouvet Island
	"AR": {"SA", "SWS", 0, 0}, // Argentina
	"FK": {"SA", "CS", 0, 0},  // Falkland Islands (Malvinas)

	////////////
	// West Asia

	// North Block (N, NWN, NEN, CN)

	"KZ": {"WA", "N", 0, 0}, // Kazakhstan

	"TM": {"WA", "NWN", 0, 1}, // Turkmenistan
	"UZ": {"WA", "NWN", 1, 1}, // Uzbekistan

	"KG": {"WA", "NEN", 0, 1}, // Kyrgyzstan
	"TJ": {"WA", "NEN", 1, 1}, // Tajikistan

	"AF": {"WA", "CN", 0, 0}, // Afghanistan

	// West Block (W, NWW, SWW, CW)

	"CY": {"WA", "W", 0, 0}, // Cyprus

	"TR": {"WA", "NWW", 0, 0}, // Turkey

	"IL": {"WA", "SWW", 0, 1}, // Israel
	"PS": {"WA", "SWW", 1, 1}, // Palestine

	"LB": {"WA", "CW", 0, 0}, // Lebanon

	// East Block (E, SEE, NEE, CE)

	"PK": {"WA", "E", 0, 0}, // Pakistan

	"IR": {"WA", "SEE", 0, 0}, // Iran

	"AM": {"WA", "NEE", 0, 2}, // Armenia
	"AZ": {"WA", "NEE", 1, 2}, // Azerbaijan
	"GE": {"WA", "NEE", 2, 2}, // Georgia

	"IQ": {"WA", "CE", 0, 2}, // Iraq
	"JO": {"WA", "CE", 1, 2}, // Jordan
	"SY": {"WA", "CE", 2, 2}, // Syrian Arab Republic

	// South Block (S, SES, SWS, CS)

	"OM": {"WA", "S", 0, 1}, // Oman
	"YE": {"WA", "S", 1, 1}, // Yemen

	"AE": {"WA", "SES", 0, 1}, // United Arab Emirates
	"QA": {"WA", "SES", 1, 1}, // Qatar

	"SA": {"WA", "SWS", 0, 0}, // Saudi Arabia

	"BH": {"WA", "CS", 0, 1}, // Bahrain
	"KW": {"WA", "CS", 1, 1}, // Kuwait
}
