package m

import (
	"errors"
	"net/netip"
)

// ErrNotFound is return when a country is not found.
var ErrNotFound = errors.New("not found")

// Continent Markers.
var continentCodeToMarker = map[string]byte{
	"EU": ContinentEurope,
	"AF": ContinentAfrica,
	"WA": ContinentWestAsia,
	"NA": ContinentNorthAmerica,
	"SA": ContinentSouthAmerica,
	"OC": ContinentOceania,
	"EA": ContinentEastAsia,
}

// Region Markers.
var (
	// Region Geo Codes:
	//          N
	//      NNW   NNE
	//   WNW    CN   ENE
	// W    CW     CE    E
	//   WSW    CS   ESE
	//      SSW   SSE
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
		"NNW": 1,
		"NNE": 2,
		"CN":  3,
		"W":   4,
		"WNW": 5,
		"WSW": 6,
		"CW":  7,
		"E":   8,
		"ESE": 9,
		"ENE": 10,
		"CE":  11,
		"S":   12,
		"SSE": 13,
		"SSW": 14,
		"CS":  15,
	}

	regionCodeToDescription = map[string]string{
		"N":   "🡹 N",
		"NNW": "🡼🡹 NNW",
		"NNE": "🡹🡽 NNE",
		"CN":  "⊙🡹 cN",
		"W":   "🡸 W",
		"WNW": "🡸🡼 WNW",
		"WSW": "🡸🡿 WSW",
		"CW":  "🡸⊙ cW",
		"E":   "🡺 E",
		"ESE": "🡺🡾 ESE",
		"ENE": "🡺🡽 ENE",
		"CE":  "⊙🡺 cE",
		"S":   "🡻 S",
		"SSE": "🡻🡾 SSE",
		"SSW": "🡿🡻 SSW",
		"CS":  "⊙🡻 cS",
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
		return MakeBaseIP([]byte{
			BaseNet,
			TypeRoutingAddress |
				continentCodeToMarker[cgm.ContinentCode] |
				regionCodeToMarker[cgm.RegionCode],
		})
	}

	// Make prefix with additional country marker.
	return MakeBaseIP([]byte{
		BaseNet,
		TypeRoutingAddress |
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

	// North Block (N, NNW, NNE, CN)

	"LY": {"AF", "N", 0, 1}, // Libya
	"TN": {"AF", "N", 1, 1}, // Tunisia

	"DZ": {"AF", "NNW", 0, 1}, // Algeria
	"MA": {"AF", "NNW", 1, 1}, // Morocco

	"EG": {"AF", "NNE", 0, 0}, // Egypt

	"NE": {"AF", "CN", 0, 1}, // Niger
	"TD": {"AF", "CN", 1, 1}, // Chad

	// West Block (W, WNW, WSW, CW)

	"CV": {"AF", "W", 0, 2}, // Cabo Verde
	"GM": {"AF", "W", 1, 2}, // Gambia
	"GW": {"AF", "W", 2, 2}, // Guinea-Bissau
	"SN": {"AF", "W", 3, 2}, // Senegal

	"BF": {"AF", "WNW", 0, 2}, // Burkina Faso
	"EH": {"AF", "WNW", 1, 2}, // Western Sahara
	"ML": {"AF", "WNW", 2, 2}, // Mali
	"MR": {"AF", "WNW", 3, 2}, // Mauritania

	"CI": {"AF", "WSW", 0, 2}, // Côte d'Ivoire
	"GN": {"AF", "WSW", 1, 2}, // Guinea
	"LR": {"AF", "WSW", 2, 2}, // Liberia
	"SL": {"AF", "WSW", 3, 2}, // Sierra Leone

	"BJ": {"AF", "CW", 0, 2}, // Benin
	"GH": {"AF", "CW", 1, 2}, // Ghana
	"NG": {"AF", "CW", 2, 2}, // Nigeria
	"TG": {"AF", "CW", 3, 2}, // Togo

	// East Block (E, ESE, ENE, CE)

	"DJ": {"AF", "E", 0, 2}, // Djibouti
	"ER": {"AF", "E", 1, 2}, // Eritrea
	"ET": {"AF", "E", 2, 2}, // Ethiopia
	"SO": {"AF", "E", 3, 2}, // Somalia

	"BI": {"AF", "ESE", 0, 3}, // Burundi
	"KE": {"AF", "ESE", 1, 3}, // Kenya
	"RW": {"AF", "ESE", 2, 3}, // Rwanda
	"TZ": {"AF", "ESE", 3, 3}, // Tanzania
	"UG": {"AF", "ESE", 4, 3}, // Uganda

	"SD": {"AF", "ENE", 0, 1}, // Sudan
	"SS": {"AF", "ENE", 1, 1}, // South Sudan

	"CD": {"AF", "CE", 0, 3}, // DR Congo
	"CF": {"AF", "CE", 1, 3}, // Central African Republic
	"CG": {"AF", "CE", 2, 3}, // Congo
	"CM": {"AF", "CE", 3, 3}, // Cameroon
	"GA": {"AF", "CE", 4, 3}, // Gabon
	"GQ": {"AF", "CE", 5, 3}, // Equatorial Guinea
	"ST": {"AF", "CE", 6, 3}, // Sao Tome and Principe

	// South Block (S, SSE, SSW, CS)

	"BW": {"AF", "S", 0, 2}, // Botswana
	"LS": {"AF", "S", 1, 2}, // Lesotho
	"SZ": {"AF", "S", 2, 2}, // Eswatini
	"ZA": {"AF", "S", 3, 2}, // South Africa

	"IO": {"AF", "SSE", 0, 3}, // British Indian Ocean Territory
	"KM": {"AF", "SSE", 1, 3}, // Comoros
	"MG": {"AF", "SSE", 2, 3}, // Madagascar
	"MU": {"AF", "SSE", 3, 3}, // Mauritius
	"RE": {"AF", "SSE", 4, 3}, // Réunion
	"SC": {"AF", "SSE", 5, 3}, // Seychelles
	"TF": {"AF", "SSE", 6, 3}, // French Southern Territories
	"YT": {"AF", "SSE", 7, 3}, // Mayotte

	"AO": {"AF", "SSW", 0, 2}, // Angola
	"NA": {"AF", "SSW", 1, 2}, // Namibia
	"SH": {"AF", "SSW", 2, 2}, // Saint Helena

	"MW": {"AF", "CS", 0, 3}, // Malawi
	"MZ": {"AF", "CS", 1, 3}, // Mozambique
	"ZM": {"AF", "CS", 2, 3}, // Zambia
	"ZW": {"AF", "CS", 3, 3}, // Zimbabwe

	////////////
	// East Asia

	// North Block (N, NNW, NNE, CN)

	"JP": {"EA", "N", 0, 1}, // Japan
	"KR": {"EA", "N", 1, 1}, // South Korea

	"CN": {"EA", "NNW", 0, 2}, // China
	"KP": {"EA", "NNW", 1, 2}, // North Korea (DPRK)
	"MN": {"EA", "NNW", 2, 2}, // Mongolia

	"TW": {"EA", "NNE", 0, 0}, // Taiwan

	"MO": {"EA", "CN", 0, 1}, // Macao
	"HK": {"EA", "CN", 1, 1}, // Hong Kong

	// West Block (W, WNW, WSW, CW)

	"LK": {"EA", "W", 0, 1}, // Sri Lanka
	"MV": {"EA", "W", 1, 1}, // Maldives

	"IN": {"EA", "WNW", 0, 0}, // India

	"BT": {"EA", "WSW", 0, 1}, // Bhutan
	"NP": {"EA", "WSW", 1, 1}, // Nepal

	"BD": {"EA", "CW", 0, 1}, // Bangladesh
	"MM": {"EA", "CW", 1, 1}, // Myanmar

	// South Block (S, SSE, SSW, CS)

	"MY": {"EA", "S", 0, 1}, // Malaysia
	"SG": {"EA", "S", 1, 1}, // Singapore

	"BN": {"EA", "SSE", 0, 0}, // Brunei Darussalam

	"KH": {"EA", "SSW", 0, 1}, // Cambodia
	"TH": {"EA", "SSW", 1, 1}, // Thailand

	"LA": {"EA", "CS", 0, 1}, // Lao
	"VN": {"EA", "CS", 1, 1}, // Viet Nam

	// East Block (E, ESE, ENE, CE)

	"TL": {"EA", "ESE", 0, 0}, // Timor-Leste
	"PH": {"EA", "ENE", 0, 0}, // Philippines
	"ID": {"EA", "CE", 0, 0},  // Indonesia
	// Info: One spot left.

	/////////
	// Europe

	// North Block (N, NNW, NNE, CN)

	"EE": {"EU", "N", 0, 1}, // Estonia
	"FI": {"EU", "N", 1, 1}, // Finland

	"DK": {"EU", "NNW", 0, 2}, // Denmark
	"NO": {"EU", "NNW", 1, 2}, // Norway
	"SE": {"EU", "NNW", 2, 2}, // Sweden
	"SJ": {"EU", "NNW", 3, 2}, // Svalbard and Jan Mayen

	"LT": {"EU", "NNE", 0, 1}, // Lithuania
	"LV": {"EU", "NNE", 1, 1}, // Latvia

	"BE": {"EU", "CN", 0, 2}, // Belgium
	"DE": {"EU", "CN", 1, 2}, // Germany
	"LU": {"EU", "CN", 2, 2}, // Luxembourg
	"NL": {"EU", "CN", 3, 2}, // Netherlands

	// West Block (W, WNW, WSW, CW)

	"IS": {"EU", "W", 0, 1}, // Iceland
	"FO": {"EU", "W", 1, 1}, // Faroe Islands

	"GB": {"EU", "WNW", 0, 3}, // United Kingdom
	"IE": {"EU", "WNW", 1, 3}, // Ireland
	"GG": {"EU", "WNW", 2, 3}, // Guernsey
	"IM": {"EU", "WNW", 3, 3}, // Isle of Man
	"JE": {"EU", "WNW", 4, 3}, // Jersey

	"AD": {"EU", "WSW", 0, 2}, // Andorra
	"ES": {"EU", "WSW", 1, 2}, // Spain
	"GI": {"EU", "WSW", 2, 2}, // Gibraltar
	"PT": {"EU", "WSW", 3, 2}, // Portugal

	"CH": {"EU", "CW", 0, 2}, // Switzerland
	"FR": {"EU", "CW", 1, 2}, // France
	"LI": {"EU", "CW", 2, 2}, // Liechtenstein
	// FYI: Spot left

	// East Block (E, ESE, ENE, CE)

	"BY": {"EU", "E", 0, 1}, // Belarus
	"RU": {"EU", "E", 1, 1}, // Russia // Assuming mostly Moscow Area

	"AL": {"EU", "ESE", 0, 2}, // Albania
	"BG": {"EU", "ESE", 1, 2}, // Bulgaria
	"GR": {"EU", "ESE", 2, 2}, // Greece
	"MK": {"EU", "ESE", 3, 2}, // North Macedonia

	"MD": {"EU", "ENE", 0, 2}, // Moldova
	"PL": {"EU", "ENE", 1, 2}, // Poland
	"RO": {"EU", "ENE", 2, 2}, // Romania
	"UA": {"EU", "ENE", 3, 2}, // Ukraine

	"CZ": {"EU", "CE", 0, 1}, // Czechia
	"SK": {"EU", "CE", 1, 1}, // Slovakia

	// South Block (S, SSE, SSW, CS)

	"MT": {"EU", "S", 0, 0}, // Malta

	"BA": {"EU", "SSE", 0, 2}, // Bosnia and Herzegovina
	"ME": {"EU", "SSE", 1, 2}, // Montenegro
	"RS": {"EU", "SSE", 2, 2}, // Serbia
	"XK": {"EU", "SSE", 3, 2}, // Kosovo

	"IT": {"EU", "SSW", 0, 2}, // Italy
	"MC": {"EU", "SSW", 1, 2}, // Monaco
	"SM": {"EU", "SSW", 2, 2}, // San Marino
	"VA": {"EU", "SSW", 3, 2}, // Holy See

	"AT": {"EU", "CS", 0, 2}, // Austria
	"HR": {"EU", "CS", 1, 2}, // Croatia
	"HU": {"EU", "CS", 2, 2}, // Hungary
	"SI": {"EU", "CS", 3, 2}, // Slovenia

	////////////////
	// North America

	// North Block (N, NNW, NNE, CN)

	"CA": {"NA", "N", 0, 2}, // Canada
	"GL": {"NA", "N", 2, 2}, // Greenland
	"PM": {"NA", "N", 3, 2}, // Saint Pierre and Miquelon

	// US North East
	"US-CT": {"NA", "NNE", 0, 4},  // US - Connecticut
	"US-DE": {"NA", "NNE", 1, 4},  // US - Delaware
	"US-MA": {"NA", "NNE", 2, 4},  // US - Massachusetts
	"US-ME": {"NA", "NNE", 3, 4},  // US - Maine
	"US-NH": {"NA", "NNE", 4, 4},  // US - New Hampshire
	"US-NJ": {"NA", "NNE", 5, 4},  // US - New Jersey
	"US-NY": {"NA", "NNE", 6, 4},  // US - New York
	"US-OH": {"NA", "NNE", 7, 4},  // US - Ohio
	"US-PA": {"NA", "NNE", 8, 4},  // US - Pennsylvania
	"US-RI": {"NA", "NNE", 9, 4},  // US - Rhode Island
	"US-VT": {"NA", "NNE", 10, 4}, // US - Vermont
	"BM":    {"NA", "NNE", 15, 4}, // Bermuda

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
	"US-IA": {"NA", "NNW", 0, 4},  // US - Iowa
	"US-IL": {"NA", "NNW", 1, 4},  // US - Illinois
	"US-IN": {"NA", "NNW", 2, 4},  // US - Indiana
	"US-KS": {"NA", "NNW", 3, 4},  // US - Kansas
	"US-KY": {"NA", "NNW", 4, 4},  // US - Kentucky
	"US-MI": {"NA", "NNW", 5, 4},  // US - Michigan
	"US-MN": {"NA", "NNW", 6, 4},  // US - Minnesota
	"US-MO": {"NA", "NNW", 7, 4},  // US - Missouri
	"US-ND": {"NA", "NNW", 8, 4},  // US - North Dakota
	"US-NE": {"NA", "NNW", 9, 4},  // US - Nebraska
	"US-SD": {"NA", "NNW", 11, 4}, // US - South Dakota
	"US-WI": {"NA", "NNW", 12, 4}, // US - Wisconsin

	// West Block (W, WNW, WSW, CW)

	"US-AK": {"NA", "W", 0, 1}, // US - Alaska
	"US-HI": {"NA", "W", 1, 1}, // US - Hawaii

	// US West North
	"US-ID": {"NA", "WNW", 0, 3}, // US - Idaho
	"US-MT": {"NA", "WNW", 1, 3}, // US - Montana
	"US-OR": {"NA", "WNW", 2, 3}, // US - Oregon
	"US-WA": {"NA", "WNW", 3, 3}, // US - Washington
	"US-WY": {"NA", "WNW", 4, 3}, // US - Wyoming

	// US West South
	"US-AZ": {"NA", "WSW", 0, 3}, // US - Arizona
	"US-CA": {"NA", "WSW", 1, 3}, // US - Kalifornien
	"US-CO": {"NA", "WSW", 2, 3}, // US - Colorado
	"US-NM": {"NA", "WSW", 3, 3}, // US - New Mexico
	"US-NV": {"NA", "WSW", 4, 3}, // US - Nevada
	"US-UT": {"NA", "WSW", 5, 3}, // US - Utah

	// US Central South
	"US-AL": {"NA", "CW", 0, 3}, // US - Alabama
	"US-AR": {"NA", "CW", 1, 3}, // US - Arkansas
	"US-LA": {"NA", "CW", 2, 3}, // US - Louisiana
	"US-MS": {"NA", "CW", 3, 3}, // US - Mississippi
	"US-OK": {"NA", "CW", 4, 3}, // US - Oklahoma
	"US-TN": {"NA", "CW", 5, 3}, // US - Tennessee
	"US-TX": {"NA", "CW", 6, 3}, // US - Texas

	// East Block (E, ESE, ENE, CE)

	"BB": {"NA", "E", 0, 3}, // Barbados
	"DM": {"NA", "E", 1, 3}, // Dominica
	"GD": {"NA", "E", 2, 3}, // Grenada
	"LC": {"NA", "E", 3, 3}, // Saint Lucia
	"MQ": {"NA", "E", 4, 3}, // Martinique
	"TT": {"NA", "E", 5, 3}, // Trinidad and Tobago
	"VC": {"NA", "E", 6, 3}, // Saint Vincent and the Grenadines

	"AG": {"NA", "ESE", 0, 3}, // Antigua and Barbuda
	"AI": {"NA", "ESE", 1, 3}, // Anguilla
	"BL": {"NA", "ESE", 2, 3}, // Saint Barthélemy
	"GP": {"NA", "ESE", 3, 3}, // Guadeloupe
	"KN": {"NA", "ESE", 4, 3}, // Saint Kitts and Nevis
	"MF": {"NA", "ESE", 5, 3}, // Saint Martin
	"MS": {"NA", "ESE", 6, 3}, // Montserrat
	"SX": {"NA", "ESE", 7, 3}, // Sint Maarten

	"AW": {"NA", "ENE", 0, 3}, // Aruba
	"CW": {"NA", "ENE", 1, 3}, // Curaçao
	"DO": {"NA", "ENE", 2, 3}, // Dominican Republic
	"HT": {"NA", "ENE", 3, 3}, // Haiti
	"PR": {"NA", "ENE", 4, 3}, // Puerto Rico
	"VG": {"NA", "ENE", 5, 3}, // Virgin Islands (British)
	"VI": {"NA", "ENE", 6, 3}, // Virgin Islands (U.S.)

	"BS": {"NA", "CE", 0, 3}, // Bahamas
	"CU": {"NA", "CE", 1, 3}, // Cuba
	"JM": {"NA", "CE", 2, 3}, // Jamaica
	"KY": {"NA", "CE", 3, 3}, // Cayman Islands
	"TC": {"NA", "CE", 4, 3}, // Turks and Caicos Islands

	// South Block (S, SSE, SSW, CS)

	"CR": {"NA", "S", 0, 2}, // Costa Rica
	"NI": {"NA", "S", 1, 2}, // Nicaragua
	"PA": {"NA", "S", 2, 2}, // Panama

	"HN": {"NA", "SSE", 0, 1}, // Honduras
	"SV": {"NA", "SSE", 1, 1}, // El Salvador

	"BZ": {"NA", "SSW", 0, 1}, // Belize
	"GT": {"NA", "SSW", 1, 1}, // Guatemala

	"MX": {"NA", "CS", 0, 0}, // Mexico

	//////////
	// Oceania
	// Note: This is split pretty weird. The main guidance here were submarine
	// cables and how islands are connected to eachother.

	// North Block (N, NNW, NNE, CN)

	"GU": {"OC", "N", 0, 1}, // Guam
	"MP": {"OC", "N", 1, 1}, // Northern Mariana Islands

	"PW": {"OC", "NNW", 0, 0}, // Palau

	"FM": {"OC", "NNE", 0, 2}, // Micronesia
	"MH": {"OC", "NNE", 1, 2}, // Marshall Islands
	"NR": {"OC", "NNE", 2, 2}, // Nauru

	"PG": {"OC", "CN", 0, 1}, // Papua New Guinea
	"SB": {"OC", "CN", 1, 1}, // Solomon Islands

	// West Block (W, WNW, WSW, CW)

	"CC": {"OC", "W", 0, 2}, // Cocos (Keeling) Islands
	"CX": {"OC", "W", 1, 2}, // Christmas Island
	"HM": {"OC", "W", 2, 2}, // Heard Island and McDonald Islands

	"AU": {"OC", "WNW", 0, 0}, // Australia

	"NZ": {"OC", "WSW", 0, 0}, // New Zealand

	"NC": {"OC", "CW", 0, 1}, // New Caledonia
	"NF": {"OC", "CW", 1, 1}, // Norfolk Island

	// South Block (S, SSE, SSW, CS)

	"VU": {"OC", "S", 0, 0}, // Vanuatu

	"FJ": {"OC", "SSE", 0, 1}, // Fiji
	"TO": {"OC", "SSE", 1, 1}, // Tonga

	"WF": {"OC", "SSW", 0, 1}, // Wallis and Futuna
	"WS": {"OC", "SSW", 1, 1}, // Samoa

	"KI": {"OC", "CS", 0, 2}, // Kiribati
	"TK": {"OC", "CS", 1, 2}, // Tokelau
	"TV": {"OC", "CS", 2, 2}, // Tuvalu

	// East Block (E, ESE, ENE, CE)

	"PN": {"OC", "E", 0, 0}, // Pitcairn

	"PF": {"OC", "ESE", 0, 0}, // French Polynesia

	"CK": {"OC", "ENE", 0, 2}, // Cook Islands
	"NU": {"OC", "ENE", 1, 2}, // Niue

	"AS": {"OC", "CE", 0, 0}, // American Samoa

	////////////////
	// South America

	// West Block (W, WNW, WSW, CW)
	"CO": {"SA", "W", 0, 0},   // Colombia
	"EC": {"SA", "WNW", 0, 0}, // Ecuador
	"PE": {"SA", "WSW", 0, 0}, // Peru
	"CL": {"SA", "CW", 0, 0},  // Chile

	// North Block (N, NNW, NNE, CN)
	"VE": {"SA", "N", 0, 0},   // Venezuela
	"GY": {"SA", "NNW", 0, 0}, // Guyana
	"SR": {"SA", "NNE", 0, 0}, // Suriname
	"GF": {"SA", "CN", 0, 0},  // French Guiana

	// East Block (E, ESE, ENE, CE)
	"BR": {"SA", "E", 0, 0},   // Brazil
	"UY": {"SA", "ESE", 0, 0}, // Uruguay
	"BO": {"SA", "ENE", 0, 0}, // Bolivia
	"PY": {"SA", "CE", 0, 0},  // Paraguay

	// South Block (S, SSE, SSW, CS)
	"GS": {"SA", "S", 0, 0},   // South Georgia and the South Sandwich Islands
	"BV": {"SA", "SSE", 0, 0}, // Bouvet Island
	"AR": {"SA", "SSW", 0, 0}, // Argentina
	"FK": {"SA", "CS", 0, 0},  // Falkland Islands (Malvinas)

	////////////
	// West Asia

	// North Block (N, NNW, NNE, CN)

	"KZ": {"WA", "N", 0, 0}, // Kazakhstan

	"TM": {"WA", "NNW", 0, 1}, // Turkmenistan
	"UZ": {"WA", "NNW", 1, 1}, // Uzbekistan

	"KG": {"WA", "NNE", 0, 1}, // Kyrgyzstan
	"TJ": {"WA", "NNE", 1, 1}, // Tajikistan

	"AF": {"WA", "CN", 0, 0}, // Afghanistan

	// West Block (W, WNW, WSW, CW)

	"CY": {"WA", "W", 0, 0}, // Cyprus

	"TR": {"WA", "WNW", 0, 0}, // Turkey

	"IL": {"WA", "WSW", 0, 1}, // Israel
	"PS": {"WA", "WSW", 1, 1}, // Palestine

	"LB": {"WA", "CW", 0, 0}, // Lebanon

	// East Block (E, ESE, ENE, CE)

	"PK": {"WA", "E", 0, 0}, // Pakistan

	"IR": {"WA", "ESE", 0, 0}, // Iran

	"AM": {"WA", "ENE", 0, 2}, // Armenia
	"AZ": {"WA", "ENE", 1, 2}, // Azerbaijan
	"GE": {"WA", "ENE", 2, 2}, // Georgia

	"IQ": {"WA", "CE", 0, 2}, // Iraq
	"JO": {"WA", "CE", 1, 2}, // Jordan
	"SY": {"WA", "CE", 2, 2}, // Syrian Arab Republic

	// South Block (S, SSE, SSW, CS)

	"OM": {"WA", "S", 0, 1}, // Oman
	"YE": {"WA", "S", 1, 1}, // Yemen

	"AE": {"WA", "SSE", 0, 1}, // United Arab Emirates
	"QA": {"WA", "SSE", 1, 1}, // Qatar

	"SA": {"WA", "SSW", 0, 0}, // Saudi Arabia

	"BH": {"WA", "CS", 0, 1}, // Bahrain
	"KW": {"WA", "CS", 1, 1}, // Kuwait
}
