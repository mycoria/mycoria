package config

import "net/netip"

// DefaultPortNumber is the default port number used by Mycoria.
const DefaultPortNumber = 47369 // M(1+3), Y(2+5), C(3), O(1+5), R(1+8); 0xB909

// DefaultAPIAddress is the default local API address used by Mycoria.
var DefaultAPIAddress = netip.MustParseAddr("fd00::b909")

// DefaultTLD is the default TLD that Mycoria uses.
var DefaultTLD = "myco"

// DefaultDotTLD is the default TLD that Mycoria uses, but with a dot prefix.
var DefaultDotTLD = ".myco"

// DefaultTLDBetweenDots is the default TLD that Mycoria uses, but between dots.
var DefaultTLDBetweenDots = ".myco."
