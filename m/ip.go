package m

import (
	"net/netip"
)

// MakeBaseIP creates an IP address from the given prefix bytes.
func MakeBaseIP(prefix []byte) netip.Addr {
	var full [16]byte
	copy(full[:], prefix)
	return netip.AddrFrom16(full)
}

// MakePrefix creates an IP prefix from the given bytes and bit length.
func MakePrefix(prefix []byte, bits int) (netip.Prefix, error) {
	return MakeBaseIP(prefix).Prefix(bits)
}

// MustPrefix creates an IP prefix and panics if it fails.
func MustPrefix(prefix []byte, bits int) netip.Prefix {
	p, err := MakePrefix(prefix, bits)
	if err != nil {
		panic(err)
	}
	return p
}

// AddrDistance holds the address distance between two IPv6s.
type AddrDistance struct {
	hi uint64
	lo uint64
}

// ZeroAddrDistance returns an address distance of zero.
func ZeroAddrDistance() AddrDistance {
	return AddrDistance{}
}

// MaxAddrDistance return the maximum address distance.
func MaxAddrDistance() AddrDistance {
	return AddrDistance{
		hi: 0xFFFFFFFF_FFFFFFFF,
		lo: 0xFFFFFFFF_FFFFFFFF,
	}
}

// IPDistance returns the IP distance of the given addresses.
func IPDistance(a, b netip.Addr) AddrDistance {
	aBytes := a.As16()
	bBytes := b.As16()

	return AddrDistance{
		beUint64(aBytes[:8]) ^ beUint64(bBytes[:8]),
		beUint64(aBytes[8:]) ^ beUint64(bBytes[8:]),
	}
}

// Compare returns an integer comparing two IP distances.
func (a AddrDistance) Compare(b AddrDistance) int {
	if a.hi < b.hi {
		return -1
	}
	if a.hi > b.hi {
		return 1
	}
	if a.lo < b.lo {
		return -1
	}
	if a.lo > b.lo {
		return 1
	}
	return 0
}

// Less reports whether the IP distance (a) sorts before the given IP distance (b).
func (a AddrDistance) Less(b AddrDistance) bool {
	return a.Compare(b) == -1
}

// IsZero reports whether the IP distance is zero.
func (a AddrDistance) IsZero() bool {
	return a.lo == 0 && a.hi == 0
}

func beUint64(b []byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}
