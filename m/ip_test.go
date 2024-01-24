package m

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDistance(t *testing.T) {
	t.Parallel()

	x, err := netip.ParseAddr("0011:2233:4455:6677:8899:aabb:ccdd:eeff")
	if err != nil {
		t.Fatal(err)
	}
	y, err := netip.ParseAddr("0010:2030:4050:6070:8090:a0b0:c0d0:e0f0")
	if err != nil {
		t.Fatal(err)
	}

	d := IPDistance(x, y)
	assert.Equalf(t, uint64(0x0001020304050607), d.hi, "unexpected high value: %x", d.hi)
	assert.Equalf(t, uint64(0x08090a0b0c0d0e0f), d.lo, "unexpected low value: %x", d.lo)
}

func BenchmarkGetDistance(b *testing.B) {
	x, err := netip.ParseAddr("0011:2233:4455:6677:8899:aabb:ccdd:eeff")
	if err != nil {
		b.Fatal(err)
	}
	y, err := netip.ParseAddr("0010:2030:4050:6070:8090:a0b0:c0d0:e0f0")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := IPDistance(x, y)
		if d.hi != 0x0001020304050607 {
			b.Fatalf("unexpected high value: %x", d.hi)
		}
		if d.lo != 0x08090a0b0c0d0e0f {
			b.Fatalf("unexpected low value: %x", d.lo)
		}
	}

	// cpu: 11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
	// BenchmarkGetDistance
	// BenchmarkGetDistance-8   	86344314	        13.59 ns/op	       0 B/op	       0 allocs/op
}

// Benchmarks to test what the fastest way is to get the uint128 out of a netip.Addr.

type Uint128Test struct {
	Hi uint64
	Lo uint64
}

func BenchmarkGetUint128ViaBytes(b *testing.B) {
	ip, err := netip.ParseAddr("0011:2233:4455:6677:8899:aabb:ccdd:eeff")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bytes := ip.As16()
		u := Uint128Test{
			beUint64(bytes[:8]),
			beUint64(bytes[8:]),
		}
		if u.Hi != 0x0011223344556677 {
			b.Fatalf("unexpected high value: %x", u.Hi)
		}
		if u.Lo != 0x8899aabbccddeeff {
			b.Fatalf("unexpected low value: %x", u.Lo)
		}
	}

	// cpu: 11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
	// BenchmarkGetUint128ViaBytes
	// BenchmarkGetUint128ViaBytes-8   	180090032	         6.649 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkGetUint128ViaReflct(b *testing.B) {
	ip, err := netip.ParseAddr("0011:2233:4455:6677:8899:aabb:ccdd:eeff")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ipUint128 := reflect.ValueOf(&ip).Elem().FieldByName("addr")
		u := Uint128Test{
			ipUint128.FieldByName("hi").Uint(),
			ipUint128.FieldByName("lo").Uint(),
		}
		if u.Hi != 0x0011223344556677 {
			b.Fatalf("unexpected high value: %x", u.Hi)
		}
		if u.Lo != 0x8899aabbccddeeff {
			b.Fatalf("unexpected low value: %x", u.Lo)
		}
	}

	// cpu: 11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
	// BenchmarkGetUint128ViaReflct
	// BenchmarkGetUint128ViaReflct-8   	 6646089	       157.0 ns/op	      24 B/op	       3 allocs/op
}
