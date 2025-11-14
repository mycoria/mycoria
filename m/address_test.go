package m

import (
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestAddressGeneration(t *testing.T) {
	t.Parallel()

	// Test random generation and verification.
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	generatedIP, err := DigestToAddress(AddressDigestAlg, "Ed25519", pubKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyAddressKey(generatedIP, AddressDigestAlg, "Ed25519", pubKey, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Test brute-force generating a privacy address.
	start := time.Now()
	addr, n, err := GeneratePrivacyAddress(t.Context())
	if err != nil {
		t.Error(err)
	} else {
		t.Logf(
			"generated privacy address %s in %s with %d tries",
			addr.IP,
			time.Since(start),
			n,
		)
	}
	err = addr.verifyPrivateKey()
	if err != nil {
		t.Error(err)
	}
	err = addr.PublicAddress.VerifyAddress()
	if err != nil {
		t.Error(err)
	}

	// Test brute-force generating a routable address.
	start = time.Now()
	addr, n, err = GenerateRoutableAddress(
		t.Context(),
		[]netip.Prefix{ExperimentsPrefix},
		CommonConflictingPrefixes,
		0xFFFF_FFFF,
	)
	if err != nil {
		t.Error(err)
	} else {
		t.Logf(
			"generated routable address %s in %s with %d tries",
			addr.IP,
			time.Since(start),
			n,
		)
	}
	err = addr.verifyPrivateKey()
	if err != nil {
		t.Error(err)
	}
	err = addr.PublicAddress.VerifyAddress()
	if err != nil {
		t.Error(err)
	}
}

func TestOldAddresss(t *testing.T) {
	t.Parallel()

	for name, storedAddr := range oldAddresses {
		t.Run(name, func(t *testing.T) {
			addr, err := AddressFromStorage(storedAddr)
			if err != nil {
				t.Fatal(err)
			}
			err = addr.verifyPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			err = addr.PublicAddress.VerifyAddress()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

var (
	oldAddresses = map[string]AddressStorage{
		"pre easing": {
			IP:         "fded:365:6fc:518:b9ec:c31e:4565:6bf2",
			Hash:       "BLAKE3",
			Type:       "Ed25519",
			PublicKey:  "ce859dda74f73f975d7c3ea51b1942f833e78b8a263dd7a981d3d8d206661170",
			PrivateKey: "a6c76135f1a94ced3f303d219861c00a464f1ffe46f1362decd6edd0a2b45639ce859dda74f73f975d7c3ea51b1942f833e78b8a263dd7a981d3d8d206661170",
		},
	}
)

func BenchmarkAddressGeneration(b *testing.B) {
	b.Run("16 bits no easing", func(b *testing.B) {
		for b.Loop() {
			start := time.Now()
			addr, n, err := GenerateRoutableAddress(
				b.Context(),
				[]netip.Prefix{ExperimentsPrefix},
				CommonConflictingPrefixes,
				0,
			)
			if err != nil {
				b.Fatal(err)
			}
			taken := time.Since(start)
			if addr != nil {
				fmt.Printf("address: %s\n", addr.IP)
			} else {
				fmt.Println("no address")
			}
			fmt.Printf(
				"time total: %s; per try: %s\n",
				taken,
				taken/time.Duration(n+1),
			)
		}
	})

	b.Run("16 bits full easing", func(b *testing.B) {
		for b.Loop() {
			start := time.Now()
			addr, n, err := tryToGenerateAddress(
				[]netip.Prefix{ExperimentsPrefix},
				CommonConflictingPrefixes,
				0xFFFF_FFFF_FFFF_FFFF,
			)
			if err != nil {
				b.Fatal(err)
			}
			taken := time.Since(start)
			if addr != nil {
				fmt.Printf("address: %s\n", addr.IP)
			} else {
				fmt.Println("no address")
			}
			fmt.Printf(
				"time total: %s; per try: %s\n",
				taken,
				taken/time.Duration(n+1),
			)
		}
	})
}
