package m

import (
	"context"
	"crypto/ed25519"
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
	generatedIP, err := DigestToAddress(AddressDigestAlg, "Ed25519", pubKey)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyAddressKey(generatedIP, AddressDigestAlg, "Ed25519", pubKey)
	if err != nil {
		t.Fatal(err)
	}

	// Test brute-force generating a privacy address.
	start := time.Now()
	addr, n, err := GeneratePrivacyAddress(context.Background())
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
		context.Background(),
		[]netip.Prefix{RoamingPrefix},
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
