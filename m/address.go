package m

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/tevino/abool"
)

// Default Cryptography.
const (
	AddressDigestAlg = BLAKE3
	AddressKeyToolID = "Ed25519"
)

// Errors.
var (
	ErrMaxTriesReached = errors.New("maximum tries to generate address reached")
)

// Address is an address with the associated private key.
type Address struct {
	PublicAddress `cbor:"-" json:"-" yaml:"-"` // Prevent serializing.

	PrivateKey ed25519.PrivateKey `cbor:"-" json:"-" yaml:"-"` // Prevent serializing.
}

// Sign signs the given data with the address private key.
func (addr *Address) Sign(data []byte) (sig []byte) {
	return ed25519.Sign(addr.PrivateKey, data)
}

// SignWithContext signs the given data and context with the address private key.
func (addr *Address) SignWithContext(data, context []byte) (sig []byte, err error) {
	return addr.PrivateKey.Sign(nil, data, &ed25519.Options{Context: string(context)})
}

// PublicAddress is the public part of an address in a shareable form.
type PublicAddress struct {
	IP        netip.Addr        `cbor:"i,omitempty" json:"ip,omitempty"   yaml:"ip,omitempty"`
	Hash      Hash              `cbor:"h,omitempty" json:"hash,omitempty" yaml:"hash,omitempty"`
	Type      string            `cbor:"t,omitempty" json:"type,omitempty" yaml:"type,omitempty"`
	PublicKey ed25519.PublicKey `cbor:"k,omitempty" json:"key,omitempty"  yaml:"key,omitempty"`
}

// VerifySig verifies the given data and signature.
func (addr *PublicAddress) VerifySig(data, sig []byte) (ok bool) {
	return ed25519.Verify(addr.PublicKey, data, sig)
}

// VerifySigWithContext verifies the given data and signature.
func (addr *PublicAddress) VerifySigWithContext(data, sig, context []byte) error {
	return ed25519.VerifyWithOptions(
		addr.PublicKey, data, sig,
		&ed25519.Options{Context: string(context)},
	)
}

// GeneratePrivacyAddress generates a new privacy address.
func GeneratePrivacyAddress(ctx context.Context) (*Address, int, error) {
	// With 9 bits to get right, there 512 possibilities
	// and we should need 256 tries on average.
	// Allow for 100 times of that.
	addr, n, err := generateAddressSingleCore(ctx, []netip.Prefix{PrivacyAddressPrefix}, 25600)
	if err != nil {
		return nil, 0, err
	}

	// Set metadata and return.
	return addr, n, nil
}

// GenerateRoutableAddress generates a new routable address within the given acceptable prefixes.
func GenerateRoutableAddress(ctx context.Context, acceptablePrefixes []netip.Prefix) (*Address, int, error) {
	var highestBits int
	for _, prefix := range acceptablePrefixes {
		prefixBits := prefix.Bits()
		if prefixBits > highestBits {
			highestBits = prefixBits
		}
	}

	// Use 100 times the average guessing tries as limit.
	maxTries := int(math.Pow(2, float64(highestBits))) / 2 * 100

	// Generate in the most adequate way.
	return generateAddressWithTries(ctx, acceptablePrefixes, maxTries)
}

func generateAddressWithTries(ctx context.Context, acceptablePrefixes []netip.Prefix, tries int) (*Address, int, error) {
	if tries < 10000 || runtime.NumCPU() < 2 {
		return generateAddressSingleCore(ctx, acceptablePrefixes, tries)
	}
	return generateAddressMultiCore(ctx, acceptablePrefixes, tries)
}

func generateAddressSingleCore(ctx context.Context, acceptablePrefixes []netip.Prefix, tries int) (*Address, int, error) {
	for i := 1; i <= tries; i++ {
		addr, err := tryToGenerateAddress(acceptablePrefixes)
		if err != nil {
			return nil, 0, err
		}
		if addr != nil {
			return addr, i, nil
		}
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
	}

	return nil, 0, ErrMaxTriesReached
}

func generateAddressMultiCore(ctx context.Context, acceptablePrefixes []netip.Prefix, tries int) (*Address, int, error) {
	var wg sync.WaitGroup
	var failedTries atomic.Uint32

	// Use one worker per core.
	workers := runtime.NumCPU()
	if workers <= 0 {
		workers = 1
	}

	done := abool.New()
	result := make(chan *Address, 1)
	errs := make(chan error, 1)
	maxTriesPerWorker := tries / workers

	// Start workers
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for i := 1; i <= maxTriesPerWorker; i++ {
				addr, err := tryToGenerateAddress(acceptablePrefixes)
				// Report error.
				if err != nil {
					select {
					case errs <- err:
					default:
					}
					return
				}
				// Report found address.
				if addr != nil {
					done.Set()
					select {
					case result <- addr:
					default:
					}
					return
				}
				// Report when context was canceled.
				if ctx.Err() != nil {
					select {
					case errs <- ctx.Err():
					default:
					}
					return
				}

				// Report failed try, stop when done.
				failedTries.Add(1)
				if done.IsSet() {
					return
				}
			}
		}()
	}

	// Wait for workers to finish.
	wg.Wait()

	// Check result.
	select {
	case addr := <-result:
		return addr, int(failedTries.Load()) + 1, nil
	default:
		select {
		case err := <-errs:
			return nil, 0, err
		default:
			return nil, 0, ErrMaxTriesReached
		}
	}
}

func tryToGenerateAddress(acceptablePrefixes []netip.Prefix) (*Address, error) {
	// Generate new key pair.
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	// Digest public key to address.
	generatedIP, err := DigestToAddress(AddressDigestAlg, "Ed25519", pubKey)
	if err != nil {
		return nil, err
	}

	// Skip if address is in internal scope.
	if InternalPrefix.Contains(generatedIP) {
		return nil, nil
	}

	// Check if address matches of the acceptable prefixes.
	for _, prefix := range acceptablePrefixes {
		if prefix.Contains(generatedIP) {
			return &Address{
				PublicAddress: PublicAddress{
					IP:        generatedIP,
					Hash:      AddressDigestAlg,
					Type:      "Ed25519",
					PublicKey: pubKey,
				},
				PrivateKey: privKey,
			}, nil
		}
	}

	return nil, nil
}

// DigestToAddress derives an IP address from the given parameters.
func DigestToAddress(digestAlg Hash, keyToolID string, pubKeyData []byte) (ip netip.Addr, err error) {
	// Digest to IP.
	digest := digestAlg.Digest(makeDigestData(keyToolID, pubKeyData))
	if len(digest) < 16 {
		return netip.Addr{}, fmt.Errorf("digest has only %d/16 of required bytes", len(digest))
	}
	ip = netip.AddrFrom16([16]byte(digest[:16]))

	return ip, nil
}

// VerifyAddressKey checks if the given IP address matches the digest of the given key type and data.
func VerifyAddressKey(ip netip.Addr, digestAlg Hash, keyType string, pubKeyData []byte) error {
	// Check parameters.
	switch {
	case !ip.IsValid():
		return errors.New("IP not specified")
	case digestAlg == "":
		return errors.New("hash algorithm not specified")
	case keyType == "":
		return errors.New("key type not specified")
	case len(pubKeyData) == 0:
		return errors.New("key not specified")
	}
	// Make comparison.
	digest := digestAlg.Digest(makeDigestData(keyType, pubKeyData))
	if len(digest) < 16 {
		return fmt.Errorf("digest has only %d/16 of required bytes", len(digest))
	}
	if subtle.ConstantTimeCompare(digest[:16], ip.AsSlice()) != 1 {
		return errors.New("address verification failed, key does not match address")
	}

	return nil
}

func makeDigestData(keyToolID string, pubKeyData []byte) []byte {
	digestData := make([]byte, 4, 1+len(keyToolID)+len(pubKeyData))
	keyToolData := []byte(keyToolID)

	// Check sizes.
	if len(keyToolData) > 0xFF || len(pubKeyData) > 0xFFFF {
		// Will be triggered in tests or generation at worst, but not in router.
		panic("sizes out of bound")
	}

	// Metadata.
	digestData[0] = 1                                   // Version
	digestData[1] = uint8(len(keyToolData))             // Key Type Length
	PutUint16(digestData[2:4], uint16(len(pubKeyData))) // Public Key Length

	// Data.
	digestData = append(digestData, keyToolData...) // Key Type
	digestData = append(digestData, pubKeyData...)  // Public Key

	return digestData
}

// AddressStorage is an address in a storable format.
type AddressStorage struct {
	IP         string `json:"ip,omitempty"      yaml:"ip,omitempty"`
	Hash       string `json:"hash,omitempty"    yaml:"hash,omitempty"`
	Type       string `json:"type,omitempty"    yaml:"type,omitempty"`
	PublicKey  string `json:"public,omitempty"  yaml:"public,omitempty"`
	PrivateKey string `json:"private,omitempty" yaml:"private,omitempty"`
}

// Store returns the address in a storable format.
func (addr *Address) Store() AddressStorage {
	return AddressStorage{
		IP:         addr.IP.String(),
		Hash:       string(addr.Hash),
		Type:       addr.Type,
		PublicKey:  hex.EncodeToString(addr.PublicKey),
		PrivateKey: hex.EncodeToString(addr.PrivateKey),
	}
}

// AddressFromStorage loads and verifies an address from storage.
func AddressFromStorage(s AddressStorage) (*Address, error) {
	ip, err := netip.ParseAddr(s.IP)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IP: %w", err)
	}
	pubKey, err := hex.DecodeString(s.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	privKey, err := hex.DecodeString(s.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	addr := &Address{
		PublicAddress: PublicAddress{
			IP:        ip,
			Hash:      Hash(s.Hash),
			Type:      s.Type,
			PublicKey: pubKey,
		},
		PrivateKey: privKey,
	}
	if len(addr.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d (should be %d)", len(addr.PrivateKey), ed25519.PrivateKeySize)
	}
	if len(addr.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid private key size: %d (should be %d)", len(addr.PublicKey), ed25519.PublicKeySize)
	}
	if !addr.Hash.IsValid() {
		return nil, errors.New("invalid address hash algorithm")
	}
	if err := addr.VerifyAddress(); err != nil {
		return nil, err
	}
	if err := addr.verifyPrivateKey(); err != nil {
		return nil, err
	}
	return addr, nil
}

// VerifyAddress check if the address is a mycoria IP and calls VerifyAddressKey.
func (addr *PublicAddress) VerifyAddress() error {
	// Check if the address is in the base prefix.
	if !BaseNetPrefix.Contains(addr.IP) {
		return errors.New("invalid ip address")
	}

	return VerifyAddressKey(addr.IP, addr.Hash, addr.Type, addr.PublicKey)
}

var privateKeyVerificationData = []byte("The quick brown fox jumps over the lazy dog. ")

func (addr *Address) verifyPrivateKey() error {
	if !addr.PublicKey.Equal(addr.PrivateKey.Public()) {
		return errors.New("private and public key do not fit together: public keys do not match")
	}
	if !addr.VerifySig(privateKeyVerificationData, addr.Sign(privateKeyVerificationData)) {
		return errors.New("private and public key do not fit together: sign/verify failed")
	}
	return nil
}
