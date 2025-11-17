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

	"github.com/mycoria/crop"
	"github.com/tevino/abool"
)

// Default Cryptography.
const (
	AddressDigestAlg = crop.BLAKE3
	AddressKeyToolID = crop.KeyPairTypeEd25519
)

// Errors.
var (
	ErrMaxTriesReached = errors.New("maximum tries to generate address reached")
)

// Address is an address with the associated private key.
type Address struct {
	PublicAddress `cbor:"-" json:"-" yaml:"-"` // Prevent serializing.

	PrivateKey ed25519.PrivateKey   `cbor:"-" json:"-" yaml:"-"` // Prevent serializing.
	KeyPair    *crop.Ed25519KeyPair `cbor:"-" json:"-" yaml:"-"` // Prevent serializing.
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
	Hash      crop.Hash         `cbor:"h,omitempty" json:"hash,omitempty" yaml:"hash,omitempty"`
	Type      crop.KeyPairType  `cbor:"t,omitempty" json:"type,omitempty" yaml:"type,omitempty"`
	PublicKey ed25519.PublicKey `cbor:"k,omitempty" json:"key,omitempty"  yaml:"key,omitempty"`
	Easing    uint64            `cbor:"e,omitempty" json:"easing,omitempty"  yaml:"easing,omitempty"`
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
	addr, n, err := generateAddressSingleCore(ctx, []netip.Prefix{PrivacyAddressPrefix}, nil, 25600, 0)
	if err != nil {
		return nil, 0, err
	}

	// Set metadata and return.
	return addr, n, nil
}

// GenerateRoutableAddress generates a new routable address within the given acceptable prefixes.
func GenerateRoutableAddress(ctx context.Context, acceptablePrefixes, ignorePrefixes []netip.Prefix, maxEasing uint64) (*Address, int, error) {
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
	return generateAddressWithTries(ctx, acceptablePrefixes, ignorePrefixes, maxTries, maxEasing)
}

func generateAddressWithTries(ctx context.Context, acceptablePrefixes, ignorePrefixes []netip.Prefix, tries int, maxEasing uint64) (*Address, int, error) {
	if tries < 10000 || runtime.NumCPU() < 2 {
		return generateAddressSingleCore(ctx, acceptablePrefixes, ignorePrefixes, tries, maxEasing)
	}
	return generateAddressMultiCore(ctx, acceptablePrefixes, ignorePrefixes, tries, maxEasing)
}

func generateAddressSingleCore(ctx context.Context, acceptablePrefixes, ignorePrefixes []netip.Prefix, tries int, maxEasing uint64) (*Address, int, error) {
	for i := 1; i <= tries; i++ {
		addr, _, err := tryToGenerateAddress(acceptablePrefixes, ignorePrefixes, maxEasing)
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

func generateAddressMultiCore(ctx context.Context, acceptablePrefixes, ignorePrefixes []netip.Prefix, tries int, maxEasing uint64) (*Address, int, error) {
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
				addr, _, err := tryToGenerateAddress(acceptablePrefixes, ignorePrefixes, maxEasing)
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

func tryToGenerateAddress(acceptablePrefixes, ignorePrefixes []netip.Prefix, maxEasing uint64) (*Address, uint64, error) {
	// Generate new key pair.
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, 0, err
	}

	// Prepare for hashing.
	h := AddressDigestAlg.New()
	baseBuf := makeAddressDigestData(crop.KeyPairTypeEd25519, pubKey)
	easingBuf := make([]byte, 8)
	digestBuf := make([]byte, 512/8)

	for easing := uint64(0); easing <= maxEasing; easing++ {
		// Make digest.
		h.Reset()
		_, _ = h.Write(baseBuf) // hash.Hash never returns an error on Write().
		if easing > 0 {
			PutUint64(easingBuf, easing)
			h.Write(easingBuf)
		}
		digestBuf = digestBuf[:0]
		digestBuf = h.Sum(digestBuf)

		// Make address from digest.
		generatedIP, err := digestToAddress(digestBuf)
		if err != nil {
			return nil, 0, err
		}

		// Skip if address is in internal scope.
		if InternalPrefix.Contains(generatedIP) {
			return nil, 0, nil
		}

		// Skip if range should be ignored.
		for _, ignore := range ignorePrefixes {
			if ignore.Contains(generatedIP) {
				return nil, 0, nil
			}
		}

		// Check if address matches of the acceptable prefixes.
		for _, prefix := range acceptablePrefixes {
			if prefix.Contains(generatedIP) {
				return &Address{
					PublicAddress: PublicAddress{
						IP:        generatedIP,
						Hash:      AddressDigestAlg,
						Type:      crop.KeyPairTypeEd25519,
						PublicKey: pubKey,
						Easing:    easing,
					},
					PrivateKey: privKey,
					KeyPair:    crop.MakeEd25519KeyPair(privKey, pubKey),
				}, easing + 1, nil
			}
		}
	}

	return nil, 0, nil
}

// VerifyAddressKey checks if the given IP address matches the digest of the given key type and data.
func VerifyAddressKey(ip netip.Addr, digestAlg crop.Hash, keyType crop.KeyPairType, pubKeyData []byte, easing uint64) error {
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
	digest := makeAddressDigest(digestAlg, keyType, pubKeyData, easing)
	if len(digest) < 16 {
		return fmt.Errorf("digest has only %d/16 of required bytes", len(digest))
	}
	if subtle.ConstantTimeCompare(digest[:16], ip.AsSlice()) != 1 {
		return errors.New("address verification failed, key does not match address")
	}

	return nil
}

// DigestToAddress derives an IP address from the given parameters.
func DigestToAddress(digestAlg crop.Hash, keyToolID crop.KeyPairType, pubKeyData []byte, easing uint64) (ip netip.Addr, err error) {
	digest := makeAddressDigest(digestAlg, keyToolID, pubKeyData, easing)
	return digestToAddress(digest)
}

func digestToAddress(digest []byte) (ip netip.Addr, err error) {
	// Digest to IP.
	if len(digest) < 16 {
		return netip.Addr{}, fmt.Errorf("digest has only %d/16 of required bytes", len(digest))
	}
	ip = netip.AddrFrom16([16]byte(digest[:16]))

	return ip, nil
}

func makeAddressDigest(digestAlg crop.Hash, keyToolID crop.KeyPairType, pubKeyData []byte, easing uint64) []byte {
	// Create hasher.
	h := digestAlg.New()

	// Hash data.
	_, _ = h.Write(makeAddressDigestData(keyToolID, pubKeyData))

	// Hash easing, if used.
	if easing > 0 {
		easingBuf := make([]byte, 8)
		PutUint64(easingBuf, easing)
		h.Write(easingBuf)
	}

	// Return result.
	defer h.Reset()
	return h.Sum(nil)
}

func makeAddressDigestData(keyToolID crop.KeyPairType, pubKeyData []byte) []byte {
	// Check sizes.
	keyToolData := []byte(keyToolID)
	if len(keyToolData) > 0xFF || len(pubKeyData) > 0xFFFF {
		// Will be triggered in tests or generation at worst, but not in router.
		panic("sizes out of bound")
	}

	// Create buf in the right size.
	buf := make([]byte, 4+len(keyToolID)+len(pubKeyData))

	// Metadata.
	buf[0] = 1                                   // Version
	buf[1] = uint8(len(keyToolData))             // Key Type Length
	PutUint16(buf[2:4], uint16(len(pubKeyData))) // Public Key Length

	// Data.
	if copy(buf[4:], keyToolData) != len(keyToolData) {
		panic("buf too small")
	}
	if copy(buf[4+len(keyToolData):], pubKeyData) != len(pubKeyData) {
		panic("buf too small")
	}

	return buf
}

// AddressStorage is an address in a storable format.
type AddressStorage struct {
	IP         string           `json:"ip,omitzero"      yaml:"ip,omitzero"`
	Hash       crop.Hash        `json:"hash,omitzero"    yaml:"hash,omitzero"`
	Type       crop.KeyPairType `json:"type,omitzero"    yaml:"type,omitzero"`
	PublicKey  string           `json:"public,omitzero"  yaml:"public,omitzero"`
	PrivateKey string           `json:"private,omitzero" yaml:"private,omitzero"`
	Easing     uint64           `json:"easing,omitzero"  yaml:"easing,omitzero"`
}

// Store returns the address in a storable format.
func (addr *Address) Store() AddressStorage {
	return AddressStorage{
		IP:         addr.IP.String(),
		Hash:       addr.Hash,
		Type:       addr.Type,
		PublicKey:  hex.EncodeToString(addr.PublicKey),
		PrivateKey: hex.EncodeToString(addr.PrivateKey),
		Easing:     addr.Easing,
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
			Hash:      s.Hash,
			Type:      s.Type,
			PublicKey: pubKey,
			Easing:    s.Easing,
		},
		PrivateKey: privKey,
		KeyPair: crop.MakeEd25519KeyPair(
			ed25519.PrivateKey(privKey),
			ed25519.PublicKey(pubKey),
		),
	}
	if len(addr.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d (should be %d)", len(addr.PrivateKey), ed25519.PrivateKeySize)
	}
	if len(addr.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d (should be %d)", len(addr.PublicKey), ed25519.PublicKeySize)
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

// AddressFromKeyPair loads and verifies an address from a key pair and custom data.
func AddressFromKeyPair(keyPair crop.KeyPair, ip netip.Addr, hash crop.Hash, easing uint64) (*Address, error) {
	// Convert to Ed25519 type.
	ed25519KeyPair, ok := keyPair.(*crop.Ed25519KeyPair)
	if !ok {
		return nil, errors.New("mycoria currently only supports Ed25519 keys")
	}

	// Create and check address.
	addr := &Address{
		PublicAddress: PublicAddress{
			IP:        ip,
			Hash:      hash,
			Type:      keyPair.Type(),
			PublicKey: ed25519.PublicKey(ed25519KeyPair.PublicKeyData()),
			Easing:    easing,
		},
		PrivateKey: ed25519.PrivateKey(ed25519KeyPair.PrivateKeyData()),
		KeyPair: crop.MakeEd25519KeyPair(
			ed25519.PrivateKey(ed25519KeyPair.PrivateKeyData()),
			ed25519.PublicKey(ed25519KeyPair.PublicKeyData()),
		),
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

	return VerifyAddressKey(addr.IP, addr.Hash, addr.Type, addr.PublicKey, addr.Easing)
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
