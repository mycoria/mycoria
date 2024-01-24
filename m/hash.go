package m

import (
	"crypto"
	_ "crypto/sha256" // Register algorithms.
	_ "crypto/sha512" // Register algorithms.
	"hash"

	"github.com/zeebo/blake3"
	_ "golang.org/x/crypto/blake2b" // Register algorithms.
	_ "golang.org/x/crypto/blake2s" // Register algorithms.
	_ "golang.org/x/crypto/sha3"    // Register algorithms.
)

// Hash is a hash algorithm.
type Hash string

// Hashes
//
//nolint:golint,stylecheck
const (
	// SHA2.
	SHA2_224     Hash = "SHA2_224"
	SHA2_256     Hash = "SHA2_256"
	SHA2_384     Hash = "SHA2_384"
	SHA2_512     Hash = "SHA2_512"
	SHA2_512_224 Hash = "SHA2_512_224"
	SHA2_512_256 Hash = "SHA2_512_256"

	// SHA3.
	SHA3_224 Hash = "SHA3_224"
	SHA3_256 Hash = "SHA3_256"
	SHA3_384 Hash = "SHA3_384"
	SHA3_512 Hash = "SHA3_512"

	// BLAKE2.
	BLAKE2s_256 Hash = "BLAKE2s_256"
	BLAKE2b_256 Hash = "BLAKE2b_256"
	BLAKE2b_384 Hash = "BLAKE2b_384"
	BLAKE2b_512 Hash = "BLAKE2b_512"

	// BLAKE3.
	BLAKE3 Hash = "BLAKE3"
)

// New returns a new hash.Hash.
func (h Hash) New() hash.Hash {
	switch h {
	// SHA2
	case SHA2_224:
		return crypto.SHA224.New()
	case SHA2_256:
		return crypto.SHA256.New()
	case SHA2_384:
		return crypto.SHA384.New()
	case SHA2_512:
		return crypto.SHA512.New()
	case SHA2_512_224:
		return crypto.SHA512_224.New()
	case SHA2_512_256:
		return crypto.SHA512_256.New()

	// SHA3
	case SHA3_224:
		return crypto.SHA3_224.New()
	case SHA3_256:
		return crypto.SHA3_256.New()
	case SHA3_384:
		return crypto.SHA3_384.New()
	case SHA3_512:
		return crypto.SHA3_512.New()

		// BLAKE2
	case BLAKE2s_256:
		return crypto.BLAKE2s_256.New()
	case BLAKE2b_256:
		return crypto.BLAKE2b_256.New()
	case BLAKE2b_384:
		return crypto.BLAKE2b_384.New()
	case BLAKE2b_512:
		return crypto.BLAKE2b_512.New()

		// BLAKE3
	case BLAKE3:
		return blake3.New()

	default:
		return nil
	}
}

// IsValid returns whether the hash is known.
func (h Hash) IsValid() bool {
	return h.New() != nil
}

// Digest calculate and returns the hash sum over the given data.
func (h Hash) Digest(data []byte) []byte {
	hasher := h.New()
	if hasher == nil {
		// TODO: Find a better way to handle this.
		panic("invalid hash algorithm")
	}

	// Calculate and return.
	_, _ = hasher.Write(data) // Never returns an error.
	defer hasher.Reset()      // Internal state may leak data if kept in memory.
	return hasher.Sum(nil)
}
