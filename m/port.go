package m

import (
	"crypto/rand"
	"math/big"
)

// GetRandomPrivatePort returns a random private port to use.
func GetRandomPrivatePort() (uint16, error) {
	p, err := rand.Int(rand.Reader, big.NewInt(9998))
	if err != nil {
		return 0, err
	}

	return uint16(p.Int64() + 50001), nil
}
