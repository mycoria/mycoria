package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/mycoria/crop"
)

const (
	tokenSecretSize = 32
	tokenNonceSize  = 8
)

// RequestToken is used for CSRF protection.
type RequestToken struct {
	Nonce string `json:"nonce"`
	Token string `json:"token"`
}

// CreateRequestToken creates a new request token with the given actions as context.
func (d *Dashboard) CreateRequestToken(actions ...string) (*RequestToken, error) {
	// Generate nonce.
	nonceData := make([]byte, tokenNonceSize)
	_, err := rand.Read(nonceData)
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceData)

	// Return Request Token.
	return &RequestToken{
		Nonce: nonce,
		Token: d.calculateToken(nonce, actions...),
	}, nil
}

// CheckRequestToken checks the given token and action context.
// The given actions must be same as when the token was created.
func (d *Dashboard) CheckRequestToken(nonce, token string, actions ...string) (ok bool) {
	return subtle.ConstantTimeCompare(
		[]byte(d.calculateToken(nonce, actions...)),
		[]byte(token),
	) == 1
}

func (d *Dashboard) calculateToken(nonce string, actions ...string) string {
	hasher := crop.BLAKE2b_256.New()

	// Write secret, nonce and lengths.
	_, _ = hasher.Write(d.tokenSecret)
	_, _ = hasher.Write([]byte{uint8(len(nonce)), uint8(len(actions))})
	_, _ = hasher.Write([]byte(nonce))

	// Write actions.
	for i, action := range actions {
		_, _ = hasher.Write([]byte{uint8(i), uint8(len(action))})
		_, _ = hasher.Write([]byte(action))
	}

	defer hasher.Reset() // Internal state may leak data if kept in memory.
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}
