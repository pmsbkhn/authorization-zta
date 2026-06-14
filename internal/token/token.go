// Package token issues and verifies decision tokens: short-lived, signed proofs
// that the PDP granted a specific decision. A downstream PEP that already holds a
// valid decision token (e.g. the elevated AAL3 token minted after a step-up) can
// present it to skip re-evaluation for the remainder of the token's TTL.
//
// Milestone-1 uses HMAC (HS256) with a shared secret — adequate for a single
// trust domain. A production multi-issuer deployment would move to asymmetric
// signing (the PDP signs with a private key; PEPs verify with the public key).
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claims is the verifiable payload of a decision token. It binds the token to the
// exact subject/action/resource tuple and assurance level that was authorized, so
// it cannot be replayed against a different request.
//
// ResDigest binds the decision-relevant resource attributes (e.g. amount,
// currency) so a token issued for a low-value settle cannot be replayed to
// authorize a high-value one: any change to the properties changes the digest and
// invalidates the token for fast-path reuse.
type Claims struct {
	Subject       string `json:"sub"`
	Action        string `json:"act"`
	Resource      string `json:"res"`
	AAL           string `json:"aal"`
	ResDigest     string `json:"rd,omitempty"`
	CorrelationID string `json:"cid,omitempty"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
}

// ResourceDigest returns a stable hash of resource properties. encoding/json
// sorts map keys, so the encoding (and thus the digest) is deterministic. Both
// the PDP (when minting) and a PEP (when validating a presented token) compute it
// the same way.
func ResourceDigest(props map[string]any) string {
	b, err := json.Marshal(props)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Issuer mints decision tokens. It is safe for concurrent use.
type Issuer struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time // injectable clock for tests
}

// NewIssuer returns an Issuer signing with secret and the given token TTL.
func NewIssuer(secret []byte, ttl time.Duration) *Issuer {
	return &Issuer{secret: secret, ttl: ttl, now: time.Now}
}

// TTLSeconds is the token lifetime in whole seconds, for the response contract.
func (i *Issuer) TTLSeconds() int { return int(i.ttl.Seconds()) }

// Issue returns a signed token string for the given claims. IssuedAt/ExpiresAt
// are stamped here from the issuer's clock and TTL.
func (i *Issuer) Issue(c Claims) (string, error) {
	now := i.now()
	c.IssuedAt = now.Unix()
	c.ExpiresAt = now.Add(i.ttl).Unix()

	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("token: marshal claims: %w", err)
	}
	body := b64(payload)
	return body + "." + b64(i.sign(body)), nil
}

// Verify checks the signature and expiry of a token and returns its claims.
func (i *Issuer) Verify(tok string) (Claims, error) {
	body, sigPart, ok := strings.Cut(tok, ".")
	if !ok {
		return Claims{}, errors.New("token: malformed (expected body.sig)")
	}
	wantSig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return Claims{}, fmt.Errorf("token: decode signature: %w", err)
	}
	// Constant-time comparison to avoid signature-timing oracles.
	if !hmac.Equal(wantSig, i.sign(body)) {
		return Claims{}, errors.New("token: signature mismatch")
	}

	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Claims{}, fmt.Errorf("token: decode body: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, fmt.Errorf("token: unmarshal claims: %w", err)
	}
	if i.now().Unix() >= c.ExpiresAt {
		return Claims{}, errors.New("token: expired")
	}
	return c, nil
}

func (i *Issuer) sign(body string) []byte {
	m := hmac.New(sha256.New, i.secret)
	m.Write([]byte(body))
	return m.Sum(nil)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
