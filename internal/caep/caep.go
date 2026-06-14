// Package caep implements a minimal Continuous Access Evaluation Protocol /
// Shared Signals Framework loop (design-v3 §6.2). The Control Plane pushes
// Security Event Tokens (SETs) — session revoked, posture/assurance change — to
// PEP receivers, which update an in-memory cache. This closes the Zero Trust gap
// left by cached decisions: a revoked session is denied at the PEP within
// milliseconds, even while a previously issued decision token is still inside
// its TTL.
//
// The SET is a signed token (HS256 over a compact JSON payload) modelled on
// RFC 8417; the trust model here is a shared transmitter/receiver secret.
package caep

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

// Event types understood by VSP PEPs.
const (
	// EventSessionRevoked: the subject's session is no longer valid — deny.
	EventSessionRevoked = "session-revoked"
	// EventSessionRestored: clears a prior revocation (e.g. re-login).
	EventSessionRestored = "session-restored"
)

// Event is the security event carried by a SET.
type Event struct {
	Type     string `json:"type"`
	Subject  string `json:"sub"`
	IssuedAt int64  `json:"iat"`
}

// Signer mints and verifies SETs with a shared secret.
type Signer struct {
	secret []byte
	now    func() time.Time
}

// NewSigner returns a SET signer/verifier.
func NewSigner(secret []byte) *Signer { return &Signer{secret: secret, now: time.Now} }

// Sign produces a signed SET string for the event.
func (s *Signer) Sign(e Event) (string, error) {
	e.IssuedAt = s.now().Unix()
	payload, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("caep: marshal event: %w", err)
	}
	body := b64(payload)
	return body + "." + b64(s.mac(body)), nil
}

// Verify checks a SET's signature and returns its event.
func (s *Signer) Verify(set string) (Event, error) {
	body, sig, ok := strings.Cut(set, ".")
	if !ok {
		return Event{}, errors.New("caep: malformed SET")
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return Event{}, fmt.Errorf("caep: decode sig: %w", err)
	}
	if !hmac.Equal(want, s.mac(body)) {
		return Event{}, errors.New("caep: SET signature mismatch")
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Event{}, fmt.Errorf("caep: decode body: %w", err)
	}
	var e Event
	if err := json.Unmarshal(payload, &e); err != nil {
		return Event{}, fmt.Errorf("caep: unmarshal event: %w", err)
	}
	return e, nil
}

func (s *Signer) mac(body string) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(body))
	return m.Sum(nil)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
