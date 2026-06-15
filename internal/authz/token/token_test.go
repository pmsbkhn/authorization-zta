package token

import (
	"testing"
	"time"
)

func TestIssueVerify_RoundTrip(t *testing.T) {
	iss := NewIssuer([]byte("secret"), 5*time.Minute)
	c := Claims{Subject: "u-1", Action: "wallet:settle", Resource: "wallet:account/acc-1", AAL: "AAL3"}

	tok, err := iss.Issue(c)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Subject != "u-1" || got.Action != "wallet:settle" || got.AAL != "AAL3" {
		t.Fatalf("claims round-trip mismatch: %+v", got)
	}
	if got.ExpiresAt <= got.IssuedAt {
		t.Fatalf("exp (%d) must be after iat (%d)", got.ExpiresAt, got.IssuedAt)
	}
}

func TestVerify_RejectsTampered(t *testing.T) {
	iss := NewIssuer([]byte("secret"), 5*time.Minute)
	tok, _ := iss.Issue(Claims{Subject: "u-1"})

	// Flip a character in the body.
	tampered := "x" + tok[1:]
	if _, err := iss.Verify(tampered); err == nil {
		t.Fatal("expected signature mismatch on tampered token")
	}
}

func TestVerify_RejectsWrongSecret(t *testing.T) {
	tok, _ := NewIssuer([]byte("secret-a"), time.Minute).Issue(Claims{Subject: "u-1"})
	if _, err := NewIssuer([]byte("secret-b"), time.Minute).Verify(tok); err == nil {
		t.Fatal("expected verification to fail under a different secret")
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	iss := NewIssuer([]byte("secret"), time.Minute)
	iss.now = func() time.Time { return base }
	tok, _ := iss.Issue(Claims{Subject: "u-1"})

	// Advance the clock past expiry.
	iss.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := iss.Verify(tok); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}
