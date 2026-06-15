package caep_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pmsbkhn/authorization-zta/internal/signals/caep"
)

func TestSET_SignVerify(t *testing.T) {
	s := caep.NewSigner([]byte("k"))
	set, err := s.Sign(caep.Event{Type: caep.EventSessionRevoked, Subject: "u-1"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	e, err := s.Verify(set)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if e.Type != caep.EventSessionRevoked || e.Subject != "u-1" {
		t.Fatalf("event mismatch: %+v", e)
	}
	if _, err := s.Verify("x" + set[1:]); err == nil {
		t.Fatal("expected tampered SET to fail")
	}
	if _, err := caep.NewSigner([]byte("other")).Verify(set); err == nil {
		t.Fatal("expected wrong-secret verify to fail")
	}
}

// A pushed SET must flow transmitter → receiver → cache and flip IsRevoked.
func TestPushUpdatesCache(t *testing.T) {
	signer := caep.NewSigner([]byte("shared"))
	cache := caep.NewRevocationCache()
	rcv := caep.NewReceiver(signer, cache)

	srv := httptest.NewServer(rcv.Handler())
	defer srv.Close()

	tx := caep.NewTransmitter(signer, []string{srv.URL})
	if cache.IsRevoked("u-1") {
		t.Fatal("precondition: u-1 not revoked")
	}
	if err := tx.Emit(context.Background(), caep.Event{Type: caep.EventSessionRevoked, Subject: "u-1"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !cache.IsRevoked("u-1") {
		t.Fatal("expected u-1 revoked after push")
	}

	// Restore clears it.
	if err := tx.Emit(context.Background(), caep.Event{Type: caep.EventSessionRestored, Subject: "u-1"}); err != nil {
		t.Fatalf("emit restore: %v", err)
	}
	if cache.IsRevoked("u-1") {
		t.Fatal("expected u-1 not revoked after restore")
	}
}

func TestReceiver_RejectsForgedSET(t *testing.T) {
	cache := caep.NewRevocationCache()
	rcv := caep.NewReceiver(caep.NewSigner([]byte("real")), cache)
	srv := httptest.NewServer(rcv.Handler())
	defer srv.Close()

	// Forge with a different secret → receiver must reject and not mutate cache.
	forged, _ := caep.NewSigner([]byte("forged")).Sign(caep.Event{Type: caep.EventSessionRevoked, Subject: "u-1"})
	resp, err := http.Post(srv.URL, "application/secevent+jwt", strings.NewReader(forged))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for forged SET, got %d", resp.StatusCode)
	}
	if cache.IsRevoked("u-1") {
		t.Fatal("forged SET must not revoke")
	}
}
