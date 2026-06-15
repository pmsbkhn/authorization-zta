package spiffe

import (
	"context"
	"testing"
	"time"
)

// The rotating source must hand out a freshly minted SVID after each interval —
// the behaviour SPIRE provides and that mTLS relies on for short-lived certs.
func TestRotatingSource_Rotates(t *testing.T) {
	ca, err := NewCA("vsp.local")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src, err := ca.RotatingSource(ctx, "spiffe://vsp.local/ns/wallet/sa/vsp-wallet-svc", 20*time.Millisecond)
	if err != nil {
		t.Fatalf("rotating source: %v", err)
	}
	defer src.Close()

	first, err := src.svid.GetX509SVID()
	if err != nil {
		t.Fatalf("first svid: %v", err)
	}
	firstSerial := first.Certificates[0].SerialNumber

	// Wait long enough for at least one rotation tick.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		cur, _ := src.svid.GetX509SVID()
		if cur.Certificates[0].SerialNumber.Cmp(firstSerial) != 0 {
			return // rotated
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("SVID did not rotate within the deadline")
}

func TestSource_ServerClientTLS(t *testing.T) {
	ca, _ := NewCA("vsp.local")
	src, err := ca.RotatingSource(context.Background(), "spiffe://vsp.local/ns/wallet/sa/vsp-wallet-svc", time.Hour)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	defer src.Close()
	if src.ServerTLS() == nil || src.ClientTLS() == nil {
		t.Fatal("expected non-nil mTLS configs from rotating source")
	}
}
