package spiffe

import (
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func TestParseAndVerify_RawLeaf(t *testing.T) {
	ca, _ := NewCA("vsp.local")
	svid, _ := ca.Mint("spiffe://vsp.local/ns/billing/sa/multi-bill-svc")
	if _, _, err := x509svid.ParseAndVerify([][]byte{svid.Certificates[0].Raw}, ca.Bundle()); err != nil {
		t.Fatalf("ParseAndVerify raw leaf: %v", err)
	}
}

// Full mutual-TLS handshake between a server and client SVID from the same CA.
func TestMTLSHandshake(t *testing.T) {
	ca, _ := NewCA("vsp.local")
	serverSVID, _ := ca.Mint("spiffe://vsp.local/ns/wallet/sa/vsp-wallet-svc")
	clientSVID, _ := ca.Mint("spiffe://vsp.local/ns/billing/sa/multi-bill-svc")

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	srvCfg := MTLSServerConfig(serverSVID, ca.Bundle())
	cliCfg := MTLSClientConfig(clientSVID, ca.Bundle())

	errc := make(chan error, 1)
	go func() {
		sc := tls.Server(s, srvCfg)
		if err := sc.Handshake(); err != nil {
			errc <- err
			return
		}
		_, _ = io.Copy(io.Discard, sc)
		errc <- nil
	}()

	cc := tls.Client(c, cliCfg)
	if err := cc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	cc.Close()
	if err := <-errc; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}
