// Command nodecert generates the PKI a production-grade SPIRE deployment needs
// (M8), standing in for an organization's existing CA tooling:
//
//   - upstream-root.{crt,key} — the org root CA. SPIRE's UpstreamAuthority "disk"
//     signs its intermediate with this, so issued SVIDs chain to a real root
//     instead of a SPIRE self-signed CA. It is also the agent's trust bundle.
//   - node-ca.{crt,key}       — the CA that signs agent node certificates. The
//     server's x509pop NodeAttestor trusts this bundle.
//   - agent-svid.{crt,key}    — the agent's node certificate (leaf signed by
//     node-ca) that it presents for x509pop attestation. No bearer token.
//
// Keys are written 0600 and are NOT committed (see deploy/.gitignore); regenerate
// with deploy/run.sh. Production would source these from Vault/PKI, not a tool.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	out := flag.String("out", "./certs", "output directory")
	agentCN := flag.String("agent-cn", "spire-agent", "common name for the agent node cert")
	flag.Parse()
	if err := run(*out, *agentCN); err != nil {
		fmt.Fprintln(os.Stderr, "nodecert:", err)
		os.Exit(1)
	}
}

func run(out, agentCN string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}

	upRootCert, upRootKey, err := newCA("VSP Upstream Root CA")
	if err != nil {
		return err
	}
	if err := writePair(out, "upstream-root", upRootCert, upRootKey); err != nil {
		return err
	}

	nodeCACert, nodeCAKey, err := newCA("VSP Node CA")
	if err != nil {
		return err
	}
	if err := writePair(out, "node-ca", nodeCACert, nodeCAKey); err != nil {
		return err
	}

	agentCert, agentKey, err := newLeaf(agentCN, nodeCACert, nodeCAKey)
	if err != nil {
		return err
	}
	if err := writePair(out, "agent-svid", agentCert, agentKey); err != nil {
		return err
	}

	fmt.Printf("wrote upstream-root, node-ca, agent-svid to %s\n", out)
	return nil
}

func newCA(cn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func newLeaf(cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func writePair(dir, name string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(filepath.Join(dir, name+".crt"), certPEM, 0o644); err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return os.WriteFile(filepath.Join(dir, name+".key"), keyPEM, 0o600)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}
