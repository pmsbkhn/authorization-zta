package spiffe

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// WriteSVID writes an SVID's certificate chain and private key as PEM files.
// This is what a SPIRE agent would deliver to a workload; here the svidmint tool
// writes them to disk for the binaries to load.
func WriteSVID(certPath, keyPath string, svid *x509svid.SVID) error {
	var certPEM []byte
	for _, c := range svid.Certificates {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("spiffe: write cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
	if err != nil {
		return fmt.Errorf("spiffe: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("spiffe: write key: %w", err)
	}
	return nil
}

// WriteBundle writes a trust bundle (CA roots) as a PEM file.
func WriteBundle(path string, bundle *x509bundle.Bundle) error {
	b, err := bundle.Marshal()
	if err != nil {
		return fmt.Errorf("spiffe: marshal bundle: %w", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("spiffe: write bundle: %w", err)
	}
	return nil
}

// LoadSVID loads an X509-SVID from PEM cert + key files.
func LoadSVID(certPath, keyPath string) (*x509svid.SVID, error) {
	return x509svid.Load(certPath, keyPath)
}

// LoadBundle loads a trust bundle for the given trust domain from a PEM file.
func LoadBundle(trustDomain, path string) (*x509bundle.Bundle, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, fmt.Errorf("spiffe: trust domain: %w", err)
	}
	return x509bundle.Load(td, path)
}
