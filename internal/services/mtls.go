package services

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/pmsbkhn/authorization-zta/internal/spiffe"
)

// mTLS environment, mirroring what a SPIRE agent would deliver to a workload:
//
//	SVID_CERT          PEM cert chain (the workload's X509-SVID)
//	SVID_KEY           PEM private key
//	SVID_BUNDLE        PEM trust bundle (CA roots)
//	SVID_TRUST_DOMAIN  trust domain (default vsp.local)
const (
	envSVIDCert        = "SVID_CERT"
	envSVIDKey         = "SVID_KEY"
	envSVIDBundle      = "SVID_BUNDLE"
	envSVIDTrustDomain = "SVID_TRUST_DOMAIN"
)

// mtlsConfigured reports whether the SVID material is present in the environment.
func mtlsConfigured() bool {
	return os.Getenv(envSVIDCert) != "" && os.Getenv(envSVIDKey) != "" && os.Getenv(envSVIDBundle) != ""
}

func loadSVIDAndBundle() (cert, bundle string, td string, err error) {
	td = os.Getenv(envSVIDTrustDomain)
	if td == "" {
		td = "vsp.local"
	}
	return os.Getenv(envSVIDCert), os.Getenv(envSVIDBundle), td, nil
}

// LoadServerTLS builds a server mTLS config from the SVID_* environment. The
// bool reports whether mTLS is enabled; when false the caller serves plain HTTP
// (dev mode).
func LoadServerTLS() (*tls.Config, bool, error) {
	if !mtlsConfigured() {
		return nil, false, nil
	}
	svid, err := spiffe.LoadSVID(os.Getenv(envSVIDCert), os.Getenv(envSVIDKey))
	if err != nil {
		return nil, false, fmt.Errorf("services: load svid: %w", err)
	}
	_, bundlePath, td, _ := loadSVIDAndBundle()
	bundle, err := spiffe.LoadBundle(td, bundlePath)
	if err != nil {
		return nil, false, fmt.Errorf("services: load bundle: %w", err)
	}
	return spiffe.MTLSServerConfig(svid, bundle), true, nil
}

// LoadClientTLS builds a client mTLS config from the SVID_* environment.
func LoadClientTLS() (*tls.Config, bool, error) {
	if !mtlsConfigured() {
		return nil, false, nil
	}
	svid, err := spiffe.LoadSVID(os.Getenv(envSVIDCert), os.Getenv(envSVIDKey))
	if err != nil {
		return nil, false, fmt.Errorf("services: load svid: %w", err)
	}
	_, bundlePath, td, _ := loadSVIDAndBundle()
	bundle, err := spiffe.LoadBundle(td, bundlePath)
	if err != nil {
		return nil, false, fmt.Errorf("services: load bundle: %w", err)
	}
	return spiffe.MTLSClientConfig(svid, bundle), true, nil
}
