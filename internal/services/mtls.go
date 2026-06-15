package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"

	"github.com/pmsbkhn/authorization-zta/internal/identity/spiffe"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// mTLS environment. The production path is a live SPIRE agent:
//
//	SPIFFE_ENDPOINT_SOCKET  Workload API socket (e.g. unix:///tmp/agent.sock).
//	                        When set, SVIDs (and rotation) come from SPIRE.
//
// The self-contained fallback loads static SVID material from disk (issued by
// cmd/svidmint), mirroring what SPIRE would otherwise deliver:
//
//	SVID_CERT          PEM cert chain (the workload's X509-SVID)
//	SVID_KEY           PEM private key
//	SVID_BUNDLE        PEM trust bundle (CA roots)
//	SVID_TRUST_DOMAIN  trust domain (default vsp.local)
const (
	envSPIFFESocket    = "SPIFFE_ENDPOINT_SOCKET"
	envSVIDCert        = "SVID_CERT"
	envSVIDKey         = "SVID_KEY"
	envSVIDBundle      = "SVID_BUNDLE"
	envSVIDTrustDomain = "SVID_TRUST_DOMAIN"
)

func trustDomain() string {
	if td := os.Getenv(envSVIDTrustDomain); td != "" {
		return td
	}
	return "vsp.local"
}

// workloadAPISource returns a SPIRE-backed Source when SPIFFE_ENDPOINT_SOCKET is
// set, else (nil, false). The source lives for the process lifetime.
func workloadAPISource() (*spiffe.Source, bool, error) {
	sock := os.Getenv(envSPIFFESocket)
	if sock == "" {
		return nil, false, nil
	}
	src, err := spiffe.FromWorkloadAPI(context.Background(), trustDomain(), sock)
	if err != nil {
		return nil, false, fmt.Errorf("services: spire workload api: %w", err)
	}
	return src, true, nil
}

// mtlsConfigured reports whether the SVID material is present in the environment.
func mtlsConfigured() bool {
	return os.Getenv(envSVIDCert) != "" && os.Getenv(envSVIDKey) != "" && os.Getenv(envSVIDBundle) != ""
}

// loadStaticSVID loads the SVID + trust bundle from the SVID_* file paths.
func loadStaticSVID() (*x509svid.SVID, *x509bundle.Bundle, error) {
	svid, err := spiffe.LoadSVID(os.Getenv(envSVIDCert), os.Getenv(envSVIDKey))
	if err != nil {
		return nil, nil, fmt.Errorf("services: load svid: %w", err)
	}
	bundle, err := spiffe.LoadBundle(trustDomain(), os.Getenv(envSVIDBundle))
	if err != nil {
		return nil, nil, fmt.Errorf("services: load bundle: %w", err)
	}
	return svid, bundle, nil
}

// LoadServerTLS builds a server mTLS config. It prefers a live SPIRE agent
// (SPIFFE_ENDPOINT_SOCKET) and otherwise loads static SVID files. The bool
// reports whether mTLS is enabled; when false the caller serves plain HTTP.
func LoadServerTLS() (*tls.Config, bool, error) {
	if src, ok, err := workloadAPISource(); err != nil {
		return nil, false, err
	} else if ok {
		return src.ServerTLS(), true, nil
	}
	if !mtlsConfigured() {
		return nil, false, nil
	}
	svid, bundle, err := loadStaticSVID()
	if err != nil {
		return nil, false, err
	}
	return spiffe.MTLSServerConfig(svid, bundle), true, nil
}

// LoadClientTLS builds a client mTLS config (SPIRE agent first, then files).
func LoadClientTLS() (*tls.Config, bool, error) {
	if src, ok, err := workloadAPISource(); err != nil {
		return nil, false, err
	} else if ok {
		return src.ClientTLS(), true, nil
	}
	if !mtlsConfigured() {
		return nil, false, nil
	}
	svid, bundle, err := loadStaticSVID()
	if err != nil {
		return nil, false, err
	}
	return spiffe.MTLSClientConfig(svid, bundle), true, nil
}
