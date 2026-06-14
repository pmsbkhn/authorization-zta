// Package spiffe is an in-process X.509 certificate authority that issues
// SPIFFE X509-SVIDs and builds mTLS configs from them. It stands in for SPIRE:
// the issuance/CA part is mocked (no SPIRE server/agent), but the resulting
// certificates, the SPIFFE URI-SAN encoding, the mutual-TLS handshake, and the
// peer-identity verification are all real — driven by the official go-spiffe
// library. This is the "SVID/mTLS real, SPIRE control-plane mocked" stance.
//
// The trust bundle this CA produces is what an East-West PEP verifies incoming
// client certificates against; the SPIFFE id carved into a verified peer cert is
// the delegation actor the PDP reasons about, and it can no longer be spoofed by
// a header.
package spiffe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// svidTTL is the leaf SVID lifetime. SPIRE rotates SVIDs frequently; for this
// stand-in a generous fixed lifetime is fine.
const svidTTL = 24 * time.Hour

// CA is a single trust domain's certificate authority.
type CA struct {
	td     spiffeid.TrustDomain
	caCert *x509.Certificate
	caKey  crypto.Signer
}

// NewCA creates a fresh CA for the given trust domain (e.g. "vsp.local").
func NewCA(trustDomain string) (*CA, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, fmt.Errorf("spiffe: trust domain: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: trustDomain + " CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{td: td, caCert: caCert, caKey: key}, nil
}

// TrustDomain returns the CA's trust domain.
func (ca *CA) TrustDomain() spiffeid.TrustDomain { return ca.td }

// Bundle returns the trust bundle (the CA root) that peers verify SVIDs against.
func (ca *CA) Bundle() *x509bundle.Bundle {
	b := x509bundle.New(ca.td)
	b.AddX509Authority(ca.caCert)
	return b
}

// Mint issues an X509-SVID for the given SPIFFE id (which must belong to this
// trust domain). The id is encoded as the certificate's URI SAN — the SPIFFE
// way of carrying workload identity.
func (ca *CA) Mint(spiffeID string) (*x509svid.SVID, error) {
	id, err := spiffeid.FromString(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("spiffe: parse id %q: %w", spiffeID, err)
	}
	if !id.MemberOf(ca.td) {
		return nil, fmt.Errorf("spiffe: id %q is not a member of trust domain %q", spiffeID, ca.td)
	}
	uri, err := url.Parse(id.String())
	if err != nil {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(svidTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// SVIDs are used as both client and server identities.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, key.Public(), ca.caKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{leaf}, PrivateKey: key}, nil
}

// MTLSServerConfig builds a server TLS config that presents svid and verifies +
// authorizes any client SVID from the bundle's trust domain. It takes only the
// SVID and the trust bundle (not the CA key), so a workload can build it from
// what SPIRE would hand it.
//
// go-spiffe sets ClientAuth = RequireAnyClientCert and does all verification in
// its VerifyPeerCertificate callback (chaining against the SPIFFE bundle, not
// crypto/tls's ClientCAs). We deliberately do NOT relax this: a peer with no
// client SVID is dropped at the TLS handshake — the L0 "drop connection"
// behaviour of design-v3 §2, enforced at the channel rather than the app.
func MTLSServerConfig(svid *x509svid.SVID, bundle *x509bundle.Bundle) *tls.Config {
	return tlsconfig.MTLSServerConfig(svid, bundle, tlsconfig.AuthorizeMemberOf(bundle.TrustDomain()))
}

// MTLSClientConfig builds a client TLS config that presents svid and verifies +
// authorizes the server SVID against the bundle's trust domain.
func MTLSClientConfig(svid *x509svid.SVID, bundle *x509bundle.Bundle) *tls.Config {
	return tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeMemberOf(bundle.TrustDomain()))
}

func serial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, _ := rand.Int(rand.Reader, max)
	return n
}
