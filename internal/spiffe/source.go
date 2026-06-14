package spiffe

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Source abstracts where a workload's SVID and trust bundle come from, and
// builds mTLS configs from them. It deliberately mirrors what SPIRE provides:
// the two implementations below are (a) a live SPIRE agent's Workload API and
// (b) an in-process rotating issuer for self-contained runs and tests. Because
// both go through go-spiffe's Source interfaces, the tls.Config re-reads the
// current SVID on every handshake — so rotation is transparent to callers.
type Source struct {
	svid   x509svid.Source
	bundle x509bundle.Source
	td     spiffeid.TrustDomain
	closer func() error
}

// ServerTLS builds the server-side mTLS config (presents the SVID, requires +
// verifies + authorizes peer SVIDs of the trust domain).
func (s *Source) ServerTLS() *tls.Config {
	return tlsconfig.MTLSServerConfig(s.svid, s.bundle, tlsconfig.AuthorizeMemberOf(s.td))
}

// ClientTLS builds the client-side mTLS config.
func (s *Source) ClientTLS() *tls.Config {
	return tlsconfig.MTLSClientConfig(s.svid, s.bundle, tlsconfig.AuthorizeMemberOf(s.td))
}

// Close releases any background resources (Workload API stream / rotation loop).
func (s *Source) Close() error {
	if s.closer != nil {
		return s.closer()
	}
	return nil
}

// FromWorkloadAPI connects to a running SPIRE agent's Workload API and returns a
// Source backed by it. It honors the SPIFFE_ENDPOINT_SOCKET environment variable
// (or pass socketPath explicitly). This is the production path: SPIRE attests the
// workload and rotates its SVID; we just consume it.
func FromWorkloadAPI(ctx context.Context, trustDomain, socketPath string) (*Source, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, fmt.Errorf("spiffe: trust domain: %w", err)
	}
	var opts []workloadapi.X509SourceOption
	if socketPath != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	}
	src, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("spiffe: workload api: %w", err)
	}
	return &Source{svid: src, bundle: src, td: td, closer: src.Close}, nil
}

// RotatingSource issues an SVID for spiffeID from this CA and re-mints it every
// `every`, mimicking SPIRE's SVID rotation. The returned Source serves the
// latest SVID; the rotation loop stops when ctx is cancelled or Close is called.
func (ca *CA) RotatingSource(ctx context.Context, spiffeID string, every time.Duration) (*Source, error) {
	rs := &rotating{ca: ca}
	if err := rs.remint(spiffeID); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	go rs.loop(ctx, spiffeID, every)
	return &Source{
		svid:   rs,
		bundle: ca.Bundle(),
		td:     ca.td,
		closer: func() error { cancel(); return nil },
	}, nil
}

// rotating holds the current SVID behind a mutex and re-mints on a ticker.
type rotating struct {
	ca   *CA
	mu   sync.RWMutex
	svid *x509svid.SVID
}

func (r *rotating) remint(spiffeID string) error {
	svid, err := r.ca.Mint(spiffeID)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.svid = svid
	r.mu.Unlock()
	return nil
}

func (r *rotating) loop(ctx context.Context, spiffeID string, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.remint(spiffeID) // best-effort; keep serving the old SVID on error
		}
	}
}

// GetX509SVID satisfies x509svid.Source — tls.Config calls it per handshake, so
// it always hands out the freshest rotated SVID.
func (r *rotating) GetX509SVID() (*x509svid.SVID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.svid, nil
}
