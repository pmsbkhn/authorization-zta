// Package bundlestore is a real S3 (MinIO) implementation of pip.PolicyStore:
// the PDP pulls its compiled OPA bundle from an immutable, versioned object
// store instead of embedding it (design-v3 §5.3). The bucket is created with
// versioning + object lock so a published bundle can never be overwritten —
// every version is retained for safe rollback and audit.
package bundlestore

import (
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/pmsbkhn/authorization-zta/internal/ports/pip"
)

// Config addresses a bundle object in an S3-compatible store.
type Config struct {
	Endpoint  string // host:port (no scheme)
	AccessKey string
	SecretKey string
	Bucket    string
	Object    string // e.g. "bundle.tar.gz"
	UseSSL    bool
}

// Store fetches OPA bundles from S3/MinIO. It satisfies pip.PolicyStore.
type Store struct {
	cfg    Config
	client *minio.Client
}

var _ pip.PolicyStore = (*Store)(nil)

// New connects a Store to the configured endpoint.
func New(cfg Config) (*Store, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("bundlestore: connect %s: %w", cfg.Endpoint, err)
	}
	return &Store{cfg: cfg, client: client}, nil
}

// LatestBundle returns the newest published bundle and its object version id.
// Versioning means this is always the most recent immutable version.
func (s *Store) LatestBundle(ctx context.Context) ([]byte, string, error) {
	obj, err := s.client.GetObject(ctx, s.cfg.Bucket, s.cfg.Object, minio.GetObjectOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("bundlestore: get %s/%s: %w", s.cfg.Bucket, s.cfg.Object, err)
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, "", fmt.Errorf("bundlestore: read bundle: %w", err)
	}
	info, err := obj.Stat()
	if err != nil {
		return nil, "", fmt.Errorf("bundlestore: stat bundle: %w", err)
	}
	return data, info.VersionID, nil
}
