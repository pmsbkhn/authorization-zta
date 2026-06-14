// Command bundlepush publishes a compiled OPA bundle to the immutable policy
// store (design-v3 §5.3). It ensures the bucket has object lock + versioning,
// then uploads the bundle under a GOVERNANCE retention so the published version
// cannot be overwritten or deleted — only superseded by a new version, keeping
// the full history for rollback. This is the "CI publishes the bundle" step.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func main() {
	endpoint := flag.String("endpoint", env("S3_ENDPOINT", "localhost:9000"), "S3 endpoint host:port")
	ak := flag.String("access-key", env("S3_ACCESS_KEY", "minioadmin"), "access key")
	sk := flag.String("secret-key", env("S3_SECRET_KEY", "minioadmin"), "secret key")
	bucket := flag.String("bucket", env("S3_BUCKET", "vsp-policy-bundles"), "bucket")
	object := flag.String("object", env("S3_OBJECT", "bundle.tar.gz"), "object key")
	file := flag.String("file", "bundle.tar.gz", "bundle file to upload")
	retainDays := flag.Int("retain-days", 1, "GOVERNANCE retention (days)")
	flag.Parse()

	if err := run(*endpoint, *ak, *sk, *bucket, *object, *file, *retainDays); err != nil {
		fmt.Fprintln(os.Stderr, "bundlepush:", err)
		os.Exit(1)
	}
}

func run(endpoint, ak, sk, bucket, object, file string, retainDays int) error {
	ctx := context.Background()
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(ak, sk, ""),
		Secure: false,
	})
	if err != nil {
		return err
	}

	// Create the bucket with object lock (which forces versioning on) if absent.
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return err
	}
	if !exists {
		if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{ObjectLocking: true}); err != nil {
			return fmt.Errorf("make bucket: %w", err)
		}
		fmt.Printf("created object-locked, versioned bucket %q\n", bucket)
	}

	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}

	info, err := client.PutObject(ctx, bucket, object, f, st.Size(), minio.PutObjectOptions{
		ContentType:     "application/gzip",
		Mode:            minio.Governance,
		RetainUntilDate: time.Now().Add(time.Duration(retainDays) * 24 * time.Hour),
	})
	if err != nil {
		return fmt.Errorf("put object: %w", err)
	}
	fmt.Printf("published %s/%s version=%s (%d bytes, WORM until +%dd)\n",
		bucket, object, info.VersionID, info.Size, retainDays)
	return nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
