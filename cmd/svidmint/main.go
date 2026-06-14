// Command svidmint stands in for SPIRE's issuance: it creates a trust-domain CA
// and mints one X509-SVID per workload, writing the trust bundle and each
// SVID's cert/key to disk for the binaries to load. In production a SPIRE agent
// would deliver these over the Workload API instead.
//
// Usage:
//
//	svidmint -out ./certs [-trust-domain vsp.local] \
//	    wallet=spiffe://vsp.local/ns/wallet/sa/vsp-wallet-svc \
//	    multibill=spiffe://vsp.local/ns/billing/sa/multi-bill-svc
//
// Writes: <out>/ca.pem, <out>/<name>.crt, <out>/<name>.key
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pmsbkhn/authorization-zta/internal/spiffe"
)

func main() {
	trustDomain := flag.String("trust-domain", "vsp.local", "SPIFFE trust domain")
	out := flag.String("out", "./certs", "output directory")
	flag.Parse()

	entries := flag.Args()
	if len(entries) == 0 {
		// Sensible defaults for the demo topology.
		entries = []string{
			"gateway=spiffe://" + *trustDomain + "/ns/edge/sa/api-gateway",
			"multibill=spiffe://" + *trustDomain + "/ns/billing/sa/multi-bill-svc",
			"wallet=spiffe://" + *trustDomain + "/ns/wallet/sa/vsp-wallet-svc",
		}
	}

	if err := run(*trustDomain, *out, entries); err != nil {
		fmt.Fprintln(os.Stderr, "svidmint:", err)
		os.Exit(1)
	}
}

func run(trustDomain, out string, entries []string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	ca, err := spiffe.NewCA(trustDomain)
	if err != nil {
		return err
	}
	bundlePath := filepath.Join(out, "ca.pem")
	if err := spiffe.WriteBundle(bundlePath, ca.Bundle()); err != nil {
		return err
	}
	fmt.Printf("trust bundle  -> %s\n", bundlePath)

	for _, e := range entries {
		name, id, ok := strings.Cut(e, "=")
		if !ok {
			return fmt.Errorf("bad entry %q (want name=spiffe://...)", e)
		}
		svid, err := ca.Mint(id)
		if err != nil {
			return err
		}
		certPath := filepath.Join(out, name+".crt")
		keyPath := filepath.Join(out, name+".key")
		if err := spiffe.WriteSVID(certPath, keyPath, svid); err != nil {
			return err
		}
		fmt.Printf("SVID %-10s -> %s (%s)\n", name, certPath, id)
	}
	return nil
}
