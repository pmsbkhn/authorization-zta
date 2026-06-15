// Command caepemit is the Control Plane admin tool that pushes a CAEP Security
// Event Token to PEP receivers (design-v3 §6.2) — e.g. when an analyst revokes a
// user's session. Each subscriber's PEP then denies that subject immediately,
// even within a decision token's TTL.
//
// Usage:
//
//	caepemit -secret <shared> -subject u-1 -type session-revoked \
//	    http://localhost:8082/events [more receiver URLs...]
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/pmsbkhn/authorization-zta/internal/services"
	"github.com/pmsbkhn/authorization-zta/internal/signals/caep"
)

func main() {
	secret := flag.String("secret", os.Getenv("CAEP_SECRET"), "shared SET signing secret")
	subject := flag.String("subject", "", "subject id")
	typ := flag.String("type", caep.EventSessionRevoked, "event type (session-revoked|session-restored)")
	flag.Parse()

	if *secret == "" || *subject == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: caepemit -secret S -subject SUB [-type T] <receiver-url>...")
		os.Exit(2)
	}

	// When pushing to a receiver behind a PEP (mTLS), present our SVID.
	client := http.DefaultClient
	if cfg, ok, err := services.LoadClientTLS(); err != nil {
		fmt.Fprintln(os.Stderr, "caepemit:", err)
		os.Exit(1)
	} else if ok {
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	}

	tx := caep.NewTransmitterWithClient(caep.NewSigner([]byte(*secret)), flag.Args(), client)
	if err := tx.Emit(context.Background(), caep.Event{Type: *typ, Subject: *subject}); err != nil {
		fmt.Fprintln(os.Stderr, "caepemit:", err)
		os.Exit(1)
	}
	fmt.Printf("pushed %s for %q to %d receiver(s)\n", *typ, *subject, flag.NArg())
}
