package app

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/pmsbkhn/zta-core/authz/pep"
)

// MultibillConfig configures the Multi-Bill workload.
type MultibillConfig struct {
	WalletURL  string
	SelfSpiffe string // delegation actor stamped on the East-West call
	Logger     *slog.Logger
	HTTPClient *http.Client
	// CacheDecisionTokens replays the wallet's decision token on identical
	// follow-up settlements, letting the wallet's PEP take its fast-path and skip
	// the PDP within the token TTL.
	CacheDecisionTokens bool
}

// MultibillHandler builds the Multi-Bill service: POST /pay settles via the
// wallet, propagating user identity and stamping its own SPIFFE id as the
// delegation actor. A step-up signalled by the wallet is bubbled up unchanged.
func MultibillHandler(cfg MultibillConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	cache := &tokenCache{enabled: cfg.CacheDecisionTokens, m: map[string]string{}}

	pay := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		key := cache.key(r, body)

		out, err := http.NewRequestWithContext(r.Context(), http.MethodPost, cfg.WalletURL+"/settle", bytes.NewReader(body))
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		out.Header.Set("Content-Type", "application/json")
		copyHeader(out, r, pep.HeaderSubjectID)
		copyHeader(out, r, pep.HeaderAAL)
		copyHeader(out, r, pep.HeaderResourceID)
		copyHeader(out, r, pep.HeaderCorrelationID)
		// Dev mode only: assert the delegation actor via header. Under mTLS,
		// SelfSpiffe is empty and identity travels in the client certificate.
		if cfg.SelfSpiffe != "" {
			out.Header.Set(pep.HeaderCallerSpiffe, cfg.SelfSpiffe)
		}
		// Replay a cached decision token (or one supplied by our caller) so the
		// wallet can skip the PDP for an identical settlement.
		if tok := firstNonEmpty(r.Header.Get(pep.HeaderDecisionToken), cache.get(key)); tok != "" {
			out.Header.Set(pep.HeaderDecisionToken, tok)
		}

		resp, err := cfg.HTTPClient.Do(out)
		if err != nil {
			cfg.Logger.Error("wallet call failed", "err", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		if su := resp.Header.Get(pep.HeaderStepUpRequired); su != "" {
			cfg.Logger.Info("bubbling up step-up from wallet", "required_acr", su,
				"correlation_id", r.Header.Get(pep.HeaderCorrelationID))
			w.Header().Set(pep.HeaderStepUpRequired, su)
		}
		if cid := resp.Header.Get(pep.HeaderCorrelationID); cid != "" {
			w.Header().Set(pep.HeaderCorrelationID, cid)
		}
		// Cache the fresh decision token the wallet minted for next time.
		if resp.StatusCode == http.StatusOK {
			cache.put(key, resp.Header.Get(pep.HeaderDecisionToken))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /pay", pay)
	mux.HandleFunc("GET /healthz", okHandler)
	return mux
}

// tokenCache maps an identical-settlement key to the wallet's decision token.
type tokenCache struct {
	enabled bool
	mu      sync.RWMutex
	m       map[string]string
}

// key derives a stable key from the decision-relevant request fields. It must
// cover everything the wallet's policy depends on, so a different amount yields a
// different key (and never a wrongly reused token).
func (c *tokenCache) key(r *http.Request, body []byte) string {
	return fmt.Sprintf("%s|%s|%s|%s",
		r.Header.Get(pep.HeaderSubjectID),
		r.Header.Get(pep.HeaderAAL),
		r.Header.Get(pep.HeaderResourceID),
		body)
}

func (c *tokenCache) get(key string) string {
	if !c.enabled {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.m[key]
}

func (c *tokenCache) put(key, tok string) {
	if !c.enabled || tok == "" {
		return
	}
	c.mu.Lock()
	c.m[key] = tok
	c.mu.Unlock()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func copyHeader(dst, src *http.Request, key string) {
	if v := src.Header.Get(key); v != "" {
		dst.Header.Set(key, v)
	}
}
