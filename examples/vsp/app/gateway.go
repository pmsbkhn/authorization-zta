package app

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/pmsbkhn/authorization-zta/internal/authz/authzen"
	"github.com/pmsbkhn/authorization-zta/internal/authz/pdpclient"
	"github.com/pmsbkhn/authorization-zta/internal/authz/pep"
)

// GatewayConfig configures the Edge PEP / API Gateway.
type GatewayConfig struct {
	PDPURL      string
	PDP         pep.PDP     // optional transport override (e.g. gRPC-over-mTLS); default HTTP
	UpstreamURL string      // Multi-Bill
	UpstreamTLS *tls.Config // when set, the gateway calls Multi-Bill over mTLS
	Logger      *slog.Logger
}

// GatewayHandler builds the edge gateway: an Edge PEP authorizes inbound bill:pay
// and reverse-proxies to Multi-Bill. A bubbled-up X-Step-Up-Required in the
// upstream response is rewritten into a user-facing 401 MFA challenge.
func GatewayHandler(cfg GatewayConfig) (http.Handler, error) {
	target, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	if cfg.UpstreamTLS != nil {
		// Present the gateway's SVID to Multi-Bill and verify its SVID — the
		// gateway→multibill hop is mutually authenticated too.
		proxy.Transport = &http.Transport{TLSClientConfig: cfg.UpstreamTLS}
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		acr := resp.Header.Get(pep.HeaderStepUpRequired)
		if acr == "" {
			return nil
		}
		log.Info("translating bubbled step-up to 401 challenge",
			"required_acr", acr, "correlation_id", resp.Header.Get(pep.HeaderCorrelationID))
		challenge, _ := json.Marshal(map[string]any{
			"error":        "step_up_required",
			"required_acr": acr,
			"method":       "mfa",
		})
		resp.StatusCode = http.StatusUnauthorized
		resp.Status = http.StatusText(http.StatusUnauthorized)
		resp.Body = io.NopCloser(bytes.NewReader(challenge))
		resp.ContentLength = int64(len(challenge))
		resp.Header.Set("Content-Type", "application/json")
		resp.Header.Set("Content-Length", strconv.Itoa(len(challenge)))
		return nil
	}

	pdpClient := cfg.PDP
	if pdpClient == nil {
		pdpClient = pdpclient.New(cfg.PDPURL)
	}
	guard := pep.New(pep.Config{
		Profile: authzen.ProfileEdge,
		PEPID:   "edge-api-gateway",
		PDP:     pdpClient,
		Logger:  log,
		Routes: []pep.Route{{
			Method:        http.MethodPost,
			Path:          "/pay",
			Action:        "bill:pay",
			ResourceType:  "bill:invoice",
			ResourceProps: []string{"amount", "currency"},
		}},
	})

	mux := http.NewServeMux()
	mux.Handle("POST /pay", guard.Middleware(proxy))
	mux.HandleFunc("GET /healthz", okHandler)
	return mux, nil
}
