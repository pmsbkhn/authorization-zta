package services

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/pmsbkhn/authorization-zta/internal/authzen"
	"github.com/pmsbkhn/authorization-zta/internal/pdpclient"
	"github.com/pmsbkhn/authorization-zta/internal/pep"
)

// GatewayConfig configures the Edge PEP / API Gateway.
type GatewayConfig struct {
	PDPURL      string
	UpstreamURL string // Multi-Bill
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

	guard := pep.New(pep.Config{
		Profile: authzen.ProfileEdge,
		PEPID:   "edge-api-gateway",
		PDP:     pdpclient.New(cfg.PDPURL),
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
