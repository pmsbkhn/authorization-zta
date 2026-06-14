// Package pdpclient is the PEP-side HTTP client for the AuthZEN Access
// Evaluation API. Every PEP uses it to reach the Control Plane PDP; it is the
// only thing a PEP needs to know about the PDP's transport.
package pdpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/authzen"
)

// Client calls a single PDP's AuthZEN evaluation endpoint.
type Client struct {
	endpoint string
	http     *http.Client
}

// New returns a client for a PDP base URL (e.g. "http://localhost:8080").
func New(baseURL string) *Client {
	return &Client{
		endpoint: baseURL + "/access/v1/evaluation",
		http:     &http.Client{Timeout: 5 * time.Second},
	}
}

// Evaluate sends one AuthZEN request and returns the decision. A non-200 PDP
// response is an error: in Zero Trust a PEP that cannot get a clean decision must
// fail closed rather than assume allow.
func (c *Client) Evaluate(ctx context.Context, req authzen.Request) (authzen.Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return authzen.Response{}, fmt.Errorf("pdpclient: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return authzen.Response{}, fmt.Errorf("pdpclient: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return authzen.Response{}, fmt.Errorf("pdpclient: call pdp: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return authzen.Response{}, fmt.Errorf("pdpclient: pdp returned HTTP %d", resp.StatusCode)
	}

	var out authzen.Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return authzen.Response{}, fmt.Errorf("pdpclient: decode response: %w", err)
	}
	return out, nil
}
