// Package rebac is a Zanzibar-style (relationship-based) decision engine backed
// by OpenFGA (design-v3 §6.3). It satisfies the same engine contract as the OPA
// engine — Eval(input) -> engine.Decision — so the PDP can route to it or
// compose it with OPA without any change to the facade or the PEPs.
//
// It maps the AuthZEN tuple onto an OpenFGA relationship check:
//
//	subject.id              -> user:<id>
//	action "<dom>:<verb>"   -> relation "can_<verb>"
//	resource "<dom>:<ent>"  -> object "<ent>:<resource.id>"
//
// e.g. (user u-1, wallet:settle, wallet:account/acc-1) becomes
// Check(user:u-1, can_settle, account:acc-1).
package rebac

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/engine"
)

// Config addresses an OpenFGA store + model.
type Config struct {
	Endpoint string // e.g. http://localhost:8089
	StoreID  string
	ModelID  string // optional; OpenFGA uses the latest model if empty
}

// Engine performs relationship checks against OpenFGA.
type Engine struct {
	cfg  Config
	http *http.Client
}

// New builds a ReBAC engine.
func New(cfg Config) *Engine {
	return &Engine{cfg: cfg, http: &http.Client{Timeout: 5 * time.Second}}
}

// Eval translates the AuthZEN request to an OpenFGA Check. A missing tuple field
// or a negative check is a deny — fail-closed, like the OPA engine.
func (e *Engine) Eval(ctx context.Context, input any) (engine.Decision, error) {
	m, ok := input.(map[string]any)
	if !ok {
		return engine.Decision{ReasonCode: "rebac_bad_input"}, nil
	}
	user := "user:" + nested(m, "subject", "id")
	relation := relationFor(nested(m, "action", "name"))
	object := objectFor(nested(m, "resource", "type"), nested(m, "resource", "id"))
	if relation == "" || object == "" || user == "user:" {
		return engine.Decision{ReasonCode: "rebac_unmapped_request"}, nil
	}

	allowed, err := e.check(ctx, user, relation, object)
	if err != nil {
		return engine.Decision{}, err
	}
	if allowed {
		return engine.Decision{Allow: true, ReasonCode: "rebac_relationship_ok"}, nil
	}
	return engine.Decision{Allow: false, ReasonCode: "rebac_no_relationship"}, nil
}

type checkReq struct {
	TupleKey    tupleKey `json:"tuple_key"`
	AuthModelID string   `json:"authorization_model_id,omitempty"`
}
type tupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

func (e *Engine) check(ctx context.Context, user, relation, object string) (bool, error) {
	body, _ := json.Marshal(checkReq{
		TupleKey:    tupleKey{User: user, Relation: relation, Object: object},
		AuthModelID: e.cfg.ModelID,
	})
	url := fmt.Sprintf("%s/stores/%s/check", e.cfg.Endpoint, e.cfg.StoreID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("rebac: check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("rebac: openfga returned HTTP %d", resp.StatusCode)
	}
	var out struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("rebac: decode check: %w", err)
	}
	return out.Allowed, nil
}

// relationFor derives the OpenFGA relation from the action verb.
func relationFor(action string) string {
	_, verb, ok := strings.Cut(action, ":")
	if !ok || verb == "" {
		return ""
	}
	return "can_" + verb
}

// objectFor maps the resource type's entity + id to an OpenFGA object.
func objectFor(resourceType, id string) string {
	_, entity, ok := strings.Cut(resourceType, ":")
	if !ok || entity == "" || id == "" {
		return ""
	}
	return entity + ":" + id
}

// nested reads input[a][b] as a string, or "".
func nested(m map[string]any, a, b string) string {
	sub, ok := m[a].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := sub[b].(string)
	return s
}
