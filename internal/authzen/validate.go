package authzen

import (
	"fmt"
	"regexp"
	"strings"
)

// nameToken matches a single `<domain>` or `<action>`/`<entity>` segment.
// Lowercase, starts with a letter, alphanumeric + underscore/hyphen.
var nameToken = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

// ValidationError aggregates everything wrong with a request so the caller (and
// the PEP) sees the full picture in one response rather than one error at a time.
type ValidationError struct {
	Issues []string
}

func (e *ValidationError) Error() string {
	return "authzen: invalid request: " + strings.Join(e.Issues, "; ")
}

// Validate enforces the VSP Standard Contract's structural and naming rules
// (design-v3 §3.1) at the AuthZEN facade, before the request reaches OPA. This
// is the cheap "front door" guard; richer, data-driven attribute requirements
// (§5.2) are enforced inside Rego where they can be changed without redeploying.
//
// It deliberately does NOT make an authorization decision — a structurally valid
// request can still be denied by policy.
func (r *Request) Validate() error {
	var issues []string

	// Subject.
	switch r.Subject.Type {
	case SubjectTypeUser, SubjectTypeWorkload:
	case "":
		issues = append(issues, "subject.type is required")
	default:
		issues = append(issues, fmt.Sprintf("subject.type %q must be %q or %q",
			r.Subject.Type, SubjectTypeUser, SubjectTypeWorkload))
	}
	if r.Subject.ID == "" {
		issues = append(issues, "subject.id is required")
	}

	// Action name must be "<domain>:<action>".
	if r.Action.Name == "" {
		issues = append(issues, "action.name is required")
	} else if !isColonPair(r.Action.Name) {
		issues = append(issues, fmt.Sprintf(
			"action.name %q must match \"<domain>:<action>\" (e.g. wallet:settle)", r.Action.Name))
	}

	// Resource type must be "<domain>:<entity>".
	if r.Resource.Type == "" {
		issues = append(issues, "resource.type is required")
	} else if !isColonPair(r.Resource.Type) {
		issues = append(issues, fmt.Sprintf(
			"resource.type %q must match \"<domain>:<entity>\" (e.g. wallet:account)", r.Resource.Type))
	}

	// Cross-field rule: action and resource must share the same domain. This
	// catches mismatched tuples like action=wallet:settle on resource=bill:invoice.
	if ad, ok := domainOf(r.Action.Name); ok {
		if rd, ok := domainOf(r.Resource.Type); ok && ad != rd {
			issues = append(issues, fmt.Sprintf(
				"domain mismatch: action %q is in domain %q but resource %q is in domain %q",
				r.Action.Name, ad, r.Resource.Type, rd))
		}
	}

	// Context: authz_profile is mandatory because OPA routes on it.
	switch r.AuthZProfile() {
	case ProfileEdge, ProfileEastWest, ProfilePartner:
	case "":
		issues = append(issues, "context.authz_profile is required (edge|east_west|partner)")
	default:
		issues = append(issues, fmt.Sprintf(
			"context.authz_profile %q must be one of edge|east_west|partner", r.AuthZProfile()))
	}

	if len(issues) > 0 {
		return &ValidationError{Issues: issues}
	}
	return nil
}

// isColonPair reports whether s is exactly "<token>:<token>".
func isColonPair(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return false
	}
	return nameToken.MatchString(parts[0]) && nameToken.MatchString(parts[1])
}

// domainOf returns the "<domain>" prefix of a colon-pair, if well-formed.
func domainOf(s string) (string, bool) {
	if !isColonPair(s) {
		return "", false
	}
	return strings.SplitN(s, ":", 2)[0], true
}
