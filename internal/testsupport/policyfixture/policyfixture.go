// Package policyfixture assembles an OPA module/data set for exercising the
// platform decision machinery (engine / pdp / grpcpdp) in tests: the real
// embedded framework policy (vsp.global / vsp.lib / vsp.profiles / vsp.authz)
// plus a small synthetic business domain (vsp.domain.acct). Core tests use this
// instead of any adopter's domain, so the platform's tests stay independent of
// the reference VSP policy (which now lives under examples/vsp).
//
// The synthetic domain mirrors the canonical "high-value needs AAL3, else
// step-up" shape so tests can assert allow / step_up_required / required-attr
// behaviour without coupling to wallet:settle.
package policyfixture

import "github.com/pmsbkhn/authorization-zta/policies"

// acctDomain defines vsp.domain.acct with the action acct:settle on acct:wallet.
const acctDomain = `package vsp.domain.acct

import data.vsp.lib

default verdict := {"allow": false, "obligations": [], "reason_code": "acct_denied"}

verdict := {"allow": true, "obligations": [lib.audit("audit_success")], "reason_code": "acct_settle_ok"} if {
	input.action.name == "acct:settle"
	input.resource.properties.amount > 5000000
	lib.aal_at_least(lib.subject_aal, "AAL3")
}

verdict := {"allow": false, "obligations": [lib.step_up("AAL3"), lib.audit("audit_denied")], "reason_code": "step_up_required"} if {
	input.action.name == "acct:settle"
	input.resource.properties.amount > 5000000
	not lib.aal_at_least(lib.subject_aal, "AAL3")
}

verdict := {"allow": true, "obligations": [lib.audit("audit_success")], "reason_code": "acct_settle_standard"} if {
	input.action.name == "acct:settle"
	input.resource.properties.amount <= 5000000
	lib.aal_at_least(lib.subject_aal, "AAL2")
}
`

// Modules returns the framework modules plus the synthetic acct domain, matching
// the signature of policies.Modules so tests can swap it in directly.
func Modules() (map[string]string, error) {
	mods, err := policies.Modules()
	if err != nil {
		return nil, err
	}
	mods["domain/acct.rego"] = acctDomain
	return mods, nil
}

// Data returns the framework data with required_attributes for acct:settle.
func Data() (map[string]any, error) {
	data, err := policies.Data()
	if err != nil {
		return nil, err
	}
	data["required_attributes"] = map[string]any{"acct:settle": []any{"amount", "currency"}}
	return data, nil
}
