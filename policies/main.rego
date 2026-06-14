# Package vsp.authz is the single decision entrypoint the embedded OPA engine
# evaluates (data.vsp.authz.decision). It is the "Unified Router": it composes
# every policy layer in a fixed order and dispatches to the right domain by name,
# so the Go side never needs to know the policy layout.
#
# Evaluation order (fail-closed at each gate):
#   1. global schema      — naming convention (vsp.global)
#   2. data-driven attrs  — required resource attributes from data.json (vsp.lib)
#   3. profile invariants  — per-hop context rules (vsp.profiles)
#   4. domain business    — dynamic dispatch to vsp.domain.<domain>.verdict
#
# Any violation in gates 1–3 denies before domain logic runs. An unknown domain
# (gate 4 undefined) is also a deny: absence of an explicit allow is denial.
package vsp.authz

import data.vsp.global
import data.vsp.lib
import data.vsp.profiles

# Aggregate of every pre-domain violation across the schema, attribute and
# profile layers. Empty set == request is well-formed enough to evaluate.
all_violations := (global.schema_violations | lib.missing_required_violations) | profiles.violations

# The domain is the prefix of resource.type, e.g. "wallet" from "wallet:account".
domain := split(input.resource.type, ":")[0]

# Dynamic dispatch: resolve the domain package's verdict by name. Undefined when
# no policy exists for that domain.
domain_verdict := data.vsp.domain[domain].verdict

# Absolute fail-closed default.
default decision := {"allow": false, "obligations": [], "reason_code": "default_deny"}

# Gate 1–3 failed → deny with the collected reasons surfaced for audit.
decision := {
	"allow": false,
	"obligations": [lib.audit("audit_denied")],
	"reason_code": "request_invalid",
	"violations": [v | some v in all_violations],
} if {
	count(all_violations) > 0
}

# Gates passed, but no domain policy exists → deny (unknown domain).
decision := {
	"allow": false,
	"obligations": [lib.audit("audit_denied")],
	"reason_code": "unknown_domain",
} if {
	count(all_violations) == 0
	not domain_verdict
}

# Gates passed and a domain verdict exists → that verdict is the decision.
decision := {
	"allow": domain_verdict.allow,
	"obligations": domain_verdict.obligations,
	"reason_code": domain_verdict.reason_code,
} if {
	count(all_violations) == 0
	domain_verdict
}
