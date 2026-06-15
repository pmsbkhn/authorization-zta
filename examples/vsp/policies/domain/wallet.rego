# Package vsp.domain.wallet holds the business authorization logic for the
# `wallet` domain. It exposes a single `verdict` object so the core router
# (vsp.authz) can dispatch to it dynamically by domain name without knowing any
# wallet-specific rules.
#
# Headline rule (design-v3 §5.1): a wallet:settle above 5,000,000 VND requires
# assurance level AAL3; otherwise the subject is told to step up.
package vsp.domain.wallet

import data.vsp.lib

# High-value threshold for settlement, in minor-unitless VND.
high_value_threshold := 5000000

# Fail-closed default: any wallet action with no matching rule is denied.
default verdict := {
	"allow": false,
	"obligations": [],
	"reason_code": "wallet_action_not_permitted",
}

# wallet:settle — high value, subject already at AAL3 → allow.
verdict := {
	"allow": true,
	"obligations": [lib.audit("audit_success")],
	"reason_code": "wallet_settle_high_value_aal3",
} if {
	input.action.name == "wallet:settle"
	input.resource.properties.amount > high_value_threshold
	lib.aal_at_least(lib.subject_aal, "AAL3")
}

# wallet:settle — high value, subject below AAL3 → deny + step_up obligation.
# This is the obligation that drives the cross-PEP "bubble-up" flow (§4).
verdict := {
	"allow": false,
	"obligations": [lib.step_up("AAL3"), lib.audit("audit_denied")],
	"reason_code": "step_up_required",
} if {
	input.action.name == "wallet:settle"
	input.resource.properties.amount > high_value_threshold
	not lib.aal_at_least(lib.subject_aal, "AAL3")
}

# wallet:settle — at or below the high-value threshold → AAL2 is sufficient.
verdict := {
	"allow": true,
	"obligations": [lib.audit("audit_success")],
	"reason_code": "wallet_settle_standard",
} if {
	input.action.name == "wallet:settle"
	input.resource.properties.amount <= high_value_threshold
	lib.aal_at_least(lib.subject_aal, "AAL2")
}

# wallet:read — any authenticated subject (AAL1+) may read.
verdict := {
	"allow": true,
	"obligations": [],
	"reason_code": "wallet_read_ok",
} if {
	input.action.name == "wallet:read"
	lib.aal_at_least(lib.subject_aal, "AAL1")
}
