# Fitness functions for the authorization core (design-v3 §5.3). These run under
# `opa test` in CI and must pass before a bundle is compiled/published. They lock
# in the decisions the system promises so a future policy edit cannot silently
# weaken authorization.
package vsp.authz_test

import data.vsp.authz

# A complete, valid edge request for a high-value wallet settlement.
settle_high(aal) := {
	"subject": {"type": "user", "id": "u-1", "properties": {"auth_assurance_level": aal}},
	"action": {"name": "wallet:settle", "properties": {"method": "POST"}},
	"resource": {"type": "wallet:account", "id": "acc-1", "properties": {"amount": 9000000, "currency": "VND"}},
	"context": {"authz_profile": "edge", "source_ip": "10.0.0.1", "correlation_id": "t-1"},
}

settle_amount(aal, amount) := req if {
	base := settle_high(aal)
	req := json.patch(base, [{"op": "replace", "path": "/resource/properties/amount", "value": amount}])
}

test_high_value_settle_aal3_allowed if {
	d := authz.decision with input as settle_high("AAL3")
	d.allow == true
	d.reason_code == "wallet_settle_high_value_aal3"
}

test_high_value_settle_aal2_denied_with_stepup if {
	d := authz.decision with input as settle_high("AAL2")
	d.allow == false
	d.reason_code == "step_up_required"
	some ob in d.obligations
	ob.type == "step_up"
	ob.details.required_acr == "AAL3"
}

test_standard_settle_aal2_allowed if {
	d := authz.decision with input as settle_amount("AAL2", 1000000)
	d.allow == true
	d.reason_code == "wallet_settle_standard"
}

test_standard_settle_aal1_denied if {
	d := authz.decision with input as settle_amount("AAL1", 1000000)
	d.allow == false
}

test_missing_required_currency_denied if {
	req := json.patch(settle_high("AAL3"), [{"op": "remove", "path": "/resource/properties/currency"}])
	d := authz.decision with input as req
	d.allow == false
	d.reason_code == "request_invalid"
}

test_east_west_without_act_denied if {
	req := json.patch(settle_high("AAL3"), [{"op": "replace", "path": "/context/authz_profile", "value": "east_west"}])
	d := authz.decision with input as req
	d.allow == false
	d.reason_code == "request_invalid"
}

test_east_west_with_workload_act_allowed if {
	withact := json.patch(settle_high("AAL3"), [
		{"op": "replace", "path": "/context/authz_profile", "value": "east_west"},
		{"op": "add", "path": "/subject/properties/act", "value": {"type": "workload", "id": "spiffe://vsp.local/ns/billing/sa/multi-bill-svc"}},
	])
	d := authz.decision with input as withact
	d.allow == true
}

test_unknown_domain_denied if {
	req := {
		"subject": {"type": "user", "id": "u-1", "properties": {"auth_assurance_level": "AAL3"}},
		"action": {"name": "ghost:do", "properties": {}},
		"resource": {"type": "ghost:thing", "id": "g-1", "properties": {}},
		"context": {"authz_profile": "edge", "source_ip": "10.0.0.1"},
	}
	d := authz.decision with input as req
	d.allow == false
	d.reason_code == "unknown_domain"
}

test_bill_pay_aal2_allowed if {
	req := {
		"subject": {"type": "user", "id": "u-1", "properties": {"auth_assurance_level": "AAL2"}},
		"action": {"name": "bill:pay", "properties": {"method": "POST"}},
		"resource": {"type": "bill:invoice", "id": "inv-1", "properties": {"amount": 200000, "currency": "VND"}},
		"context": {"authz_profile": "edge", "source_ip": "10.0.0.1"},
	}
	d := authz.decision with input as req
	d.allow == true
	d.reason_code == "bill_pay_ok"
}
