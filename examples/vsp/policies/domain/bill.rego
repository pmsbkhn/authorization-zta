# Package vsp.domain.bill holds business authorization logic for the `bill`
# domain (Multi-Bill). Like every domain it exposes a single `verdict` object for
# the router to dispatch to.
package vsp.domain.bill

import data.vsp.lib

default verdict := {
	"allow": false,
	"obligations": [],
	"reason_code": "bill_action_not_permitted",
}

# bill:pay — paying an invoice requires AAL2+.
verdict := {
	"allow": true,
	"obligations": [lib.audit("audit_success")],
	"reason_code": "bill_pay_ok",
} if {
	input.action.name == "bill:pay"
	lib.aal_at_least(lib.subject_aal, "AAL2")
}

# bill:read — any authenticated subject may read an invoice.
verdict := {
	"allow": true,
	"obligations": [],
	"reason_code": "bill_read_ok",
} if {
	input.action.name == "bill:read"
	lib.aal_at_least(lib.subject_aal, "AAL1")
}
