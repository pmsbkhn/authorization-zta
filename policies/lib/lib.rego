# Package vsp.lib holds cross-cutting helpers shared by every policy layer:
# AAL comparison, obligation constructors, and the data-driven required-attribute
# check (design-v3 §5.2). Keeping these here means domain authors never restate
# the obligation shape or the assurance-level ordering.
package vsp.lib

# aal_rank gives a total order to the NIST assurance levels so policies can ask
# "is the subject at least AAL2?" instead of enumerating cases.
aal_rank := {"AAL1": 1, "AAL2": 2, "AAL3": 3}

# aal_at_least(have, want) is true when the subject's level `have` meets or
# exceeds the required level `want`. Undefined (false) if either is unknown.
aal_at_least(have, want) if {
	aal_rank[have] >= aal_rank[want]
}

# subject_aal is a convenience accessor with no default — undefined when absent,
# which naturally fails aal_at_least and forces a deny.
subject_aal := input.subject.properties.auth_assurance_level

# --- Obligation constructors ------------------------------------------------

# step_up(acr) instructs the (edge) PEP to challenge the user for a stronger
# authentication that yields assurance level `acr`.
step_up(acr) := {
	"type": "step_up",
	"details": {"required_acr": acr, "method": "mfa"},
}

# audit(level) instructs the PEP to emit an audit log record.
audit(level) := {
	"type": "log",
	"details": {"level": level},
}

# --- Data-driven required attributes (design-v3 §5.2) -----------------------

# required_attributes_for(action) returns the list configured in data.json for
# the given action name (undefined when the action has no requirements).
required_attributes_for(action) := data.required_attributes[action]

# missing_required_violations is the set of human-readable messages for every
# required resource attribute the PEP failed to supply. Engineers extend the
# contract by editing data.json only — this rule never changes.
missing_required_violations contains msg if {
	some attr in data.required_attributes[input.action.name]
	not input.resource.properties[attr]
	msg := sprintf("missing required attribute %q for action %q", [attr, input.action.name])
}
