# Package vsp.global re-validates the AuthZEN VSP Standard Contract naming
# convention (design-v3 §3.1) inside the policy engine. The Go facade validates
# the same rules at the front door; doing it again here is deliberate defense in
# depth so a policy bundle is correct regardless of which PEP/facade calls it.
package vsp.global

# colon_pair matches "<domain>:<name>" with lowercase tokens.
colon_pair := `^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$`

schema_violations contains "subject.type must be \"user\" or \"workload\"" if {
	not valid_subject_type
}

valid_subject_type if input.subject.type == "user"

valid_subject_type if input.subject.type == "workload"

schema_violations contains "subject.id is required" if {
	not input.subject.id
}

schema_violations contains "action.name must match <domain>:<action>" if {
	not regex.match(colon_pair, input.action.name)
}

schema_violations contains "resource.type must match <domain>:<entity>" if {
	not regex.match(colon_pair, input.resource.type)
}

# action and resource must agree on domain (e.g. wallet:settle on wallet:account).
schema_violations contains "action/resource domain mismatch" if {
	regex.match(colon_pair, input.action.name)
	regex.match(colon_pair, input.resource.type)
	split(input.action.name, ":")[0] != split(input.resource.type, ":")[0]
}
