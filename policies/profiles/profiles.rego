# Package vsp.profiles enforces the contextual invariants of each authorization
# "chặng" (hop), keyed by context.authz_profile (design-v3 §5.1):
#
#   edge       — user-facing traffic at the API Gateway; must carry the caller's
#                source IP so edge policies can reason about network posture.
#   east_west  — service-to-service traffic inside the mesh; must carry a
#                delegation actor (subject.properties.act = the calling workload's
#                SPIFFE id) so the PDP can authorize the delegation chain.
#   partner    — external partner systems; must identify the partner.
#
# Each rule contributes a human-readable string to `violations`; a non-empty set
# fails the request closed in vsp.authz before any domain logic runs.
package vsp.profiles

violations contains "edge profile requires context.source_ip" if {
	input.context.authz_profile == "edge"
	not input.context.source_ip
}

violations contains "east_west profile requires subject.properties.act (delegation actor)" if {
	input.context.authz_profile == "east_west"
	not input.subject.properties.act
}

# On the east-west hop the delegated actor must be a workload identified by a
# SPIFFE id — a user cannot be the delegated actor of an internal call.
violations contains "east_west delegation actor must be a workload with a spiffe:// id" if {
	input.context.authz_profile == "east_west"
	act := input.subject.properties.act
	not valid_workload_act(act)
}

valid_workload_act(act) if {
	act.type == "workload"
	startswith(act.id, "spiffe://")
}

violations contains "partner profile requires context.partner_id" if {
	input.context.authz_profile == "partner"
	not input.context.partner_id
}
