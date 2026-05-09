# METADATA
# title: CC6.3 - Overly Permissive Policies
# description: GCP primitive roles (Owner/Editor) should not be used in production
# scope: package
package sigcomply.soc2.cc6_3_permissive

metadata := {
	"id": "soc2-cc6.3-overly-permissive",
	"name": "Overly Permissive IAM Policies",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["gcp:iam:policy"],
	"remediation": "Replace primitive roles (roles/owner, roles/editor) with more granular predefined or custom roles.",
	"evidence_type": "automated",
}

primitive_roles := {"roles/owner", "roles/editor"}

violations contains violation if {
	input.resource_type == "gcp:iam:policy"
	binding := input.data.bindings[_]
	primitive_roles[binding.role]
	member := binding.members[_]
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Primitive role '%s' assigned to '%s'. Use granular roles instead.", [binding.role, member]),
		"details": {
			"role": binding.role,
			"member": member,
		},
	}
}
