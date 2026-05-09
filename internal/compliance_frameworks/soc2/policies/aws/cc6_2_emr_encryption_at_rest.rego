# METADATA
# title: CC6.2 - EMR Encryption at Rest
# description: EMR clusters must have encryption at rest enabled
# scope: package
package sigcomply.soc2.cc6_2_emr_encryption_at_rest

metadata := {
	"id": "soc2-cc6.2-emr-encryption-at-rest",
	"name": "EMR Encryption at Rest",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:emr:cluster"],
	"remediation": "Enable encryption at rest in the EMR security configuration. Create a security configuration with at-rest encryption enabled and associate it with the cluster.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:emr:cluster"
	input.data.encryption_at_rest == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EMR cluster '%s' does not have encryption at rest enabled", [input.data.name]),
		"details": {
			"name": input.data.name,
			"id": input.data.id,
		},
	}
}
