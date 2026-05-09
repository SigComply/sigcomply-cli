# METADATA
# title: CC6.2 - Redshift Encryption at Rest
# description: Redshift clusters must have encryption at rest enabled
# scope: package
package sigcomply.soc2.cc6_2_redshift_encryption

metadata := {
	"id": "soc2-cc6.2-redshift-encryption",
	"name": "Redshift Encryption at Rest",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:redshift:cluster"],
	"remediation": "Enable encryption at rest for the Redshift cluster. Modify the cluster to use KMS encryption.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:redshift:cluster"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Redshift cluster '%s' does not have encryption at rest enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
