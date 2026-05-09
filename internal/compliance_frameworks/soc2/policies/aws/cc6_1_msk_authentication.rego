# METADATA
# title: CC6.1 - MSK Authentication Enabled
# description: MSK clusters should require client authentication via IAM, SASL/SCRAM, or TLS
# scope: package
package sigcomply.soc2.cc6_1_msk_authentication

metadata := {
	"id": "soc2-cc6.1-msk-authentication",
	"name": "MSK Authentication Enabled",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:msk:cluster"],
	"remediation": "Enable client authentication on the MSK cluster using IAM, SASL/SCRAM, or mutual TLS. Configure ClientAuthentication when creating or updating the cluster.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:msk:cluster"
	input.data.authentication_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("MSK cluster '%s' does not have client authentication enabled", [input.data.cluster_name]),
		"details": {"cluster_name": input.data.cluster_name},
	}
}
