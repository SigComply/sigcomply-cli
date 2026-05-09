# METADATA
# title: CC6.6 - MSK No Public Access
# description: MSK clusters should not be publicly accessible from the internet
# scope: package
package sigcomply.soc2.cc6_6_msk_no_public_access

metadata := {
	"id": "soc2-cc6.6-msk-no-public-access",
	"name": "MSK No Public Access",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:msk:cluster"],
	"remediation": "Disable public access on the MSK cluster by setting ConnectivityInfo.PublicAccess.Type to DISABLED. Ensure the cluster is only accessible within the VPC.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:msk:cluster"
	input.data.public_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("MSK cluster '%s' is publicly accessible from the internet", [input.data.cluster_name]),
		"details": {"cluster_name": input.data.cluster_name},
	}
}
