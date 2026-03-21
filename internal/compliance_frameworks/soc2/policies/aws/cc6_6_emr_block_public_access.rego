# METADATA
# title: CC6.6 - EMR Block Public Access
# description: EMR block public access must be enabled to prevent public access to clusters
# scope: package
package sigcomply.soc2.cc6_6_emr_block_public_access

metadata := {
	"id": "soc2-cc6.6-emr-block-public-access",
	"name": "EMR Block Public Access",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:emr:block-public-access"],
	"remediation": "Enable EMR block public access: aws emr put-block-public-access-configuration --block-public-access-configuration BlockPublicSecurityGroupRules=true",
}

violations contains violation if {
	input.resource_type == "aws:emr:block-public-access"
	input.data.block_public_access == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "EMR block public access is not enabled",
		"details": {
			"region": input.data.region,
		},
	}
}
