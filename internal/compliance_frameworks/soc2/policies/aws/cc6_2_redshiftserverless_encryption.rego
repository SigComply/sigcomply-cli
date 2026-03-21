# METADATA
# title: CC6.2 - Redshift Serverless Encryption
# description: Redshift Serverless workgroups should be encrypted
# scope: package
package sigcomply.soc2.cc6_2_redshiftserverless_encryption

metadata := {
	"id": "soc2-cc6.2-redshiftserverless-encryption",
	"name": "Redshift Serverless Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:redshift-serverless:workgroup"],
	"remediation": "Enable encryption with a KMS key for the Redshift Serverless namespace.",
}

violations contains violation if {
	input.resource_type == "aws:redshift-serverless:workgroup"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Redshift Serverless workgroup '%s' is not encrypted", [input.data.name]),
		"details": {"workgroup_name": input.data.name},
	}
}
