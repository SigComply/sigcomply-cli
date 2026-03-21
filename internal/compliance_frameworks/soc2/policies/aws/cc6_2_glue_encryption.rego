# METADATA
# title: CC6.2 - Glue Job Encryption
# description: AWS Glue jobs must use a security configuration to encrypt data at rest and in transit
# scope: package
package sigcomply.soc2.cc6_2_glue_encryption

metadata := {
	"id": "soc2-cc6.2-glue-encryption",
	"name": "Glue Job Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:glue:job"],
	"remediation": "Attach a SecurityConfiguration to the Glue job that enables encryption for data at rest (S3, CloudWatch logs) and data in transit.",
}

violations contains violation if {
	input.resource_type == "aws:glue:job"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Glue job '%s' does not have a security configuration (encryption) enabled", [input.data.job_name]),
		"details": {"job_name": input.data.job_name},
	}
}
