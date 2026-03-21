# METADATA
# title: CC6.2 - CloudTrail Log Encryption
# description: CloudTrail trails should use KMS encryption for log files
# scope: package
package sigcomply.soc2.cc6_2_cloudtrail_encryption

metadata := {
	"id": "soc2-cc6.2-cloudtrail-encryption",
	"name": "CloudTrail Log Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Enable KMS encryption on CloudTrail trails to protect log file integrity and confidentiality.",
}

violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.kms_key_id == ""
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' does not use KMS encryption for log files", [input.data.name]),
		"details": {
			"trail_name": input.data.name,
		},
	}
}
