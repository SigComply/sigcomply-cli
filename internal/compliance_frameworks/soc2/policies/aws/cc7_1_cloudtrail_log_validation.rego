# METADATA
# title: CC7.1 - CloudTrail Log File Validation
# description: CloudTrail trails must have log file validation enabled to detect tampering
# scope: package
package sigcomply.soc2.cc7_1_cloudtrail_log_validation

metadata := {
	"id": "soc2-cc7.1-cloudtrail-log-validation",
	"name": "CloudTrail Log File Validation",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Enable log file validation: aws cloudtrail update-trail --name <trail> --enable-log-file-validation",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.log_file_validation == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' does not have log file validation enabled", [input.data.name]),
		"details": {
			"trail_name": input.data.name,
			"log_file_validation": false,
		},
	}
}
