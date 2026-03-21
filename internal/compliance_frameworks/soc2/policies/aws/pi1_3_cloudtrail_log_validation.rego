# METADATA
# title: PI1.3 - CloudTrail Log File Validation
# description: CloudTrail trails should have log file validation enabled to ensure integrity
# scope: package
package sigcomply.soc2.pi1_3_cloudtrail_log_validation

metadata := {
	"id": "soc2-pi1.3-cloudtrail-log-validation",
	"name": "CloudTrail Log File Validation",
	"framework": "soc2",
	"control": "PI1.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Enable log file validation on CloudTrail trails: aws cloudtrail update-trail --name <trail> --enable-log-file-validation",
}

violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.log_file_validation == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' does not have log file validation enabled", [input.data.name]),
		"details": {"trail_name": input.data.name},
	}
}
