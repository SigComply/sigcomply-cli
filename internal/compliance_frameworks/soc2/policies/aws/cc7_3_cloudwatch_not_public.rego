# METADATA
# title: CC7.3 - CloudWatch Log Group Not Publicly Accessible
# description: CloudWatch Log Groups should not be publicly accessible
# scope: package
package sigcomply.soc2.cc7_3_cloudwatch_not_public

metadata := {
	"id": "soc2-cc7.3-cloudwatch-not-public",
	"name": "CloudWatch Log Group Not Public",
	"framework": "soc2",
	"control": "CC7.3",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:logs:log-group"],
	"remediation": "Remove public access from the CloudWatch Log Group resource policy.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:logs:log-group"
	input.data.is_public == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudWatch Log Group '%s' is publicly accessible", [input.data.name]),
		"details": {"log_group_name": input.data.name},
	}
}
