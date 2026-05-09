# METADATA
# title: CC7.1 - Log Retention
# description: CloudWatch log groups must have retention periods configured
# scope: package
package sigcomply.soc2.cc7_1_retention

metadata := {
	"id": "soc2-cc7.1-log-retention",
	"name": "Log Retention Configured",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:logs:log-group"],
	"remediation": "Set a retention period on CloudWatch log groups: aws logs put-retention-policy --log-group-name <name> --retention-in-days 365",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:logs:log-group"
	input.data.has_retention == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudWatch log group '%s' has no retention period set (logs retained indefinitely)", [input.data.name]),
		"details": {
			"log_group_name": input.data.name,
		},
	}
}
