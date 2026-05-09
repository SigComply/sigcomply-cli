# METADATA
# title: CC6.3 - IAM Console Access Not Unused
# description: IAM users with console access should have recently used it
# scope: package
package sigcomply.soc2.cc6_3_iam_user_console_unused

metadata := {
	"id": "soc2-cc6.3-iam-user-console-unused",
	"name": "IAM Console Access Not Unused",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"],
	"remediation": "Remove console access for users who have not logged in recently.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.has_console_access == true
	input.data.console_last_used_days > 90
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' has console access but has not logged in for %d days", [input.data.username, input.data.console_last_used_days]),
		"details": {"username": input.data.username, "days_since_login": input.data.console_last_used_days},
	}
}
