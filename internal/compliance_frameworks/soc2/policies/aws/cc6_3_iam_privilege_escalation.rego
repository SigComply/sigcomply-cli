# METADATA
# title: CC6.3 - IAM No Privilege Escalation Paths
# description: IAM policies should not allow privilege escalation through dangerous permission combinations
# scope: package
package sigcomply.soc2.cc6_3_iam_privilege_escalation

metadata := {
	"id": "soc2-cc6.3-iam-privilege-escalation",
	"name": "IAM No Privilege Escalation Paths",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:policy"],
	"remediation": "Review and restrict IAM policy permissions to prevent privilege escalation.",
}

violations contains violation if {
	input.resource_type == "aws:iam:policy"
	input.data.allows_privilege_escalation == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM policy '%s' contains permissions that allow privilege escalation", [input.data.policy_name]),
		"details": {"policy_name": input.data.policy_name},
	}
}
