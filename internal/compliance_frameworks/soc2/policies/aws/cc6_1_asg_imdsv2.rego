# METADATA
# title: CC6.1 - Auto Scaling IMDSv2 Required
# description: Auto Scaling groups should use launch templates configured to require IMDSv2 to prevent SSRF attacks
# scope: package
package sigcomply.soc2.cc6_1_asg_imdsv2

metadata := {
	"id": "soc2-cc6.1-asg-imdsv2",
	"name": "Auto Scaling IMDSv2 Required",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:autoscaling:group"],
	"remediation": "Use a launch template with HttpTokens=required to enforce IMDSv2 on all instances in the Auto Scaling group.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:autoscaling:group"
	input.data.imdsv2_required == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Auto Scaling group '%s' does not enforce IMDSv2 on its instances", [input.data.group_name]),
		"details": {"group_name": input.data.group_name},
	}
}
