# METADATA
# title: CC5.1 - IAM Permission Boundary
# description: IAM users should have permission boundaries configured for least privilege governance
# scope: package
package sigcomply.soc2.cc5_1_iam_permission_boundary

metadata := {
	"id": "soc2-cc5.1-iam-permission-boundary",
	"name": "IAM Permission Boundary",
	"framework": "soc2",
	"control": "CC5.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"],
	"remediation": "Attach a permission boundary to the IAM user to enforce maximum permissions limits.",
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.has_permission_boundary == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' does not have a permission boundary configured", [input.data.user_name]),
		"details": {
			"user_name": input.data.user_name,
		},
	}
}
