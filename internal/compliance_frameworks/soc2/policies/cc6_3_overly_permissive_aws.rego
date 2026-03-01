# METADATA
# title: CC6.3 - Overly Permissive AWS IAM Policies
# description: IAM users should not have AdministratorAccess managed policy attached
# scope: package
package sigcomply.soc2.cc6_3_permissive_aws

metadata := {
	"id": "soc2-cc6.3-overly-permissive-aws",
	"name": "Overly Permissive AWS IAM Policies",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"],
	"remediation": "Replace AdministratorAccess with more granular IAM policies following the principle of least privilege.",
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.has_admin_policy == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' has AdministratorAccess policy attached", [input.data.user_name]),
		"details": {
			"user_name": input.data.user_name,
			"attached_policies": input.data.attached_policies,
		},
	}
}
