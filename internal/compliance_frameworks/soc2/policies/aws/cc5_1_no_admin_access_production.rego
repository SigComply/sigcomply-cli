# METADATA
# title: CC5.1 - No AdministratorAccess in Production
# description: The AdministratorAccess managed policy should not be used in production accounts
# scope: package
package sigcomply.soc2.cc5_1_no_admin_access_production

metadata := {
	"id": "soc2-cc5.1-no-admin-access-production",
	"name": "No AdministratorAccess in Production",
	"framework": "soc2",
	"control": "CC5.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:role"],
	"remediation": "Replace AdministratorAccess with more granular IAM policies following the principle of least privilege. Use service-specific policies.",
}

violations contains violation if {
	input.resource_type == "aws:iam:role"
	input.data.has_admin_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM role '%s' has AdministratorAccess policy attached", [input.data.role_name]),
		"details": {
			"role_name": input.data.role_name,
			"attached_policies": input.data.attached_policies,
		},
	}
}
