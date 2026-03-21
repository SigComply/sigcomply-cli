# METADATA
# title: CC1.5 - Organizations SCPs Enabled
# description: AWS Organizations should have Service Control Policies enabled for governance
# scope: package
package sigcomply.soc2.cc1_5_organizations_scps

metadata := {
	"id": "soc2-cc1.5-organizations-scps",
	"name": "Organizations SCPs Enabled",
	"framework": "soc2",
	"control": "CC1.5",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:organizations:status"],
	"remediation": "Enable and configure Service Control Policies in AWS Organizations for centralized access governance.",
}

# Violation: in org but SCPs not enabled
violations contains violation if {
	input.resource_type == "aws:organizations:status"
	input.data.is_organization_member == true
	input.data.scp_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "AWS Organizations member account does not have custom Service Control Policies enabled. SCPs provide centralized access governance.",
		"details": {
			"is_organization_member": true,
			"scp_enabled": false,
			"scp_count": input.data.scp_count,
		},
	}
}
