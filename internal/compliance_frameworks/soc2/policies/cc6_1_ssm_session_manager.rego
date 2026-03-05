# METADATA
# title: CC6.1 - SSM Session Manager
# description: SSM Session Manager must be enabled for secure instance access
# scope: package
package sigcomply.soc2.cc6_1_ssm_session_manager

metadata := {
	"id": "soc2-cc6.1-ssm-session-manager",
	"name": "SSM Session Manager Enabled",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ssm:status"],
	"remediation": "Install SSM Agent on instances and configure Session Manager",
}

violations contains violation if {
	input.resource_type == "aws:ssm:status"
	input.data.session_manager_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "SSM Session Manager is not enabled (no managed instances)",
		"details": {
			"managed_instance_count": input.data.managed_instance_count,
			"region": input.data.region,
		},
	}
}
