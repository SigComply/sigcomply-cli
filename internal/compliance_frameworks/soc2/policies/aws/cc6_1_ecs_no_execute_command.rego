# METADATA
# title: CC6.1 - ECS Execute Command Disabled
# description: ECS clusters should not have Execute Command enabled by default
# scope: package
package sigcomply.soc2.cc6_1_ecs_no_execute_command

metadata := {
	"id": "soc2-cc6.1-ecs-no-execute-command",
	"name": "ECS Execute Command Disabled",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecs:cluster"],
	"remediation": "Disable Execute Command on the ECS cluster to prevent interactive shell access.",
}

violations contains violation if {
	input.resource_type == "aws:ecs:cluster"
	input.data.execute_command_enabled == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECS cluster '%s' has Execute Command enabled", [input.data.name]),
		"details": {"cluster_name": input.data.name},
	}
}
