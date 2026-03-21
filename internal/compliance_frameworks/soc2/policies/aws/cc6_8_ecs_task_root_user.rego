# METADATA
# title: CC6.8 - ECS Task Definition No Root User
# description: ECS task definitions must not run containers as root user
# scope: package
package sigcomply.soc2.cc6_8_ecs_task_root_user

metadata := {
	"id": "soc2-cc6.8-ecs-task-root-user",
	"name": "ECS Task Definition No Root User",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecs:task-definition"],
	"remediation": "Configure ECS task definitions to run as a non-root user by setting the 'user' parameter.",
}

violations contains violation if {
	input.resource_type == "aws:ecs:task-definition"
	input.data.runs_as_root == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECS task definition '%s' runs containers as root user", [input.data.family]),
		"details": {"task_definition_arn": input.data.task_definition_arn, "family": input.data.family},
	}
}
