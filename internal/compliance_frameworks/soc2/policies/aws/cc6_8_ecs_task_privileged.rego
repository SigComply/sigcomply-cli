# METADATA
# title: CC6.8 - ECS Task Definition No Privileged Containers
# description: ECS task definitions must not run containers in privileged mode
# scope: package
package sigcomply.soc2.cc6_8_ecs_task_privileged

metadata := {
	"id": "soc2-cc6.8-ecs-task-privileged",
	"name": "ECS Task Definition No Privileged Containers",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecs:task-definition"],
	"remediation": "Remove privileged mode from ECS task definition containers. Use specific Linux capabilities instead.",
}

violations contains violation if {
	input.resource_type == "aws:ecs:task-definition"
	input.data.has_privileged_container == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECS task definition '%s' has containers running in privileged mode", [input.data.family]),
		"details": {"task_definition_arn": input.data.task_definition_arn, "family": input.data.family},
	}
}
