# METADATA
# title: CC7.1 - ECS Task Definition Logging Configured
# description: ECS task definitions must have logging configured for all containers
# scope: package
package sigcomply.soc2.cc7_1_ecs_task_logging

metadata := {
	"id": "soc2-cc7.1-ecs-task-logging",
	"name": "ECS Task Definition Logging Configured",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecs:task-definition"],
	"remediation": "Configure log drivers (e.g., awslogs) for all containers in the ECS task definition.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ecs:task-definition"
	input.data.logging_configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECS task definition '%s' does not have logging configured for all containers", [input.data.family]),
		"details": {"task_definition_arn": input.data.task_definition_arn, "family": input.data.family},
	}
}
