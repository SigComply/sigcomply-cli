# METADATA
# title: CC6.6 - ECS Task Definition Network Mode
# description: ECS task definitions must not use host network mode
# scope: package
package sigcomply.soc2.cc6_6_ecs_task_networking

metadata := {
	"id": "soc2-cc6.6-ecs-task-networking",
	"name": "ECS Task Definition Network Mode",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecs:task-definition"],
	"remediation": "Use 'awsvpc' or 'bridge' network mode instead of 'host' to isolate container networking.",
}

violations contains violation if {
	input.resource_type == "aws:ecs:task-definition"
	input.data.network_mode == "host"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECS task definition '%s' uses host network mode", [input.data.family]),
		"details": {"task_definition_arn": input.data.task_definition_arn, "family": input.data.family, "network_mode": input.data.network_mode},
	}
}
