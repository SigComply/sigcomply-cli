# METADATA
# title: CC6.2 - ECS Task Definition Transit Encryption
# description: ECS task definitions with EFS volumes must have transit encryption enabled
# scope: package
package sigcomply.soc2.cc6_2_ecs_task_encryption

metadata := {
	"id": "soc2-cc6.2-ecs-task-encryption",
	"name": "ECS Task Definition Transit Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecs:task-definition"],
	"remediation": "Enable transit encryption for EFS volumes in ECS task definitions.",
}

violations contains violation if {
	input.resource_type == "aws:ecs:task-definition"
	input.data.has_efs_volumes == true
	input.data.efs_transit_encryption_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECS task definition '%s' has EFS volumes without transit encryption enabled", [input.data.family]),
		"details": {"task_definition_arn": input.data.task_definition_arn, "family": input.data.family},
	}
}
