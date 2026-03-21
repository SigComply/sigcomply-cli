# METADATA
# title: CC6.8 - ECS Read-Only Root Filesystem
# description: ECS task containers should use read-only root filesystems
# scope: package
package sigcomply.soc2.cc6_8_ecs_readonly_root_fs

metadata := {
	"id": "soc2-cc6.8-ecs-readonly-root-fs",
	"name": "ECS Read-Only Root Filesystem",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecs:task-definition"],
	"remediation": "Set readonlyRootFilesystem to true for all containers in the task definition.",
}

violations contains violation if {
	input.resource_type == "aws:ecs:task-definition"
	input.data.has_readonly_root_filesystem == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECS task definition '%s' does not have read-only root filesystem for all containers", [input.data.family]),
		"details": {
			"family": input.data.family,
		},
	}
}
