# METADATA
# title: CC6.8 - ECS No Host PID Namespace
# description: ECS task definitions should not share the host's process namespace
# scope: package
package sigcomply.soc2.cc6_8_ecs_no_host_namespace

metadata := {
	"id": "soc2-cc6.8-ecs-no-host-namespace",
	"name": "ECS No Host PID Namespace",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecs:task-definition"],
	"remediation": "Remove pidMode: host from the task definition to prevent containers from accessing host processes.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ecs:task-definition"
	input.data.has_host_pid_mode == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECS task definition '%s' shares the host's process namespace", [input.data.family]),
		"details": {
			"family": input.data.family,
		},
	}
}
