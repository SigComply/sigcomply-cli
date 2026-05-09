# METADATA
# title: CC7.1 - Step Functions X-Ray Tracing
# description: Step Functions state machines should have X-Ray tracing enabled
# scope: package
package sigcomply.soc2.cc7_1_stepfunctions_tracing

metadata := {
	"id": "soc2-cc7.1-stepfunctions-tracing",
	"name": "Step Functions X-Ray Tracing",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:stepfunctions:state-machine"],
	"remediation": "Enable X-Ray tracing for the Step Functions state machine.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:stepfunctions:state-machine"
	input.data.tracing_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Step Functions state machine '%s' does not have X-Ray tracing enabled", [input.data.name]),
		"details": {"state_machine_name": input.data.name},
	}
}
