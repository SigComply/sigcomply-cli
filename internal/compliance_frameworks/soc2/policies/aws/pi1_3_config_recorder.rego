# METADATA
# title: PI1.3 - AWS Config Recorder
# description: AWS Config recorder should record all resource types across all regions for processing integrity
# scope: package
package sigcomply.soc2.pi1_3_config_recorder

metadata := {
	"id": "soc2-pi1.3-config-recorder",
	"name": "AWS Config Recorder All Resources",
	"framework": "soc2",
	"control": "PI1.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:config:recorder"],
	"remediation": "Configure AWS Config recorder to record all supported resource types.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:config:recorder"
	some i
	recorder := input.data.recorders[i]
	recorder.all_supported == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Config recorder '%s' does not record all supported resource types", [recorder.name]),
		"details": {"recorder_name": recorder.name, "region": recorder.region},
	}
}
