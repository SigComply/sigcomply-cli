# METADATA
# title: CC6.8 - SageMaker Root Access
# description: SageMaker notebook instances must not have root access enabled
# scope: package
package sigcomply.soc2.cc6_8_sagemaker_root

metadata := {
	"id": "soc2-cc6.8-sagemaker-no-root-access",
	"name": "SageMaker Root Access",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:sagemaker:notebook"],
	"remediation": "Disable root access on SageMaker notebook instances to follow least-privilege principles.",
}

violations contains violation if {
	input.resource_type == "aws:sagemaker:notebook"
	input.data.root_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("SageMaker notebook '%s' has root access enabled", [input.data.name]),
		"details": {
			"notebook_name": input.data.name,
		},
	}
}
