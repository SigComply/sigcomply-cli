# METADATA
# title: CC6.6 - SageMaker Direct Internet Access
# description: SageMaker notebook instances must not have direct internet access enabled
# scope: package
package sigcomply.soc2.cc6_6_sagemaker_internet

metadata := {
	"id": "soc2-cc6.6-sagemaker-no-direct-internet",
	"name": "SageMaker Direct Internet Access",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:sagemaker:notebook"],
	"remediation": "Disable direct internet access on SageMaker notebook instances and use VPC networking instead.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:sagemaker:notebook"
	input.data.direct_internet_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("SageMaker notebook '%s' has direct internet access enabled", [input.data.name]),
		"details": {
			"notebook_name": input.data.name,
		},
	}
}
