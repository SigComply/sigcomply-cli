# METADATA
# title: CC6.8 - SSM Patch Compliance
# description: SSM-managed instances should be compliant with patch baselines
# scope: package
package sigcomply.soc2.cc6_8_ssm_compliant_patching

metadata := {
	"id": "soc2-cc6.8-ssm-compliant-patching",
	"name": "SSM Patch Compliance",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ssm:managed-instance"],
	"remediation": "Apply missing patches using AWS Systems Manager Patch Manager.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ssm:managed-instance"
	input.data.patch_compliant == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("SSM-managed instance '%s' is not compliant with patch baseline", [input.data.instance_id]),
		"details": {"instance_id": input.data.instance_id},
	}
}
