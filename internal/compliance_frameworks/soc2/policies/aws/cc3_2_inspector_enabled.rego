# METADATA
# title: CC3.2 - Inspector Enabled
# description: AWS Inspector should be enabled for vulnerability scanning
# scope: package
package sigcomply.soc2.cc3_2_inspector_enabled

metadata := {
	"id": "soc2-cc3.2-inspector-enabled",
	"name": "Inspector Vulnerability Scanning",
	"framework": "soc2",
	"control": "CC3.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:inspector:status"],
	"remediation": "Enable AWS Inspector: aws inspector2 enable --resource-types EC2 ECR LAMBDA",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:inspector:status"
	input.data.enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("AWS Inspector is not enabled in region '%s'. Enable Inspector for automated vulnerability scanning.", [input.data.region]),
		"details": {
			"region": input.data.region,
			"ec2_scanning": input.data.ec2_scanning,
			"ecr_scanning": input.data.ecr_scanning,
			"lambda_scanning": input.data.lambda_scanning,
		},
	}
}
