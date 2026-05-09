# METADATA
# title: CC6.8 - Container Image Scanning
# description: Container registries must have vulnerability scanning enabled
# scope: package
package sigcomply.soc2.cc6_8_scanning

metadata := {
	"id": "soc2-cc6.8-container-scanning",
	"name": "Container Image Scanning",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecr:repository"],
	"remediation": "Enable scan-on-push for ECR repositories: aws ecr put-image-scanning-configuration --repository-name <name> --image-scanning-configuration scanOnPush=true",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ecr:repository"
	input.data.scan_on_push == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECR repository '%s' does not have scan-on-push enabled", [input.data.name]),
		"details": {
			"repository_name": input.data.name,
		},
	}
}
