# METADATA
# title: C1.2 - ECR Lifecycle Policy
# description: ECR repositories should have a lifecycle policy to manage image retention
# scope: package
package sigcomply.soc2.c1_2_ecr_lifecycle_policy

metadata := {
	"id": "soc2-c1.2-ecr-lifecycle-policy",
	"name": "ECR Lifecycle Policy",
	"framework": "soc2",
	"control": "C1.2",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecr:repository"],
	"remediation": "Configure a lifecycle policy for the ECR repository to automatically clean up old or untagged images: aws ecr put-lifecycle-policy --repository-name <name> --lifecycle-policy-text <policy>",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ecr:repository"
	input.data.has_lifecycle_policy == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECR repository '%s' does not have a lifecycle policy configured", [input.data.name]),
		"details": {
			"repository_name": input.data.name,
		},
	}
}
