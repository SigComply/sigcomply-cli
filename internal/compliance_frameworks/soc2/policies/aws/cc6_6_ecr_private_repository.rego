# METADATA
# title: CC6.6 - ECR Private Repository
# description: ECR repositories must be private to restrict unauthorized access
# scope: package
package sigcomply.soc2.cc6_6_ecr_private_repository

metadata := {
	"id": "soc2-cc6.6-ecr-private-repository",
	"name": "ECR Private Repository",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecr:repository"],
	"remediation": "Use private ECR repositories instead of public ones. Migrate images to private repositories and update references.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ecr:repository"
	input.data.is_public == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECR repository '%s' is public. Use private repositories to restrict access.", [input.data.name]),
		"details": {
			"repository_name": input.data.name,
		},
	}
}
