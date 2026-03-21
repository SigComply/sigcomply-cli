# METADATA
# title: CC8.1 - ECR Tag Immutability
# description: ECR repositories must have image tag immutability enabled to prevent tag overwriting
# scope: package
package sigcomply.soc2.cc8_1_ecr_tag_immutability

metadata := {
	"id": "soc2-cc8.1-ecr-tag-immutability",
	"name": "ECR Tag Immutability",
	"framework": "soc2",
	"control": "CC8.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ecr:repository"],
	"remediation": "Enable image tag immutability for ECR repositories: aws ecr put-image-tag-mutability --repository-name <name> --image-tag-mutability IMMUTABLE",
}

violations contains violation if {
	input.resource_type == "aws:ecr:repository"
	input.data.tag_immutable == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ECR repository '%s' does not have image tag immutability enabled", [input.data.name]),
		"details": {
			"repository_name": input.data.name,
		},
	}
}
