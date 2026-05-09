# METADATA
# title: CC6.1 - CodeBuild No Source Credentials in URL
# description: CodeBuild projects should not have credentials embedded in source URLs
# scope: package
package sigcomply.soc2.cc6_1_codebuild_no_source_credentials_url

metadata := {
	"id": "soc2-cc6.1-codebuild-no-source-credentials-url",
	"name": "CodeBuild No Source Credentials in URL",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:codebuild:project"],
	"remediation": "Use AWS CodeBuild source credentials or AWS Secrets Manager instead of embedding credentials in source URLs.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:codebuild:project"
	input.data.source_credentials_in_url == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CodeBuild project '%s' has credentials embedded in source URL", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
