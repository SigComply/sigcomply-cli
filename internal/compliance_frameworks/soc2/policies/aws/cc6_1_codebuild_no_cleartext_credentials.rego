# METADATA
# title: CC6.1 - CodeBuild No Cleartext Credentials
# description: CodeBuild projects must not store sensitive credentials as plaintext environment variables
# scope: package
package sigcomply.soc2.cc6_1_codebuild_no_cleartext_credentials

metadata := {
	"id": "soc2-cc6.1-codebuild-no-cleartext-credentials",
	"name": "CodeBuild No Cleartext Credentials",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:codebuild:project"],
	"remediation": "Use AWS Systems Manager Parameter Store or AWS Secrets Manager to store sensitive credentials instead of plaintext environment variables.",
}

violations contains violation if {
	input.resource_type == "aws:codebuild:project"
	input.data.cleartext_credentials == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CodeBuild project '%s' has sensitive credentials stored as plaintext environment variables", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
