# METADATA
# title: CC6.2 - CodeBuild S3 Logs Encrypted
# description: CodeBuild projects with S3 log storage should have encryption enabled
# scope: package
package sigcomply.soc2.cc6_2_codebuild_s3_logs_encrypted

metadata := {
	"id": "soc2-cc6.2-codebuild-s3-logs-encrypted",
	"name": "CodeBuild S3 Logs Encrypted",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:codebuild:project"],
	"remediation": "Enable encryption for S3 log storage in CodeBuild projects to protect build logs at rest.",
}

violations contains violation if {
	input.resource_type == "aws:codebuild:project"
	input.data.s3_logs_encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CodeBuild project '%s' has unencrypted S3 logs", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
