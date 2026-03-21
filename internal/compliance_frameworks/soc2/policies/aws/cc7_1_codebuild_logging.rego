# METADATA
# title: CC7.1 - CodeBuild Logging
# description: CodeBuild projects should have logging configured for monitoring and audit purposes
# scope: package
package sigcomply.soc2.cc7_1_codebuild_logging

metadata := {
	"id": "soc2-cc7.1-codebuild-logging",
	"name": "CodeBuild Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:codebuild:project"],
	"remediation": "Enable CloudWatch Logs or S3 logging for CodeBuild projects to ensure build activity is monitored and auditable.",
}

violations contains violation if {
	input.resource_type == "aws:codebuild:project"
	input.data.logging_configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CodeBuild project '%s' does not have logging configured", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
