# METADATA
# title: CC6.8 - CodeBuild No Privileged Mode
# description: CodeBuild projects should not run in privileged mode unless required for Docker builds
# scope: package
package sigcomply.soc2.cc6_8_codebuild_no_privileged_mode

metadata := {
	"id": "soc2-cc6.8-codebuild-no-privileged-mode",
	"name": "CodeBuild No Privileged Mode",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:codebuild:project"],
	"remediation": "Disable privileged mode in CodeBuild projects unless specifically required for building Docker images.",
}

violations contains violation if {
	input.resource_type == "aws:codebuild:project"
	input.data.privileged_mode == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CodeBuild project '%s' is running in privileged mode", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
