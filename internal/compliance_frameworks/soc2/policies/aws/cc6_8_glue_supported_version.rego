# METADATA
# title: CC6.8 - Glue Job Supported Version
# description: AWS Glue jobs must use a supported Glue version (3.0 or higher)
# scope: package
package sigcomply.soc2.cc6_8_glue_supported_version

metadata := {
	"id": "soc2-cc6.8-glue-supported-version",
	"name": "Glue Job Supported Version",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:glue:job"],
	"remediation": "Upgrade the Glue job to use Glue version 3.0 or higher to ensure access to the latest security patches and features.",
	"evidence_type": "automated",
}

supported_versions := {"3.0", "4.0"}

violations contains violation if {
	input.resource_type == "aws:glue:job"
	not supported_versions[input.data.glue_version]
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Glue job '%s' uses unsupported Glue version '%s'; must be 3.0 or higher", [input.data.job_name, input.data.glue_version]),
		"details": {
			"job_name": input.data.job_name,
			"glue_version": input.data.glue_version,
		},
	}
}
