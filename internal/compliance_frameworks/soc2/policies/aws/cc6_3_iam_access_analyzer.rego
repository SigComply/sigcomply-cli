# METADATA
# title: CC6.3 - IAM Access Analyzer
# description: IAM Access Analyzer should be enabled to identify resources shared externally
# scope: package
package sigcomply.soc2.cc6_3_iam_access_analyzer

metadata := {
	"id": "soc2-cc6.3-iam-access-analyzer",
	"name": "IAM Access Analyzer",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:accessanalyzer:status"],
	"remediation": "Enable IAM Access Analyzer to continuously analyze resource policies and identify resources shared with external entities.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:accessanalyzer:status"
	input.data.enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "IAM Access Analyzer is not enabled",
		"details": {"region": input.data.region},
	}
}
