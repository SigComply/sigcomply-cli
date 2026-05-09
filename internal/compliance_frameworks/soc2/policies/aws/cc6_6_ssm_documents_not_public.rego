# METADATA
# title: CC6.6 - SSM Documents Not Public
# description: SSM documents should not be publicly shared
# scope: package
package sigcomply.soc2.cc6_6_ssm_documents_not_public

metadata := {
	"id": "soc2-cc6.6-ssm-documents-not-public",
	"name": "SSM Documents Not Public",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ssm:document-status"],
	"remediation": "Review and remove public sharing from SSM documents using: aws ssm modify-document-permission --name <doc-name> --permission-type Share --account-ids-to-remove all",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ssm:document-status"
	input.data.has_public_documents == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "SSM documents are publicly shared",
		"details": {
			"region": input.data.region,
		},
	}
}
