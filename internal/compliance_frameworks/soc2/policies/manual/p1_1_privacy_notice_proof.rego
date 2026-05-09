# METADATA
# title: P1.1 - Privacy Notice Publication Proof
# description: Annual proof of privacy notice publication must be uploaded
# scope: package
package sigcomply.soc2.p1_1_privacy_notice_proof

metadata := {
	"id": "soc2-p1.1-privacy-notice-proof",
	"name": "Privacy Notice Publication Proof",
	"framework": "soc2",
	"control": "P1.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:privacy_notice_proof"],
	"category": "privacy",
	"remediation": "Upload proof that the privacy notice is published and accessible (screenshot, URL, or archived copy).",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:privacy_notice_proof"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Privacy Notice Publication Proof for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
