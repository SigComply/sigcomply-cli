# METADATA
# title: P2.1 - Marketing Opt-In Consent Proof
# description: Quarterly marketing opt-in consent proof must be uploaded
# scope: package
package sigcomply.soc2.p2_1_marketing_optin_proof

metadata := {
	"id": "soc2-p2.1-marketing-optin-proof",
	"name": "Marketing Opt-In Consent Proof",
	"framework": "soc2",
	"control": "P2.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:marketing_optin_proof"],
	"category": "privacy",
	"remediation": "Upload proof that marketing communications only go to users who have given explicit opt-in consent.",
}

violations contains violation if {
	input.resource_type == "manual:marketing_optin_proof"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Marketing opt-in consent proof for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:marketing_optin_proof"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Marketing opt-in proof evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:marketing_optin_proof"
	input.data.status == "uploaded"
	input.data.files[i].error
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Attachment '%s' not found in storage", [input.data.files[i].name]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"file": input.data.files[i].name,
		},
	}
}
