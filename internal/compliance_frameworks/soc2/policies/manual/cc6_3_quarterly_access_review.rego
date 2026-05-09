# METADATA
# title: CC6.3 - Quarterly Access Review
# description: Quarterly user access review must be completed with valid documentation
# scope: package
package sigcomply.soc2.cc6_3_quarterly_access_review

metadata := {
	"id": "soc2-cc6.3-quarterly-access-review",
	"name": "Quarterly Access Review",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:quarterly_access_review"],
	"category": "access_control",
	"remediation": "Complete the quarterly access review by uploading a signed access review document.",
	"evidence_type": "manual",
}

# Violation: evidence not uploaded and overdue
violations contains violation if {
	input.resource_type == "manual:quarterly_access_review"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Quarterly access review for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

# Violation: hash verification failed
violations contains violation if {
	input.resource_type == "manual:quarterly_access_review"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Quarterly access review evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

# Violation: invalid file format
violations contains violation if {
	input.resource_type == "manual:quarterly_access_review"
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
