# METADATA
# title: CC1.5 - Performance Review (Security Adherence)
# description: Annual performance reviews must cover security policy adherence
# scope: package
package sigcomply.soc2.cc1_5_performance_review_security

metadata := {
	"id": "soc2-cc1.5-performance-review-security",
	"name": "Performance Review (Security Adherence)",
	"framework": "soc2",
	"control": "CC1.5",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["manual:performance_review_security"],
	"category": "hr_governance",
	"remediation": "Upload evidence of annual performance reviews covering security policy adherence.",
	"evidence_type": "manual",
}

# Violation: not uploaded and overdue
violations contains violation if {
	input.resource_type == "manual:performance_review_security"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Performance review (security adherence) for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

# Violation: hash verification failed
violations contains violation if {
	input.resource_type == "manual:performance_review_security"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Performance review evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

# Violation: attachment not found
violations contains violation if {
	input.resource_type == "manual:performance_review_security"
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
