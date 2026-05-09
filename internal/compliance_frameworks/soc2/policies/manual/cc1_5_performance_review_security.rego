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

violations contains violation if {
	input.resource_type == "manual:performance_review_security"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Performance Review (Security Adherence) for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
