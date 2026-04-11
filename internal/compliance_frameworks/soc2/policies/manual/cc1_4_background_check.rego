# METADATA
# title: CC1.4 - Background Check Summary
# description: Annual background check declaration must be completed for all new hires in the period
# scope: package
package sigcomply.soc2.cc1_4_background_check

metadata := {
	"id": "soc2-cc1.4-background-check",
	"name": "Background Check Summary",
	"framework": "soc2",
	"control": "CC1.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:background_check"],
	"category": "hr_governance",
	"remediation": "Declare that background checks were completed for all new hires (or that no new hires joined) in this period.",
}

# Violation: not uploaded and overdue
violations contains violation if {
	input.resource_type == "manual:background_check"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Background check summary for period %s is overdue and not completed", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

# Violation: declaration not accepted
violations contains violation if {
	input.resource_type == "manual:background_check"
	input.data.status == "uploaded"
	input.data.accepted != true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Background check declaration was not accepted",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

# Violation: hash verification failed
violations contains violation if {
	input.resource_type == "manual:background_check"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Background check evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}
