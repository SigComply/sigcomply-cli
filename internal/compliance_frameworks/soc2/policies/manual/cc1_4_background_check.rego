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
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:background_check"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Background Check Summary for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
