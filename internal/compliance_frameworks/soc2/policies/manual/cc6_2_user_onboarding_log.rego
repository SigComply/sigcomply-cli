# METADATA
# title: CC6.2 - User Onboarding Access Grants Log
# description: Quarterly log of user onboarding access grants must be uploaded
# scope: package
package sigcomply.soc2.cc6_2_user_onboarding_log

metadata := {
	"id": "soc2-cc6.2-user-onboarding-log",
	"name": "User Onboarding Access Grants Log",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:user_onboarding_log"],
	"category": "hr_governance",
	"remediation": "Upload the quarterly user onboarding log detailing access grants for new users.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:user_onboarding_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("User Onboarding Access Grants Log for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
