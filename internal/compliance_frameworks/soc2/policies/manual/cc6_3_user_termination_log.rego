# METADATA
# title: CC6.3 - User Termination Access Revocation Log
# description: Quarterly log of user terminations with access revocation must be uploaded
# scope: package
package sigcomply.soc2.cc6_3_user_termination_log

metadata := {
	"id": "soc2-cc6.3-user-termination-log",
	"name": "User Termination Access Revocation Log",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:user_termination_log"],
	"category": "hr_governance",
	"remediation": "Upload the quarterly user termination log showing timely access revocation for departed users.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:user_termination_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("User Termination Access Revocation Log for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
