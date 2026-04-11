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
}

violations contains violation if {
	input.resource_type == "manual:user_termination_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("User termination log for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:user_termination_log"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "User termination log evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:user_termination_log"
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
