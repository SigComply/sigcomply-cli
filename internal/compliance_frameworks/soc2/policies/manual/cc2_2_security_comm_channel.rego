# METADATA
# title: CC2.2 - Security Communication Channel Evidence
# description: Quarterly declaration that a security communication channel is active
# scope: package
package sigcomply.soc2.cc2_2_security_comm_channel

metadata := {
	"id": "soc2-cc2.2-security-comm-channel",
	"name": "Security Communication Channel Evidence",
	"framework": "soc2",
	"control": "CC2.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["manual:security_comm_channel"],
	"category": "risk_compliance",
	"remediation": "Declare that a security communication channel (Slack, email, intranet) has been used to communicate security updates to employees this period.",
}

violations contains violation if {
	input.resource_type == "manual:security_comm_channel"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security communication channel declaration for period %s is overdue and not completed", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:security_comm_channel"
	input.data.status == "uploaded"
	input.data.accepted != true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Security communication channel declaration was not accepted",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:security_comm_channel"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Security communication channel evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}
