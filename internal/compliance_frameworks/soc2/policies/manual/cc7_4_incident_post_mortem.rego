# METADATA
# title: CC7.4 - Incident Post-Mortem Summary
# description: Post-mortem summaries for security incidents must be documented each period
# scope: package
package sigcomply.soc2.cc7_4_incident_post_mortem

metadata := {
	"id": "soc2-cc7.4-incident-post-mortem",
	"name": "Incident Post-Mortem Summary",
	"framework": "soc2",
	"control": "CC7.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:incident_post_mortem"],
	"category": "system_ops_bcdr",
	"remediation": "Declare that all security incidents have post-mortem documentation (or that none occurred) this period.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:incident_post_mortem"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Incident Post-Mortem Summary for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
