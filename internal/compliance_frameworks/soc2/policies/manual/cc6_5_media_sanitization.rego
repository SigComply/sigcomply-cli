# METADATA
# title: CC6.5 - Media Sanitization Certificate
# description: Media sanitization events must be declared and certified each period
# scope: package
package sigcomply.soc2.cc6_5_media_sanitization

metadata := {
	"id": "soc2-cc6.5-media-sanitization",
	"name": "Media Sanitization Certificate",
	"framework": "soc2",
	"control": "CC6.5",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:media_sanitization"],
	"category": "data_protection",
	"remediation": "Declare that media was sanitized or destroyed (or that no such events occurred) this period.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:media_sanitization"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Media Sanitization Certificate for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
