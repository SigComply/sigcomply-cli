# METADATA
# title: CC7.3 - GuardDuty No Unresolved High-Severity Findings
# description: GuardDuty should have no unresolved high-severity findings
# scope: package
package sigcomply.soc2.cc7_3_guardduty_no_high_findings

metadata := {
	"id": "soc2-cc7.3-guardduty-no-high-findings",
	"name": "GuardDuty No High-Severity Findings",
	"framework": "soc2",
	"control": "CC7.3",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:guardduty:detector"],
	"remediation": "Review and remediate all high-severity GuardDuty findings.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:guardduty:detector"
	input.data.high_severity_findings_count > 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GuardDuty has %d unresolved high-severity findings in region %s", [input.data.high_severity_findings_count, input.data.region]),
		"details": {"region": input.data.region, "finding_count": input.data.high_severity_findings_count},
	}
}
