# METADATA
# title: CC7.2 - Security Hub Enabled
# description: AWS Security Hub must be enabled for centralized security monitoring
# scope: package
package sigcomply.soc2.cc7_2_security_hub

metadata := {
	"id": "soc2-cc7.2-security-hub",
	"name": "Security Hub Enabled",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:securityhub:hub"],
	"remediation": "Enable Security Hub: aws securityhub enable-security-hub",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:securityhub:hub"
	input.data.enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security Hub is not enabled in region '%s'", [input.data.region]),
		"details": {
			"region": input.data.region,
		},
	}
}
