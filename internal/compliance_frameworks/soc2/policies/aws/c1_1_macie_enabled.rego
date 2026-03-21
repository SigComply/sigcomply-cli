# METADATA
# title: C1.1 - Macie Data Discovery
# description: Amazon Macie must be enabled for sensitive data discovery
# scope: package
package sigcomply.soc2.c1_1_macie_enabled

metadata := {
	"id": "soc2-c1.1-macie-enabled",
	"name": "Macie Data Discovery Enabled",
	"framework": "soc2",
	"control": "C1.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:macie2:session"],
	"remediation": "Enable Macie: aws macie2 enable-macie",
}

violations contains violation if {
	input.resource_type == "aws:macie2:session"
	input.data.enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Macie is not enabled in region '%s'", [input.data.region]),
		"details": {"region": input.data.region},
	}
}
