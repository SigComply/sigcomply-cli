# METADATA
# title: A1.2 - OpenSearch Zone Awareness Enabled
# description: OpenSearch domains should have zone awareness enabled for high availability
# scope: package
package sigcomply.soc2.a1_2_opensearch_zone_awareness

metadata := {
	"id": "soc2-a1.2-opensearch-zone-awareness",
	"name": "OpenSearch Zone Awareness Enabled",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:opensearch:domain"],
	"remediation": "Enable zone awareness for the OpenSearch domain to deploy data nodes across multiple Availability Zones.",
}

violations contains violation if {
	input.resource_type == "aws:opensearch:domain"
	input.data.zone_awareness_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("OpenSearch domain '%s' does not have zone awareness enabled", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
