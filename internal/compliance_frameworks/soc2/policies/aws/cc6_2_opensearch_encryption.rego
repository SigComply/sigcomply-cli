# METADATA
# title: CC6.2 - OpenSearch Encryption at Rest
# description: OpenSearch domains must have encryption at rest enabled
# scope: package
package sigcomply.soc2.cc6_2_opensearch_encryption

metadata := {
	"id": "soc2-cc6.2-opensearch-encryption",
	"name": "OpenSearch Encryption at Rest",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:opensearch:domain"],
	"remediation": "Enable encryption at rest for the OpenSearch domain. This can be configured during domain creation or by modifying the domain configuration.",
}

violations contains violation if {
	input.resource_type == "aws:opensearch:domain"
	input.data.encrypted_at_rest == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("OpenSearch domain '%s' does not have encryption at rest enabled", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
