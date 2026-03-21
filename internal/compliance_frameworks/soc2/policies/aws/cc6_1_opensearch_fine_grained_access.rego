# METADATA
# title: CC6.1 - OpenSearch Fine-Grained Access Control
# description: OpenSearch domains must have fine-grained access control enabled
# scope: package
package sigcomply.soc2.cc6_1_opensearch_fine_grained_access

metadata := {
	"id": "soc2-cc6.1-opensearch-fine-grained-access",
	"name": "OpenSearch Fine-Grained Access Control",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:opensearch:domain"],
	"remediation": "Enable fine-grained access control on the OpenSearch domain for IAM-based or internal database authentication.",
}

violations contains violation if {
	input.resource_type == "aws:opensearch:domain"
	input.data.fine_grained_access_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("OpenSearch domain '%s' does not have fine-grained access control enabled", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
