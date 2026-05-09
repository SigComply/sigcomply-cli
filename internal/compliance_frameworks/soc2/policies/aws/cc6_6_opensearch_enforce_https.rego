# METADATA
# title: CC6.6 - OpenSearch HTTPS Enforcement
# description: OpenSearch domains should enforce HTTPS for all traffic
# scope: package
package sigcomply.soc2.cc6_6_opensearch_enforce_https

metadata := {
	"id": "soc2-cc6.6-opensearch-enforce-https",
	"name": "OpenSearch HTTPS Enforcement",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:opensearch:domain"],
	"remediation": "Enable 'Require HTTPS' in the OpenSearch domain endpoint options to enforce encrypted connections.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:opensearch:domain"
	input.data.enforce_https == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("OpenSearch domain '%s' does not enforce HTTPS", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
