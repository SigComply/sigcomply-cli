# METADATA
# title: CC6.7 - OpenSearch Node-to-Node Encryption
# description: OpenSearch domains should have node-to-node encryption enabled
# scope: package
package sigcomply.soc2.cc6_7_opensearch_node_tls

metadata := {
	"id": "soc2-cc6.7-opensearch-node-tls",
	"name": "OpenSearch Node-to-Node Encryption",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:opensearch:domain"],
	"remediation": "Enable node-to-node encryption for the OpenSearch domain to encrypt traffic between nodes within the cluster.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:opensearch:domain"
	input.data.node_to_node_encryption == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("OpenSearch domain '%s' does not have node-to-node encryption enabled", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
