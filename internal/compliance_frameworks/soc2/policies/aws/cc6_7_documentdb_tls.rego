# METADATA
# title: CC6.7 - DocumentDB TLS Encryption in Transit
# description: DocumentDB clusters must enforce TLS for all connections
# scope: package
package sigcomply.soc2.cc6_7_documentdb_tls

metadata := {
	"id": "soc2-cc6.7-documentdb-tls",
	"name": "DocumentDB TLS Encryption in Transit",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:documentdb:cluster"],
	"remediation": "Ensure TLS is enabled on the DocumentDB cluster parameter group. Set the tls parameter to 'enabled' in the cluster parameter group.",
}

violations contains violation if {
	input.resource_type == "aws:documentdb:cluster"
	input.data.tls_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DocumentDB cluster '%s' does not enforce TLS for connections", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
