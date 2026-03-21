# METADATA
# title: CC6.7 - DAX Cluster TLS
# description: DAX clusters should use TLS for endpoint encryption
# scope: package
package sigcomply.soc2.cc6_7_dax_tls

metadata := {
	"id": "soc2-cc6.7-dax-tls",
	"name": "DAX Cluster TLS",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dax:cluster"],
	"remediation": "Enable TLS endpoint encryption for the DAX cluster.",
}

violations contains violation if {
	input.resource_type == "aws:dax:cluster"
	input.data.cluster_endpoint_encryption_type != "TLS"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DAX cluster '%s' does not use TLS endpoint encryption", [input.data.name]),
		"details": {"cluster_name": input.data.name, "encryption_type": input.data.cluster_endpoint_encryption_type},
	}
}
