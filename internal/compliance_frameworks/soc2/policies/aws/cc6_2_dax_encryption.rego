# METADATA
# title: CC6.2 - DAX Cluster Encryption
# description: DAX clusters should have server-side encryption enabled
# scope: package
package sigcomply.soc2.cc6_2_dax_encryption

metadata := {
	"id": "soc2-cc6.2-dax-encryption",
	"name": "DAX Cluster Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dax:cluster"],
	"remediation": "Enable server-side encryption (SSE) for the DAX cluster.",
}

violations contains violation if {
	input.resource_type == "aws:dax:cluster"
	input.data.sse_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DAX cluster '%s' does not have server-side encryption enabled", [input.data.name]),
		"details": {"cluster_name": input.data.name},
	}
}
