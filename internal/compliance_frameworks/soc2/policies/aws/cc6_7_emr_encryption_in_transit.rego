# METADATA
# title: CC6.7 - EMR Encryption in Transit
# description: EMR clusters must have encryption in transit enabled
# scope: package
package sigcomply.soc2.cc6_7_emr_encryption_in_transit

metadata := {
	"id": "soc2-cc6.7-emr-encryption-in-transit",
	"name": "EMR Encryption in Transit",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:emr:cluster"],
	"remediation": "Enable encryption in transit in the EMR security configuration. Create a security configuration with in-transit encryption enabled and associate it with the cluster.",
}

violations contains violation if {
	input.resource_type == "aws:emr:cluster"
	input.data.encryption_in_transit == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EMR cluster '%s' does not have encryption in transit enabled", [input.data.name]),
		"details": {
			"name": input.data.name,
			"id": input.data.id,
		},
	}
}
