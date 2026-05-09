# METADATA
# title: CC6.7 - MSK Encryption in Transit
# description: MSK clusters should encrypt data in transit between clients and brokers
# scope: package
package sigcomply.soc2.cc6_7_msk_encryption_in_transit

metadata := {
	"id": "soc2-cc6.7-msk-encryption-in-transit",
	"name": "MSK Encryption in Transit",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:msk:cluster"],
	"remediation": "Enable TLS encryption for client-broker communication: set EncryptionInTransit.ClientBroker to TLS when creating or updating the MSK cluster.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:msk:cluster"
	input.data.encryption_in_transit == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("MSK cluster '%s' does not enforce encryption in transit", [input.data.cluster_name]),
		"details": {"cluster_name": input.data.cluster_name},
	}
}
