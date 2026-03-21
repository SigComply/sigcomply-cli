# METADATA
# title: CC7.1 - Transfer Family In-Transit Encryption
# description: AWS Transfer Family servers should use encryption for data in transit
# scope: package
package sigcomply.soc2.cc7_1_transfer_encryption

metadata := {
	"id": "soc2-cc7.1-transfer-encryption",
	"name": "Transfer Family In-Transit Encryption",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:transfer:server"],
	"remediation": "Configure SFTP/FTPS protocol on the Transfer Family server instead of FTP.",
}

violations contains violation if {
	input.resource_type == "aws:transfer:server"
	input.data.protocol == "FTP"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Transfer Family server '%s' uses unencrypted FTP protocol", [input.data.server_id]),
		"details": {"server_id": input.data.server_id, "protocol": input.data.protocol},
	}
}
