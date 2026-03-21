# METADATA
# title: PI1.4 - Kinesis Stream Encryption
# description: Kinesis streams should have encryption at rest enabled
# scope: package
package sigcomply.soc2.pi1_4_kinesis_encryption

metadata := {
	"id": "soc2-pi1.4-kinesis-encryption",
	"name": "Kinesis Stream Encryption at Rest",
	"framework": "soc2",
	"control": "PI1.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:kinesis:stream"],
	"remediation": "Enable server-side encryption on the Kinesis stream.",
}

violations contains violation if {
	input.resource_type == "aws:kinesis:stream"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Kinesis stream '%s' does not have encryption at rest enabled", [input.data.stream_name]),
		"details": {"stream_name": input.data.stream_name},
	}
}
