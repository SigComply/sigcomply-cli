# METADATA
# title: CC6.2 - Kinesis Stream Encryption
# description: Kinesis data streams must have server-side encryption enabled
# scope: package
package sigcomply.soc2.cc6_2_kinesis_encryption

metadata := {
	"id": "soc2-cc6.2-kinesis-encryption",
	"name": "Kinesis Stream Encryption Enabled",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:kinesis:stream"],
	"remediation": "Enable KMS encryption: aws kinesis start-stream-encryption --stream-name STREAM --encryption-type KMS --key-id alias/aws/kinesis",
}

violations contains violation if {
	input.resource_type == "aws:kinesis:stream"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Kinesis stream '%s' does not have server-side encryption enabled", [input.data.stream_name]),
		"details": {"stream_name": input.data.stream_name},
	}
}
