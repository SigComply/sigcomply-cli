# METADATA
# title: CC6.2 - DynamoDB Encryption
# description: DynamoDB tables must have server-side encryption enabled
# scope: package
package sigcomply.soc2.cc6_2_dynamodb_encryption

metadata := {
	"id": "soc2-cc6.2-dynamodb-encryption",
	"name": "DynamoDB Encryption Enabled",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dynamodb:table"],
	"remediation": "Enable SSE with KMS: aws dynamodb update-table --table-name TABLE --sse-specification Enabled=true,SSEType=KMS",
}

violations contains violation if {
	input.resource_type == "aws:dynamodb:table"
	input.data.sse_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DynamoDB table '%s' does not have server-side encryption enabled", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
