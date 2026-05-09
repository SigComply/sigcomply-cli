# METADATA
# title: A1.2 - DynamoDB Deletion Protection
# description: DynamoDB tables must have deletion protection enabled to prevent accidental deletion
# scope: package
package sigcomply.soc2.a1_2_dynamodb_deletion_protection

metadata := {
	"id": "soc2-a1.2-dynamodb-deletion-protection",
	"name": "DynamoDB Deletion Protection",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dynamodb:table"],
	"remediation": "Enable deletion protection on the DynamoDB table: aws dynamodb update-table --table-name <name> --deletion-protection-enabled",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:dynamodb:table"
	input.data.deletion_protection == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DynamoDB table '%s' does not have deletion protection enabled", [input.data.name]),
		"details": {
			"name": input.data.name,
		},
	}
}
