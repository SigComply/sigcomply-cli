# METADATA
# title: A1.2 - DynamoDB Point-in-Time Recovery
# description: DynamoDB tables must have point-in-time recovery enabled
# scope: package
package sigcomply.soc2.a1_2_dynamodb_pitr

metadata := {
	"id": "soc2-a1.2-dynamodb-pitr",
	"name": "DynamoDB PITR Enabled",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dynamodb:table"],
	"remediation": "Enable PITR: aws dynamodb update-continuous-backups --table-name TABLE --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:dynamodb:table"
	input.data.pitr_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DynamoDB table '%s' does not have point-in-time recovery enabled", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
