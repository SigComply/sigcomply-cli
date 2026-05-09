# METADATA
# title: CC7.4 - DynamoDB Point-in-Time Recovery
# description: DynamoDB tables should have PITR enabled for incident response data recovery
# scope: package
package sigcomply.soc2.cc7_4_dynamodb_pitr

metadata := {
	"id": "soc2-cc7.4-dynamodb-pitr",
	"name": "DynamoDB Point-in-Time Recovery",
	"framework": "soc2",
	"control": "CC7.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dynamodb:table"],
	"remediation": "Enable point-in-time recovery on the DynamoDB table.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:dynamodb:table"
	input.data.pitr_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DynamoDB table '%s' does not have point-in-time recovery enabled", [input.data.name]),
		"details": {"table_name": input.data.name},
	}
}
