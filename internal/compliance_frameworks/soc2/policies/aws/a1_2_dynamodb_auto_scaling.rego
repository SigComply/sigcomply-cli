# METADATA
# title: A1.2 - DynamoDB Auto Scaling
# description: DynamoDB tables should use on-demand billing for automatic scaling
# scope: package
package sigcomply.soc2.a1_2_dynamodb_auto_scaling

metadata := {
	"id": "soc2-a1.2-dynamodb-auto-scaling",
	"name": "DynamoDB Auto Scaling",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dynamodb:table"],
	"remediation": "Switch to on-demand billing: aws dynamodb update-table --table-name TABLE --billing-mode PAY_PER_REQUEST",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:dynamodb:table"
	input.data.billing_mode == "PROVISIONED"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DynamoDB table '%s' uses provisioned billing mode without auto-scaling guarantee", [input.data.name]),
		"details": {"name": input.data.name, "billing_mode": input.data.billing_mode},
	}
}
