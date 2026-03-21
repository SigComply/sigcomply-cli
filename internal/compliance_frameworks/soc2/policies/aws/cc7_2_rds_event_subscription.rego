# METADATA
# title: CC7.2 - RDS Event Notification Subscription
# description: RDS event subscriptions should be configured for critical instance and cluster events
# scope: package
package sigcomply.soc2.cc7_2_rds_event_subscription

metadata := {
	"id": "soc2-cc7.2-rds-event-subscription",
	"name": "RDS Event Notification Subscription",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:event-subscription"],
	"remediation": "Create an RDS event subscription for critical events: aws rds create-event-subscription --subscription-name <name> --sns-topic-arn <arn> --source-type db-instance --event-categories failure,maintenance,notification",
}

violations contains violation if {
	input.resource_type == "aws:rds:event-subscription"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No RDS event subscription configured for critical instance events",
		"details": {},
	}
}
