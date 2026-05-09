# METADATA
# title: CC7.1 - MSK Logging Enabled
# description: MSK clusters should have broker logging enabled to CloudWatch, S3, or Firehose
# scope: package
package sigcomply.soc2.cc7_1_msk_logging

metadata := {
	"id": "soc2-cc7.1-msk-logging",
	"name": "MSK Logging Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:msk:cluster"],
	"remediation": "Enable broker log delivery for the MSK cluster to at least one destination: CloudWatch Logs, Amazon S3, or Amazon Kinesis Data Firehose. Configure LoggingInfo.BrokerLogs when creating or updating the cluster.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:msk:cluster"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("MSK cluster '%s' does not have broker logging enabled", [input.data.cluster_name]),
		"details": {"cluster_name": input.data.cluster_name},
	}
}
