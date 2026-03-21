# METADATA
# title: CC7.1 - OpenSearch Slow Logs Publishing
# description: OpenSearch domains should have slow log publishing enabled
# scope: package
package sigcomply.soc2.cc7_1_opensearch_slow_logs

metadata := {
	"id": "soc2-cc7.1-opensearch-slow-logs",
	"name": "OpenSearch Slow Logs Publishing",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:opensearch:domain"],
	"remediation": "Enable slow log publishing to CloudWatch Logs for the OpenSearch domain.",
}

violations contains violation if {
	input.resource_type == "aws:opensearch:domain"
	input.data.slow_logs_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("OpenSearch domain '%s' does not have slow log publishing enabled", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
