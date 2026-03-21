# METADATA
# title: CC7.1 - WAF Logging Enabled
# description: WAF web ACLs should have logging enabled when WAF is in use
# scope: package
package sigcomply.soc2.cc7_1_waf_logging

metadata := {
	"id": "soc2-cc7.1-waf-logging",
	"name": "WAF Logging Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:wafv2:status"],
	"remediation": "Enable WAF logging to Amazon S3, CloudWatch Logs, or Kinesis Data Firehose.",
}

violations contains violation if {
	input.resource_type == "aws:wafv2:status"
	input.data.web_acl_count > 0
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("WAF logging is not enabled in region '%s' with %d web ACL(s) configured", [input.data.region, input.data.web_acl_count]),
		"details": {
			"region": input.data.region,
			"web_acl_count": input.data.web_acl_count,
		},
	}
}
