# METADATA
# title: CC7.1 - OpenSearch Audit Logging Enabled
# description: OpenSearch domains must have audit logging enabled to track user activity
# scope: package
package sigcomply.soc2.cc7_1_opensearch_audit_logging

metadata := {
	"id": "soc2-cc7.1-opensearch-audit-logging",
	"name": "OpenSearch Audit Logging Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:opensearch:domain"],
	"remediation": "Enable audit logging for the OpenSearch domain to track user activity and access patterns.",
}

violations contains violation if {
	input.resource_type == "aws:opensearch:domain"
	input.data.audit_logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("OpenSearch domain '%s' does not have audit logging enabled", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
