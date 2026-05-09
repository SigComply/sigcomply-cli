# METADATA
# title: CC6.6 - WAF Enabled
# description: WAF must have at least one Web ACL configured
# scope: package
package sigcomply.soc2.cc6_6_waf_enabled

metadata := {
	"id": "soc2-cc6.6-waf-enabled",
	"name": "WAF Web ACL Configured",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:wafv2:status"],
	"remediation": "Create a WAF Web ACL and associate it with your resources",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:wafv2:status"
	input.data.web_acl_count == 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No WAF Web ACLs are configured",
		"details": {"region": input.data.region},
	}
}
