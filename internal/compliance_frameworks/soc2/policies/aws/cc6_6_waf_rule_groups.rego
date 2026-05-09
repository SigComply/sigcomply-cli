# METADATA
# title: CC6.6 - WAF Web ACL Has Rules
# description: WAF web ACLs should have rules configured when WAF is in use
# scope: package
package sigcomply.soc2.cc6_6_waf_rule_groups

metadata := {
	"id": "soc2-cc6.6-waf-rule-groups",
	"name": "WAF Web ACL Has Rules",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:wafv2:status"],
	"remediation": "Add managed or custom rule groups to WAF web ACLs to actively protect resources.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:wafv2:status"
	input.data.web_acl_count > 0
	input.data.has_rules == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("WAF web ACLs in region '%s' do not have rules configured", [input.data.region]),
		"details": {
			"region": input.data.region,
			"web_acl_count": input.data.web_acl_count,
		},
	}
}
