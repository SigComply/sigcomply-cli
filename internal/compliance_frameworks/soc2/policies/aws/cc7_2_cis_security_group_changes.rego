# METADATA
# title: CC7.2 - CIS Metric Filter for Security Group Changes
# description: A metric filter and alarm should exist for security group changes
# scope: package
package sigcomply.soc2.cc7_2_cis_security_group_changes

metadata := {
	"id": "soc2-cc7.2-cis-security-group-changes",
	"name": "CIS Alarm - Security Group Changes",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for security group changes (AuthorizeSecurityGroupIngress, RevokeSecurityGroupIngress, CreateSecurityGroup, DeleteSecurityGroup) and associate an SNS alarm.",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "security_group_changes"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for security group changes (CIS 4.10)",
		"details": {
			"cis_control": "4.10",
			"filter_name": "security_group_changes",
		},
	}
}
