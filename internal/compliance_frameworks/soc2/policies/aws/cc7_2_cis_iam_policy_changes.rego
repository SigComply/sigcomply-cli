# METADATA
# title: CC7.2 - CIS Metric Filter for IAM Policy Changes
# description: A metric filter and alarm should exist for IAM policy changes
# scope: package
package sigcomply.soc2.cc7_2_cis_iam_policy_changes

metadata := {
	"id": "soc2-cc7.2-cis-iam-policy-changes",
	"name": "CIS Alarm - IAM Policy Changes",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for IAM policy changes (CreatePolicy, DeletePolicy, AttachRolePolicy, etc.) and associate an SNS alarm.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "iam_policy_changes"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for IAM policy changes (CIS 4.4)",
		"details": {
			"cis_control": "4.4",
			"filter_name": "iam_policy_changes",
		},
	}
}
