# METADATA
# title: CC7.2 - CIS Metric Filter for Console Sign-in Without MFA
# description: A metric filter and alarm should exist for console sign-in without MFA
# scope: package
package sigcomply.soc2.cc7_2_cis_console_signin_no_mfa

metadata := {
	"id": "soc2-cc7.2-cis-console-signin-no-mfa",
	"name": "CIS Alarm - Console Sign-in Without MFA",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for console sign-in events where MFA is not used and associate an SNS alarm.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "console_signin_no_mfa"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for console sign-in without MFA (CIS 4.2)",
		"details": {
			"cis_control": "4.2",
			"filter_name": "console_signin_no_mfa",
		},
	}
}
