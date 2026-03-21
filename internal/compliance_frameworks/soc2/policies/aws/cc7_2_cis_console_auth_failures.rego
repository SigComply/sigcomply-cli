# METADATA
# title: CC7.2 - CIS Metric Filter for Console Authentication Failures
# description: A metric filter and alarm should exist for console authentication failures
# scope: package
package sigcomply.soc2.cc7_2_cis_console_auth_failures

metadata := {
	"id": "soc2-cc7.2-cis-console-auth-failures",
	"name": "CIS Alarm - Console Auth Failures",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for failed console authentication attempts and associate an SNS alarm.",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "console_auth_failures"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for console authentication failures (CIS 4.6)",
		"details": {
			"cis_control": "4.6",
			"filter_name": "console_auth_failures",
		},
	}
}
