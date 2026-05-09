# METADATA
# title: CC7.2 - CIS Metric Filter for Unauthorized API Calls
# description: A metric filter and alarm should exist for unauthorized API calls
# scope: package
package sigcomply.soc2.cc7_2_cis_unauthorized_api_calls

metadata := {
	"id": "soc2-cc7.2-cis-unauthorized-api-calls",
	"name": "CIS Alarm - Unauthorized API Calls",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for unauthorized API calls (AccessDenied, UnauthorizedAccess) and associate an SNS alarm.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "unauthorized_api_calls"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for unauthorized API calls (CIS 4.1)",
		"details": {
			"cis_control": "4.1",
			"filter_name": "unauthorized_api_calls",
		},
	}
}
