# METADATA
# title: CC7.1 - CloudWatch Security Alarms
# description: Critical security alarms must be configured in CloudWatch
# scope: package
package sigcomply.soc2.cc7_1_cloudwatch_alarms

metadata := {
	"id": "soc2-cc7.1-security-alarms",
	"name": "CloudWatch Security Alarms Configured",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:alarm-config"],
	"remediation": "Configure CloudWatch alarms for unauthorized API calls, root account usage, and console sign-in failures",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:alarm-config"
	input.data.all_critical_alarms_configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Not all critical security alarms are configured in CloudWatch",
		"details": {
			"has_unauthorized_api_calls": input.data.has_unauthorized_api_calls,
			"has_root_usage": input.data.has_root_usage,
			"has_console_sign_in_failures": input.data.has_console_sign_in_failures,
		},
	}
}
