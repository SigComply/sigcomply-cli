# METADATA
# title: CC6.6 - SNS Topic No Public Access
# description: SNS topic access policies must not allow public access
# scope: package
package sigcomply.soc2.cc6_6_sns_public_access

metadata := {
	"id": "soc2-cc6.6-sns-public-access",
	"name": "SNS Topic No Public Access",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:sns:topic"],
	"remediation": "Update the SNS topic policy to remove wildcard principal (*) access. Restrict to specific AWS accounts or IAM roles.",
}

violations contains violation if {
	input.resource_type == "aws:sns:topic"
	input.data.policy_public_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("SNS topic '%s' has a policy that allows public access", [input.data.topic_name]),
		"details": {
			"topic_name": input.data.topic_name,
			"topic_arn": input.data.topic_arn,
		},
	}
}
