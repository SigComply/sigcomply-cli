# METADATA
# title: CC6.1 - EC2 IMDSv2 Required
# description: EC2 instances must require IMDSv2 (HttpTokens=required) to prevent SSRF attacks
# scope: package
package sigcomply.soc2.cc6_1_ec2_imdsv2

metadata := {
	"id": "soc2-cc6.1-ec2-imdsv2",
	"name": "EC2 IMDSv2 Required",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:instance"],
	"remediation": "Require IMDSv2: aws ec2 modify-instance-metadata-options --instance-id INSTANCE_ID --http-tokens required --http-endpoint enabled",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:instance"
	input.data.http_tokens != "required"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EC2 instance '%s' does not require IMDSv2 (http_tokens='%s')", [input.data.instance_id, input.data.http_tokens]),
		"details": {
			"instance_id": input.data.instance_id,
			"http_tokens": input.data.http_tokens,
		},
	}
}
