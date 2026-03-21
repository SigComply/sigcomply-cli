# METADATA
# title: CC6.1 - IMDSv2 Required in Launch Templates
# description: EC2 launch templates should enforce IMDSv2 (HttpTokens=required)
# scope: package
package sigcomply.soc2.cc6_1_ec2_imdsv2_launch_template

metadata := {
	"id": "soc2-cc6.1-ec2-imdsv2-launch-template",
	"name": "IMDSv2 Required in Launch Templates",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:launch-template"],
	"remediation": "Update the launch template to require IMDSv2: set HttpTokens to 'required' in the metadata options.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:launch-template"
	input.data.http_tokens != "required"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Launch template '%s' does not enforce IMDSv2 (HttpTokens != required)", [input.data.launch_template_name]),
		"details": {
			"launch_template_name": input.data.launch_template_name,
			"launch_template_id": input.data.launch_template_id,
			"http_tokens": input.data.http_tokens,
		},
	}
}
