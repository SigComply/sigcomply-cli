# METADATA
# title: CC6.6 - Launch Template No Public IP
# description: EC2 launch templates should not assign public IPs by default
# scope: package
package sigcomply.soc2.cc6_6_ec2_launch_template_no_public_ip

metadata := {
	"id": "soc2-cc6.6-ec2-launch-template-no-public-ip",
	"name": "Launch Template No Public IP",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:launch-template"],
	"remediation": "Configure launch template to not auto-assign public IP addresses.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:launch-template"
	input.data.assigns_public_ip == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Launch template '%s' assigns public IP addresses by default", [input.data.name]),
		"details": {"template_name": input.data.name},
	}
}
