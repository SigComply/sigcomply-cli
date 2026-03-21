# METADATA
# title: CC8.1 - Auto Scaling Uses Launch Template
# description: Auto Scaling groups should use launch templates instead of launch configurations for better change management
# scope: package
package sigcomply.soc2.cc8_1_asg_launch_template

metadata := {
	"id": "soc2-cc8.1-asg-launch-template",
	"name": "Auto Scaling Uses Launch Template",
	"framework": "soc2",
	"control": "CC8.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:autoscaling:group"],
	"remediation": "Migrate from launch configurations to launch templates: aws autoscaling update-auto-scaling-group --auto-scaling-group-name NAME --launch-template LaunchTemplateId=lt-XXXXX,Version='$Latest'",
}

violations contains violation if {
	input.resource_type == "aws:autoscaling:group"
	input.data.uses_launch_template == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Auto Scaling group '%s' does not use a launch template for change management", [input.data.group_name]),
		"details": {"group_name": input.data.group_name},
	}
}
