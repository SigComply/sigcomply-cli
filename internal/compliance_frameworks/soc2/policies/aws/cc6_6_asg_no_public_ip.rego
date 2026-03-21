# METADATA
# title: CC6.6 - Auto Scaling No Public IP Assignment
# description: Auto Scaling groups should not automatically assign public IP addresses to instances
# scope: package
package sigcomply.soc2.cc6_6_asg_no_public_ip

metadata := {
	"id": "soc2-cc6.6-asg-no-public-ip",
	"name": "Auto Scaling No Public IP Assignment",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:autoscaling:group"],
	"remediation": "Update the launch configuration or launch template to set AssociatePublicIpAddress=false and place instances behind a load balancer in a private subnet.",
}

violations contains violation if {
	input.resource_type == "aws:autoscaling:group"
	input.data.associate_public_ip == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Auto Scaling group '%s' assigns public IP addresses to its instances", [input.data.group_name]),
		"details": {"group_name": input.data.group_name},
	}
}
