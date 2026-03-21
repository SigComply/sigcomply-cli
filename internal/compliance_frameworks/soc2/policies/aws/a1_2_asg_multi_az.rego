# METADATA
# title: A1.2 - Auto Scaling Multi-AZ Deployment
# description: Auto Scaling groups should span multiple Availability Zones for high availability
# scope: package
package sigcomply.soc2.a1_2_asg_multi_az

metadata := {
	"id": "soc2-a1.2-asg-multi-az",
	"name": "Auto Scaling Multi-AZ Deployment",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:autoscaling:group"],
	"remediation": "Configure the Auto Scaling group to use multiple Availability Zones for fault tolerance and high availability.",
}

violations contains violation if {
	input.resource_type == "aws:autoscaling:group"
	input.data.multi_az == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Auto Scaling group '%s' is not configured across multiple Availability Zones", [input.data.group_name]),
		"details": {"group_name": input.data.group_name},
	}
}
