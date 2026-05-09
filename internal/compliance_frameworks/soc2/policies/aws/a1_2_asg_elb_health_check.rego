# METADATA
# title: A1.2 - Auto Scaling ELB Health Check
# description: Auto Scaling groups should use ELB health checks for accurate instance health monitoring
# scope: package
package sigcomply.soc2.a1_2_asg_elb_health_check

metadata := {
	"id": "soc2-a1.2-asg-elb-health-check",
	"name": "Auto Scaling ELB Health Check",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:autoscaling:group"],
	"remediation": "Enable ELB health checks on the Auto Scaling group: aws autoscaling update-auto-scaling-group --auto-scaling-group-name NAME --health-check-type ELB --health-check-grace-period 300",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:autoscaling:group"
	input.data.elb_health_check == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Auto Scaling group '%s' does not use ELB health checks", [input.data.group_name]),
		"details": {"group_name": input.data.group_name},
	}
}
