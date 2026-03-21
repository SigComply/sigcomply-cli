# METADATA
# title: CC6.6 - Stopped EC2 Instances Cleanup
# description: EC2 instances stopped for extended periods should be terminated
# scope: package
package sigcomply.soc2.cc6_6_ec2_stopped_instances

metadata := {
	"id": "soc2-cc6.6-ec2-stopped-instances",
	"name": "Stopped EC2 Instances Cleanup",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:instance"],
	"remediation": "Review stopped EC2 instances and terminate those no longer needed. Create AMIs for instances that may need to be relaunched later.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:instance"
	input.data.state == "stopped"
	input.data.days_since_stopped > 30
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EC2 instance '%s' has been stopped for %d days (threshold: 30)", [input.data.instance_id, input.data.days_since_stopped]),
		"details": {
			"instance_id": input.data.instance_id,
			"days_since_stopped": input.data.days_since_stopped,
		},
	}
}
