# METADATA
# title: CC7.1 - EC2 Detailed Monitoring
# description: EC2 instances should have detailed monitoring enabled for enhanced observability
# scope: package
package sigcomply.soc2.cc7_1_ec2_detailed_monitoring

metadata := {
	"id": "soc2-cc7.1-ec2-detailed-monitoring",
	"name": "EC2 Detailed Monitoring",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:instance"],
	"remediation": "Enable detailed monitoring: aws ec2 monitor-instances --instance-ids INSTANCE_ID",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:instance"
	input.data.detailed_monitoring_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EC2 instance '%s' does not have detailed monitoring enabled", [input.data.instance_id]),
		"details": {
			"instance_id": input.data.instance_id,
		},
	}
}
