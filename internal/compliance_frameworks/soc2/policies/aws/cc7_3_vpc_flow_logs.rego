# METADATA
# title: CC7.3 - VPC Flow Logs Enabled
# description: VPCs should have flow logs enabled for network security event evaluation
# scope: package
package sigcomply.soc2.cc7_3_vpc_flow_logs

metadata := {
	"id": "soc2-cc7.3-vpc-flow-logs",
	"name": "VPC Flow Logs for Security Event Evaluation",
	"framework": "soc2",
	"control": "CC7.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:vpc"],
	"remediation": "Enable VPC flow logs for network traffic analysis.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:vpc"
	input.data.flow_logs_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("VPC '%s' does not have flow logs enabled for security event evaluation", [input.data.vpc_id]),
		"details": {"vpc_id": input.data.vpc_id},
	}
}
