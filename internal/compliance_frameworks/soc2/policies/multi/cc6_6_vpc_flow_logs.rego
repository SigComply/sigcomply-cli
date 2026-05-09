# METADATA
# title: CC6.6 - VPC/Subnet Flow Logs
# description: VPCs and subnets must have flow logs enabled for network monitoring
# scope: package
package sigcomply.soc2.cc6_6_flow_logs

metadata := {
	"id": "soc2-cc6.6-flow-logs",
	"name": "VPC/Subnet Flow Logs",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:vpc", "gcp:compute:subnet"],
	"remediation": "Enable flow logs on VPCs (AWS) or subnets (GCP) for network traffic monitoring.",
	"evidence_type": "automated",
}

# AWS VPC
violations contains violation if {
	input.resource_type == "aws:ec2:vpc"
	input.data.flow_logs_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("VPC '%s' does not have flow logs enabled", [input.data.vpc_id]),
		"details": {
			"vpc_id": input.data.vpc_id,
			"is_default": input.data.is_default,
		},
	}
}

# GCP Subnet
violations contains violation if {
	input.resource_type == "gcp:compute:subnet"
	input.data.flow_logs_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Subnet '%s' does not have flow logs enabled", [input.data.name]),
		"details": {
			"subnet_name": input.data.name,
			"region": input.data.region,
		},
	}
}
