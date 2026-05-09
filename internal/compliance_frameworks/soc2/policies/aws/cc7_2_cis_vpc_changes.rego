# METADATA
# title: CC7.2 - CIS Metric Filter for VPC Changes
# description: A metric filter and alarm should exist for VPC changes
# scope: package
package sigcomply.soc2.cc7_2_cis_vpc_changes

metadata := {
	"id": "soc2-cc7.2-cis-vpc-changes",
	"name": "CIS Alarm - VPC Changes",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for VPC changes (CreateVpc, DeleteVpc, ModifyVpcAttribute, CreateVpcPeeringConnection, etc.) and associate an SNS alarm.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "vpc_changes"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for VPC changes (CIS 4.14)",
		"details": {
			"cis_control": "4.14",
			"filter_name": "vpc_changes",
		},
	}
}
