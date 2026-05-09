# METADATA
# title: CC6.6 - Default VPC Should Not Be Used
# description: Default VPCs should not be used in production as they have permissive default configurations
# scope: package
package sigcomply.soc2.cc6_6_default_vpc

metadata := {
	"id": "soc2-cc6.6-default-vpc",
	"name": "Default VPC Not Used",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:vpc"],
	"remediation": "Delete the default VPC or ensure it is not used for production workloads. Create custom VPCs with appropriate security controls.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:vpc"
	input.data.is_default == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("VPC '%s' is a default VPC. Default VPCs have permissive configurations and should not be used for production workloads.", [input.data.vpc_id]),
		"details": {
			"vpc_id": input.data.vpc_id,
			"is_default": true,
		},
	}
}
