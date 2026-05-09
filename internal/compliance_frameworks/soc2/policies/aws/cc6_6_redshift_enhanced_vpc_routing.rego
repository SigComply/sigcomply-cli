# METADATA
# title: CC6.6 - Redshift Enhanced VPC Routing
# description: Redshift clusters must have enhanced VPC routing enabled to force traffic through VPC
# scope: package
package sigcomply.soc2.cc6_6_redshift_enhanced_vpc_routing

metadata := {
	"id": "soc2-cc6.6-redshift-enhanced-vpc-routing",
	"name": "Redshift Enhanced VPC Routing",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:redshift:cluster"],
	"remediation": "Enable enhanced VPC routing on the Redshift cluster: aws redshift modify-cluster --cluster-identifier <id> --enhanced-vpc-routing",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:redshift:cluster"
	input.data.enhanced_vpc_routing == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Redshift cluster '%s' does not have enhanced VPC routing enabled", [input.data.cluster_id]),
		"details": {
			"cluster_id": input.data.cluster_id,
		},
	}
}
