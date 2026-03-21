# METADATA
# title: CC6.6 - OpenSearch VPC Configuration
# description: OpenSearch domains should be deployed within a VPC
# scope: package
package sigcomply.soc2.cc6_6_opensearch_vpc

metadata := {
	"id": "soc2-cc6.6-opensearch-vpc",
	"name": "OpenSearch VPC Configuration",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:opensearch:domain"],
	"remediation": "Deploy the OpenSearch domain within a VPC to restrict network access. Public domains are accessible from the internet.",
}

violations contains violation if {
	input.resource_type == "aws:opensearch:domain"
	input.data.vpc_configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("OpenSearch domain '%s' is not deployed within a VPC", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
