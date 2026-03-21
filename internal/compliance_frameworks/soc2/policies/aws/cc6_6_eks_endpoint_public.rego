# METADATA
# title: CC6.6 - EKS Cluster Endpoint Not Public
# description: EKS clusters should not have public API server endpoints
# scope: package
package sigcomply.soc2.cc6_6_eks_endpoint_public

metadata := {
	"id": "soc2-cc6.6-eks-endpoint-public",
	"name": "EKS Cluster Endpoint Not Public",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:eks:cluster"],
	"remediation": "Disable public access to the EKS API server endpoint or restrict to specific CIDR blocks.",
}

violations contains violation if {
	input.resource_type == "aws:eks:cluster"
	input.data.endpoint_public_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EKS cluster '%s' has public endpoint access enabled", [input.data.name]),
		"details": {"name": input.data.name, "endpoint_public_access": input.data.endpoint_public_access},
	}
}
