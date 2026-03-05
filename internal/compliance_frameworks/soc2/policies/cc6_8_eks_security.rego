# METADATA
# title: CC6.8 - EKS Cluster Security
# description: EKS clusters must have private endpoint, logging, and secrets encryption
# scope: package
package sigcomply.soc2.cc6_8_eks_security

metadata := {
	"id": "soc2-cc6.8-eks-security",
	"name": "EKS Cluster Security",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:eks:cluster"],
	"remediation": "Restrict endpoint access, enable logging, and enable secrets encryption for EKS cluster",
}

violations contains violation if {
	input.resource_type == "aws:eks:cluster"
	input.data.endpoint_public_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EKS cluster '%s' has public endpoint access enabled", [input.data.name]),
		"details": {"name": input.data.name, "issue": "endpoint_public_access"},
	}
}

violations contains violation if {
	input.resource_type == "aws:eks:cluster"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EKS cluster '%s' does not have logging enabled", [input.data.name]),
		"details": {"name": input.data.name, "issue": "logging_disabled"},
	}
}

violations contains violation if {
	input.resource_type == "aws:eks:cluster"
	input.data.secrets_encryption == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EKS cluster '%s' does not have secrets encryption enabled", [input.data.name]),
		"details": {"name": input.data.name, "issue": "secrets_encryption_disabled"},
	}
}
