# METADATA
# title: CC7.1 - EKS Cluster Audit Logging Enabled
# description: EKS clusters must have control plane logging enabled
# scope: package
package sigcomply.soc2.cc7_1_eks_audit_logging

metadata := {
	"id": "soc2-cc7.1-eks-audit-logging",
	"name": "EKS Cluster Audit Logging Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:eks:cluster"],
	"remediation": "Enable EKS control plane logging for audit, api, authenticator, controllerManager, and scheduler log types.",
}

violations contains violation if {
	input.resource_type == "aws:eks:cluster"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EKS cluster '%s' does not have audit logging enabled", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
