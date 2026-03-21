# METADATA
# title: CC6.2 - EKS Secrets Encryption
# description: EKS clusters should have envelope encryption enabled for Kubernetes secrets
# scope: package
package sigcomply.soc2.cc6_2_eks_secrets_encryption

metadata := {
	"id": "soc2-cc6.2-eks-secrets-encryption",
	"name": "EKS Secrets Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:eks:cluster"],
	"remediation": "Enable secrets encryption when creating an EKS cluster: aws eks create-cluster --encryption-config '[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"<kms-key-arn>\"}}]'",
}

violations contains violation if {
	input.resource_type == "aws:eks:cluster"
	input.data.secrets_encryption == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EKS cluster '%s' does not have secrets encryption enabled", [input.data.name]),
		"details": {
			"cluster_name": input.data.name,
		},
	}
}
