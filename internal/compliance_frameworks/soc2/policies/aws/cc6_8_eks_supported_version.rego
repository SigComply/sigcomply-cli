# METADATA
# title: CC6.8 - EKS Supported Kubernetes Version
# description: EKS clusters should run a supported Kubernetes version
# scope: package
package sigcomply.soc2.cc6_8_eks_supported_version

metadata := {
	"id": "soc2-cc6.8-eks-supported-version",
	"name": "EKS Supported Kubernetes Version",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:eks:cluster"],
	"remediation": "Upgrade the EKS cluster to a supported Kubernetes version (1.28 or later).",
}

eol_versions := {"1.21", "1.22", "1.23", "1.24", "1.25", "1.26", "1.27"}

violations contains violation if {
	input.resource_type == "aws:eks:cluster"
	eol_versions[input.data.version]
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EKS cluster '%s' is running end-of-life Kubernetes version '%s'", [input.data.name, input.data.version]),
		"details": {
			"cluster_name": input.data.name,
			"version": input.data.version,
		},
	}
}
