# METADATA
# title: CC7.2 - GuardDuty EKS Audit Log Monitoring
# description: GuardDuty EKS Audit Log Monitoring must be enabled for Kubernetes threat detection
# scope: package
package sigcomply.soc2.cc7_2_guardduty_eks_protection

metadata := {
	"id": "soc2-cc7.2-guardduty-eks-protection",
	"name": "GuardDuty EKS Audit Log Monitoring",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:guardduty:detector"],
	"remediation": "Enable GuardDuty EKS Audit Log Monitoring: aws guardduty update-detector --detector-id <id> --features [{Name=EKS_AUDIT_LOGS,Status=ENABLED}]",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:guardduty:detector"
	input.data.enabled == true
	input.data.eks_audit_logs_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GuardDuty EKS Audit Log Monitoring is not enabled in region '%s'", [input.data.region]),
		"details": {
			"region": input.data.region,
			"detector_id": input.data.detector_id,
		},
	}
}
