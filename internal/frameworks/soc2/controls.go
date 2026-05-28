package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// Controls returns the SOC 2 (TSC 2017) control catalog: the common
// criteria (CC1–CC9) plus the Availability (A1), Confidentiality (C1),
// Processing Integrity (PI1), and Privacy (P-series) categories
// referenced by the policy library.
func Controls() []core.Control {
	return []core.Control{
		// CC1 — Control environment.
		ctrl("CC1.1", "Integrity and Ethical Values", "governance", core.SeverityMedium),
		ctrl("CC1.2", "Board Oversight", "governance", core.SeverityMedium),
		ctrl("CC1.3", "Organizational Structure", "governance", core.SeverityMedium),
		ctrl("CC1.4", "Commitment to Competence", "governance", core.SeverityMedium),
		ctrl("CC1.5", "Accountability", "governance", core.SeverityMedium),
		// CC2 — Communication and information.
		ctrl("CC2.1", "Information Quality", "governance", core.SeverityMedium),
		ctrl("CC2.2", "Internal Communication", "governance", core.SeverityMedium),
		ctrl("CC2.3", "External Communication", "governance", core.SeverityMedium),
		// CC3 — Risk assessment.
		ctrl("CC3.1", "Risk Assessment Objectives", "risk", core.SeverityMedium),
		ctrl("CC3.2", "Risk Identification and Fraud", "risk", core.SeverityMedium),
		ctrl("CC3.3", "Fraud Risk", "risk", core.SeverityMedium),
		ctrl("CC3.4", "Change Risk", "risk", core.SeverityMedium),
		// CC4 — Monitoring activities.
		ctrl("CC4.1", "Control Monitoring", "monitoring", core.SeverityMedium),
		ctrl("CC4.2", "Control Deficiency Communication", "monitoring", core.SeverityMedium),
		// CC5 — Control activities.
		ctrl("CC5.1", "Control Selection", "governance", core.SeverityMedium),
		ctrl("CC5.2", "Technology Controls", "governance", core.SeverityMedium),
		ctrl("CC5.3", "Policy Deployment", "governance", core.SeverityMedium),
		// CC6 — Logical and physical access.
		ctrl("CC6.1", "Logical Access Security", "access", core.SeverityHigh),
		ctrl("CC6.2", "User Provisioning", "access", core.SeverityHigh),
		ctrl("CC6.3", "Access Review", "access", core.SeverityMedium),
		ctrl("CC6.4", "Physical Access", "access", core.SeverityMedium),
		ctrl("CC6.5", "Asset Disposal and Secret Hygiene", "data-protection", core.SeverityMedium),
		ctrl("CC6.6", "Network Access Restriction", "network", core.SeverityHigh),
		ctrl("CC6.7", "Transmission and Encryption", "data-protection", core.SeverityHigh),
		ctrl("CC6.8", "Malware and Threat Detection", "monitoring", core.SeverityHigh),
		// CC7 — System operations.
		ctrl("CC7.1", "Detection Infrastructure", "monitoring", core.SeverityHigh),
		ctrl("CC7.2", "Security Monitoring", "monitoring", core.SeverityHigh),
		ctrl("CC7.3", "Incident Evaluation", "monitoring", core.SeverityHigh),
		ctrl("CC7.4", "Incident Response", "monitoring", core.SeverityHigh),
		ctrl("CC7.5", "Recovery", "availability", core.SeverityMedium),
		// CC8 — Change management.
		ctrl("CC8.1", "Change Management", "change-management", core.SeverityHigh),
		// CC9 — Risk mitigation.
		ctrl("CC9.1", "Risk Mitigation and Vendors", "risk", core.SeverityMedium),
		ctrl("CC9.2", "Vendor Management", "risk", core.SeverityMedium),
		// A1 — Availability.
		ctrl("A1.1", "Capacity and Backups", "availability", core.SeverityHigh),
		ctrl("A1.2", "Recovery Infrastructure", "availability", core.SeverityMedium),
		ctrl("A1.3", "Recovery Testing", "availability", core.SeverityMedium),
		// C1 — Confidentiality.
		ctrl("C1.1", "Confidential Data Protection", "data-protection", core.SeverityHigh),
		ctrl("C1.2", "Confidential Data Retention", "data-protection", core.SeverityMedium),
		ctrl("C1.3", "Confidentiality Agreements", "governance", core.SeverityMedium),
		// PI1 — Processing integrity.
		ctrl("PI1.1", "Processing Integrity", "governance", core.SeverityMedium),
		// P-series — Privacy.
		ctrl("P1.1", "Privacy Notice", "privacy", core.SeverityMedium),
		ctrl("P3.1", "Data Collection", "privacy", core.SeverityMedium),
		ctrl("P6.1", "Data Retention and Disposal", "privacy", core.SeverityMedium),
	}
}

func ctrl(id, name, category string, sev core.Severity) core.Control {
	return core.Control{
		ID:               id,
		Name:             name,
		Description:      name + " (SOC 2 TSC 2017 " + id + ").",
		Category:         category,
		BaselineSeverity: sev,
	}
}
