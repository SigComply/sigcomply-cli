package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// Control IDs referenced by more than one policy in the tables below.
// The catalog above spells each ID out once; the policy tables name the
// repeated ones through these constants.
const (
	ctrlCC61 = "CC6.1"
	ctrlCC62 = "CC6.2"
	ctrlCC65 = "CC6.5"
	ctrlCC66 = "CC6.6"
	ctrlCC67 = "CC6.7"
	ctrlCC68 = "CC6.8"
	ctrlCC71 = "CC7.1"
	ctrlCC73 = "CC7.3"
	ctrlCC81 = "CC8.1"
	ctrlCC92 = "CC9.2"
	ctrlA11  = "A1.1"
	ctrlA12  = "A1.2"
	ctrlC11  = "C1.1"
)

// Control categories: the closed set every control in the catalog and
// every automated policy is filed under.
const (
	catAccess           = "access"
	catAvailability     = "availability"
	catChangeManagement = "change-management"
	catDataProtection   = "data-protection"
	catGovernance       = "governance"
	catLogging          = "logging"
	catMonitoring       = "monitoring"
	catNetwork          = "network"
	catPrivacy          = "privacy"
	catRisk             = "risk"
)

// Controls returns the SOC 2 (TSC 2017) control catalog: the common
// criteria (CC1–CC9) plus the Availability (A1), Confidentiality (C1),
// Processing Integrity (PI1), and Privacy (P-series) categories
// referenced by the policy library.
func Controls() []core.Control {
	return []core.Control{
		// CC1 — Control environment.
		ctrl("CC1.1", "Integrity and Ethical Values", catGovernance, core.SeverityMedium),
		ctrl("CC1.2", "Board Oversight", catGovernance, core.SeverityMedium),
		ctrl("CC1.3", "Organizational Structure", catGovernance, core.SeverityMedium),
		ctrl("CC1.4", "Commitment to Competence", catGovernance, core.SeverityMedium),
		ctrl("CC1.5", "Accountability", catGovernance, core.SeverityMedium),
		// CC2 — Communication and information.
		ctrl("CC2.1", "Information Quality", catGovernance, core.SeverityMedium),
		ctrl("CC2.2", "Internal Communication", catGovernance, core.SeverityMedium),
		ctrl("CC2.3", "External Communication", catGovernance, core.SeverityMedium),
		// CC3 — Risk assessment.
		ctrl("CC3.1", "Risk Assessment Objectives", catRisk, core.SeverityMedium),
		ctrl("CC3.2", "Risk Identification and Fraud", catRisk, core.SeverityMedium),
		ctrl("CC3.3", "Fraud Risk", catRisk, core.SeverityMedium),
		ctrl("CC3.4", "Change Risk", catRisk, core.SeverityMedium),
		// CC4 — Monitoring activities.
		ctrl("CC4.1", "Control Monitoring", catMonitoring, core.SeverityMedium),
		ctrl("CC4.2", "Control Deficiency Communication", catMonitoring, core.SeverityMedium),
		// CC5 — Control activities.
		ctrl("CC5.1", "Control Selection", catGovernance, core.SeverityMedium),
		ctrl("CC5.2", "Technology Controls", catGovernance, core.SeverityMedium),
		ctrl("CC5.3", "Policy Deployment", catGovernance, core.SeverityMedium),
		// CC6 — Logical and physical access.
		ctrl("CC6.1", "Logical Access Security", catAccess, core.SeverityHigh),
		ctrl("CC6.2", "User Provisioning", catAccess, core.SeverityHigh),
		ctrl("CC6.3", "Access Review", catAccess, core.SeverityMedium),
		ctrl("CC6.4", "Physical Access", catAccess, core.SeverityMedium),
		ctrl("CC6.5", "Asset Disposal and Secret Hygiene", catDataProtection, core.SeverityMedium),
		ctrl("CC6.6", "Network Access Restriction", catNetwork, core.SeverityHigh),
		ctrl("CC6.7", "Transmission and Encryption", catDataProtection, core.SeverityHigh),
		ctrl("CC6.8", "Malware and Threat Detection", catMonitoring, core.SeverityHigh),
		// CC7 — System operations.
		ctrl("CC7.1", "Detection Infrastructure", catMonitoring, core.SeverityHigh),
		ctrl("CC7.2", "Security Monitoring", catMonitoring, core.SeverityHigh),
		ctrl("CC7.3", "Incident Evaluation", catMonitoring, core.SeverityHigh),
		ctrl("CC7.4", "Incident Response", catMonitoring, core.SeverityHigh),
		ctrl("CC7.5", "Recovery", catAvailability, core.SeverityMedium),
		// CC8 — Change management.
		ctrl("CC8.1", "Change Management", catChangeManagement, core.SeverityHigh),
		// CC9 — Risk mitigation.
		ctrl("CC9.1", "Risk Mitigation and Vendors", catRisk, core.SeverityMedium),
		ctrl("CC9.2", "Vendor Management", catRisk, core.SeverityMedium),
		// A1 — Availability.
		ctrl("A1.1", "Capacity and Backups", catAvailability, core.SeverityHigh),
		ctrl("A1.2", "Recovery Infrastructure", catAvailability, core.SeverityMedium),
		ctrl("A1.3", "Recovery Testing", catAvailability, core.SeverityMedium),
		// C1 — Confidentiality.
		ctrl("C1.1", "Confidential Data Protection", catDataProtection, core.SeverityHigh),
		ctrl("C1.2", "Confidential Data Retention", catDataProtection, core.SeverityMedium),
		ctrl("C1.3", "Confidentiality Agreements", catGovernance, core.SeverityMedium),
		// PI1 — Processing integrity.
		ctrl("PI1.1", "Processing Integrity", catGovernance, core.SeverityMedium),
		// P-series — Privacy.
		ctrl("P1.1", "Privacy Notice", catPrivacy, core.SeverityMedium),
		ctrl("P3.1", "Data Collection", catPrivacy, core.SeverityMedium),
		ctrl("P6.1", "Data Retention and Disposal", catPrivacy, core.SeverityMedium),
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
