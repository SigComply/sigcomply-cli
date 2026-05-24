package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// Controls returns the SOC 2 control catalog used by the M6 walking
// skeleton plus the additional Common Criteria controls referenced by
// the infrastructure-source policies (CC7.1 monitoring, CC7.2 system
// operations / log capture). The full TSC 2017 catalog is post-M6 work.
func Controls() []core.Control {
	return []core.Control{
		{
			ID:               "SOC2.CC6.1",
			Name:             "Logical and Physical Access",
			Description:      "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
			Category:         "access",
			BaselineSeverity: core.SeverityHigh,
		},
		{
			ID:               "SOC2.CC6.3",
			Name:             "Periodic Access Reviews",
			Description:      "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, and authority.",
			Category:         "access",
			BaselineSeverity: core.SeverityMedium,
		},
		{
			ID:               "SOC2.CC7.1",
			Name:             "System Monitoring for Anomalies",
			Description:      "The entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities.",
			Category:         "monitoring",
			BaselineSeverity: core.SeverityHigh,
		},
		{
			ID:               "SOC2.CC7.2",
			Name:             "System Operations and Audit Logging",
			Description:      "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives.",
			Category:         "logging",
			BaselineSeverity: core.SeverityHigh,
		},
	}
}
