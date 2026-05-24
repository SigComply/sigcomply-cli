package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// Controls returns the SOC 2 control catalog used by the shipped
// policy set: the M6 walking-skeleton CC6.1 / CC6.3 plus the access /
// data-protection / monitoring / logging controls referenced by the
// post-M6 plugin-set policies. The full TSC 2017 catalog is still
// post-M6 work.
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
			ID:               "SOC2.CC6.6",
			Name:             "Logical Access to System Components",
			Description:      "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
			Category:         "access",
			BaselineSeverity: core.SeverityHigh,
		},
		{
			ID:               "SOC2.CC6.7",
			Name:             "Transmission and Movement of Information",
			Description:      "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal.",
			Category:         "data-protection",
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
