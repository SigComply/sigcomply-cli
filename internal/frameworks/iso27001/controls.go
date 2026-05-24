package iso27001

import "github.com/sigcomply/sigcomply-cli/internal/core"

// Controls returns the representative subset of ISO/IEC 27001:2022
// Annex A controls covered by this framework skeleton. The full Annex
// A catalog (93 controls) is post-M6 work; this list pins the controls
// that the 5 representative policies map to plus a few adjacent
// controls (A.5.15, A.8.7, A.8.16) declared up-front so the catalog
// is additive when their policies land.
//
// Control titles and identifiers follow ISO/IEC 27001:2022 Annex A.
func Controls() []core.Control {
	return []core.Control{
		{
			ID:               "ISO27001.A.5.15",
			Name:             "Access control",
			Description:      "Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements.",
			Category:         "access",
			BaselineSeverity: core.SeverityHigh,
		},
		{
			ID:               "ISO27001.A.5.18",
			Name:             "Access rights",
			Description:      "Access rights to information and other associated assets shall be provisioned, reviewed, modified and removed in accordance with the organization's topic-specific policy on, and rules for, access control.",
			Category:         "access",
			BaselineSeverity: core.SeverityMedium,
		},
		{
			ID:               "ISO27001.A.8.2",
			Name:             "Privileged access rights",
			Description:      "The allocation and use of privileged access rights shall be restricted and managed.",
			Category:         "access",
			BaselineSeverity: core.SeverityHigh,
		},
		{
			ID:               "ISO27001.A.8.5",
			Name:             "Secure authentication",
			Description:      "Secure authentication technologies and procedures shall be implemented based on information access restrictions and the topic-specific policy on access control.",
			Category:         "access",
			BaselineSeverity: core.SeverityHigh,
		},
		{
			ID:               "ISO27001.A.8.7",
			Name:             "Protection against malware",
			Description:      "Protection against malware shall be implemented and supported by appropriate user awareness.",
			Category:         "endpoint",
			BaselineSeverity: core.SeverityHigh,
		},
		{
			ID:               "ISO27001.A.8.16",
			Name:             "Monitoring activities",
			Description:      "Networks, systems and applications shall be monitored for anomalous behavior and appropriate actions taken to evaluate potential information security incidents.",
			Category:         "monitoring",
			BaselineSeverity: core.SeverityMedium,
		},
		{
			ID:               "ISO27001.A.8.24",
			Name:             "Use of cryptography",
			Description:      "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
			Category:         "crypto",
			BaselineSeverity: core.SeverityMedium,
		},
	}
}
