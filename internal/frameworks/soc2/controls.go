package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// Controls returns the SOC 2 control catalog used by the M6 walking
// skeleton plus the identity-source policies layered on top. Only the
// controls referenced by the registered policies are listed today;
// the full TSC 2017 catalog is deferred.
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
			Name:             "Change Management for Production Systems",
			Description:      "The entity implements logical access controls over the changes to system components to protect against unauthorized changes — including enforced code review and protected branches in source control.",
			Category:         "change-management",
			BaselineSeverity: core.SeverityHigh,
		},
		{
			ID:               "SOC2.CC6.7",
			Name:             "Restrict Information Transmission",
			Description:      "The entity restricts the transmission, movement, and removal of information to authorized internal and external users — including enforcing MFA on applications that handle production data.",
			Category:         "access",
			BaselineSeverity: core.SeverityHigh,
		},
	}
}
