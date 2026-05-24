package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// Controls returns the SOC 2 control catalog used by the M6 walking
// skeleton. Only the controls referenced by the three seed policies
// are listed today; the full TSC 2017 catalog is post-M6 work.
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
	}
}
