package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// availabilityPolicies — A1.2 availability: backups and point-in-time
// recovery. Versioning and multi-AZ also back A1.2, filed under their
// common criterion (cc6.7.storage_versioning_enabled,
// cc7.5.database_multi_az).
func availabilityPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.a1.2.database_backup_enabled", control: ctrlA12, severity: core.SeverityHigh, category: catAvailability, cadence: cadenceDaily,
			accepts: []string{etManagedDatabaseInstance},
			desc:    "All managed databases have automated backups enabled.",
			rem:     "Enable automated backups on each database.",
			clause:  all(leaf("payload.backup_enabled", "eq", true), "database {{.payload.name}} does not have backups enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.a1.2.backup_plan_exists", control: ctrlA12, severity: core.SeverityMedium, category: catAvailability, cadence: cadenceDaily,
			presence: "backup plans",
			accepts:  []string{"backup_plan"},
			desc:     "At least one active backup plan with a retention rule exists.",
			rem:      "Create an active backup plan with a retention rule.",
			clause:   anyRec(allOf(leaf("payload.is_active", "eq", true), leaf("payload.has_retention_rule", "eq", true)), "no active backup plan with a retention rule exists"),
		}.policy(),
		autoPolicy{
			id: "soc2.a1.2.dynamodb_pitr_enabled", control: ctrlA12, severity: core.SeverityMedium, category: catAvailability, cadence: cadenceDaily,
			accepts: []string{etNoSQLTable},
			desc:    "All NoSQL tables have point-in-time recovery enabled.",
			rem:     "Enable point-in-time recovery on each NoSQL table.",
			clause:  all(leaf("payload.point_in_time_recovery_enabled", "eq", true), "table {{.payload.name}} does not have point-in-time recovery"),
		}.policy(),
		autoPolicy{
			id: "soc2.a1.2.dynamodb_deletion_protection", control: ctrlA12, severity: core.SeverityLow, category: catAvailability, cadence: cadenceDaily,
			accepts: []string{etNoSQLTable},
			desc:    "All NoSQL tables have deletion protection enabled.",
			rem:     "Enable deletion protection on each NoSQL table.",
			clause:  all(leaf("payload.deletion_protection", "eq", true), "table {{.payload.name}} does not have deletion protection"),
		}.policy(),
	}
}

// confidentialityPolicies — C1.1 confidentiality. The public-access
// checks also back C1.1 and are filed under their common criterion
// (CC6.7, CC6.8) so one exposed bucket counts once.
func confidentialityPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.c1.1.dynamodb_encryption_enabled", control: ctrlC11, severity: core.SeverityHigh, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{etNoSQLTable},
			desc:    "All NoSQL tables are encrypted at rest.",
			rem:     "Enable encryption at rest on each NoSQL table.",
			clause:  all(leaf("payload.encryption_enabled", "eq", true), "table {{.payload.name}} is not encrypted at rest"),
		}.policy(),
	}
}
