package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// availabilityPolicies — A1 availability: backups, redundancy, and
// point-in-time recovery.
func availabilityPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.a1.1.database_backup_enabled", control: "A1.1", severity: core.SeverityHigh, category: "availability", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "All managed databases have automated backups enabled.",
			rem:     "Enable automated backups on each database.",
			clause:  all(leaf("payload.backup_enabled", "eq", true), "database {{.payload.name}} does not have backups enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.a1.1.database_multi_az", control: "A1.1", severity: core.SeverityMedium, category: "availability", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "All managed databases are deployed multi-AZ for availability.",
			rem:     "Enable multi-AZ deployment on each database.",
			clause:  all(leaf("payload.multi_az", "eq", true), "database {{.payload.name}} is not multi-AZ"),
		}.policy(),
		autoPolicy{
			id: "soc2.a1.1.storage_versioning_enabled", control: "A1.1", severity: core.SeverityLow, category: "availability", cadence: "daily",
			accepts: []string{"object_storage_bucket"},
			desc:    "All object storage buckets have versioning enabled for recovery.",
			rem:     "Enable versioning on each bucket.",
			clause:  all(leaf("payload.versioning_enabled", "eq", true), "bucket {{.payload.name}} does not have versioning enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.a1.1.backup_plan_exists", control: "A1.1", severity: core.SeverityMedium, category: "availability", cadence: "daily",
			accepts: []string{"backup_plan"},
			desc:    "At least one active backup plan with a retention rule exists.",
			rem:     "Create an active backup plan with a retention rule.",
			clause:  anyRec(allOf(leaf("payload.is_active", "eq", true), leaf("payload.has_retention_rule", "eq", true)), "no active backup plan with a retention rule exists"),
		}.policy(),
		autoPolicy{
			id: "soc2.a1.2.dynamodb_pitr_enabled", control: "A1.2", severity: core.SeverityMedium, category: "availability", cadence: "daily",
			accepts: []string{"nosql_table"},
			desc:    "All NoSQL tables have point-in-time recovery enabled.",
			rem:     "Enable point-in-time recovery on each NoSQL table.",
			clause:  all(leaf("payload.point_in_time_recovery_enabled", "eq", true), "table {{.payload.name}} does not have point-in-time recovery"),
		}.policy(),
		autoPolicy{
			id: "soc2.a1.2.dynamodb_deletion_protection", control: "A1.2", severity: core.SeverityLow, category: "availability", cadence: "daily",
			accepts: []string{"nosql_table"},
			desc:    "All NoSQL tables have deletion protection enabled.",
			rem:     "Enable deletion protection on each NoSQL table.",
			clause:  all(leaf("payload.deletion_protection", "eq", true), "table {{.payload.name}} does not have deletion protection"),
		}.policy(),
	}
}

// confidentialityPolicies — C1 confidentiality: restricting access to
// confidential data stores.
func confidentialityPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.c1.1.storage_no_public_access", control: "C1.1", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"object_storage_bucket"},
			desc:    "All object storage buckets block public access.",
			rem:     "Block public access on each bucket.",
			clause:  all(leaf("payload.public_access_blocked", "eq", true), "bucket {{.payload.name}} does not block public access"),
		}.policy(),
		autoPolicy{
			id: "soc2.c1.1.database_no_public_access", control: "C1.1", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "No managed database is publicly accessible.",
			rem:     "Disable public accessibility on each database.",
			clause:  all(leaf("payload.publicly_accessible", "eq", false), "database {{.payload.name}} is publicly accessible"),
		}.policy(),
		autoPolicy{
			id: "soc2.c1.1.no_public_container_repos", control: "C1.1", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"container_registry"},
			desc:    "No container registry is publicly accessible.",
			rem:     "Make public container repositories private.",
			clause:  none(leaf("payload.is_public", "eq", true), "registry {{.payload.name}} is publicly accessible"),
		}.policy(),
		autoPolicy{
			id: "soc2.c1.1.dynamodb_encryption_enabled", control: "C1.1", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"nosql_table"},
			desc:    "All NoSQL tables are encrypted at rest.",
			rem:     "Enable encryption at rest on each NoSQL table.",
			clause:  all(leaf("payload.encryption_enabled", "eq", true), "table {{.payload.name}} is not encrypted at rest"),
		}.policy(),
	}
}
