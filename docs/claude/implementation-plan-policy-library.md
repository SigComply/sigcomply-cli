# Implementation Plan: SOC2 Type 2 + ISO 27001 Policy Library

_Written 2026-05-28. Execute in the next session._

---

## Ground Truth: Current State

| Layer | Status |
|---|---|
| Architecture (L0–L9) | Complete, 44 test packages passing |
| Evidence type schemas | 16 registered — 8 are vendor-specific and need redesign |
| Source plugins | 15 shipped (AWS ×10, GCP ×4, GitHub, Okta, Manual) |
| SOC2 policies | 17 seed policies |
| ISO 27001 policies | 0 (skeleton only, fails at runtime) |

---

## Decision: Fresh Rewrite of Policy Library

**Keep all architecture layers (L0–L9)** — planner, evaluator, vault, orchestrator, spec parsers, registries, signing, submitter are solid and well-tested.

**Rewrite the policy library from scratch.** 17 SOC2 seeds are a reference, not production coverage. ISO 27001 has nothing.

**Redesign 8 existing evidence type schemas** that are vendor-specific but represent cross-vendor concepts. Breaking change — necessary before writing 200 policies on top.

**Add 10 new evidence type schemas** to cover missing domain concepts.

**Add 12 new source plugins**, update 11 existing ones.

If `internal/compliance_frameworks/` still exists (old `.rego`-based approach), **delete it entirely** — dead code from the pre-rewrite architecture.

---

## Scope Boundary (Important)

**This plan implements the core policy logic — schemas + policy definitions — not API integrations.**

- **In scope**: evidence type schemas (what data looks like), policy YAML definitions (what to check), framework controls, manual catalogs.
- **Deferred**: Phase 2 new plugins. Policies that reference new evidence types (e.g. `firewall_rule`, `cloudwatch_alarm`) will exist in the framework but the planner simply skips them in a run until a matching source plugin is registered. That is correct behavior — not an error.
- **Exception in Phase 0**: the 11 existing plugins that emit renamed types (e.g. `aws.ec2` emits `ec2_instance` → must emit `compute_instance`) require updating. These are field normalization changes on already-working API calls, not new integrations.

**Schema design principle**: every `required` field in a schema must be answerable by any reasonable implementation of the concept (AWS, GCP, Azure, etc.) without a null or a sentinel value. Optional fields carry vendor-specific enrichment. This contract is what allows a future plugin author to translate their vendor API → canonical schema with zero changes to existing policies.

---

## Execution Sequence

Run phases sequentially — each phase's output is input to the next.

```
Phase 0 → Phase 1 → make test
  → Phase 3 → Phase 4 → Phase 5 → Phase 6
  → make test → make lint → commit

Phase 2 (new API plugins) — DEFERRED to future sessions
```

---

## Phase 0: Evidence Schema Redesign (Breaking)

### Renames and Unifications

| Old Schema(s) | New Schema | Plugins to Update |
|---|---|---|
| `ec2_instance` + `compute_instance` (GCP) | `compute_instance` | `aws.ec2`, `gcp.compute` |
| `rds_instance` + `cloudsql_instance` | `managed_database_instance` | `aws.rds`, `gcp.sql` |
| `cloudtrail_trail` | `audit_log_trail` | `aws.cloudtrail` |
| `cloudwatch_log_group` | `log_group` | `aws.cloudwatch` |
| `guardduty_detector` | `threat_detection_service` | `aws.guardduty` |
| `config_recorder` | `configuration_recorder` | `aws.config` |
| `gcp_iam_binding` | `iam_binding` | `gcp.iam` |
| `eks_cluster` | `kubernetes_cluster` | `aws.eks` |

Also: update `aws.iam` to emit `directory_user.v2` with added fields.

### Schema Field Specs

**`compute_instance`** (replaces ec2_instance + compute_instance)
```json
{
  "required": ["id", "name", "has_public_ip", "is_running", "root_volume_encrypted", "monitoring_enabled"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "region": "string",
    "is_running": "boolean",
    "has_public_ip": "boolean",
    "root_volume_encrypted": "boolean",
    "monitoring_enabled": "boolean",
    "metadata_service_hardened": "boolean"
  },
  "additionalProperties": true
}
```
`additionalProperties: true` carries AWS fields (vpc_id, iam_instance_profile) and GCP fields (uses_default_service_account, shielded_vm_enabled, os_login_enabled).

**`managed_database_instance`** (replaces rds_instance + cloudsql_instance)
```json
{
  "required": ["id", "name", "storage_encrypted", "publicly_accessible", "backup_enabled", "ssl_required"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "engine": "string",
    "engine_version": "string",
    "storage_encrypted": "boolean",
    "publicly_accessible": "boolean",
    "backup_enabled": "boolean",
    "ssl_required": "boolean",
    "multi_az": "boolean",
    "deletion_protection": "boolean",
    "kms_key_id": "string"
  },
  "additionalProperties": true
}
```

**`audit_log_trail`** (replaces cloudtrail_trail)
```json
{
  "required": ["id", "name", "is_enabled", "is_multi_region", "log_file_validation_enabled", "kms_encrypted"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "is_enabled": "boolean",
    "is_multi_region": "boolean",
    "log_file_validation_enabled": "boolean",
    "kms_encrypted": "boolean"
  },
  "additionalProperties": true
}
```

**`log_group`** (replaces cloudwatch_log_group)
```json
{
  "required": ["id", "name", "retention_set", "retention_days"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "retention_set": "boolean",
    "retention_days": {"type": "integer", "minimum": 0},
    "kms_encrypted": "boolean"
  },
  "additionalProperties": true
}
```

**`threat_detection_service`** (replaces guardduty_detector)
```json
{
  "required": ["id", "name", "is_enabled"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "region": "string",
    "is_enabled": "boolean"
  },
  "additionalProperties": true
}
```

**`configuration_recorder`** (replaces config_recorder)
```json
{
  "required": ["id", "name", "is_recording"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "is_recording": "boolean",
    "all_resource_types": "boolean"
  },
  "additionalProperties": true
}
```

**`iam_binding`** (replaces gcp_iam_binding)
```json
{
  "required": ["id", "role", "principal_id", "principal_type", "is_broad_admin_role"],
  "properties": {
    "id": "string",
    "role": "string",
    "principal_id": "string",
    "principal_type": {"type": "string", "enum": ["user", "group", "service_account"]},
    "is_broad_admin_role": "boolean",
    "has_condition": "boolean"
  },
  "additionalProperties": true
}
```

**`kubernetes_cluster`** (replaces eks_cluster)
```json
{
  "required": ["id", "name", "secrets_encryption_enabled", "logging_enabled"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "version": "string",
    "secrets_encryption_enabled": "boolean",
    "logging_enabled": "boolean",
    "is_private_endpoint": "boolean",
    "node_auto_upgrade_enabled": "boolean"
  },
  "additionalProperties": true
}
```

**`directory_user.v2`** — additive extension of v1
```json
{
  "allOf": [{"$ref": "directory_user.v1"}],
  "properties": {
    "is_root": "boolean",
    "has_console_access": "boolean",
    "has_programmatic_access": "boolean",
    "direct_policy_count": {"type": "integer", "minimum": 0},
    "unused_days": {"type": "integer", "minimum": -1},
    "groups": {"type": "array", "items": {"type": "string"}}
  },
  "additionalProperties": true
}
```

---

## Phase 1: New Evidence Type Schemas (10 New Types)

All files go in `internal/evidence_types/schemas/`.

**`firewall_rule`** — one record per inbound/outbound rule (not per security group)
```json
{
  "required": ["id", "name", "direction", "protocol", "from_port", "to_port", "is_unrestricted_ipv4", "is_unrestricted_ipv6"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "group_id": "string",
    "direction": {"type": "string", "enum": ["ingress", "egress"]},
    "protocol": {"type": "string", "enum": ["tcp", "udp", "icmp", "all"]},
    "from_port": {"type": "integer", "minimum": -1},
    "to_port": {"type": "integer", "minimum": -1},
    "source_cidr": "string",
    "dest_cidr": "string",
    "is_unrestricted_ipv4": "boolean",
    "is_unrestricted_ipv6": "boolean"
  },
  "additionalProperties": true
}
```
Identity key: `id` (unique per rule within a group).

**`network`** — one record per VPC / VNet / GCP VPC Network
```json
{
  "required": ["id", "name", "flow_logs_enabled", "is_default"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "region": "string",
    "flow_logs_enabled": "boolean",
    "is_default": "boolean",
    "cidr_block": "string"
  },
  "additionalProperties": true
}
```

**`password_policy`** — one record per account/org (singleton)
```json
{
  "required": ["id", "min_length", "max_age_days", "reuse_prevention_count", "requires_uppercase", "requires_lowercase", "requires_numbers", "requires_symbols"],
  "properties": {
    "id": "string",
    "provider": "string",
    "min_length": {"type": "integer", "minimum": 0},
    "max_age_days": {"type": "integer", "minimum": 0},
    "reuse_prevention_count": {"type": "integer", "minimum": 0},
    "requires_uppercase": "boolean",
    "requires_lowercase": "boolean",
    "requires_numbers": "boolean",
    "requires_symbols": "boolean",
    "mfa_required": "boolean"
  },
  "additionalProperties": true
}
```

**`iam_access_key`** — one record per programmatic credential
```json
{
  "required": ["id", "user_id", "is_active", "age_days", "last_used_days", "never_used"],
  "properties": {
    "id": "string",
    "user_id": "string",
    "is_active": "boolean",
    "age_days": {"type": "integer", "minimum": 0},
    "last_used_days": {"type": "integer", "minimum": -1},
    "never_used": "boolean"
  },
  "additionalProperties": true
}
```

**`tls_certificate`** — one record per certificate
```json
{
  "required": ["id", "domain", "status", "days_until_expiry", "is_managed", "auto_renew"],
  "properties": {
    "id": "string",
    "domain": "string",
    "provider": "string",
    "status": "string",
    "days_until_expiry": {"type": "integer"},
    "is_managed": "boolean",
    "auto_renew": "boolean"
  },
  "additionalProperties": true
}
```

**`secret`** — one record per secret
```json
{
  "required": ["id", "name", "rotation_enabled", "last_rotated_days", "kms_encrypted"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "rotation_enabled": "boolean",
    "last_rotated_days": {"type": "integer", "minimum": -1},
    "kms_encrypted": "boolean"
  },
  "additionalProperties": true
}
```

**`container_registry`** — one record per registry/repository
```json
{
  "required": ["id", "name", "scan_on_push_enabled", "is_public", "encryption_enabled"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "scan_on_push_enabled": "boolean",
    "image_immutability_enabled": "boolean",
    "is_public": "boolean",
    "encryption_enabled": "boolean"
  },
  "additionalProperties": true
}
```

**`vulnerability_finding`** — one record per active finding
```json
{
  "required": ["id", "resource_id", "resource_type", "severity", "status"],
  "properties": {
    "id": "string",
    "resource_id": "string",
    "resource_type": "string",
    "title": "string",
    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]},
    "status": {"type": "string", "enum": ["ACTIVE", "SUPPRESSED", "RESOLVED"]},
    "cve_id": "string",
    "score": "number",
    "remediation_available": "boolean"
  },
  "additionalProperties": true
}
```

**`backup_plan`** — one record per backup plan
```json
{
  "required": ["id", "name", "is_active", "has_retention_rule", "retention_days"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "is_active": "boolean",
    "has_retention_rule": "boolean",
    "retention_days": {"type": "integer", "minimum": 0},
    "covers_resource_types": {"type": "array", "items": {"type": "string"}}
  },
  "additionalProperties": true
}
```

**`serverless_function`** — one record per function
```json
{
  "required": ["id", "name", "runtime", "is_in_vpc", "tracing_enabled"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "runtime": "string",
    "is_in_vpc": "boolean",
    "tracing_enabled": "boolean",
    "reserved_concurrency_set": "boolean",
    "environment_variables_encrypted": "boolean"
  },
  "additionalProperties": true
}
```

---

## Phase 2: New Source Plugins (12 New)

All follow the standard self-registering pattern. Blank-import in `internal/sources/builtin/builtin.go`.

| Plugin ID | Path | Emits | Key AWS API |
|---|---|---|---|
| `aws.security_groups` | `internal/sources/aws/securitygroups/` | `firewall_rule` | `DescribeSecurityGroups` — flatten each ingress/egress rule to one record |
| `aws.vpc` | `internal/sources/aws/vpc/` | `network` | `DescribeVpcs` + `DescribeFlowLogs` |
| `aws.iam_password_policy` | `internal/sources/aws/iampasswordpolicy/` | `password_policy` | `GetAccountPasswordPolicy` — emits exactly one record |
| `aws.iam_access_keys` | `internal/sources/aws/iamaccesskeys/` | `iam_access_key` | `ListUsers` + `ListAccessKeys` + `GetAccessKeyLastUsed` |
| `aws.acm` | `internal/sources/aws/acm/` | `tls_certificate` | `ListCertificates` + `DescribeCertificate` |
| `aws.secrets_manager` | `internal/sources/aws/secretsmanager/` | `secret` | `ListSecrets` |
| `aws.ecr` | `internal/sources/aws/ecr/` | `container_registry`, `vulnerability_finding` | `DescribeRepositories` + `DescribeImageScanFindings` |
| `aws.backup` | `internal/sources/aws/backup/` | `backup_plan` | `ListBackupPlans` + `GetBackupPlan` |
| `aws.lambda` | `internal/sources/aws/lambda/` | `serverless_function` | `ListFunctions` |
| `gcp.firewall` | `internal/sources/gcp/firewall/` | `firewall_rule` | `firewalls.list` — flatten each allow/deny rule to one record |
| `gcp.logging` | `internal/sources/gcp/logging/` | `audit_log_trail`, `log_group` | `sinks.list` + `logMetrics.list` |
| `gcp.kms` | `internal/sources/gcp/kms/` | `kms_key` | `projects.locations.keyRings.cryptoKeys.list` |

### aws.security_groups: Flattening Strategy

A security group has N inbound rules and M outbound rules. Emit N+M `firewall_rule` records total.
- Record `id`: `{sg-id}:{direction}:{index}` (e.g., `sg-0abc:ingress:0`)
- `name`: security group name + description suffix
- Set `is_unrestricted_ipv4 = (source_cidr == "0.0.0.0/0")`
- Set `is_unrestricted_ipv6 = (source_cidr == "::/0")`
- AWS port range `0–65535` (all ports) → `from_port=-1, to_port=-1, protocol=all`

### gcp.firewall: Flattening Strategy

GCP firewall rules have `allowed[]` or `denied[]` arrays with protocol+ports. Emit one record per (rule, protocol, port-range) tuple.
- Record `id`: `{rule-name}:{protocol}:{port-range-index}`
- `direction`: GCP INGRESS → "ingress", EGRESS → "egress"
- `source_cidr`: first entry of `sourceRanges[]` (if multiple, emit multiple records)
- Set `is_unrestricted_ipv4 = (source_cidr == "0.0.0.0/0")`

---

## Phase 3: SOC2 Type 2 Policy Library (~102 policies)

### File Layout

```
internal/frameworks/soc2/
├── framework.go
├── controls.go                       # Expand to all TSC controls
├── policies_cc6_access.go            # CC6.1, CC6.3, CC6.5
├── policies_cc6_network.go           # CC6.6
├── policies_cc6_encryption.go        # CC6.7
├── policies_cc6_threat.go            # CC6.8
├── policies_cc7_operations.go        # CC7.1–CC7.5
├── policies_cc8_change.go            # CC8.1
├── policies_a1_availability.go       # A1.1–A1.2
├── policies_c1_confidentiality.go    # C1.1–C1.2
├── policies_manual.go                # All manual evidence policies
└── policies_test.go                  # Registry smoke tests
```

### CC6.1 — Logical Access Security (12 policies)

```
soc2.cc6.1.mfa_enforced_all_users
  evidence_mode: automated
  slots: users: accepts: [directory_user.v1]
  pass_when: all: mfa_enabled == true
  violation_message: "User {{.payload.email}} does not have MFA enabled"
  severity: critical

soc2.cc6.1.mfa_enforced_admins
  slots: users: accepts: [directory_user.v2]
  pass_when: filter: is_admin==true, all: mfa_enabled==true
  severity: critical

soc2.cc6.1.root_mfa_enabled
  slots: users: accepts: [directory_user.v2]
  pass_when: filter: is_root==true, all: mfa_enabled==true
  severity: critical

soc2.cc6.1.no_root_access_keys
  slots: users: accepts: [directory_user.v2]
  pass_when: filter: is_root==true, all: has_programmatic_access==false
  severity: critical

soc2.cc6.1.no_direct_iam_policies
  slots: users: accepts: [directory_user.v2]
  pass_when: all: direct_policy_count==0
  severity: medium

soc2.cc6.1.access_keys_rotated_90d
  slots: keys: accepts: [iam_access_key]
  pass_when: filter: is_active==true, all: age_days<=90
  parameters: max_age_days: {type: int, default: 90}
  severity: high

soc2.cc6.1.no_unused_active_keys_90d
  slots: keys: accepts: [iam_access_key]
  pass_when: filter: is_active==true, all: last_used_days<=90
  severity: medium

soc2.cc6.1.no_never_used_active_keys
  slots: keys: accepts: [iam_access_key]
  pass_when: filter: is_active==true, none: never_used==true
  severity: high

soc2.cc6.1.password_min_length_14
  slots: policy: accepts: [password_policy]
  pass_when: all: min_length>=14
  severity: medium

soc2.cc6.1.password_expiry_90d
  slots: policy: accepts: [password_policy]
  pass_when: all: {op: any_of, conditions: [{op: eq, field: max_age_days, value: 0}, {op: lte, field: max_age_days, value: 90}]}
  NOTE: max_age_days==0 means "no expiry" — use rule: escape hatch for this logic
  severity: medium

soc2.cc6.1.password_reuse_prevention
  slots: policy: accepts: [password_policy]
  pass_when: all: reuse_prevention_count>=24
  severity: low

soc2.cc6.1.password_complexity
  slots: policy: accepts: [password_policy]
  rule: (Go rule — AND of 4 boolean fields)
  severity: medium
```

### CC6.3 + CC6.5 — Access Review + Termination (2 manual)

```
soc2.cc6.3.access_review_quarterly
  evidence_mode: manual
  cadence: quarterly
  catalog_entry: access_review_quarterly

soc2.cc6.5.termination_access_removal_process
  evidence_mode: manual
  cadence: annual
  catalog_entry: termination_process_documented
```

### CC6.6 — Network Access (8 policies)

Port-range checks need `rule:` escape hatch because `from_port <= target <= to_port` is not expressible in pass_when's current operators.

```
soc2.cc6.6.no_unrestricted_ssh          # rule: — port 22 range check
soc2.cc6.6.no_unrestricted_rdp          # rule: — port 3389 range check
soc2.cc6.6.no_unrestricted_mysql        # rule: — port 3306 range check
soc2.cc6.6.no_unrestricted_postgres     # rule: — port 5432 range check
soc2.cc6.6.no_unrestricted_all_traffic  # pass_when: filter: protocol==all, none: is_unrestricted_ipv4==true
soc2.cc6.6.vpc_flow_logs_enabled        # pass_when: all: flow_logs_enabled==true
soc2.cc6.6.no_default_vpc_in_use        # pass_when: none: is_default==true  (severity: low)
soc2.cc6.6.network_segmentation_policy  # manual
```

For the port-range rules, write a shared Go `portRangeRule` helper that takes target port + evidence type and returns a `core.Rule` implementation. All four port policies share this helper.

### CC6.7 — Encryption at Rest & Transit (15 policies)

All are pure `pass_when` policies — no rule: needed.

```
soc2.cc6.7.storage_encryption_at_rest       object_storage_bucket  encryption_at_rest_enabled==true
soc2.cc6.7.storage_public_access_blocked    object_storage_bucket  public_access_blocked==true
soc2.cc6.7.storage_versioning_enabled       object_storage_bucket  versioning_enabled==true
soc2.cc6.7.database_encryption_at_rest      managed_database_instance  storage_encrypted==true
soc2.cc6.7.database_no_public_access        managed_database_instance  publicly_accessible==false
soc2.cc6.7.database_ssl_required            managed_database_instance  ssl_required==true
soc2.cc6.7.kms_key_rotation_enabled         kms_key  rotation_enabled==true
soc2.cc6.7.kms_customer_managed_keys        kms_key  is_customer_managed==true
soc2.cc6.7.compute_root_volume_encrypted    compute_instance  root_volume_encrypted==true
soc2.cc6.7.kubernetes_secrets_encrypted     kubernetes_cluster  secrets_encryption_enabled==true
soc2.cc6.7.tls_certificates_not_expiring    tls_certificate  days_until_expiry>=30
soc2.cc6.7.tls_auto_renew_enabled          tls_certificate  auto_renew==true
soc2.cc6.7.secrets_rotation_enabled         secret  rotation_enabled==true
soc2.cc6.7.secrets_kms_encrypted            secret  kms_encrypted==true
soc2.cc6.7.data_classification_policy       manual
```

### CC6.8 — Threat & Malware Detection (5 policies)

```
soc2.cc6.8.threat_detection_enabled         threat_detection_service  all: is_enabled==true
soc2.cc6.8.no_critical_findings_active      vulnerability_finding  filter: severity==CRITICAL, none: status==ACTIVE
soc2.cc6.8.no_high_findings_unaddressed     vulnerability_finding  filter: severity==HIGH, none: status==ACTIVE
soc2.cc6.8.container_scan_on_push           container_registry  all: scan_on_push_enabled==true
soc2.cc6.8.no_public_container_repos        container_registry  none: is_public==true
```

### CC7.1–CC7.5 — System Operations (14 policies)

```
soc2.cc7.1.audit_logging_enabled             audit_log_trail  all: is_enabled==true AND is_multi_region==true  → rule:
soc2.cc7.1.audit_log_integrity_enabled       audit_log_trail  all: log_file_validation_enabled==true
soc2.cc7.1.audit_log_kms_encrypted           audit_log_trail  all: kms_encrypted==true
soc2.cc7.1.log_retention_min_90d             log_group  rule: retention_set==true AND retention_days>=90
soc2.cc7.1.config_recording_enabled          configuration_recorder  all: is_recording==true
soc2.cc7.1.config_all_resource_types         configuration_recorder  all: all_resource_types==true
soc2.cc7.2.threat_detection_all_regions      threat_detection_service  all: is_enabled==true
soc2.cc7.3.compute_monitoring_enabled        compute_instance  all: monitoring_enabled==true
soc2.cc7.3.incident_response_plan            manual  annual
soc2.cc7.3.incident_response_tested          manual  annual
soc2.cc7.4.vulnerability_disclosure_policy   manual  annual
soc2.cc7.4.no_critical_vulns_active         vulnerability_finding  filter: severity==CRITICAL AND status==ACTIVE, none: true (= count==0)
soc2.cc7.5.database_multi_az                managed_database_instance  all: multi_az==true
soc2.cc7.5.database_deletion_protection     managed_database_instance  all: deletion_protection==true
```

### CC8.1 — Change Management (8 policies)

```
soc2.cc8.1.default_branch_protected         git_repository  all: default_branch_protected==true
soc2.cc8.1.required_code_reviews            git_repository  all: required_reviewers_count>=1
soc2.cc8.1.no_force_push_to_main            git_repository  none: allows_force_push==true
soc2.cc8.1.signed_commits_required          git_repository  all: requires_signed_commits==true
soc2.cc8.1.change_management_policy         manual  annual
soc2.cc8.1.security_sdlc_process            manual  annual
soc2.cc8.1.penetration_test_annual          manual  annual
soc2.cc8.1.vulnerability_management_policy  manual  annual
```

### A1 — Availability (5 policies)

```
soc2.a1.1.database_backup_enabled           managed_database_instance  all: backup_enabled==true
soc2.a1.1.database_multi_az                managed_database_instance  all: multi_az==true
soc2.a1.1.storage_versioning_enabled        object_storage_bucket  all: versioning_enabled==true
soc2.a1.1.backup_plan_exists                backup_plan  any: is_active==true AND has_retention_rule==true → rule:
soc2.a1.2.business_continuity_plan          manual  annual
```

### C1 — Confidentiality (4 policies)

```
soc2.c1.1.storage_no_public_access          object_storage_bucket  all: public_access_blocked==true
soc2.c1.1.database_no_public_access         managed_database_instance  all: publicly_accessible==false
soc2.c1.1.no_public_container_repos         container_registry  none: is_public==true
soc2.c1.2.data_retention_policy             manual  annual
```

### CC1–CC5, CC9, P-series — Manual Policies (27 policies)

All `evidence_mode: manual`, cadence: annual unless specified.

```
soc2.cc1.1.security_awareness_training       annual  — employee training completion
soc2.cc1.1.code_of_conduct_acknowledgment   annual  — signed code of conduct
soc2.cc1.2.board_security_oversight         annual  — board/exec security review evidence
soc2.cc1.3.org_chart_security_roles         annual  — org chart with security responsibilities
soc2.cc1.4.background_check_policy          annual  — background check process
soc2.cc2.1.information_security_policy      annual  — written IS policy
soc2.cc2.2.internal_security_communication  annual  — evidence of internal security comms
soc2.cc3.1.risk_assessment                  annual  — annual risk assessment
soc2.cc3.2.fraud_risk_assessment            annual  — fraud risk consideration
soc2.cc4.1.control_monitoring               quarterly — evidence of ongoing monitoring
soc2.cc5.1.control_selection_rationale      annual  — control design rationale
soc2.cc5.3.technology_controls_deployment   annual  — technology controls implementation evidence
soc2.cc6.2.user_provisioning_process        annual  — user onboarding/provisioning SOP
soc2.cc9.1.vendor_risk_assessment           annual  — third-party/vendor risk management
soc2.cc9.2.vendor_contracts_reviewed        annual  — vendor contracts with security clauses
soc2.p1.1.privacy_notice                    annual  — privacy notice/policy
soc2.p3.1.data_collection_policy            annual  — data collection and use policy
soc2.p6.1.data_retention_disposal           annual  — data retention and disposal policy
soc2.c1.3.nda_policy                        annual  — NDA policy and template
soc2.pi1.1.processing_integrity_policy      annual  — processing integrity documentation
soc2.cc7.3.security_monitoring_policy       annual  — security monitoring and alerting policy
soc2.cc8.1.code_review_policy               annual  — code review requirements documented
soc2.a1.3.recovery_procedures_tested        annual  — DR/recovery procedure test results
soc2.cc6.6.firewall_review_policy           annual  — firewall rules review process
soc2.cc6.1.privileged_access_policy         annual  — privileged access management policy
soc2.cc7.1.log_review_process               annual  — log review and alerting procedures
soc2.cc9.1.due_diligence_process            annual  — vendor due diligence process documented
```

**SOC2 Total: ~75 automated + ~27 manual = ~102 policies**

---

## Phase 4: ISO 27001:2022 Policy Library (~95 policies)

### Design Principle: Reuse Evidence Types, Separate Policy IDs

ISO 27001 automated policies check the same infrastructure as SOC2 — they differ in policy ID, `control:` field, description, and ISO control reference. Never create ISO-specific evidence types.

### File Layout

```
internal/frameworks/iso27001/
├── framework.go
├── controls.go                       # Expand to all 93 Annex A controls
├── policies_8_technological.go       # 8.1–8.34 technological controls
├── policies_5_organizational.go      # 5.x automated checks only
├── policies_manual.go                # All manual evidence policies
└── policies_test.go
```

### Theme D: Technological Controls — Automated (8.1–8.34)

Full list of automated policies:

```
iso27001.8.2.privileged_mfa_enforced
  control: A.8.2  directory_user.v2  filter: is_admin==true, all: mfa_enabled==true

iso27001.8.3.storage_no_public_access
  control: A.8.3  object_storage_bucket  all: public_access_blocked==true

iso27001.8.3.database_no_public_access
  control: A.8.3  managed_database_instance  all: publicly_accessible==false

iso27001.8.3.no_broad_admin_iam_bindings
  control: A.8.3  iam_binding
  pass_when: filter: principal_type==user, none: is_broad_admin_role==true AND has_condition==false → rule:

iso27001.8.4.branch_protection_enabled
  control: A.8.4  git_repository  all: default_branch_protected==true

iso27001.8.4.required_code_reviews
  control: A.8.4  git_repository  all: required_reviewers_count>=1

iso27001.8.5.mfa_enforced_all_users
  control: A.8.5  directory_user.v1  all: mfa_enabled==true

iso27001.8.5.password_minimum_length
  control: A.8.5  password_policy  all: min_length>=12

iso27001.8.5.password_complexity
  control: A.8.5  password_policy  rule: (compound AND)

iso27001.8.7.threat_detection_enabled
  control: A.8.7  threat_detection_service  all: is_enabled==true

iso27001.8.7.no_critical_malware_findings
  control: A.8.7  vulnerability_finding  filter: severity==CRITICAL, none: status==ACTIVE

iso27001.8.8.container_scan_on_push
  control: A.8.8  container_registry  all: scan_on_push_enabled==true

iso27001.8.8.no_critical_vulnerabilities
  control: A.8.8  vulnerability_finding  filter: severity==CRITICAL, none: status==ACTIVE

iso27001.8.9.config_recording_enabled
  control: A.8.9  configuration_recorder  all: is_recording==true

iso27001.8.9.config_all_resources
  control: A.8.9  configuration_recorder  all: all_resource_types==true

iso27001.8.12.storage_no_public_access
  control: A.8.12  object_storage_bucket  all: public_access_blocked==true

iso27001.8.12.database_no_public_access
  control: A.8.12  managed_database_instance  all: publicly_accessible==false

iso27001.8.12.no_public_container_repos
  control: A.8.12  container_registry  none: is_public==true

iso27001.8.13.database_backup_enabled
  control: A.8.13  managed_database_instance  all: backup_enabled==true

iso27001.8.13.database_multi_az
  control: A.8.13  managed_database_instance  all: multi_az==true

iso27001.8.13.storage_versioning_enabled
  control: A.8.13  object_storage_bucket  all: versioning_enabled==true

iso27001.8.13.backup_plan_exists
  control: A.8.13  backup_plan  rule: any(is_active AND has_retention_rule)

iso27001.8.15.audit_logging_enabled
  control: A.8.15  audit_log_trail  rule: all(is_enabled AND is_multi_region)

iso27001.8.15.audit_log_integrity
  control: A.8.15  audit_log_trail  all: log_file_validation_enabled==true

iso27001.8.15.audit_log_encrypted
  control: A.8.15  audit_log_trail  all: kms_encrypted==true

iso27001.8.15.log_retention_min_365d
  control: A.8.15  log_group  rule: retention_set==true AND retention_days>=365
  NOTE: ISO 27001 default is 1 year; SOC2 is 90d — different thresholds, separate policies

iso27001.8.16.threat_detection_active
  control: A.8.16  threat_detection_service  all: is_enabled==true

iso27001.8.16.compute_monitoring_enabled
  control: A.8.16  compute_instance  all: monitoring_enabled==true

iso27001.8.20.no_unrestricted_ssh
  control: A.8.20  firewall_rule  rule: portRangeCheck(22)

iso27001.8.20.no_unrestricted_rdp
  control: A.8.20  firewall_rule  rule: portRangeCheck(3389)

iso27001.8.20.no_unrestricted_database_ports
  control: A.8.20  firewall_rule  rule: portRangeCheck([3306,5432,1433])

iso27001.8.20.vpc_flow_logs_enabled
  control: A.8.20  network  all: flow_logs_enabled==true

iso27001.8.21.tls_certificates_valid
  control: A.8.21  tls_certificate  all: days_until_expiry>=30

iso27001.8.21.tls_auto_renew_enabled
  control: A.8.21  tls_certificate  all: auto_renew==true

iso27001.8.24.storage_encryption_at_rest
  control: A.8.24  object_storage_bucket  all: encryption_at_rest_enabled==true

iso27001.8.24.database_encryption_at_rest
  control: A.8.24  managed_database_instance  all: storage_encrypted==true

iso27001.8.24.compute_disk_encrypted
  control: A.8.24  compute_instance  all: root_volume_encrypted==true

iso27001.8.24.kms_key_rotation
  control: A.8.24  kms_key  all: rotation_enabled==true

iso27001.8.24.secrets_rotation_enabled
  control: A.8.24  secret  all: rotation_enabled==true

iso27001.8.25.branch_protection
  control: A.8.25  git_repository  all: default_branch_protected==true

iso27001.8.25.required_reviewers
  control: A.8.25  git_repository  all: required_reviewers_count>=1

iso27001.8.25.no_force_push_to_main
  control: A.8.25  git_repository  none: allows_force_push==true

iso27001.8.28.dependency_vulnerability_scanning
  control: A.8.28  container_registry  all: scan_on_push_enabled==true

iso27001.8.32.required_code_reviews
  control: A.8.32  git_repository  all: required_reviewers_count>=1

iso27001.8.32.no_force_push
  control: A.8.32  git_repository  none: allows_force_push==true

iso27001.5.3.no_broad_admin_bindings
  control: A.5.3  iam_binding  rule: none(is_broad_admin_role AND no_condition AND principal_type==user)

iso27001.5.16.inactive_user_accounts
  control: A.5.16  directory_user.v2  filter: is_active==true, all: unused_days<=90 (or -1)
  NOTE: -1 means never logged in — that's a finding too

iso27001.5.17.mfa_enforced
  control: A.5.17  directory_user.v1  all: mfa_enabled==true

iso27001.5.18.access_rights_review
  control: A.5.18  manual  quarterly

iso27001.5.36.compliance_with_policies
  control: A.5.36  (aggregate check — uses summary counts, implemented as manual attestation)
  manual  annual
```

**ISO 27001 Automated Total: ~47 policies**

### Manual Policies — All 4 Themes (~48 policies)

```
# Theme A: Organizational
iso27001.5.1.information_security_policies       annual
iso27001.5.2.roles_and_responsibilities          annual
iso27001.5.4.management_direction               annual
iso27001.5.5.contact_with_authorities           annual
iso27001.5.8.information_security_in_projects   annual
iso27001.5.9.asset_inventory                    annual
iso27001.5.10.acceptable_use_policy             annual
iso27001.5.12.data_classification_policy        annual
iso27001.5.13.information_labelling_policy      annual
iso27001.5.14.information_transfer_policy       annual
iso27001.5.19.supplier_security_policy          annual
iso27001.5.20.supplier_security_agreements      annual
iso27001.5.22.supplier_service_monitoring       annual
iso27001.5.24.incident_management_plan          annual
iso27001.5.26.incident_response_tested          annual
iso27001.5.27.lessons_learned_from_incidents    annual
iso27001.5.29.information_security_in_bcp       annual
iso27001.5.30.ict_continuity_tested             annual
iso27001.5.31.legal_requirements_inventory      annual
iso27001.5.34.privacy_and_pii_protection        annual
iso27001.5.35.independent_security_review       annual

# Theme B: People
iso27001.6.1.personnel_screening                annual
iso27001.6.2.terms_of_employment                annual
iso27001.6.3.security_awareness_training        annual
iso27001.6.4.disciplinary_process               annual
iso27001.6.5.responsibilities_on_termination    annual
iso27001.6.6.nda_confidentiality_agreement      annual

# Theme C: Physical (representative subset)
iso27001.7.1.physical_security_perimeters       annual
iso27001.7.2.physical_entry_controls            annual
iso27001.7.4.physical_security_monitoring       annual
iso27001.7.7.clear_desk_clear_screen_policy     annual
iso27001.7.10.storage_media_policy              annual
iso27001.7.14.secure_disposal_policy            annual

# Theme D: Manual portions
iso27001.8.1.endpoint_device_policy             annual
iso27001.8.6.capacity_management_process        annual
iso27001.8.10.information_deletion_policy       annual
iso27001.8.19.software_installation_policy      annual
iso27001.8.23.web_filtering_policy              annual
iso27001.8.26.application_security_requirements annual
iso27001.8.27.secure_architecture_principles    annual
iso27001.8.30.outsourced_development_policy     annual
iso27001.8.33.test_information_policy           annual
iso27001.8.34.audit_testing_protection_policy   annual
iso27001.8.32.change_management_policy          annual
```

**ISO 27001 Total: ~47 automated + ~48 manual = ~95 policies**

---

## Phase 5: Manual Evidence Catalogs

### `internal/core/manual/catalogs/soc2.yaml` (expand existing)

Add entries for all new manual policy catalog_entry IDs:

```yaml
# New entries to add (existing access_review_quarterly stays):
- id: termination_process_documented
  title: "User Offboarding Process"
  type: document_upload
  description: "Documented procedure for revoking access when employees leave"

- id: security_awareness_training
  title: "Security Awareness Training Completion"
  type: document_upload
  description: "Evidence of completed security awareness training (e.g., training platform certificate)"

- id: information_security_policy
  title: "Information Security Policy"
  type: document_upload
  description: "Written and approved information security policy document"

# ... ~25 more entries
```

### `internal/core/manual/catalogs/iso27001.yaml` (new file)

```yaml
catalog:
  - id: information_security_policies
    title: "Information Security Policy Suite"
    type: document_upload
    description: "Complete set of IS policies approved by management"

  - id: access_rights_review
    title: "Access Rights Review"
    type: document_upload
    description: "Formal periodic access rights review evidence"

  # ... ~46 more entries matching the manual policy list above
```

---

## Phase 6: Controls Registration

### `internal/frameworks/soc2/controls.go`

Expand to register all TSC criteria:

```go
var Controls = []core.Control{
    {ID: "CC1", Name: "Control Environment", Description: "..."},
    {ID: "CC1.1", ...},
    // CC1–CC9, A1, C1, PI1, P1–P8
}
```

### `internal/frameworks/iso27001/controls.go`

Register all 93 Annex A controls across 4 themes:

```go
var Controls = []core.Control{
    // Theme A: 5.1–5.37 (37 controls)
    {ID: "A.5.1", Name: "Policies for information security", Theme: "Organizational"},
    // Theme B: 6.1–6.8 (8 controls)
    // Theme C: 7.1–7.14 (14 controls)
    // Theme D: 8.1–8.34 (34 controls)
}
```

---

## Addenda from Research (Validated 2026-05-28)

The two research agents completed after the plan was written. Their findings validate the plan and surface these additions:

### A. `git_repository` Schema Needs 6 More Fields

Add to `git_repository.v1.yaml` (all optional, additionalProperties already true, but declare them for pass_when visibility):

```json
"secret_scanning_enabled": "boolean",
"push_protection_enabled": "boolean",
"dependabot_alerts_enabled": "boolean",
"code_scanning_enabled": "boolean",
"dismiss_stale_reviews": "boolean",
"require_code_owner_reviews": "boolean"
```

These unlock 6 new CC8.1 and CC6.5 policies.

### B. 4 Additional Evidence Types (High Value, Not in Phase 1)

Add these to Phase 1:

**`cloudwatch_alarm`** — one record per CloudWatch alarm (enables monitoring-as-code checks for CC7.2)
```json
{
  "required": ["id", "name", "state", "metric_filter_pattern", "has_sns_action"],
  "properties": {
    "id": "string",
    "name": "string",
    "state": {"type": "string", "enum": ["OK", "ALARM", "INSUFFICIENT_DATA"]},
    "metric_filter_pattern": "string",
    "has_sns_action": "boolean",
    "namespace": "string"
  },
  "additionalProperties": true
}
```

**`gcp_service_account_key`** — one record per SA key (enables GCP key hygiene checks)
```json
{
  "required": ["id", "service_account_id", "key_type", "age_days", "is_user_managed"],
  "properties": {
    "id": "string",
    "service_account_id": "string",
    "key_type": {"type": "string", "enum": ["USER_MANAGED", "SYSTEM_MANAGED"]},
    "age_days": {"type": "integer", "minimum": 0},
    "is_user_managed": "boolean"
  },
  "additionalProperties": true
}
```

**`nosql_table`** — DynamoDB, Firestore, Azure Cosmos DB (separate from managed_database_instance which is SQL-focused)
```json
{
  "required": ["id", "name", "encryption_enabled", "point_in_time_recovery_enabled", "deletion_protection"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "encryption_enabled": "boolean",
    "point_in_time_recovery_enabled": "boolean",
    "deletion_protection": "boolean",
    "stream_enabled": "boolean"
  },
  "additionalProperties": true
}
```

**`security_service`** — enablement status of account-level security services (SecurityHub, Macie, Inspector, GCP SCC)
```json
{
  "required": ["id", "name", "service_type", "is_enabled"],
  "properties": {
    "id": "string",
    "name": "string",
    "provider": "string",
    "service_type": {"type": "string", "enum": ["siem", "vulnerability_scanner", "dlp", "threat_detection", "cspm"]},
    "is_enabled": "boolean"
  },
  "additionalProperties": true
}
```

### C. 5 Additional Source Plugins (Add to Phase 2)

| Plugin ID | Path | Emits |
|---|---|---|
| `aws.dynamodb` | `internal/sources/aws/dynamodb/` | `nosql_table` |
| `aws.inspector` | `internal/sources/aws/inspector/` | `vulnerability_finding`, `security_service` |
| `aws.securityhub` | `internal/sources/aws/securityhub/` | `security_service`, `vulnerability_finding` |
| `aws.macie` | `internal/sources/aws/macie/` | `security_service` |
| `gcp.service_account_keys` | `internal/sources/gcp/serviceaccountkeys/` | `gcp_service_account_key` |

### D. Additional SOC2 Policies (Add to Phase 3)

**CC6.5 — Secret hygiene in repositories** (uses extended git_repository fields):
```
soc2.cc6.5.secret_scanning_enabled        git_repository  all: secret_scanning_enabled==true
soc2.cc6.5.push_protection_enabled        git_repository  all: push_protection_enabled==true
soc2.cc8.1.dependabot_alerts_enabled      git_repository  all: dependabot_alerts_enabled==true
soc2.cc8.1.code_scanning_enabled          git_repository  all: code_scanning_enabled==true
soc2.cc8.1.dismiss_stale_reviews          git_repository  all: dismiss_stale_reviews==true
soc2.cc8.1.require_code_owner_reviews     git_repository  all: require_code_owner_reviews==true
```

**CC7.2 — CloudWatch metric alarms** (uses cloudwatch_alarm):

These 8 alarms are required by CIS AWS Benchmark v1.4 and are standard SOC2 CC7.2 evidence:
```
soc2.cc7.2.alarm_unauthorized_api_calls    cloudwatch_alarm  any: metric_filter_pattern contains "UnauthorizedAttempt"
soc2.cc7.2.alarm_root_account_usage        cloudwatch_alarm  any: metric_filter_pattern contains "RootAccount"
soc2.cc7.2.alarm_iam_policy_changes        cloudwatch_alarm  any: metric_filter_pattern contains "DeleteGroupPolicy|PutGroupPolicy"
soc2.cc7.2.alarm_cloudtrail_config_changes cloudwatch_alarm  any: metric_filter_pattern contains "StopLogging|DeleteTrail"
soc2.cc7.2.alarm_console_login_no_mfa      cloudwatch_alarm  any: metric_filter_pattern contains "ConsoleLogin" AND "MFAUsed"
soc2.cc7.2.alarm_security_group_changes    cloudwatch_alarm  any: metric_filter_pattern contains "CreateSecurityGroup|DeleteSecurityGroup"
soc2.cc7.2.alarm_vpc_changes               cloudwatch_alarm  any: metric_filter_pattern contains "CreateVpc|DeleteVpc"
soc2.cc7.2.alarm_kms_key_deletion          cloudwatch_alarm  any: metric_filter_pattern contains "DisableKey|ScheduleKeyDeletion"
```
NOTE: These checks use `any:` quantifier — at least one alarm must match each pattern. Use `rule:` escape hatch with substring matching.

**CC7.1 — Security service enablement** (uses security_service):
```
soc2.cc7.1.securityhub_enabled             security_service  filter: service_type==siem, any: is_enabled==true
soc2.cc7.1.inspector_enabled               security_service  filter: service_type==vulnerability_scanner, any: is_enabled==true
soc2.cc6.8.macie_enabled                   security_service  filter: service_type==dlp, any: is_enabled==true
```

**C1.1/A1.2 — DynamoDB** (uses nosql_table):
```
soc2.c1.1.dynamodb_encryption_enabled      nosql_table  all: encryption_enabled==true
soc2.a1.2.dynamodb_pitr_enabled            nosql_table  all: point_in_time_recovery_enabled==true
soc2.a1.2.dynamodb_deletion_protection     nosql_table  all: deletion_protection==true
```

**CC6.1 — GCP service account key hygiene** (uses gcp_service_account_key):
```
soc2.cc6.1.gcp_no_user_managed_sa_keys     gcp_service_account_key  none: is_user_managed==true
soc2.cc6.1.gcp_sa_keys_rotated_90d         gcp_service_account_key  filter: is_user_managed==true, all: age_days<=90
```

**Updated policy total: ~125 automated + ~27 manual = ~152 SOC2 policies**

### E. Additional ISO 27001 Policies from Research

**A.8.25 — Secure coding** (uses extended git_repository fields):
```
iso27001.8.25.secret_scanning_enabled       git_repository  all: secret_scanning_enabled==true
iso27001.8.28.code_scanning_enabled         git_repository  all: code_scanning_enabled==true
iso27001.8.28.dependabot_alerts_enabled     git_repository  all: dependabot_alerts_enabled==true
```

**A.8.14 — Redundancy** (uses nosql_table):
```
iso27001.8.14.nosql_table_pitr_enabled      nosql_table  all: point_in_time_recovery_enabled==true
```

**A.8.16 — Monitoring** (uses security_service):
```
iso27001.8.16.security_aggregation_enabled  security_service  filter: service_type==siem, any: is_enabled==true
```

**A.5.3 — GCP service account key hygiene** (uses gcp_service_account_key):
```
iso27001.5.3.gcp_no_user_managed_sa_keys    gcp_service_account_key  none: is_user_managed==true
```

**Updated policy total: ~57 automated + ~48 manual = ~105 ISO 27001 policies**

### F. Updated Source Plugin Counts

Phase 2 grows from 12 to **17 new plugins**. Add `aws.dynamodb`, `aws.inspector`, `aws.securityhub`, `aws.macie`, `gcp.service_account_keys` to the Phase 2 list.

### G. Schema Additions to Existing Types

The `aws.cloudwatch` existing plugin needs updating — it currently emits `log_group` records but should ALSO emit `cloudwatch_alarm` records. Either update the existing plugin or create a separate `aws.cloudwatch_alarms` plugin (preferred: keep them separate).

The `aws.iam` plugin update (Phase 0) should also emit a `password_policy` record (single record from `GetAccountPasswordPolicy`). This means `aws.iam_password_policy` from Phase 2 may be redundant — merge it into `aws.iam` plugin instead.

---

## Key Design Invariants to Enforce

1. **No vendor names in policy IDs.** `soc2.cc6.7.storage_encryption_at_rest` ✓, `soc2.cc6.7.s3_bucket_encrypted` ✗
2. **pass_when fields must be satisfiable by all emitting plugins.** If a field only exists on AWS, it goes in `additionalProperties`, not `required`.
3. **No null guards.** If a policy condition requires `field != null`, the schema is wrong. Make the field required with a safe zero-value default.
4. **One record per atomic unit.** `firewall_rule`: one per rule. `vulnerability_finding`: one per finding. `password_policy`: one per account.
5. **Plugins sort output by `id` lexicographically.** Deterministic envelopes.
6. **`evidence_mode` must be explicit on every policy.** Never omit it.
7. **`rule:` escape hatch for compound boolean conditions.** `pass_when` handles single-field conditions. Use `rule:` for `AND` across multiple fields, port-range arithmetic, or cross-slot joins.
8. **ISO 27001 reuses SOC2 evidence types.** Never create `iso27001_`-prefixed types.

---

## Prompt for Next Session

Paste this entire prompt at the start of the next session:

---

**TASK**: Implement the SOC2 Type 2 + ISO 27001 policy library per the execution plan at `docs/claude/implementation-plan-policy-library.md`. Read that file first, then read `CLAUDE.md` and `CLAUDE.local.md`, then execute.

Work sequentially through 6 phases. Run `make test` after Phase 2 and after Phase 4. Run `make test && make lint` at the end.

**Phase 0 — Schema Redesign (Breaking)**
In `internal/evidence_types/schemas/`:
1. Delete: `ec2_instance.v1.yaml`, `compute_instance.v1.yaml` (GCP) → create unified `compute_instance.v1.yaml`
2. Delete: `rds_instance.v1.yaml`, `cloudsql_instance.v1.yaml` → create `managed_database_instance.v1.yaml`
3. Rename/replace: `cloudtrail_trail` → `audit_log_trail`, `cloudwatch_log_group` → `log_group`, `guardduty_detector` → `threat_detection_service`, `config_recorder` → `configuration_recorder`, `gcp_iam_binding` → `iam_binding`, `eks_cluster` → `kubernetes_cluster`
4. Add `directory_user.v2.yaml` (additive extension)
Update the 11 source plugins that emit the changed types. Schema field specs are in the plan file.

**Phase 1 — New Schemas**
Add to `internal/evidence_types/schemas/`: `firewall_rule.v1.yaml`, `network.v1.yaml`, `password_policy.v1.yaml`, `iam_access_key.v1.yaml`, `tls_certificate.v1.yaml`, `secret.v1.yaml`, `container_registry.v1.yaml`, `vulnerability_finding.v1.yaml`, `backup_plan.v1.yaml`, `serverless_function.v1.yaml`. Full field specs in the plan file.

**Phase 2 — DEFERRED.** New API plugins (aws.security_groups, aws.vpc, etc.) are out of scope for this session. Policies that reference new evidence types will exist in the framework but be skipped by the planner until a plugin is registered. Implement plugins in a future session when a specific API integration is needed.

**Phase 3 — SOC2 Policy Library**
Rewrite `internal/frameworks/soc2/` with ~102 policies across 10 files. Complete policy table in the plan file. Delete old compliance_frameworks/soc2 if it still exists.

**Phase 4 — ISO 27001 Policy Library**
Implement `internal/frameworks/iso27001/` with ~95 policies. Complete policy table in the plan file. Run `make test`.

**Phase 5 — Manual Evidence Catalogs**
Expand `internal/core/manual/catalogs/soc2.yaml` with ~28 new entries. Create `internal/core/manual/catalogs/iso27001.yaml` with ~48 entries.

**Phase 6 — Controls Registration**
Expand `internal/frameworks/soc2/controls.go` (all TSC criteria). Expand `internal/frameworks/iso27001/controls.go` (all 93 Annex A controls).

Final: `make test && make lint`. Commit with message `feat(frameworks): implement comprehensive SOC2 Type 2 + ISO 27001 policy library`.

If anything is ambiguous, check the plan file — it has complete schema field specs and the full policy table for every phase.
