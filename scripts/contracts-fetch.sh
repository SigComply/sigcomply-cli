#!/usr/bin/env bash
#
# contracts-fetch.sh — WU-3.1. Refresh the pinned vendor API-spec snapshots in
# contracts/ from their upstream sources, sliced to only the operations our
# source plugins call (see scripts/contracts/slice_*.py). Re-running overwrites
# each committed snapshot in place, so `git diff contracts/` after a fetch is the
# raw drift signal (WU-3.2 classifies it; WU-3.3 runs this on a schedule).
#
# Pin only services we actually have a plugin + cassette for. GitLab is omitted
# (its published OpenAPI is too thin to cover the endpoints we call — it leans on
# L4a live re-record per the strategy doc §2); Azure is added when its plugins
# land.
#
# Requires: curl, python3, ruby (only for the YAML→JSON Okta spec).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SLICE_DIR="scripts/contracts"
# Output root; contracts-diff.sh overrides this to fetch fresh into a temp dir
# without touching the committed snapshots.
OUT_ROOT="${CONTRACTS_DIR:-contracts}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

GH_RAW="https://raw.githubusercontent.com"
AWS_MODELS="$GH_RAW/aws/aws-sdk-go-v2/main/codegen/sdk-codegen/aws-models"
AZURE_SPECS="$GH_RAW/Azure/azure-rest-api-specs/main/specification"

# fetch_openapi <url> <out> <title> <source> <slice> <METHOD:/path>...
fetch_openapi() {
    local url="$1" out="$2" title="$3" source="$4" slice="$5"; shift 5
    curl -sSL "$url" -o "$TMP/in.json"
    mkdir -p "$(dirname "$out")"
    python3 "$SLICE_DIR/slice_openapi.py" "$TMP/in.json" "$out" "$title" "$source" "$slice" "$@"
}

# fetch_openapi_yaml: same but the upstream is YAML (converted via ruby's stdlib).
fetch_openapi_yaml() {
    local url="$1" out="$2" title="$3" source="$4" slice="$5"; shift 5
    curl -sSL "$url" -o "$TMP/in.yaml"
    ruby -ryaml -rjson -e 'File.write(ARGV[1], JSON.generate(YAML.load(File.read(ARGV[0]))))' "$TMP/in.yaml" "$TMP/in.json"
    mkdir -p "$(dirname "$out")"
    python3 "$SLICE_DIR/slice_openapi.py" "$TMP/in.json" "$out" "$title" "$source" "$slice" "$@"
}

# fetch_discovery <api> <version> <SeedSchema>...
#   → contracts/gcp/<api>@<version>.json
# GCP Discovery Documents are public (no auth). Older APIs publish to the legacy
# aggregated directory; newer ones (artifactregistry, backupdr, certificatemanager,
# securitycenter v1beta2) only to the per-service $discovery endpoint — try both.
fetch_discovery() {
    local api="$1" version="$2"; shift 2
    if ! curl -fsSL "https://www.googleapis.com/discovery/v1/apis/$api/$version/rest" -o "$TMP/disc.json" 2>/dev/null; then
        curl -fsSL "https://$api.googleapis.com/\$discovery/rest?version=$version" -o "$TMP/disc.json"
    fi
    mkdir -p "$OUT_ROOT/gcp"
    python3 "$SLICE_DIR/slice_discovery.py" "$TMP/disc.json" "$OUT_ROOT/gcp/$api@$version.json" "$@"
}

# fetch_swagger <out@apiver> <spec-subpath> <title> <source> <slice> <Def>...
#   → contracts/azure/<out@apiver>.json
# Azure RPs publish fragmented per-area/per-version OpenAPI-2.0 swaggers, so the
# api-version + file are pinned in the subpath (re-fetch is byte-stable; drift
# detection catches in-place edits — new api-versions are a manual bump). The
# armXXX SDK is go.mod-pinned anyway, so this tracks the upstream shape, not the
# exact wire our client speaks (that is the L2 cassette's job).
fetch_swagger() {
    local out="$1" sub="$2" title="$3" source="$4" slice="$5"; shift 5
    curl -fsSL "$AZURE_SPECS/$sub" -o "$TMP/az.json"
    mkdir -p "$OUT_ROOT/azure"
    python3 "$SLICE_DIR/slice_swagger.py" "$TMP/az.json" "$OUT_ROOT/azure/$out.json" "$title" "$source" "$slice" "$@"
}

# fetch_smithy <out-name> <model-basename> <Op>...
#   → contracts/aws/<out-name>@<api-version>.json
# out-name matches our plugin dir (e.g. secretsmanager); model-basename is the
# upstream aws-models filename (e.g. secrets-manager), which sometimes differs.
fetch_smithy() {
    local out="$1" model="$2"; shift 2
    curl -sSL "$AWS_MODELS/$model.json" -o "$TMP/$model.json"
    local ver
    ver="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(next((v.get("version","") for v in d["shapes"].values() if v.get("type")=="service"), ""))' "$TMP/$model.json")"
    [ -n "$ver" ] || { echo "contracts-fetch: could not derive $out API version" >&2; exit 1; }
    mkdir -p "$OUT_ROOT/aws"
    python3 "$SLICE_DIR/slice_smithy.py" "$TMP/$model.json" "$OUT_ROOT/aws/$out@$ver.json" "$@"
}

echo "GitHub:"
fetch_openapi \
    "$GH_RAW/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json" \
    "$OUT_ROOT/github/api.github.com@2026-06-28.json" \
    "GitHub REST API (sigcomply contract slice)" \
    "github/rest-api-description descriptions/api.github.com/api.github.com.json" \
    "operations consumed by internal/sources/github; see github_spec_conformance_test.go" \
    "GET:/orgs/{org}/repos" \
    "GET:/repos/{owner}/{repo}/branches/{branch}/protection" \
    "GET:/orgs/{org}/members" \
    "GET:/orgs/{org}/memberships/{username}" \
    "GET:/orgs/{org}/outside_collaborators"

echo "Okta:"
fetch_openapi_yaml \
    "$GH_RAW/okta/okta-management-openapi-spec/master/dist/current/management-minimal.yaml" \
    "$OUT_ROOT/okta/management@2026-06-28.json" \
    "Okta Management API (sigcomply contract slice)" \
    "okta/okta-management-openapi-spec dist/current/management-minimal.yaml" \
    "operations consumed by internal/sources/okta; see okta_spec_conformance_test.go" \
    "GET:/api/v1/users" \
    "GET:/api/v1/users/{userId}/factors" \
    "GET:/api/v1/users/{userId}/roles" \
    "GET:/api/v1/apps"

echo "AWS:"
fetch_smithy iam iam \
    ListUsers ListMFADevices ListAccessKeys ListAttachedUserPolicies \
    ListGroupsForUser ListAttachedGroupPolicies GenerateCredentialReport \
    GetCredentialReport GetAccessKeyLastUsed GetAccountPasswordPolicy
fetch_smithy s3 s3 ListBuckets GetBucketEncryption GetPublicAccessBlock GetBucketVersioning
fetch_smithy rds rds DescribeDBInstances DescribeDBParameters
fetch_smithy dynamodb dynamodb ListTables DescribeTable DescribeContinuousBackups
fetch_smithy kms kms ListKeys DescribeKey GetKeyRotationStatus
fetch_smithy secretsmanager secrets-manager ListSecrets
fetch_smithy backup backup ListBackupPlans GetBackupPlan

echo "GCP (public Discovery Docs; sliced to response-schema closure):"
# Foundation (WU-2.7)
fetch_discovery compute v1 InstanceAggregatedList Firewall Network Subnetwork
fetch_discovery cloudresourcemanager v1 Policy
fetch_discovery sqladmin v1 InstancesListResponse
fetch_discovery storage v1 Buckets
# Expansion (WU-2.11): one snapshot per API the 14 expansion plugins read
fetch_discovery cloudresourcemanager v3 Policy
fetch_discovery cloudkms v1 CryptoKey KeyRing Location
fetch_discovery secretmanager v1 Secret SecretVersion
fetch_discovery logging v2 LogBucket CmekSettings
fetch_discovery admin directory_v1 User
fetch_discovery cloudasset v1 Feed
fetch_discovery securitycenter v1 Finding
fetch_discovery securitycenter v1beta2 EventThreatDetectionSettings SecurityHealthAnalyticsSettings
fetch_discovery artifactregistry v1 Repository Policy Location
fetch_discovery container v1 Cluster
fetch_discovery firestore v1 GoogleFirestoreAdminV1Database
fetch_discovery backupdr v1 BackupPlan
fetch_discovery certificatemanager v1 Certificate

echo "Azure (azure-rest-api-specs OpenAPI-2.0 swaggers, sliced to definition closure):"
fetch_swagger "storage@2026-04-01" \
    "storage/resource-manager/Microsoft.Storage/stable/2026-04-01/openapi.json" \
    "Azure Storage (sigcomply slice)" \
    "Azure/azure-rest-api-specs Microsoft.Storage/stable/2026-04-01/openapi.json" \
    "object_storage_bucket: account + blob service properties" \
    StorageAccount BlobServiceProperties
fetch_swagger "documentdb@2026-03-15" \
    "cosmos-db/resource-manager/Microsoft.DocumentDB/DocumentDB/stable/2026-03-15/openapi.json" \
    "Azure Cosmos DB (sigcomply slice)" \
    "Azure/azure-rest-api-specs Microsoft.DocumentDB/DocumentDB/stable/2026-03-15/openapi.json" \
    "nosql_table: database account" \
    DatabaseAccountGetResults
fetch_swagger "containerregistry@2025-11-01" \
    "containerregistry/resource-manager/Microsoft.ContainerRegistry/Registry/stable/2025-11-01/containerregistry.json" \
    "Azure Container Registry (sigcomply slice)" \
    "Azure/azure-rest-api-specs Microsoft.ContainerRegistry/Registry/stable/2025-11-01/containerregistry.json" \
    "container_registry: registry" \
    Registry
fetch_swagger "containerservice@2026-04-01" \
    "containerservice/resource-manager/Microsoft.ContainerService/aks/stable/2026-04-01/managedClusters.json" \
    "Azure Kubernetes Service (sigcomply slice)" \
    "Azure/azure-rest-api-specs Microsoft.ContainerService/aks/stable/2026-04-01/managedClusters.json" \
    "kubernetes_cluster: managed cluster" \
    ManagedCluster
fetch_swagger "policy@2026-06-01" \
    "resources/resource-manager/Microsoft.Authorization/policy/stable/2026-06-01/openapi.json" \
    "Azure Policy (sigcomply slice)" \
    "Azure/azure-rest-api-specs Microsoft.Authorization/policy/stable/2026-06-01/openapi.json" \
    "config_change_tracking: policy assignment" \
    PolicyAssignment
SQL="sql/resource-manager/Microsoft.Sql/SQL/stable/2025-01-01"
fetch_swagger "sql-servers@2025-01-01"   "$SQL/servers.json"   "Azure SQL servers (slice)"   "Azure/azure-rest-api-specs $SQL/servers.json"   "managed_database_instance: SQL server" Server
fetch_swagger "sql-databases@2025-01-01" "$SQL/databases.json" "Azure SQL databases (slice)" "Azure/azure-rest-api-specs $SQL/databases.json" "managed_database_instance: SQL database" Database
fetch_swagger "sql-tde@2025-01-01" "$SQL/transparentDataEncryptions.json" "Azure SQL TDE (slice)" "Azure/azure-rest-api-specs $SQL/transparentDataEncryptions.json" "managed_database_instance: TDE state" LogicalDatabaseTransparentDataEncryption
NET="network/resource-manager/Microsoft.Network/Network/stable/2025-03-01"
fetch_swagger "network-nsg@2025-03-01"  "$NET/networkSecurityGroup.json" "Azure NSG (slice)"  "Azure/azure-rest-api-specs $NET/networkSecurityGroup.json" "firewall_rule: network security group" NetworkSecurityGroup
fetch_swagger "network-vnet@2025-03-01" "$NET/virtualNetwork.json"       "Azure VNet (slice)" "Azure/azure-rest-api-specs $NET/virtualNetwork.json" "network: virtual network" VirtualNetwork
fetch_swagger "network-nic@2025-03-01"  "$NET/networkInterface.json"     "Azure NIC (slice)"  "Azure/azure-rest-api-specs $NET/networkInterface.json" "compute_instance: network interface" NetworkInterface
fetch_swagger "compute@2026-03-01" "compute/resource-manager/Microsoft.Compute/Compute/stable/2026-03-01/ComputeRP.json" "Azure Compute (slice)" "Azure/azure-rest-api-specs Microsoft.Compute/Compute/stable/2026-03-01/ComputeRP.json" "compute_instance: virtual machine" VirtualMachine
fetch_swagger "keyvault@2026-02-01" "keyvault/resource-manager/Microsoft.KeyVault/KeyVault/stable/2026-02-01/openapi.json" "Azure Key Vault (slice)" "Azure/azure-rest-api-specs Microsoft.KeyVault/KeyVault/stable/2026-02-01/openapi.json" "kms_key + secret: vault, keys, secrets" Vault Key Secret
fetch_swagger "operationalinsights@2025-07-01" "operationalinsights/resource-manager/Microsoft.OperationalInsights/OperationalInsights/stable/2025-07-01/openapi.json" "Azure Log Analytics (slice)" "Azure/azure-rest-api-specs Microsoft.OperationalInsights/OperationalInsights/stable/2025-07-01/openapi.json" "log_group: workspace" Workspace
fetch_swagger "recoveryservices@2026-05-01" "recoveryservices/resource-manager/Microsoft.RecoveryServices/RecoveryServices/stable/2026-05-01/openapi.json" "Azure Recovery Services (slice)" "Azure/azure-rest-api-specs Microsoft.RecoveryServices/RecoveryServices/stable/2026-05-01/openapi.json" "backup_plan: vault" Vault
fetch_swagger "recoveryservicesbackup@2026-05-01" "recoveryservicesbackup/resource-manager/Microsoft.RecoveryServices/RecoveryServicesBackup/stable/2026-05-01/bms.json" "Azure Backup (slice)" "Azure/azure-rest-api-specs Microsoft.RecoveryServices/RecoveryServicesBackup/stable/2026-05-01/bms.json" "backup_plan: protection policy" ProtectionPolicyResource
fetch_swagger "appservice@2026-03-15" "web/resource-manager/Microsoft.Web/AppService/stable/2026-03-15/openapi.json" "Azure App Service certs (slice)" "Azure/azure-rest-api-specs Microsoft.Web/AppService/stable/2026-03-15/openapi.json" "tls_certificate: app service certificate" Certificate
fetch_swagger "certificateregistration@2024-11-01" "certificateregistration/resource-manager/Microsoft.CertificateRegistration/CertificateRegistration/stable/2024-11-01/openapi.json" "Azure cert orders (slice)" "Azure/azure-rest-api-specs Microsoft.CertificateRegistration/CertificateRegistration/stable/2024-11-01/openapi.json" "tls_certificate: certificate order" AppServiceCertificateOrder
fetch_swagger "postgresql@2025-08-01" "postgresql/resource-manager/Microsoft.DBforPostgreSQL/stable/2025-08-01/openapi.json" "Azure PostgreSQL flexible (slice)" "Azure/azure-rest-api-specs Microsoft.DBforPostgreSQL/stable/2025-08-01/openapi.json" "managed_database_instance: PG flexible server" Server
fetch_swagger "mysql@2024-12-30" "mysql/resource-manager/Microsoft.DBforMySQL/FlexibleServers/stable/2024-12-30/openapi.json" "Azure MySQL flexible (slice)" "Azure/azure-rest-api-specs Microsoft.DBforMySQL/FlexibleServers/stable/2024-12-30/openapi.json" "managed_database_instance: MySQL flexible server" Server
fetch_swagger "security-pricings@2024-01-01" "security/resource-manager/Microsoft.Security/Security/stable/2024-01-01/pricings.json" "Azure Defender pricings (slice)" "Azure/azure-rest-api-specs Microsoft.Security/Security/stable/2024-01-01/pricings.json" "threat_detection_service + security_service: Defender pricings" Pricing
# Residual (not yet pinned): monitor DiagnosticSettingsResource (audit_log_trail) and
# Microsoft.Security sub-assessments (vulnerability_finding) — buried in Azure's
# inconsistent per-area layout; L2 cassettes cover them. See testing_strategy_revamp.md.

echo "contracts-fetch: done"
