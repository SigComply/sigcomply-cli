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
# L4a live re-record per the strategy doc §2); GCP/Azure are added when their
# plugins land.
#
# Requires: curl, python3, ruby (only for the YAML→JSON Okta spec).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SLICE_DIR="scripts/contracts"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

GH_RAW="https://raw.githubusercontent.com"
AWS_MODELS="$GH_RAW/aws/aws-sdk-go-v2/main/codegen/sdk-codegen/aws-models"

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
    mkdir -p contracts/aws
    python3 "$SLICE_DIR/slice_smithy.py" "$TMP/$model.json" "contracts/aws/$out@$ver.json" "$@"
}

echo "GitHub:"
fetch_openapi \
    "$GH_RAW/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json" \
    "contracts/github/api.github.com@2026-06-28.json" \
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
    "contracts/okta/management@2026-06-28.json" \
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

echo "contracts-fetch: done"
