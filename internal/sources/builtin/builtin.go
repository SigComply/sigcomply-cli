// Package builtin imports every in-tree source plugin for the side
// effect of running its init() — which registers a factory under the
// sources.Register registry. Anyone wanting all shipped sources
// available simply blank-imports this package; nothing else needs to
// be touched.
//
// Adding a new in-tree source plugin: drop its package under
// internal/sources/, give it an init() that calls sources.Register,
// then add one line below. cmd/sigcomply does not need to know about
// it.
//
// Project-local plugins under .sigcomply/plugins/ are wired in by
// `sigcomply build` (M16) — that command generates a similar import
// list into the project-specific binary.
package builtin

import (
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/accesskeys"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/acm"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/backup"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/cloudtrail"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/cloudwatch"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/config"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/dynamodb"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/ec2"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/ecr"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/eks"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/guardduty"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/iam"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/inspector"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/kms"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/lambda"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/passwordpolicy"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/rds"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/s3"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/secretsmanager"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/securityalert"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/securitygroups"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/securityservices"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/vpc"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/azure/acr"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/azure/compute"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/azure/defender"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/azure/entra"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/azure/keyvault"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/azure/monitor"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/azure/network"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/azure/sql"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/azure/storage"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/artifactregistry"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/asset"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/audit"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/backup"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/certs"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/compute"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/directory"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/firestore"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/firewall"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/gke"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/iam"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/kms"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/logging"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/network"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/scc"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/secretmanager"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/sql"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/storage"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/github"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/gitlab"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/manual/builtin" // side-effect: registers every in-tree manual.pdf reader backend
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/okta"
)
