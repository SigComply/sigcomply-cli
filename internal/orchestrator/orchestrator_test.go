package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	gcs "cloud.google.com/go/storage"
	awsct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	awscwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	awscfgsvc "github.com/aws/aws-sdk-go-v2/service/configservice"
	cfgtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	awsgd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	awsrds "github.com/aws/aws-sdk-go-v2/service/rds"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	gce "google.golang.org/api/compute/v1"
	sqladmin "google.golang.org/api/sqladmin/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/cloudtrail"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/cloudwatch"
	awsconfigsrc "github.com/sigcomply/sigcomply-cli/internal/sources/aws/config"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/ec2"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/eks"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/guardduty"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/iam"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/kms"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/rds"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/s3"
	gcpcompute "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/compute"
	gcpiam "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/iam"
	gcpsql "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/sql"
	gcpstorage "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/storage"
	ghsource "github.com/sigcomply/sigcomply-cli/internal/sources/github"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	oktasource "github.com/sigcomply/sigcomply-cli/internal/sources/okta"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/submitter"
	"github.com/sigcomply/sigcomply-cli/internal/vault/local"
)

// --- empty stub APIs for the four infrastructure plugins.
// They exist solely to satisfy plugin construction at registration
// time; their Collect calls return zero records, which exercises the
// no-record code paths in the cloudtrail/cloudwatch/guardduty/config
// rules deterministically.

// stubCloudtrailAPI returns one compliant multi-region trail with
// logging on, exercising the happy path of the multi-region rule.
type stubCloudtrailAPI struct{}

func (stubCloudtrailAPI) DescribeTrails(context.Context, *awsct.DescribeTrailsInput, ...func(*awsct.Options)) (*awsct.DescribeTrailsOutput, error) {
	name := "primary"
	arn := "arn:aws:cloudtrail:us-east-1::trail/primary"
	region := "us-east-1"
	multi := true
	return &awsct.DescribeTrailsOutput{
		TrailList: []cttypes.Trail{{
			Name: &name, TrailARN: &arn, HomeRegion: &region, IsMultiRegionTrail: &multi,
		}},
	}, nil
}

func (stubCloudtrailAPI) GetTrailStatus(context.Context, *awsct.GetTrailStatusInput, ...func(*awsct.Options)) (*awsct.GetTrailStatusOutput, error) {
	logging := true
	return &awsct.GetTrailStatusOutput{IsLogging: &logging}, nil
}

// stubCloudwatchAPI returns one log group with 365-day retention, so the
// retention rule passes on the happy path.
type stubCloudwatchAPI struct{}

func (stubCloudwatchAPI) DescribeLogGroups(context.Context, *awscwl.DescribeLogGroupsInput, ...func(*awscwl.Options)) (*awscwl.DescribeLogGroupsOutput, error) {
	name := "/aws/lambda/test"
	arn := "arn:aws:logs:us-east-1::log-group:/aws/lambda/test:*"
	ret := int32(365)
	return &awscwl.DescribeLogGroupsOutput{
		LogGroups: []cwltypes.LogGroup{{LogGroupName: &name, Arn: &arn, RetentionInDays: &ret}},
	}, nil
}

// stubGuardDutyAPI returns exactly one disabled detector so the
// guardduty_enabled rule has a record to evaluate and fails the
// "at-least-one-enabled" check.
type stubGuardDutyAPI struct{}

func (stubGuardDutyAPI) ListDetectors(context.Context, *awsgd.ListDetectorsInput, ...func(*awsgd.Options)) (*awsgd.ListDetectorsOutput, error) {
	return &awsgd.ListDetectorsOutput{DetectorIds: []string{"det-1"}}, nil
}

func (stubGuardDutyAPI) GetDetector(context.Context, *awsgd.GetDetectorInput, ...func(*awsgd.Options)) (*awsgd.GetDetectorOutput, error) {
	return &awsgd.GetDetectorOutput{Status: "DISABLED"}, nil
}

// stubConfigAPI returns exactly one non-recording configuration
// recorder so the config_recorder_enabled rule has a record to
// evaluate and fails.
type stubConfigAPI struct{}

func (stubConfigAPI) DescribeConfigurationRecorders(context.Context, *awscfgsvc.DescribeConfigurationRecordersInput, ...func(*awscfgsvc.Options)) (*awscfgsvc.DescribeConfigurationRecordersOutput, error) {
	name := "default"
	return &awscfgsvc.DescribeConfigurationRecordersOutput{
		ConfigurationRecorders: []cfgtypes.ConfigurationRecorder{{Name: &name, Arn: ptrStr("arn:aws:config:1::recorder/default")}},
	}, nil
}

func (stubConfigAPI) DescribeConfigurationRecorderStatus(context.Context, *awscfgsvc.DescribeConfigurationRecorderStatusInput, ...func(*awscfgsvc.Options)) (*awscfgsvc.DescribeConfigurationRecorderStatusOutput, error) {
	name := "default"
	return &awscfgsvc.DescribeConfigurationRecorderStatusOutput{
		ConfigurationRecordersStatus: []cfgtypes.ConfigurationRecorderStatus{{Name: &name, Recording: false}},
	}, nil
}

func ptrStr(s string) *string { return &s }

type stubIAMAPI struct {
	users []iamtypes.User
	mfa   map[string][]iamtypes.MFADevice
}

func (s *stubIAMAPI) ListUsers(context.Context, *awsiam.ListUsersInput, ...func(*awsiam.Options)) (*awsiam.ListUsersOutput, error) {
	return &awsiam.ListUsersOutput{Users: s.users}, nil
}

func (s *stubIAMAPI) ListMFADevices(_ context.Context, in *awsiam.ListMFADevicesInput, _ ...func(*awsiam.Options)) (*awsiam.ListMFADevicesOutput, error) {
	if in.UserName == nil {
		return &awsiam.ListMFADevicesOutput{}, nil
	}
	return &awsiam.ListMFADevicesOutput{MFADevices: s.mfa[*in.UserName]}, nil
}

func ptr[T any](v T) *T { return &v }

// TestE2E_WalkingSkeleton drives the orchestrator end-to-end against
// a stubbed AWS IAM API and a local-filesystem vault. The fixture
// matches docs/architecture/09-implementation-roadmap.md M6 row:
//
//   - sigcomply check --config testdata/fixture.yaml runs to completion
//   - the run produces a signed manifest.json that sign.VerifyManifest
//     accepts
//   - per-policy result.json files exist with the expected statuses
//   - the cloud SubmissionPayload, when captured, has no resource IDs
func TestE2E_WalkingSkeleton(t *testing.T) {
	now := time.Date(2026, 2, 15, 14, 0, 0, 0, time.UTC)
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")
	manualDir := filepath.Join(tmp, "manual")
	setupManualFixture(t, manualDir)

	cfg := loadE2EFixture(t, vaultDir, manualDir)
	regs := buildE2ERegistries(t, &cfg, manualDir, now)

	v := local.New(vaultDir)
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("vault init: %v", err)
	}

	capturePath := filepath.Join(tmp, "captured-payload.json")
	res, err := orchestrator.Run(context.Background(), &orchestrator.Options{
		Config:             &cfg,
		Registries:         regs,
		Vault:              v,
		CLIVersion:         "test",
		CommitSHA:          "deadbeef",
		CommitTime:         time.Date(2026, 2, 15, 13, 55, 0, 0, time.UTC),
		Branch:             "main",
		Stdout:             &bytes.Buffer{},
		Logger:             log.New(&bytes.Buffer{}, false),
		CapturePayloadPath: capturePath,
		Now:                func() time.Time { return now },
		SubmitterOpts:      submitter.Options{},
	})
	if err != nil {
		t.Fatalf("orchestrator.Run: %v", err)
	}

	assertRunCounts(t, &res)
	assertManifestVerifies(t, v, res.RunRoot)
	// The four GCP policies have required slots; their stubs return
	// empty result sets, so the evaluator emits status=skip rather than
	// invoking the rule. This is the v1 evaluator behavior
	// (internal/evaluator: "required slot has no records" → skip).
	assertResultStatuses(t, v, res.RunRoot, map[string]core.PolicyStatus{
		soc2.PolicyMFAUnion:                         core.StatusFail,
		soc2.PolicyAccessReview:                     core.StatusPass,
		soc2.PolicyCloudTrailMultiRegionEnabled:     core.StatusPass,
		soc2.PolicyCloudWatchLogsRetentionSet:       core.StatusPass,
		soc2.PolicyGuardDutyEnabled:                 core.StatusFail,
		soc2.PolicyConfigRecorderEnabled:            core.StatusFail,
		soc2.PolicyGCPIAMNoOwnerRoleForUsers:        core.StatusSkip,
		soc2.PolicyObjectStoragePublicAccessBlocked: core.StatusSkip,
		soc2.PolicyComputeNoDefaultServiceAccount:   core.StatusSkip,
		soc2.PolicyCloudSQLRequireSSL:               core.StatusSkip,
		soc2.PolicyGitHubBranchProtection:           core.StatusFail,
		soc2.PolicyOktaAppsMFA:                      core.StatusFail,
	})
	assertEnvelopesVerify(t, v, res.RunRoot, soc2.PolicyMFAUnion, soc2.PolicyAccessReview)
	assertCapturedPayloadPrivacy(t, capturePath)
}

func setupManualFixture(t *testing.T, manualDir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(manualDir, "manual", "access_review_quarterly", "2026-Q1"), 0o750); err != nil {
		t.Fatalf("mkdir manual: %v", err)
	}
	pdfPath := filepath.Join(manualDir, "manual", "access_review_quarterly", "2026-Q1", "evidence.pdf")
	// Padded past the manual.pdf plugin's minPDFBytes sanity threshold,
	// carries the %PDF- magic prefix, and contains a /Page marker so the
	// page-presence check passes. Real PDFs are always far larger.
	fakePDF := bytes.Join([][]byte{
		[]byte("%PDF-1.7\n"),
		[]byte("1 0 obj\n<< /Type /Page >>\nendobj\n"),
		bytes.Repeat([]byte("x"), 200),
	}, nil)
	if err := os.WriteFile(pdfPath, fakePDF, 0o600); err != nil {
		t.Fatalf("write pdf: %v", err)
	}
	pdfUploadedAt := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(pdfPath, pdfUploadedAt, pdfUploadedAt); err != nil {
		t.Fatalf("chtimes pdf: %v", err)
	}
}

func loadE2EFixture(t *testing.T, vaultDir, manualDir string) spec.ProjectConfig {
	t.Helper()
	fixtureBytes, err := os.ReadFile("testdata/fixture.yaml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	cfg, err := spec.LoadProjectConfig(fixtureBytes)
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	cfg.Vault.Path = vaultDir
	if cfg.Sources["manual.pdf"] != nil {
		cfg.Sources["manual.pdf"]["path"] = manualDir
	}
	return cfg
}

func buildE2ERegistries(t *testing.T, cfg *spec.ProjectConfig, manualDir string, now time.Time) *registry.Set {
	t.Helper()
	regs := bootstrapWithRegistries(cfg)
	if err := soc2.Register(regs); err != nil {
		t.Fatalf("register soc2: %v", err)
	}
	// aws.iam stub: two users, only alice has MFA on.
	stubAPI := &stubIAMAPI{
		users: []iamtypes.User{
			{UserName: ptr("alice"), UserId: ptr("AIDAALICE"), CreateDate: ptr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))},
			{UserName: ptr("bob"), UserId: ptr("AIDABOB"), CreateDate: ptr(time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC))},
		},
		mfa: map[string][]iamtypes.MFADevice{
			"alice": {{SerialNumber: ptr("arn:aws:iam::1:mfa/alice")}},
		},
	}
	if err := regs.Sources.Register(iam.New(iam.Options{API: stubAPI, Now: func() time.Time { return now }})); err != nil {
		t.Fatalf("register iam: %v", err)
	}
	// AWS infrastructure plugins — registered with empty stubs so the
	// new SOC 2 CC6.6/6.7 policies plan cleanly and pass against a
	// clean account. (Tests for non-empty fixtures live in each
	// plugin's package.)
	if err := regs.Sources.Register(s3.New(s3.Options{API: emptyS3API{}, Now: func() time.Time { return now }})); err != nil {
		t.Fatalf("register aws.s3: %v", err)
	}
	if err := regs.Sources.Register(kms.New(kms.Options{API: emptyKMSAPI{}, Now: func() time.Time { return now }})); err != nil {
		t.Fatalf("register aws.kms: %v", err)
	}
	if err := regs.Sources.Register(rds.New(rds.Options{API: emptyRDSAPI{}, Now: func() time.Time { return now }})); err != nil {
		t.Fatalf("register aws.rds: %v", err)
	}
	if err := regs.Sources.Register(ec2.New(ec2.Options{API: emptyEC2API{}, Now: func() time.Time { return now }})); err != nil {
		t.Fatalf("register aws.ec2: %v", err)
	}
	if err := regs.Sources.Register(eks.New(eks.Options{API: emptyEKSAPI{}, Now: func() time.Time { return now }})); err != nil {
		t.Fatalf("register aws.eks: %v", err)
	}
	if err := regs.Sources.Register(manual.New(manual.Options{
		Reader:  &localManualReader{root: manualDir},
		Bucket:  manualDir,
		Prefix:  "manual/",
		Scheme:  "file",
		Catalog: soc2.ManualCatalog(),
	})); err != nil {
		t.Fatalf("register manual.pdf: %v", err)
	}
	// Stub plugins for the four AWS-observability policies. Each
	// returns at least one record so the evaluator runs the rule (a
	// required-slot policy with zero records is skipped, not failed).
	// cloudtrail + cloudwatch stubs return compliant resources → pass.
	// guardduty + config stubs return non-compliant resources → fail.
	if err := regs.Sources.Register(cloudtrail.New(cloudtrail.Options{API: stubCloudtrailAPI{}, Now: func() time.Time { return now }})); err != nil {
		t.Fatalf("register cloudtrail: %v", err)
	}
	if err := regs.Sources.Register(cloudwatch.New(cloudwatch.Options{API: stubCloudwatchAPI{}, Now: func() time.Time { return now }})); err != nil {
		t.Fatalf("register cloudwatch: %v", err)
	}
	if err := regs.Sources.Register(guardduty.New(guardduty.Options{API: stubGuardDutyAPI{}, Now: func() time.Time { return now }})); err != nil {
		t.Fatalf("register guardduty: %v", err)
	}
	if err := regs.Sources.Register(awsconfigsrc.New(awsconfigsrc.Options{API: stubConfigAPI{}, Now: func() time.Time { return now }})); err != nil {
		t.Fatalf("register aws.config: %v", err)
	}
	registerGCPStubs(t, regs, now)
	registerIdentityStubs(t, regs, now)
	return regs
}

// registerGCPStubs registers in-memory stubs for the four GCP source
// plugins so the walking-skeleton fixture can bind the four GCP SOC 2
// policies and exercise their pass paths without live GCP credentials.
// Each stub returns an empty result set — the GCP rules treat empty
// inputs as "no violations to report", i.e. status=pass.
func registerGCPStubs(t *testing.T, regs *registry.Set, now time.Time) {
	t.Helper()
	if err := regs.Sources.Register(gcpiam.New(gcpiam.Options{
		API:       &stubGCPIAMAPI{},
		ProjectID: "example-project",
		Now:       func() time.Time { return now },
	})); err != nil {
		t.Fatalf("register gcp.iam: %v", err)
	}
	if err := regs.Sources.Register(gcpstorage.New(gcpstorage.Options{
		API:       &stubGCPStorageAPI{},
		ProjectID: "example-project",
		Now:       func() time.Time { return now },
	})); err != nil {
		t.Fatalf("register gcp.storage: %v", err)
	}
	if err := regs.Sources.Register(gcpcompute.New(gcpcompute.Options{
		API:       &stubGCPComputeAPI{},
		ProjectID: "example-project",
		Now:       func() time.Time { return now },
	})); err != nil {
		t.Fatalf("register gcp.compute: %v", err)
	}
	if err := regs.Sources.Register(gcpsql.New(gcpsql.Options{
		API:       &stubGCPSQLAPI{},
		ProjectID: "example-project",
		Now:       func() time.Time { return now },
	})); err != nil {
		t.Fatalf("register gcp.sql: %v", err)
	}
}

// --- GCP stub APIs returning empty result sets ---

type stubGCPIAMAPI struct{}

func (*stubGCPIAMAPI) GetIamPolicy(context.Context, string) (*crm.Policy, error) {
	return &crm.Policy{}, nil
}

type stubGCPStorageAPI struct{}

func (*stubGCPStorageAPI) ListBuckets(context.Context, string) ([]*gcs.BucketAttrs, error) {
	return nil, nil
}

type stubGCPComputeAPI struct{}

func (*stubGCPComputeAPI) AggregatedListInstances(context.Context, string) ([]*gce.Instance, error) {
	return nil, nil
}

type stubGCPSQLAPI struct{}

func (*stubGCPSQLAPI) ListInstances(context.Context, string) ([]*sqladmin.DatabaseInstance, error) {
	return nil, nil
}

// --- Empty AWS API stubs for the M7 infrastructure plugins. Each
// returns no resources so the corresponding SOC 2 policies skip
// cleanly (required slots with no records → skip, not fail).

type emptyS3API struct{}

func (emptyS3API) ListBuckets(context.Context, *awss3.ListBucketsInput, ...func(*awss3.Options)) (*awss3.ListBucketsOutput, error) {
	return &awss3.ListBucketsOutput{}, nil
}

func (emptyS3API) GetBucketEncryption(context.Context, *awss3.GetBucketEncryptionInput, ...func(*awss3.Options)) (*awss3.GetBucketEncryptionOutput, error) {
	return &awss3.GetBucketEncryptionOutput{}, nil
}

func (emptyS3API) GetPublicAccessBlock(context.Context, *awss3.GetPublicAccessBlockInput, ...func(*awss3.Options)) (*awss3.GetPublicAccessBlockOutput, error) {
	return &awss3.GetPublicAccessBlockOutput{}, nil
}

func (emptyS3API) GetBucketVersioning(context.Context, *awss3.GetBucketVersioningInput, ...func(*awss3.Options)) (*awss3.GetBucketVersioningOutput, error) {
	return &awss3.GetBucketVersioningOutput{}, nil
}

type emptyKMSAPI struct{}

func (emptyKMSAPI) ListKeys(context.Context, *awskms.ListKeysInput, ...func(*awskms.Options)) (*awskms.ListKeysOutput, error) {
	return &awskms.ListKeysOutput{}, nil
}

func (emptyKMSAPI) DescribeKey(context.Context, *awskms.DescribeKeyInput, ...func(*awskms.Options)) (*awskms.DescribeKeyOutput, error) {
	return &awskms.DescribeKeyOutput{}, nil
}

func (emptyKMSAPI) GetKeyRotationStatus(context.Context, *awskms.GetKeyRotationStatusInput, ...func(*awskms.Options)) (*awskms.GetKeyRotationStatusOutput, error) {
	return &awskms.GetKeyRotationStatusOutput{}, nil
}

type emptyRDSAPI struct{}

func (emptyRDSAPI) DescribeDBInstances(context.Context, *awsrds.DescribeDBInstancesInput, ...func(*awsrds.Options)) (*awsrds.DescribeDBInstancesOutput, error) {
	return &awsrds.DescribeDBInstancesOutput{}, nil
}

type emptyEC2API struct{}

func (emptyEC2API) DescribeInstances(context.Context, *awsec2.DescribeInstancesInput, ...func(*awsec2.Options)) (*awsec2.DescribeInstancesOutput, error) {
	return &awsec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{}}, nil
}

type emptyEKSAPI struct{}

func (emptyEKSAPI) ListClusters(context.Context, *awseks.ListClustersInput, ...func(*awseks.Options)) (*awseks.ListClustersOutput, error) {
	return &awseks.ListClustersOutput{}, nil
}

func (emptyEKSAPI) DescribeCluster(context.Context, *awseks.DescribeClusterInput, ...func(*awseks.Options)) (*awseks.DescribeClusterOutput, error) {
	return &awseks.DescribeClusterOutput{}, nil
}

// registerIdentityStubs registers in-memory stubs for github + okta
// so the four identity SOC 2 policies plan + collect + evaluate.
// The stubs return mixed-pass/fail records so each policy exercises
// its failure path at least once in the E2E.
func registerIdentityStubs(t *testing.T, regs *registry.Set, now time.Time) {
	t.Helper()
	if err := regs.Sources.Register(ghsource.New(ghsource.Options{
		API: &stubGitHubAPI{
			repos: []ghsource.Repo{
				{Name: "web", DefaultBranch: "main", ProtectionOn: true, RequiredReviews: 2},
				{Name: "legacy", DefaultBranch: "master", ProtectionOn: false},
			},
			members: []ghsource.Member{
				{Login: "alice", TwoFactorOn: true, Role: "admin"},
				{Login: "bob", TwoFactorOn: false, Role: "member"},
			},
		},
		Org: "acme",
		Now: func() time.Time { return now },
	})); err != nil {
		t.Fatalf("register github: %v", err)
	}
	if err := regs.Sources.Register(oktasource.New(oktasource.Options{
		API: &stubOktaAPI{
			users: []oktasource.User{
				{ID: "u_alice", Email: "alice@acme.com", Status: "ACTIVE", MFAFactorCount: 2},
				{ID: "u_bob", Email: "bob@acme.com", Status: "ACTIVE", MFAFactorCount: 0},
			},
			apps: []oktasource.App{
				{ID: "0oa1", Label: "Slack", SignOnMode: "SAML_2_0", MFARequired: true},
				{ID: "0oa2", Label: "Legacy", SignOnMode: "AUTO_LOGIN", MFARequired: false},
			},
		},
		Org: "https://acme.okta.com",
		Now: func() time.Time { return now },
	})); err != nil {
		t.Fatalf("register okta: %v", err)
	}
}

// stubGitHubAPI satisfies the github source plugin's API interface
// without touching the network.
type stubGitHubAPI struct {
	repos   []ghsource.Repo
	members []ghsource.Member
}

func (s *stubGitHubAPI) ListRepos(context.Context) ([]ghsource.Repo, error) {
	return s.repos, nil
}

func (s *stubGitHubAPI) ListOrgMembers(context.Context) ([]ghsource.Member, error) {
	return s.members, nil
}

// stubOktaAPI satisfies the okta source plugin's API interface
// without touching the network.
type stubOktaAPI struct {
	users []oktasource.User
	apps  []oktasource.App
}

func (s *stubOktaAPI) ListUsers(context.Context) ([]oktasource.User, error) {
	return s.users, nil
}

func (s *stubOktaAPI) ListApps(context.Context) ([]oktasource.App, error) {
	return s.apps, nil
}

func assertRunCounts(t *testing.T, res *orchestrator.Result) {
	t.Helper()
	if res.ExitCode != orchestrator.ExitViolation {
		t.Errorf("ExitCode = %d; want %d (violation)", res.ExitCode, orchestrator.ExitViolation)
	}
	// 2 seed + 4 infra + 5 aws + 4 gcp + 2 identity = 17 policies.
	// (Phase 2 consolidated the three per-source MFA policies into the
	// single cross-vendor PolicyMFAUnion via directory_user.)
	if res.Summary.PoliciesTotal != 17 {
		t.Errorf("PoliciesTotal = %d; want 17", res.Summary.PoliciesTotal)
	}
	// 3 pass: access_review, cloudtrail, cloudwatch.
	// 5 fail: mfa_enforced_all_sources (union across iam+okta+github),
	//         guardduty, config, github_branch_protection, okta_apps_mfa.
	// 9 skip: 5 aws-infra empty stubs + 4 GCP empty stubs.
	if res.Summary.PoliciesPassed != 3 || res.Summary.PoliciesFailed != 5 || res.Summary.PoliciesSkipped != 9 {
		t.Errorf("counts: pass=%d fail=%d skip=%d; want 3/5/9",
			res.Summary.PoliciesPassed, res.Summary.PoliciesFailed, res.Summary.PoliciesSkipped)
	}
}

func assertManifestVerifies(t *testing.T, v core.Vault, runRoot string) {
	t.Helper()
	manifestBytes, err := v.GetBinary(context.Background(), runRoot+"/manifest.json")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest core.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if err := sign.VerifyManifest(&manifest); err != nil {
		t.Errorf("VerifyManifest: %v", err)
	}
	if len(manifest.FileHashes) == 0 {
		t.Errorf("manifest.FileHashes empty")
	}
}

func assertResultStatuses(t *testing.T, v core.Vault, runRoot string, want map[string]core.PolicyStatus) {
	t.Helper()
	for policyID, wantStatus := range want {
		path := runRoot + "/policies/" + policyID + "/result.json"
		body, err := v.GetBinary(context.Background(), path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var pr core.PolicyResult
		if err := json.Unmarshal(body, &pr); err != nil {
			t.Fatalf("unmarshal %s: %v", path, err)
		}
		if pr.Status != wantStatus {
			t.Errorf("%s status = %q; want %q", policyID, pr.Status, wantStatus)
		}
	}
}

func assertEnvelopesVerify(t *testing.T, v core.Vault, runRoot string, policyIDs ...string) {
	t.Helper()
	for _, policyID := range policyIDs {
		entries, err := v.List(context.Background(), runRoot+"/policies/"+policyID+"/envelopes")
		if err != nil {
			t.Errorf("list envelopes for %s: %v", policyID, err)
			continue
		}
		if len(entries) == 0 {
			t.Errorf("no envelopes for %s", policyID)
		}
		for _, key := range entries {
			verifyOneEnvelope(t, v, key)
		}
	}
}

func verifyOneEnvelope(t *testing.T, v core.Vault, key string) {
	t.Helper()
	body, err := v.GetBinary(context.Background(), key)
	if err != nil {
		t.Errorf("read %s: %v", key, err)
		return
	}
	var env core.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Errorf("unmarshal %s: %v", key, err)
		return
	}
	if err := sign.VerifyEnvelope(&env); err != nil {
		t.Errorf("envelope %s did not verify: %v", key, err)
	}
}

func assertCapturedPayloadPrivacy(t *testing.T, capturePath string) {
	t.Helper()
	captured, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("read captured payload: %v", err)
	}
	var payload core.SubmissionPayload
	if err := json.Unmarshal(captured, &payload); err != nil {
		t.Fatalf("unmarshal captured: %v", err)
	}
	if payload.Schema != "sigcomply.cloud.v2" {
		t.Errorf("Schema = %q", payload.Schema)
	}
	if len(payload.Policies) != 17 {
		t.Errorf("Policies len = %d; want 17", len(payload.Policies))
	}
	// Resource IDs must not leak. The vault has AIDABOB; the captured
	// JSON must not.
	if bytes.Contains(captured, []byte("AIDABOB")) {
		t.Errorf("captured payload leaked resource ID: contains AIDABOB")
	}
	if bytes.Contains(captured, []byte("violations")) {
		t.Errorf("captured payload contains 'violations' key — privacy boundary leak")
	}
}

func TestE2E_NoPoliciesPassThroughGracefully(t *testing.T) {
	tmp := t.TempDir()
	v := local.New(filepath.Join(tmp, "vault"))
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	regs := bootstrapWithRegistries(&spec.ProjectConfig{
		Framework: "soc2",
		Vault:     spec.VaultConfig{Backend: "local", Path: filepath.Join(tmp, "vault")},
	})
	// Don't register soc2 — no policies → plan empty.
	res, err := orchestrator.Run(context.Background(), &orchestrator.Options{
		Config:     &spec.ProjectConfig{Framework: "soc2"},
		Registries: regs,
		Vault:      v,
		Stdout:     &bytes.Buffer{},
		Logger:     log.New(&bytes.Buffer{}, false),
		Now:        func() time.Time { return time.Now().UTC() },
	})
	if err == nil {
		t.Fatalf("expected planner error (framework not registered); got nil, exit=%d", res.ExitCode)
	}
}

// localManualReader satisfies manual.Reader against a local directory
// rooted at root. Mirror of cmd/sigcomply's helper; duplicated here to
// avoid an import cycle into a binary-only package.
type localManualReader struct{ root string }

func (r *localManualReader) Get(_ context.Context, uri string) ([]byte, time.Time, error) {
	full := filepath.Join(r.root, uri)
	info, err := os.Stat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, time.Time{}, manual.ErrNotFound
		}
		return nil, time.Time{}, err
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, time.Time{}, err
	}
	return data, info.ModTime().UTC(), nil
}

// bootstrapWithRegistries is the test's version of orchestrator.Bootstrap
// that accepts an already-parsed config. The production Bootstrap reads
// from a file; tests inject the config directly. Mirrors production by
// pre-loading the embedded evidence-type registry so the collector's
// schema validation runs against real schemas — the silent-skip is
// gone, and tests must conform to the schemas they exercise.
func bootstrapWithRegistries(_ *spec.ProjectConfig) *registry.Set {
	set := registry.NewSet()
	if err := evidencetypes.Register(set); err != nil {
		panic(fmt.Sprintf("bootstrapWithRegistries: register evidence types: %v", err))
	}
	return set
}
