package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	awsrds "github.com/aws/aws-sdk-go-v2/service/rds"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/ec2"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/eks"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/iam"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/kms"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/rds"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/s3"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/submitter"
	"github.com/sigcomply/sigcomply-cli/internal/vault/local"
)

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
	assertResultStatuses(t, v, res.RunRoot, map[string]core.PolicyStatus{
		soc2.PolicyMFAEnforced:  core.StatusFail,
		soc2.PolicyMFAUnion:     core.StatusFail,
		soc2.PolicyAccessReview: core.StatusPass,
	})
	assertEnvelopesVerify(t, v, res.RunRoot, soc2.PolicyMFAEnforced, soc2.PolicyAccessReview)
	assertCapturedPayloadPrivacy(t, capturePath)
}

func setupManualFixture(t *testing.T, manualDir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(manualDir, "manual", "access_review_quarterly", "2026-Q1"), 0o750); err != nil {
		t.Fatalf("mkdir manual: %v", err)
	}
	pdfPath := filepath.Join(manualDir, "manual", "access_review_quarterly", "2026-Q1", "evidence.pdf")
	if err := os.WriteFile(pdfPath, []byte("%PDF-1.7 fake bytes\n"), 0o600); err != nil {
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
	return regs
}

// --- Empty AWS API stubs for the M7 plugins. Each returns no
// resources so the corresponding SOC 2 policies pass cleanly.

type emptyS3API struct{}

func (emptyS3API) ListBuckets(context.Context, *awss3.ListBucketsInput, ...func(*awss3.Options)) (*awss3.ListBucketsOutput, error) {
	return &awss3.ListBucketsOutput{}, nil
}

func (emptyS3API) GetBucketEncryption(context.Context, *awss3.GetBucketEncryptionInput, ...func(*awss3.Options)) (*awss3.GetBucketEncryptionOutput, error) {
	return &awss3.GetBucketEncryptionOutput{}, nil
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

func assertRunCounts(t *testing.T, res *orchestrator.Result) {
	t.Helper()
	if res.ExitCode != orchestrator.ExitViolation {
		t.Errorf("ExitCode = %d; want %d (violation)", res.ExitCode, orchestrator.ExitViolation)
	}
	// 3 access-control policies + 5 AWS infrastructure policies (M7).
	if res.Summary.PoliciesTotal != 8 {
		t.Errorf("PoliciesTotal = %d; want 8", res.Summary.PoliciesTotal)
	}
	// Access control policies: 1 pass (access review), 2 fail (MFA).
	// AWS infrastructure policies bind empty stub plugins → required
	// slots have no records → 5 skips. (Confirmed behavior of
	// requiredSlotsPopulated in internal/evaluator/evaluator.go.)
	if res.Summary.PoliciesPassed != 1 || res.Summary.PoliciesFailed != 2 || res.Summary.PoliciesSkipped != 5 {
		t.Errorf("counts: pass=%d fail=%d skip=%d; want 1/2/5",
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
	if payload.Schema != "sigcomply.cloud.v1" {
		t.Errorf("Schema = %q", payload.Schema)
	}
	if len(payload.Policies) != 8 {
		t.Errorf("Policies len = %d; want 8", len(payload.Policies))
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
// from a file; tests inject the config directly.
func bootstrapWithRegistries(_ *spec.ProjectConfig) *registry.Set {
	return registry.NewSet()
}
