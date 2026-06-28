package awstest

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// awstest_test.go is the WU-2.1 acceptance check: an IAM (query protocol) and
// an S3 (REST) cassette both replay correctly offline through the real SDK
// deserializer, and the AWS-aware matcher disambiguates query operations that
// share one identical URL.

func TestReplayIAMQueryProtocol(t *testing.T) {
	// Both operations are POST https://iam.amazonaws.com/ with the operation in
	// the form body — the default method+URL matcher can't tell them apart, so a
	// correct route here proves sourcetest.AWSMatcher's body disambiguation.
	c := iam.NewFromConfig(ReplayConfig(t, "testdata/cassettes/iam_query"))
	ctx := context.Background()

	users, err := c.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users.Users) != 2 {
		t.Errorf("ListUsers returned %d users, want 2", len(users.Users))
	}

	summary, err := c.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		t.Fatalf("GetAccountSummary: %v", err)
	}
	if len(summary.SummaryMap) == 0 {
		t.Error("GetAccountSummary returned an empty SummaryMap")
	}

	// Replayable: a second ListUsers still resolves (the harness's conformance
	// runs Collect twice; cassettes must serve repeat requests).
	if _, err := c.ListUsers(ctx, &iam.ListUsersInput{}); err != nil {
		t.Errorf("second ListUsers: %v", err)
	}
}

func TestReplayMatcherRejectsUnrecordedOp(t *testing.T) {
	// ListRoles shares the IAM URL but is not in the cassette; the matcher must
	// NOT match it (proving it disambiguates by body, not just URL).
	c := iam.NewFromConfig(ReplayConfig(t, "testdata/cassettes/iam_query"))
	if _, err := c.ListRoles(context.Background(), &iam.ListRolesInput{}); err == nil {
		t.Error("ListRoles (unrecorded) unexpectedly succeeded; matcher matched on URL alone")
	}
}

func TestReplayS3RESTProtocol(t *testing.T) {
	c := s3.NewFromConfig(ReplayConfig(t, "testdata/cassettes/s3_rest"), func(o *s3.Options) {
		o.UsePathStyle = true
	})
	if _, err := c.ListBuckets(context.Background(), &s3.ListBucketsInput{}); err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
}

func TestRecordConfigConstructs(t *testing.T) {
	// Construction only — recording does real AWS I/O and is never run in CI.
	cfg := RecordConfig(t, t.TempDir()+"/rec")
	if cfg.Region != Region {
		t.Errorf("region = %q, want %q", cfg.Region, Region)
	}
	if cfg.HTTPClient == nil {
		t.Error("HTTPClient not set")
	}
}
