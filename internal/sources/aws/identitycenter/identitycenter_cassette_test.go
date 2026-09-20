//go:build cassette

// identitycenter_cassette_test.go — the throwaway driver that CONSTRUCTS
// testdata/cassettes/identity_store_users.yaml. Build-tagged, so it never runs
// in the per-PR suite.
//
// SigComply has no AWS IAM Identity Center tenant, so this cassette cannot be
// recorded from real traffic. It is constructed the way the original was, and
// this file is that procedure written down instead of remembered:
//
//   - the REQUEST side is genuine — every byte is produced by driving the real
//     aws-sdk-go-v2 identitystore + ssoadmin clients, whose serializers are
//     generated from the published Smithy models, through the canned transport
//     below while go-vcr records. That is what keeps the cassette honest about
//     request shape, which is what AWSMatcher matches on.
//   - the RESPONSE bodies are hand-transcribed from those same service models
//     (awsJson1_1: epoch-second timestamps) and live in cannedResponses.
//
// To regenerate:
//
//	rm -f internal/sources/aws/identitycenter/testdata/cassettes/identity_store_users.yaml
//	go test -tags cassette -run TestConstructCassette ./internal/sources/aws/identitycenter/ -v
//	# then re-add the provenance header the recorder cannot write (see below)
//
// go-vcr writes the YAML itself and drops leading comments, so the PROVENANCE
// block at the top of the cassette must be pasted back after regenerating. It
// is not decoration: the file is a SHAPE test, not a contract test, until
// someone re-records it against a live tenant.
package identitycenter

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// cannedResponse is one transcribed service reply. target is the X-Amz-Target
// operation; bodyContains disambiguates repeat calls of the same operation
// (per permission set, per page) — first match wins, so the most specific
// entries come first.
type cannedResponse struct {
	target       string
	bodyContains string
	body         string
}

// The identity store, instance and permission-set ARNs every fixture shares.
// Account ids are the all-zeros placeholder and emails the house
// user-<hash>@example.com form (docs/architecture/11-testing-strategy.md §4),
// so scripts/check-fixtures.sh stays green.
const (
	cassetteStoreID     = "d-9067012345"
	cassetteInstanceARN = "arn:aws:sso:::instance/ssoins-7223bcdeffedcbaa"
	cassetteAdminPS     = "arn:aws:sso:::permissionSet/ssoins-7223bcdeffedcbaa/ps-1111111111111111"
	cassetteReadOnlyPS  = "arn:aws:sso:::permissionSet/ssoins-7223bcdeffedcbaa/ps-2222222222222222"
	cassetteGroupID     = "9067abcd-1111-2222-3333-444455556666"
	cassetteAccountID   = "000000000000"
)

var cannedResponses = []cannedResponse{
	{target: "SWBExternalService.ListInstances", body: `{"Instances":[{"CreatedDate":1.7182944E9,"IdentityStoreId":"` + cassetteStoreID + `","InstanceArn":"` + cassetteInstanceARN + `","Name":"example-instance","OwnerAccountId":"` + cassetteAccountID + `","Status":"ACTIVE"}]}`},

	// ListUsers page 2 is the one carrying a NextToken in its REQUEST.
	{target: "AWSIdentityStore.ListUsers", bodyContains: `"NextToken"`, body: `{"Users":[{"IdentityStoreId":"` + cassetteStoreID + `","UserId":"c1f81a90-30b1-7093-4c66-7a8b9c0d1e2f","UserName":"example-user-3","UserStatus":"ENABLED"}]}`},
	{target: "AWSIdentityStore.ListUsers", body: `{"NextToken":"eyJwYWdlIjoyfQ","Users":[{"CreatedAt":1.7182944E9,"DisplayName":"Ada Example","Emails":[{"Primary":true,"Type":"work","Value":"user-a1b2c3@example.com"}],"IdentityStoreId":"` + cassetteStoreID + `","Name":{"FamilyName":"Example","Formatted":"Ada Example","GivenName":"Ada"},"UserId":"90677c50-e0f1-70ab-7e94-1a2b3c4d5e6f","UserName":"example-user","UserStatus":"ENABLED","UserType":"employee"},{"CreatedAt":1.7204832E9,"Emails":[{"Primary":true,"Type":"work","Value":"user-d4e5f6@example.com"}],"IdentityStoreId":"` + cassetteStoreID + `","Name":{"FamilyName":"Example","GivenName":"Dana"},"UserId":"b0e7fc40-a021-7033-1b55-6f7e8d9c0a1b","UserName":"example-user-2","UserStatus":"DISABLED"}]}`},

	{target: "SWBExternalService.ListPermissionSets", body: `{"PermissionSets":["` + cassetteAdminPS + `","` + cassetteReadOnlyPS + `"]}`},

	// Ada holds AdministratorAccess only through the group; Dana holds
	// ReadOnly directly. That pair is the whole point of the fixture: it
	// separates "is_admin resolves group membership" from "iam_binding
	// mirrors the assignment as made".
	{target: "SWBExternalService.DescribePermissionSet", bodyContains: "ps-1111111111111111", body: `{"PermissionSet":{"CreatedDate":1.7182944E9,"Description":"Full administrative access","Name":"AdministratorAccess","PermissionSetArn":"` + cassetteAdminPS + `","SessionDuration":"PT8H"}}`},
	{target: "SWBExternalService.DescribePermissionSet", bodyContains: "ps-2222222222222222", body: `{"PermissionSet":{"CreatedDate":1.7182944E9,"Description":"Read-only access","Name":"ReadOnly","PermissionSetArn":"` + cassetteReadOnlyPS + `","SessionDuration":"PT8H"}}`},

	{target: "SWBExternalService.ListManagedPoliciesInPermissionSet", bodyContains: "ps-1111111111111111", body: `{"AttachedManagedPolicies":[{"Arn":"arn:aws:iam::aws:policy/AdministratorAccess","Name":"AdministratorAccess"}]}`},
	{target: "SWBExternalService.ListManagedPoliciesInPermissionSet", bodyContains: "ps-2222222222222222", body: `{"AttachedManagedPolicies":[{"Arn":"arn:aws:iam::aws:policy/ReadOnlyAccess","Name":"ReadOnlyAccess"}]}`},

	{target: "SWBExternalService.ListAccountsForProvisionedPermissionSet", bodyContains: "ps-1111111111111111", body: `{"AccountIds":["` + cassetteAccountID + `"]}`},
	{target: "SWBExternalService.ListAccountsForProvisionedPermissionSet", bodyContains: "ps-2222222222222222", body: `{"AccountIds":["` + cassetteAccountID + `"]}`},

	{target: "SWBExternalService.ListAccountAssignments", bodyContains: "ps-1111111111111111", body: `{"AccountAssignments":[{"AccountId":"` + cassetteAccountID + `","PermissionSetArn":"` + cassetteAdminPS + `","PrincipalId":"` + cassetteGroupID + `","PrincipalType":"GROUP"}]}`},
	{target: "SWBExternalService.ListAccountAssignments", bodyContains: "ps-2222222222222222", body: `{"AccountAssignments":[{"AccountId":"` + cassetteAccountID + `","PermissionSetArn":"` + cassetteReadOnlyPS + `","PrincipalId":"b0e7fc40-a021-7033-1b55-6f7e8d9c0a1b","PrincipalType":"USER"}]}`},

	{target: "AWSIdentityStore.DescribeGroup", body: `{"DisplayName":"Platform Admins","GroupId":"` + cassetteGroupID + `","IdentityStoreId":"` + cassetteStoreID + `"}`},
	{target: "AWSIdentityStore.ListGroupMemberships", body: `{"GroupMemberships":[{"GroupId":"` + cassetteGroupID + `","IdentityStoreId":"` + cassetteStoreID + `","MemberId":{"UserId":"90677c50-e0f1-70ab-7e94-1a2b3c4d5e6f"},"MembershipId":"90671111-2222-3333-4444-555566667777"}]}`},
}

// cannedTransport answers each SDK request from cannedResponses, so the
// recorder captures a genuine request paired with a transcribed reply.
type cannedTransport struct{ t *testing.T }

func (c cannedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	target := r.Header.Get("X-Amz-Target")
	for _, cr := range cannedResponses {
		if cr.target != target {
			continue
		}
		if cr.bodyContains != "" && !strings.Contains(string(body), cr.bodyContains) {
			continue
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Content-Type":     []string{"application/x-amz-json-1.1"},
				"Date":             []string{time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat)},
				"X-Amzn-Requestid": []string{"1c3d6934-e473-4309-b499-2a3cf3011901"},
			},
			ContentLength: int64(len(cr.body)),
			Body:          io.NopCloser(strings.NewReader(cr.body)),
			Request:       r,
		}, nil
	}
	c.t.Fatalf("cassette driver: no canned response for target %q body %s", target, body)
	return nil, nil
}

func TestConstructCassette(t *testing.T) {
	client := sourcetest.RecordClientWithMatcher(t,
		"testdata/cassettes/identity_store_users", cannedTransport{t}, sourcetest.AWSMatcher)
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithHTTPClient(client),
		config.WithRegion(awstest.Region),
		config.WithRetryer(func() aws.Retryer { return aws.NopRetryer{} }),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("AKIAEXAMPLE0000000000", "secret", ""),
		),
	)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	p := New(Options{
		API: &awsAPI{
			store: identitystore.NewFromConfig(cfg),
			admin: ssoadmin.NewFromConfig(cfg),
		},
		Region: awstest.Region,
		Now:    func() time.Time { return testNow },
	})
	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: p.Emits()})
	if err != nil {
		t.Fatalf("Collect while recording: %v", err)
	}
	t.Logf("recorded a run producing %d records", len(recs))
}
