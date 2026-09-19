package sources

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	smithy "github.com/aws/smithy-go"
	"github.com/go-ldap/ldap/v3"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"google.golang.org/api/googleapi"
)

const testCodeAccessDenied = "AccessDenied"

// wrap buries err a couple of levels deep the way the collector and
// the plugins do, so every case also proves errors.As survives the
// real wrap chain.
func wrap(err error) error {
	return fmt.Errorf("collector: policy %q slot %q: %w", "p", "s", fmt.Errorf("list users: %w", err))
}

func TestTerminal_NilAndUnclassified(t *testing.T) {
	if Terminal(nil) {
		t.Error("Terminal(nil) = true; want false")
	}
	// The load-bearing default: anything we do not recognize keeps
	// the pre-classification behavior, which is to retry.
	if Terminal(errors.New("some vendor error nobody converted yet")) {
		t.Error("unclassified error must be reported as retryable")
	}
	if Terminal(wrap(errors.New("boom"))) {
		t.Error("wrapped unclassified error must be reported as retryable")
	}
}

func TestAPIError_Retryable(t *testing.T) {
	cases := []struct {
		status       int
		wantTerminal bool
	}{
		{http.StatusOK, false},
		{0, false},   // never reached a response
		{408, false}, // request timeout
		{429, false}, // throttled
		{500, false},
		{502, false},
		{503, false},
		{400, true},
		{401, true},
		{403, true},
		{404, true},
		{409, true},
		{422, true},
	}
	for _, tc := range cases {
		err := &APIError{Source: "github", StatusCode: tc.status, Message: "x"}
		if got := Terminal(wrap(err)); got != tc.wantTerminal {
			t.Errorf("status %d: Terminal = %v; want %v", tc.status, got, tc.wantTerminal)
		}
		if got := err.Retryable(); got == tc.wantTerminal {
			t.Errorf("status %d: Retryable = %v; want %v", tc.status, got, !tc.wantTerminal)
		}
	}
}

func TestAPIError_MessageFormatting(t *testing.T) {
	e := &APIError{Source: "okta", StatusCode: 403, Message: "/api/v1/users: 403 Forbidden: denied"}
	if got, want := e.Error(), "okta: /api/v1/users: 403 Forbidden: denied"; got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
	// No source prefix when Source is empty.
	if got, want := (&APIError{StatusCode: 403, Message: "403 Forbidden"}).Error(), "403 Forbidden"; got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
	// Falls back to Code, then to the status text.
	if got, want := (&APIError{Code: testCodeAccessDenied}).Error(), testCodeAccessDenied; got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
	if got, want := (&APIError{StatusCode: 503}).Error(), "Service Unavailable"; got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
	if got, want := (&APIError{StatusCode: 799}).Error(), "status 799"; got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
}

func TestAPIError_UnwrapsCause(t *testing.T) {
	cause := errors.New("short read")
	e := &APIError{Source: "github", StatusCode: 403, Message: "m", Err: cause}
	if !errors.Is(wrap(e), cause) {
		t.Error("APIError must expose its cause via Unwrap")
	}
}

// stubRetryable is a third-party-style error that opts in to the
// interface without being an APIError.
type stubRetryable struct{ retryable bool }

func (s *stubRetryable) Error() string   { return "stub" }
func (s *stubRetryable) Retryable() bool { return s.retryable }

func TestTerminal_OptInInterfaceWins(t *testing.T) {
	if !Terminal(wrap(&stubRetryable{retryable: false})) {
		t.Error("Retryable()==false must classify as terminal")
	}
	if Terminal(wrap(&stubRetryable{retryable: true})) {
		t.Error("Retryable()==true must classify as retryable")
	}
}

func TestTerminal_AWSSmithy(t *testing.T) {
	cases := []struct {
		code         string
		fault        smithy.ErrorFault
		wantTerminal bool
	}{
		{"ThrottlingException", smithy.FaultClient, false},
		{"RequestLimitExceeded", smithy.FaultClient, false},
		{"TooManyRequestsException", smithy.FaultClient, false},
		{"RequestThrottled", smithy.FaultClient, false},
		{"SlowDown", smithy.FaultServer, false},
		{"InternalError", smithy.FaultServer, false},
		{testCodeAccessDenied, smithy.FaultClient, true},
		{"AccessDeniedException", smithy.FaultClient, true},
		{"UnauthorizedOperation", smithy.FaultClient, true},
		{"InvalidClientTokenId", smithy.FaultClient, true},
		{"ExpiredToken", smithy.FaultClient, true},
		{"ExpiredTokenException", smithy.FaultClient, true},
		{"NoSuchEntity", smithy.FaultClient, true},
		// Unlisted codes fall back to the fault.
		{"SomeNewClientError", smithy.FaultClient, true},
		{"SomeNewServerError", smithy.FaultServer, false},
		{"SomeNewMysteryError", smithy.FaultUnknown, false},
	}
	for _, tc := range cases {
		err := &smithy.GenericAPIError{Code: tc.code, Message: "m", Fault: tc.fault}
		if got := Terminal(wrap(err)); got != tc.wantTerminal {
			t.Errorf("aws %s/%v: Terminal = %v; want %v", tc.code, tc.fault, got, tc.wantTerminal)
		}
	}
}

func TestTerminal_AzureResponseError(t *testing.T) {
	if !Terminal(wrap(&azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"})) {
		t.Error("azure 403 must be terminal")
	}
	if Terminal(wrap(&azcore.ResponseError{StatusCode: 429, ErrorCode: "TooManyRequests"})) {
		t.Error("azure 429 must be retryable")
	}
	if Terminal(wrap(&azcore.ResponseError{StatusCode: 503})) {
		t.Error("azure 503 must be retryable")
	}
}

func TestTerminal_GoogleAPIError(t *testing.T) {
	if !Terminal(wrap(&googleapi.Error{Code: 403, Message: "caller lacks permission"})) {
		t.Error("gcp 403 must be terminal")
	}
	if Terminal(wrap(&googleapi.Error{Code: 429})) {
		t.Error("gcp 429 must be retryable")
	}
	if Terminal(wrap(&googleapi.Error{Code: 500})) {
		t.Error("gcp 500 must be retryable")
	}
}

func TestTerminal_GitLabErrorResponse(t *testing.T) {
	if !Terminal(wrap(&gitlab.ErrorResponse{StatusCode: 401, Message: "401 Unauthorized"})) {
		t.Error("gitlab 401 must be terminal")
	}
	if Terminal(wrap(&gitlab.ErrorResponse{StatusCode: 429})) {
		t.Error("gitlab 429 must be retryable")
	}
	// Falls back to the retained *http.Response when the scalar is unset.
	if !Terminal(wrap(&gitlab.ErrorResponse{Response: &http.Response{StatusCode: 403}})) {
		t.Error("gitlab 403 via Response must be terminal")
	}
}

func TestTerminal_LDAP(t *testing.T) {
	cases := []struct {
		code         uint16
		wantTerminal bool
	}{
		{ldap.LDAPResultInvalidCredentials, true},
		{ldap.LDAPResultInsufficientAccessRights, true},
		{ldap.LDAPResultInappropriateAuthentication, true},
		{ldap.LDAPResultStrongAuthRequired, true},
		{ldap.LDAPResultNoSuchObject, true},
		{ldap.LDAPResultBusy, false},
		{ldap.LDAPResultUnavailable, false},
		{ldap.ErrorNetwork, false},
	}
	for _, tc := range cases {
		err := &ldap.Error{ResultCode: tc.code, Err: errors.New("ldap")}
		if got := Terminal(wrap(err)); got != tc.wantTerminal {
			t.Errorf("ldap result %d: Terminal = %v; want %v", tc.code, got, tc.wantTerminal)
		}
	}
}

func TestTerminal_TransportAndContext(t *testing.T) {
	transient := []error{
		&net.OpError{Op: "dial", Err: errors.New("connection refused")},
		context.DeadlineExceeded,
		context.Canceled,
	}
	for _, err := range transient {
		if Terminal(wrap(err)) {
			t.Errorf("%v must be reported as retryable", err)
		}
	}
}
