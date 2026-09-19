package sources

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	smithy "github.com/aws/smithy-go"
	"github.com/go-ldap/ldap/v3"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"google.golang.org/api/googleapi"
)

// This file is the one deliberate exception to the "source plugins
// share no helper package" rule: error *classification* has to be
// shared, because the collector (L4) has to make one retry decision
// for every plugin and cannot grow a per-vendor switch without
// learning every source ID — which Invariant #4 forbids. Nothing
// vendor-specific belongs here; this is a pure err -> bool function
// plus the one error type our own hand-rolled HTTP call sites return.

// RetryableError is the opt-in interface. Any error — ours or a
// third party's — that knows whether retrying could ever succeed
// implements it, and the classifier below believes it over every
// heuristic. Prefer implementing this on our own error types rather
// than teaching Terminal about them: it keeps the knowledge next to
// the error that has it.
type RetryableError interface {
	error
	// Retryable reports whether repeating the same call could
	// plausibly succeed. A permanent rejection (401, 403, an
	// unconvertible file) returns false.
	Retryable() bool
}

// APIError is the error our hand-rolled HTTP call sites return
// instead of a bare fmt.Errorf, so the status code survives the wrap
// chain to the collector. SDK-backed sources need nothing: their
// typed errors are wrapped with %w and the adapters below read them
// through errors.As.
//
// Message carries the human-readable text the call site used to
// format directly, so converting a site does not change what the
// operator sees in CI logs.
type APIError struct {
	// Source is a short plugin-family label ("github", "okta"). It
	// is prefixed to Message by Error(); empty means no prefix.
	Source string
	// StatusCode is the HTTP status, or 0 when the request never
	// reached a response (treated as retryable).
	StatusCode int
	// Code is the vendor's machine-readable error code, when the
	// call site has one. Optional.
	Code string
	// Message is the full human-readable detail, minus the Source
	// prefix.
	Message string
	// Err is an optional underlying cause (e.g. a body-read
	// failure), exposed via Unwrap.
	Err error
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		switch {
		case e.Code != "":
			msg = e.Code
		case http.StatusText(e.StatusCode) != "":
			msg = http.StatusText(e.StatusCode)
		default:
			msg = fmt.Sprintf("status %d", e.StatusCode)
		}
	}
	if e.Source != "" {
		return e.Source + ": " + msg
	}
	return msg
}

// Unwrap exposes the optional underlying cause.
func (e *APIError) Unwrap() error { return e.Err }

// Retryable implements RetryableError from the HTTP status.
func (e *APIError) Retryable() bool { return retryableStatus(e.StatusCode) }

// Terminal reports whether err is a permanent failure — one that
// will fail identically on every subsequent attempt, so spending the
// retry budget on it only delays the report.
//
// The default answer is false. An error this function does not
// recognize is reported as *not* terminal, i.e. retryable, so that
// adding a classifier can only ever shorten a doomed retry loop and
// never shortens a loop that might have succeeded. Every source that
// has not been converted keeps exactly its previous behavior.
func Terminal(err error) bool {
	if err == nil {
		return false
	}

	// 1. Anything that classifies itself wins outright — our own
	//    APIError, fileconv.UnsupportedTypeError, project-local
	//    plugins that opt in.
	var self RetryableError
	if errors.As(err, &self) {
		return !self.Retryable()
	}

	// 2. AWS (every aws-sdk-go-v2 service client). Classified on the
	//    protocol-agnostic code + fault rather than the HTTP status,
	//    which would require the awshttp transport package.
	var smithyErr smithy.APIError
	if errors.As(err, &smithyErr) {
		return terminalAWSCode(smithyErr)
	}

	// 3. Azure ARM + Blob (every armXxx client, azblob).
	var azErr *azcore.ResponseError
	if errors.As(err, &azErr) {
		return !retryableStatus(azErr.StatusCode)
	}

	// 4. GCP (every google.golang.org/api client).
	var gErr *googleapi.Error
	if errors.As(err, &gErr) {
		return !retryableStatus(gErr.Code)
	}

	// 5. GitLab.
	var glErr *gitlab.ErrorResponse
	if errors.As(err, &glErr) {
		return !retryableStatus(gitlabStatus(glErr))
	}

	// 6. Active Directory / LDAP.
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return terminalLDAPResult(ldapErr.ResultCode)
	}

	// 7. Transport-level failures and context deadlines are the
	//    textbook transient case. Stated explicitly rather than left
	//    to the default so the intent is testable.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}

	// 8. Unclassified: retry, as before.
	return false
}

// retryableStatus maps an HTTP status onto the retry decision. 0 (no
// response) is retryable; 408 and 429 are the two 4xx that are worth
// repeating; everything else in 4xx is a permanent rejection.
func retryableStatus(code int) bool {
	switch {
	case code == 0:
		return true
	case code == http.StatusRequestTimeout, code == http.StatusTooManyRequests:
		return true
	case code >= 500:
		return true
	case code >= 400:
		return false
	default:
		return true
	}
}

// gitlabStatus reads the status off an ErrorResponse, falling back to
// the retained *http.Response when the scalar field is unset.
func gitlabStatus(e *gitlab.ErrorResponse) int {
	if e.StatusCode != 0 {
		return e.StatusCode
	}
	if e.Response != nil {
		return e.Response.StatusCode
	}
	return 0
}

// awsRetryableCodes are throttle/capacity/server codes that a later
// attempt can clear. Checked before the terminal set, because several
// are FaultClient and would otherwise be read as permanent.
var awsRetryableCodes = map[string]bool{
	"RequestLimitExceeded":                   true,
	"TooManyRequestsException":               true,
	"ProvisionedThroughputExceededException": true,
	"TransactionInProgressException":         true,
	"PriorRequestNotComplete":                true,
	"RequestTimeout":                         true,
	"RequestTimeoutException":                true,
	"SlowDown":                               true,
	"InternalError":                          true,
	"InternalFailure":                        true,
	"InternalServerError":                    true,
	"InternalServerException":                true,
	"InternalServiceError":                   true,
	"ServiceUnavailable":                     true,
	"ServiceUnavailableException":            true,
}

// awsTerminalCodes are permission, credential and request-shape codes.
// A mis-scoped role produces one of these on every attempt.
var awsTerminalCodes = map[string]bool{
	"UnauthorizedOperation":         true,
	"UnrecognizedClientException":   true,
	"InvalidClientTokenId":          true,
	"AuthFailure":                   true,
	"SignatureDoesNotMatch":         true,
	"MissingAuthenticationToken":    true,
	"InvalidAccessKeyId":            true,
	"TokenRefreshRequired":          true,
	"OptInRequired":                 true,
	"SubscriptionRequiredException": true,
	"ValidationException":           true,
	"InvalidParameterValue":         true,
	"InvalidAction":                 true,
	"UnsupportedOperation":          true,
	"NoSuchEntity":                  true,
	"NoSuchBucket":                  true,
	"ResourceNotFoundException":     true,
}

// terminalAWSCode classifies a smithy API error. The explicit code
// sets come first; the fault is the fallback (server = retry, client
// = permanent), and an unknown fault falls through to retryable.
func terminalAWSCode(e smithy.APIError) bool {
	code := e.ErrorCode()
	if awsRetryableCodes[code] || strings.Contains(code, "Throttl") {
		return false
	}
	if awsTerminalCodes[code] ||
		strings.HasPrefix(code, "AccessDenied") ||
		strings.HasPrefix(code, "ExpiredToken") {
		return true
	}
	switch e.ErrorFault() {
	case smithy.FaultServer:
		return false
	case smithy.FaultClient:
		return true
	default:
		return false
	}
}

// terminalLDAPResult classifies an LDAP result code. Bind and ACL
// rejections are permanent; busy/unavailable/network are not.
func terminalLDAPResult(code uint16) bool {
	switch code {
	case ldap.LDAPResultBusy,
		ldap.LDAPResultUnavailable,
		ldap.LDAPResultTimeLimitExceeded,
		ldap.ErrorNetwork:
		return false
	case ldap.LDAPResultStrongAuthRequired,
		ldap.LDAPResultNoSuchObject,
		ldap.LDAPResultInappropriateAuthentication,
		ldap.LDAPResultInvalidCredentials,
		ldap.LDAPResultInsufficientAccessRights,
		ldap.LDAPResultUnwillingToPerform,
		ldap.LDAPResultInvalidDNSyntax:
		return true
	default:
		return false
	}
}
