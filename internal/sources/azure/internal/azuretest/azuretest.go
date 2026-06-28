// Package azuretest is the Azure ARM test seam (WU-2.12): it builds the
// arm.ClientOptions (transport + endpoint) and a fake credential that point an
// Azure SDK ARM client at a go-vcr cassette instead of the live management
// plane, so Azure source plugins run offline through the real deserializer.
//
// The subscription used in this org is empty, so cassettes are hand-authored:
// canned ARM JSON is served from an httptest server at record time
// (RecordOptions, endpoint = the httptest URL), captured by the recorder, then
// the recorded URL is rewritten to https://management.azure.com; replay
// (ReplayOptions, default endpoint) matches on method+URL — ARM gives each
// resource-type list a distinct URL, and the matcher ignores the Authorization
// and x-ms-date headers, so the differing SigV4-equivalent bearer token + clock
// between record and replay are irrelevant.
package azuretest

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// SubscriptionID is the fake subscription the cassettes are recorded against.
const SubscriptionID = "00000000-0000-0000-0000-000000000000"

type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// FakeCredential is a no-network TokenCredential — the cassette transport never
// makes a real call, and the matcher ignores the Authorization header.
func FakeCredential() azcore.TokenCredential { return fakeCred{} }

func options(httpClient *http.Client, endpoint string) *arm.ClientOptions {
	c := cloud.AzurePublic
	if endpoint != "" { // record mode: point the ARM plane at the httptest server
		c = cloud.Configuration{
			ActiveDirectoryAuthorityHost: cloud.AzurePublic.ActiveDirectoryAuthorityHost,
			Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
				cloud.ResourceManager: {Endpoint: endpoint, Audience: "https://management.azure.com"},
			},
		}
	}
	return &arm.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: httpClient, Cloud: c}}
}

// ReplayOptions returns ARM client options that replay the named cassette
// offline against the default (public) management endpoint.
func ReplayOptions(t *testing.T, cassetteName string) *arm.ClientOptions {
	t.Helper()
	return options(sourcetest.ReplayClient(t, cassetteName), "")
}

// RecordOptions returns ARM client options that record into the named cassette,
// with the management plane pointed at endpoint (an httptest TLS server). The
// ARM SDK refuses bearer auth over plain HTTP, so the record server must be TLS
// and base must be its srv.Client().Transport (to trust the self-signed cert).
// Maintainer path.
func RecordOptions(t *testing.T, cassetteName, endpoint string, base http.RoundTripper) *arm.ClientOptions {
	t.Helper()
	return options(sourcetest.RecordClient(t, cassetteName, base), endpoint)
}
