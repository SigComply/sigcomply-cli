package directory

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/oauth2"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

// stubTokenSource swaps the newTokenSource seam for the test's duration
// and returns a pointer to the captured config plus a call counter.
func stubTokenSource(t *testing.T, err error) (got *impersonate.CredentialsConfig, calls *int) {
	t.Helper()
	orig := newTokenSource
	t.Cleanup(func() { newTokenSource = orig })
	got = &impersonate.CredentialsConfig{}
	calls = new(int)
	newTokenSource = func(_ context.Context, c impersonate.CredentialsConfig, _ ...option.ClientOption) (oauth2.TokenSource, error) {
		*calls++
		*got = c
		if err != nil {
			return nil, err
		}
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"}), nil
	}
	return got, calls
}

func TestClientOptions_NoImpersonation_ADCWithReadonlyScope(t *testing.T) {
	_, calls := stubTokenSource(t, nil)
	opts, err := clientOptions(context.Background(), AuthConfig{})
	if err != nil {
		t.Fatalf("clientOptions: %v", err)
	}
	want := []option.ClientOption{option.WithScopes(admin.AdminDirectoryUserReadonlyScope)}
	if !reflect.DeepEqual(opts, want) {
		t.Errorf("opts = %#v; want %#v", opts, want)
	}
	if *calls != 0 {
		t.Errorf("newTokenSource calls = %d; want 0 without impersonation", *calls)
	}
}

func TestClientOptions_TargetServiceAccount(t *testing.T) {
	got, calls := stubTokenSource(t, nil)
	opts, err := clientOptions(context.Background(), AuthConfig{TargetServiceAccount: "reader@proj.iam.gserviceaccount.com"})
	if err != nil {
		t.Fatalf("clientOptions: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("newTokenSource calls = %d; want 1", *calls)
	}
	want := impersonate.CredentialsConfig{
		TargetPrincipal: "reader@proj.iam.gserviceaccount.com",
		Scopes:          []string{admin.AdminDirectoryUserReadonlyScope},
	}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("config = %+v; want %+v", *got, want)
	}
	if len(opts) != 1 {
		t.Fatalf("len(opts) = %d; want 1 (token source only)", len(opts))
	}
	if reflect.DeepEqual(opts[0], option.WithScopes(admin.AdminDirectoryUserReadonlyScope)) {
		t.Error("impersonation path must not fall back to the plain ADC scope option")
	}
}

func TestClientOptions_DomainWideDelegationSubject(t *testing.T) {
	got, _ := stubTokenSource(t, nil)
	_, err := clientOptions(context.Background(), AuthConfig{
		TargetServiceAccount: "dwd@proj.iam.gserviceaccount.com",
		ImpersonateSubject:   "admin@acme.com",
	})
	if err != nil {
		t.Fatalf("clientOptions: %v", err)
	}
	want := impersonate.CredentialsConfig{
		TargetPrincipal: "dwd@proj.iam.gserviceaccount.com",
		Scopes:          []string{admin.AdminDirectoryUserReadonlyScope},
		Subject:         "admin@acme.com",
	}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("config = %+v; want %+v", *got, want)
	}
}

func TestClientOptions_SubjectWithoutTarget_ConfigError(t *testing.T) {
	_, calls := stubTokenSource(t, nil)
	_, err := clientOptions(context.Background(), AuthConfig{ImpersonateSubject: "admin@acme.com"})
	if !errors.Is(err, errSubjectWithoutTarget) {
		t.Fatalf("err = %v; want errSubjectWithoutTarget", err)
	}
	if *calls != 0 {
		t.Errorf("newTokenSource calls = %d; want 0", *calls)
	}
}

func TestClientOptions_TokenSourceError_Wrapped(t *testing.T) {
	boom := errors.New("no base credentials")
	stubTokenSource(t, boom)
	_, err := clientOptions(context.Background(), AuthConfig{TargetServiceAccount: "sa@p.iam.gserviceaccount.com"})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v; want wrapped %v", err, boom)
	}
}

func TestBuild_SubjectWithoutTarget_ConfigError(t *testing.T) {
	_, calls := stubTokenSource(t, nil)
	_, err := build(context.Background(), sources.Env{Config: map[string]any{
		"impersonate_subject": "admin@acme.com",
	}})
	if err == nil || !strings.Contains(err.Error(), "target_service_account") {
		t.Fatalf("err = %v; want config error naming target_service_account", err)
	}
	if *calls != 0 {
		t.Errorf("newTokenSource calls = %d; want 0", *calls)
	}
}

func TestBuild_PassesImpersonationConfig(t *testing.T) {
	got, _ := stubTokenSource(t, nil)
	p, err := build(context.Background(), sources.Env{Config: map[string]any{
		"customer_id":            "C01abc",
		"target_service_account": "dwd@proj.iam.gserviceaccount.com",
		"impersonate_subject":    "admin@acme.com",
	}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got.TargetPrincipal != "dwd@proj.iam.gserviceaccount.com" || got.Subject != "admin@acme.com" {
		t.Errorf("config = %+v; want target + subject from config", *got)
	}
	if dp, ok := p.(*Plugin); !ok || dp.customer != "C01abc" {
		t.Errorf("plugin customer = %v; want C01abc", p)
	}
}
