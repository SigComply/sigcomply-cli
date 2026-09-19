package azureblob

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// Config keys the factory reads, mirrored from the external test file.
const (
	keyAccount          = "account"
	keyContainer        = "container"
	testConfigContainer = "mycontainer"

	testContainerName = "evidence"
)

// DefaultAzureCredential's constructor cannot fail, so without a token
// request a manual.pdf bucket with no Azure identity anywhere in the
// environment builds cleanly and fails at the first List — once per manual
// policy, as a collection error, rather than once as the configuration
// error it is.
func TestNew_MissingCredentialsIsAnError(t *testing.T) {
	stub(t, errors.New("no identity found in the chain"))

	_, err := New(context.Background(), Options{Account: "acme", Container: testContainerName})
	if err == nil {
		t.Fatal("New with an unusable credential = nil error; want an error")
	}
	for _, want := range []string{"AZURE_CLIENT_ID", "az login"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("New error = %q; want it to mention %q", err, want)
		}
	}
}

func TestNew_VerifiedCredentialSucceeds(t *testing.T) {
	stub(t, nil)

	r, err := New(context.Background(), Options{Account: "acme", Container: testContainerName})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if r.Container != testContainerName {
		t.Errorf("Container = %q; want %q", r.Container, testContainerName)
	}
}

func stub(t *testing.T, err error) {
	t.Helper()
	orig := verifyCredential
	t.Cleanup(func() { verifyCredential = orig })
	verifyCredential = func(context.Context, azcore.TokenCredential) error { return err }
}

// --- factory build path -------------------------------------------------
//
// These live in the internal test package because the factory now resolves
// credentials at construction: they need the seam above. Before that they
// passed only because the SDK built a client without authenticating, which
// quietly made them depend on whatever credentials the machine happened to
// have — green on a developer laptop, red in CI.

func TestBuild_DefaultsPrefix(t *testing.T) {
	stub(t, nil)
	f, ok := manual.LookupReader("azure_blob")
	if !ok {
		t.Fatal("azure_blob factory not registered")
	}
	// Azure SDK creates the client without connecting; New() succeeds here.
	r, scheme, bucket, prefix, err := f(map[string]any{
		keyAccount:   "myaccount",
		keyContainer: testConfigContainer,
	})
	if err != nil {
		t.Fatalf("build with valid config: %v", err)
	}
	if r == nil {
		t.Fatal("build returned nil reader")
	}
	if scheme != "azure" {
		t.Errorf("scheme = %q; want azure", scheme)
	}
	if bucket != testConfigContainer {
		t.Errorf("bucket = %q; want mycontainer (container name)", bucket)
	}
	if prefix != "manual/" {
		t.Errorf("prefix = %q; want manual/ (default)", prefix)
	}
}

func TestBuild_ExplicitPrefix(t *testing.T) {
	stub(t, nil)
	f, ok := manual.LookupReader("azure_blob")
	if !ok {
		t.Fatal("azure_blob factory not registered")
	}
	_, _, _, prefix, err := f(map[string]any{
		keyAccount:   "myaccount",
		keyContainer: testConfigContainer,
		"prefix":     "evidence/",
	})
	if err != nil {
		t.Fatalf("build with explicit prefix: %v", err)
	}
	if prefix != "evidence/" {
		t.Errorf("prefix = %q; want evidence/", prefix)
	}
}
