package azureblob

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

const (
	testVaultAccount   = "acmevault"
	testVaultContainer = "evidence"
)

// DefaultAzureCredential's constructor cannot fail, so without a token
// request a vault with no Azure identity anywhere in the environment
// builds cleanly and fails at the first write — after the run has already
// collected and evaluated everything.
func TestNew_MissingCredentialsIsAnError(t *testing.T) {
	stubVaultVerify(t, errors.New("no identity found in the chain"))

	_, err := New(context.Background(), Options{Account: testVaultAccount, Container: testVaultContainer})
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
	stubVaultVerify(t, nil)

	v, err := New(context.Background(), Options{Account: testVaultAccount, Container: testVaultContainer})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if v.Container != testVaultContainer {
		t.Errorf("Container = %q; want %q", v.Container, testVaultContainer)
	}
}

func stubVaultVerify(t *testing.T, err error) {
	t.Helper()
	orig := verifyCredential
	t.Cleanup(func() { verifyCredential = orig })
	verifyCredential = func(context.Context, azcore.TokenCredential) error { return err }
}
