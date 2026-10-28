package azureblob

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/storagetest"
	"github.com/sigcomply/sigcomply-cli/internal/vault/vaulttest"
)

const sdkContainer = "sdk-vault"

// sdkVault returns a Vault whose client is the production realAzure over a
// real azblob.Client, talking to a fake Blob Storage server.
func sdkVault(t *testing.T, pageSize int) (*Vault, *storagetest.AzureBlob) {
	t.Helper()
	srv := storagetest.NewAzureBlob(t, sdkContainer, pageSize)
	v := &Vault{
		Client:    &realAzure{svc: srv.Client(t), container: sdkContainer},
		Account:   "acme",
		Container: sdkContainer,
		Prefix:    "sigcomply/",
	}
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return v, srv
}

func TestRealAzure_Contract(t *testing.T) {
	vaulttest.RunContractSuite(t, func(t *testing.T) core.Vault {
		t.Helper()
		v, _ := sdkVault(t, 1000)
		return v
	})
}

// A listing longer than one page must follow NextMarker to the end.
func TestRealAzure_ListFollowsEveryPage(t *testing.T) {
	v, srv := sdkVault(t, 2)
	ctx := context.Background()
	want := make([]string, 0, 5)
	for i := range 5 {
		key := fmt.Sprintf("runs/r%d.json", i)
		want = append(want, key)
		if err := v.PutJSON(ctx, key, map[string]int{"i": i}); err != nil {
			t.Fatalf("PutJSON: %v", err)
		}
	}
	if err := v.PutJSON(ctx, "state/other.json", 1); err != nil {
		t.Fatal(err)
	}

	before := len(srv.PageTokens())
	got, err := v.List(ctx, "runs/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("List = %v; want %v", got, want)
	}
	if tokens := srv.PageTokens()[before:]; len(tokens) != 3 {
		t.Errorf("list requests = %d (markers %q); want 3 pages of at most 2", len(tokens), tokens)
	}
}

// A missing blob must read as "not found": the orchestrator treats that
// string as a first run rather than a vault failure.
func TestRealAzure_MissingBlobIsNotFound(t *testing.T) {
	v, _ := sdkVault(t, 10)
	_, err := v.GetBinary(context.Background(), "state/soc2/policies/p.json")
	if err == nil {
		t.Fatal("GetBinary on a missing blob returned no error")
	}
	if !bloberror.HasCode(err, bloberror.BlobNotFound) || !strings.Contains(err.Error(), "azure blob vault: not found:") {
		t.Errorf("err = %v; want a not-found error carrying BlobNotFound", err)
	}
}

func TestRealAzure_PutBinaryStoresMetadata(t *testing.T) {
	v, srv := sdkVault(t, 10)
	meta := map[string]string{"sigcomply-evidence-type": "signed_document"}
	if err := v.PutBinary(context.Background(), "evidence/doc.pdf", []byte("%PDF-1.4"), meta); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	o, ok := srv.Get("sigcomply/evidence/doc.pdf")
	if !ok {
		t.Fatal("blob not stored under the vault prefix")
	}
	if o.Metadata["sigcomply-evidence-type"] != "signed_document" || string(o.Data) != "%PDF-1.4" {
		t.Errorf("stored blob = %+v; want the body and metadata sent", o)
	}
}
