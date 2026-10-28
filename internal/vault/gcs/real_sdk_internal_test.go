package gcs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"cloud.google.com/go/storage"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/storagetest"
	"github.com/sigcomply/sigcomply-cli/internal/vault/vaulttest"
)

const sdkBucket = "sdk-bucket"

// sdkVault returns a Vault whose client is the production realGCS over a
// real storage.Client, talking to a fake GCS server.
func sdkVault(t *testing.T, pageSize int) (*Vault, *storagetest.GCS) {
	t.Helper()
	srv := storagetest.NewGCS(t, sdkBucket, pageSize)
	v := &Vault{
		Client: &realGCS{bucket: srv.Client(t).Bucket(sdkBucket)},
		Bucket: sdkBucket,
		Prefix: "sigcomply/",
	}
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return v, srv
}

func TestRealGCS_Contract(t *testing.T) {
	vaulttest.RunContractSuite(t, func(t *testing.T) core.Vault {
		t.Helper()
		v, _ := sdkVault(t, 1000)
		return v
	})
}

// A listing longer than one page must follow nextPageToken to the end.
func TestRealGCS_ListFollowsEveryPage(t *testing.T) {
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
		t.Errorf("list requests = %d (tokens %q); want 3 pages of at most 2", len(tokens), tokens)
	}
}

// A missing object must read as "not found": the orchestrator treats that
// string as a first run rather than a vault failure.
func TestRealGCS_MissingObjectIsNotFound(t *testing.T) {
	v, _ := sdkVault(t, 10)
	_, err := v.GetBinary(context.Background(), "state/soc2/policies/p.json")
	if err == nil {
		t.Fatal("GetBinary on a missing object returned no error")
	}
	if !errors.Is(err, storage.ErrObjectNotExist) || !strings.Contains(err.Error(), "gcs vault: not found:") {
		t.Errorf("err = %v; want a not-found error wrapping storage.ErrObjectNotExist", err)
	}
}

func TestRealGCS_PutBinaryStoresMetadata(t *testing.T) {
	v, srv := sdkVault(t, 10)
	meta := map[string]string{"sigcomply-evidence-type": "signed_document"}
	if err := v.PutBinary(context.Background(), "evidence/doc.pdf", []byte("%PDF-1.4"), meta); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	o, ok := srv.Get("sigcomply/evidence/doc.pdf")
	if !ok {
		t.Fatal("object not stored under the vault prefix")
	}
	if o.Metadata["sigcomply-evidence-type"] != "signed_document" || string(o.Data) != "%PDF-1.4" {
		t.Errorf("stored object = %+v; want the body and metadata sent", o)
	}
}

// Object names are percent-encoded on the wire. A name that itself holds
// a '%' must round-trip unchanged.
func TestRealGCS_KeyWithPercentRoundTrips(t *testing.T) {
	v, _ := sdkVault(t, 10)
	ctx := context.Background()
	const key = "evidence/uptime 99.9% report.pdf"
	if err := v.PutBinary(ctx, key, []byte("%PDF-1.4"), nil); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	got, err := v.GetBinary(ctx, key)
	if err != nil {
		t.Fatalf("GetBinary: %v", err)
	}
	if string(got) != "%PDF-1.4" {
		t.Errorf("GetBinary = %q; want the stored body", got)
	}
}
