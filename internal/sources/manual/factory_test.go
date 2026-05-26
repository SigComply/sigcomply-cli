package manual

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func TestBuildReader_DefaultsToLocal(t *testing.T) {
	tmp := t.TempDir()
	r, scheme, bucket, prefix, err := buildReader(map[string]any{"path": tmp})
	if err != nil {
		t.Fatalf("buildReader: %v", err)
	}
	if r == nil {
		t.Fatal("nil reader")
	}
	if scheme != "file" {
		t.Errorf("scheme = %q; want file", scheme)
	}
	if bucket != tmp {
		t.Errorf("bucket = %q; want %q (default to path)", bucket, tmp)
	}
	if prefix != "manual/" {
		t.Errorf("prefix = %q; want manual/", prefix)
	}
}

func TestBuildReader_PathRequired(t *testing.T) {
	r, scheme, bucket, prefix, err := buildReader(map[string]any{})
	if err == nil {
		t.Fatal("want error on missing path")
	}
	if r != nil || scheme != "" || bucket != "" || prefix != "" {
		t.Errorf("want zero values on error path; got r=%v scheme=%q bucket=%q prefix=%q", r, scheme, bucket, prefix)
	}
}

func TestBuildReader_ExplicitBucketAndPrefix(t *testing.T) {
	tmp := t.TempDir()
	_, _, bucket, prefix, err := buildReader(map[string]any{
		"path":   tmp,
		"bucket": "acme-evidence",
		"prefix": "ev/",
	})
	if err != nil {
		t.Fatalf("buildReader: %v", err)
	}
	if bucket != "acme-evidence" {
		t.Errorf("bucket = %q", bucket)
	}
	if prefix != "ev/" {
		t.Errorf("prefix = %q", prefix)
	}
}

func TestBuildReader_UnregisteredBackend(t *testing.T) {
	// In-tree backends are local, s3, gcs, azure_blob — each in its own
	// subpackage with an init() that calls RegisterReader. Third parties
	// register their own backends via RegisterReader from a project-local
	// plugin under .sigcomply/plugins/, compiled in by `sigcomply build`.
	// This test confirms the registry surfaces a clear error for a
	// genuinely unknown backend name.
	const unknown = "definitely-not-a-real-backend"
	r, scheme, bucket, prefix, err := buildReader(map[string]any{"backend": unknown, "path": "/x"})
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Errorf("want \"not registered\" error; got %v", err)
	}
	if !strings.Contains(err.Error(), unknown) {
		t.Errorf("error %q does not name the offending backend", err.Error())
	}
	if r != nil || scheme != "" || bucket != "" || prefix != "" {
		t.Errorf("error path should return zero values: r=%v scheme=%q bucket=%q prefix=%q", r, scheme, bucket, prefix)
	}
}

func TestRegisterReader_LocalRegistered(t *testing.T) {
	// init() must have registered the local backend in the manual.pdf
	// reader registry. This is the canary for any in-tree backend that
	// quietly fails to register at package init.
	if _, ok := LookupReader("local"); !ok {
		t.Fatalf("manual.pdf \"local\" reader not registered")
	}
}

func TestLocalReader_GetSuccess(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "sub"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "sub", "evidence.pdf"), []byte("body"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := &localReader{root: tmp}
	data, _, err := r.Get(context.Background(), "sub/evidence.pdf")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != "body" {
		t.Errorf("data = %q", data)
	}
}

func TestLocalReader_GetMissing(t *testing.T) {
	r := &localReader{root: t.TempDir()}
	_, _, err := r.Get(context.Background(), "nope.pdf")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v; want ErrNotFound", err)
	}
}

func TestFactoryRegistration(t *testing.T) {
	// init() must have registered manual.pdf in the global sources
	// factory registry. This test is the canary for any plugin that
	// quietly fails to register at package init.
	if _, ok := sources.Lookup(SourceID); !ok {
		t.Fatalf("manual.pdf not registered in sources factory registry")
	}
}
