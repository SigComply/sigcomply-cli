package manual

import (
	"context"
	"testing"
)

func TestFolderPrefix(t *testing.T) {
	got := FolderPrefix(defaultPrefix, testCatalogID, testPeriodID)
	want := "manual/access_review_quarterly/2026-Q1/"
	if got != want {
		t.Errorf("FolderPrefix = %q; want %q", got, want)
	}
}

func TestFolderPrefix_EmptyPrefix(t *testing.T) {
	if got, want := FolderPrefix("", "e1", testPeriodID), "e1/2026-Q1/"; got != want {
		t.Errorf("FolderPrefix = %q; want %q", got, want)
	}
}

func TestFolderURI(t *testing.T) {
	cases := []struct {
		name           string
		scheme, bucket string
		want           string
	}{
		{"s3", "s3", "eb", "s3://eb/manual/e1/2026-Q1/"},
		{"gcs", "gs", "eb", "gs://eb/manual/e1/2026-Q1/"},
		{"azure", azureScheme, "ct", "azure://ct/manual/e1/2026-Q1/"},
		{"local with bucket", localScheme, "/srv", "file:///srv/manual/e1/2026-Q1/"},
		{"local no bucket", localScheme, "", "manual/e1/2026-Q1/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FolderURI(tc.scheme, tc.bucket, defaultPrefix, "e1", testPeriodID)
			if got != tc.want {
				t.Errorf("FolderURI = %q; want %q", got, tc.want)
			}
		})
	}
}

// The plugin's own Collect path must agree with the exported helpers:
// they are the single source of truth for the folder scheme, which the
// Evidence SPA mirrors in src/lib/storage-path.ts. A drift here is a
// cross-repo contract break, so it is asserted rather than assumed.
func TestFolderURI_MatchesCollectExpectedURI(t *testing.T) {
	p := newTestPlugin(map[string]InMemoryFile{})
	recs, err := p.Collect(context.Background(), baseReq(testPeriodID, nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, recs)
	want := FolderURI("s3", testBucket, defaultPrefix, testCatalogID, testPeriodID)
	if m.ExpectedURI != want {
		t.Errorf("Collect expected_uri = %q; FolderURI = %q", m.ExpectedURI, want)
	}
}

func TestNewReaderFromConfig_UnknownBackend(t *testing.T) {
	_, err := readerFor(t, map[string]any{"backend": "nope"})
	if err == nil {
		t.Fatal("expected an error for an unregistered backend")
	}
}

// readerFor collapses the five-value constructor down to what these
// tests assert on.
func readerFor(t *testing.T, raw map[string]any) (Reader, error) {
	t.Helper()
	reader, _, _, _, err := NewReaderFromConfig(raw) //nolint:dogsled // only the reader and error are under test
	return reader, err
}

func TestNewReaderFromConfig_DefaultsToLocal(t *testing.T) {
	dir := t.TempDir()
	reader, _, bucket, prefix, err := NewReaderFromConfig(map[string]any{keyPath: dir})
	if err != nil {
		t.Fatalf("NewReaderFromConfig: %v", err)
	}
	if reader == nil {
		t.Fatal("reader is nil")
	}
	if prefix != defaultPrefix {
		t.Errorf("prefix = %q; want %q", prefix, defaultPrefix)
	}
	if bucket != dir {
		t.Errorf("bucket = %q; want %q", bucket, dir)
	}
}
