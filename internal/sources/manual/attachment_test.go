package manual

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// The merged PDF is what the record's file_hash attests to, so the
// plugin hands the exact bytes to the collector for the vault. Without
// them an auditor holding the envelope has nothing to re-hash when the
// folder held more than one file.
func TestCollect_AttachesMergedPDF(t *testing.T) {
	at := mustTime("2026-02-01T00:00:00Z")
	files := map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/a.pdf": {Data: realPDF(t), UploadedAt: at},
		"manual/access_review_quarterly/2026-Q1/b.png": {Data: minimalPNG(), UploadedAt: at},
	}
	recs, err := newTestPlugin(files).Collect(context.Background(), baseReq(testPeriodID, nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, recs)
	if m.FileHash == "" {
		t.Fatal("file_hash empty; want the merged PDF's hash")
	}
	atts := recs[0].Attachments
	if len(atts) != 1 {
		t.Fatalf("len(Attachments) = %d; want 1", len(atts))
	}
	if atts[0].Name != testCatalogID+".pdf" {
		t.Errorf("attachment name = %q; want %q", atts[0].Name, testCatalogID+".pdf")
	}
	if got := sha256Hex(atts[0].Data); got != m.FileHash {
		t.Errorf("sha256(attachment) = %s; record file_hash = %s", got, m.FileHash)
	}
	if len(atts[0].Data) != m.FileSize {
		t.Errorf("attachment size = %d; record file_size = %d", len(atts[0].Data), m.FileSize)
	}
}

// An empty folder has no merged PDF, so there is nothing to store.
func TestCollect_NoAttachmentWhenFolderEmpty(t *testing.T) {
	recs, err := newTestPlugin(map[string]InMemoryFile{}).Collect(context.Background(), baseReq(testPeriodID, nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if n := len(recs[0].Attachments); n != 0 {
		t.Errorf("len(Attachments) = %d; want 0", n)
	}
}

// A fan-out entry stores one merged PDF per member that uploaded files,
// named after the member's folder, and each matches that member's
// file_hash in the record.
func TestCollect_FanOut_AttachesOnePDFPerMember(t *testing.T) {
	at := mustTime("2026-02-01T00:00:00Z")
	files := map[string]InMemoryFile{
		"manual/vendor_assurance.acme_cloud/2026-Q1/soc2.pdf": {Data: fakePDF(), UploadedAt: at},
		"manual/vendor_assurance.initech/2026-Q1/iso.pdf":     {Data: realPDF(t), UploadedAt: at},
	}
	recs, err := fanOutPlugin(files, threeVendors).Collect(context.Background(), fanOutReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, recs)
	want := map[string]string{}
	for _, im := range m.Instances {
		if im.FileHash != "" {
			want[testFanOutCatalogID+"."+im.ID+".pdf"] = im.FileHash
		}
	}
	if len(want) != 2 {
		t.Fatalf("members with a file_hash = %d; want 2", len(want))
	}
	atts := recs[0].Attachments
	if len(atts) != len(want) {
		t.Fatalf("len(Attachments) = %d; want %d", len(atts), len(want))
	}
	for _, a := range atts {
		if got := sha256Hex(a.Data); want[a.Name] != got {
			t.Errorf("attachment %q hash = %s; member file_hash = %s", a.Name, got, want[a.Name])
		}
	}
}
