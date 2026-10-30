package sign_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/collector"
	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// updateSPAGolden regenerates the Evidence SPA envelope vectors:
//
//	go test ./internal/sign/ -run TestSPAGoldenEnvelopes -update
//
// then copy testdata/spa-golden/ byte-for-byte to the SPA's
// src/lib/verification/__fixtures__/golden/ (see the README there).
var updateSPAGolden = flag.Bool("update", false, "regenerate the SPA golden envelope vectors")

const spaGoldenDir = "testdata/spa-golden"

// goldenKey is a fixed test key. The CLI signs every file with a fresh
// ephemeral key (Invariant 3); a fixed one only makes these vectors
// reproducible, so a regenerated file differs only when the format does.
func goldenKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("sigcomply spa golden test key, not a secret"))
	return ed25519.NewKeyFromSeed(seed[:])
}

var (
	goldenRunTime     = time.Date(2026, 2, 15, 14, 0, 0, 0, time.UTC)
	goldenCollectedAt = time.Date(2026, 2, 15, 14, 0, 1, 0, time.UTC)
	goldenUploadedAt  = time.Date(2026, 2, 10, 9, 30, 0, 0, time.UTC)
)

// goldenVector is one signed envelope plus any merged PDFs its record
// attests to.
type goldenVector struct {
	name        string
	records     []core.EvidenceRecord
	attachments []core.Attachment
}

func TestSPAGoldenEnvelopes(t *testing.T) {
	vectors := []goldenVector{
		basicVector(t),
		bignumVector(t),
		unicodeKeysVector(t),
		manualVector(t),
		fanOutVector(t),
	}
	want := map[string][]byte{}
	for i := range vectors {
		for name, data := range renderVector(t, &vectors[i]) {
			want[name] = data
		}
	}

	if *updateSPAGolden {
		writeGoldenDir(t, want)
	}
	assertGoldenDir(t, want)
	for name := range want {
		if strings.HasSuffix(name, ".json") {
			verifyGoldenEnvelope(t, name)
		}
	}
}

// renderVector signs the vector's records with the fixed key and returns
// the files the vector contributes: the envelope as written to the vault,
// the canonical bytes that were signed, and each attachment.
func renderVector(t *testing.T, v *goldenVector) map[string][]byte {
	t.Helper()
	env := &core.Envelope{
		FormatVersion: collector.EnvelopeFormatVersion,
		ProducedAt:    goldenRunTime,
		Records:       v.records,
	}
	signed, err := sign.EnvelopeSigningBytes(env)
	if err != nil {
		t.Fatalf("%s: signing bytes: %v", v.name, err)
	}
	key := goldenKey()
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("ed25519 public key has an unexpected type")
	}
	env.Signature = core.EnvelopeSignature{
		Algorithm: sign.AlgorithmEd25519,
		PublicKey: pub,
		Value:     ed25519.Sign(key, signed),
	}
	if err := sign.VerifyEnvelope(env); err != nil {
		t.Fatalf("%s: fixed-key envelope does not verify: %v", v.name, err)
	}
	encoded, err := sign.EncodeEnvelope(env)
	if err != nil {
		t.Fatalf("%s: encode: %v", v.name, err)
	}
	out := map[string][]byte{
		v.name + ".json":          append(encoded, '\n'),
		v.name + ".canonical.txt": signed,
	}
	for _, a := range v.attachments {
		out[v.name+"."+a.Name] = a.Data
	}
	return out
}

func basicVector(t *testing.T) goldenVector {
	t.Helper()
	// Keys out of order, non-ASCII, HTML-sensitive characters and an
	// escaped control character: the parts canonical JSON gets wrong
	// most easily.
	payload := json.RawMessage(`{"user_name":"Zoë Ångström","mfa_enabled":false,"is_admin":true,` +
		`"last_used_at":"2026-02-12T09:14:00Z","note":"<admin> & \"ops\"\ttab","groups":["b","a"],"meta":{"z":1,"a":null}}`)
	return goldenVector{name: "basic", records: []core.EvidenceRecord{{
		Type:        "user_account",
		ID:          "user-0001",
		IdentityKey: "zoe@example.com",
		Payload:     payload,
		SourceID:    "okta",
		CollectedAt: goldenCollectedAt,
		Scope:       &core.RecordScope{Account: "example-org", Region: "us-east-1"},
	}}}
}

func bignumVector(t *testing.T) goldenVector {
	t.Helper()
	// Integers above 2^53 lose precision in a JavaScript number; the SPA
	// must keep their source digits to rebuild the signed bytes.
	payload := json.RawMessage(`{"max_int64":9223372036854775807,"epoch_nanos":1771164001000000123,` +
		`"max_uint64":18446744073709551615,"negative":-9007199254740993,"small":42,"zero":0}`)
	return goldenVector{name: "bignum", records: []core.EvidenceRecord{{
		Type:        "audit_log_trail",
		ID:          "trail-1",
		Payload:     payload,
		SourceID:    "aws.cloudtrail",
		CollectedAt: goldenCollectedAt,
	}}}
}

func unicodeKeysVector(t *testing.T) goldenVector {
	t.Helper()
	// Canonical JSON sorts object keys by their UTF-8 bytes (Go string
	// order). JavaScript's default sort compares UTF-16 code units, which
	// puts an astral character (😀, a surrogate pair starting 0xD83D)
	// before private-use U+E000 and fullwidth U+FF01; UTF-8 puts it after
	// both. The SPA must sort by code point to rebuild these bytes.
	payload := json.RawMessage(`{"😀":"astral","！":"fullwidth","":"private use","é":"latin-1",` +
		`"Z":"upper","a":"lower","nested":{"😀":1,"！":2,"":3,"é":4,"a":5}}`)
	return goldenVector{name: "unicodekeys", records: []core.EvidenceRecord{{
		Type:        "user_account",
		ID:          "user-0002",
		Payload:     payload,
		SourceID:    "okta",
		CollectedAt: goldenCollectedAt,
	}}}
}

// manualVector runs the real manual.pdf plugin over one PDF, so the
// record and the stored PDF are exactly what `check` writes. One file
// per folder on purpose: merging several stamps pdfcpu's creation time
// into the output, so a multi-file vector would change on every -update.
func manualVector(t *testing.T) goldenVector {
	t.Helper()
	const id = "access_review_quarterly"
	files := map[string]manual.InMemoryFile{
		"manual/" + id + "/2026-Q1/access-review.pdf": {Data: fixturePDF(t), UploadedAt: goldenUploadedAt},
	}
	entry := manual.CatalogEntry{
		EvidenceID: id, Cadence: "quarterly", TemporalRule: "retrospective", GracePeriod: 15 * 24 * time.Hour,
	}
	recs := collectManual(t, files, &entry)
	return goldenVector{name: "manual", records: stripAttachments(recs), attachments: allAttachments(recs)}
}

// fanOutVector is a vendor fan-out entry: two members with documents, one
// missing, and one approved exemption.
func fanOutVector(t *testing.T) goldenVector {
	t.Helper()
	const id = "vendor_assurance"
	files := map[string]manual.InMemoryFile{
		"manual/" + id + ".acme_cloud/2026/soc2-report.pdf": {Data: fixturePDF(t), UploadedAt: goldenUploadedAt},
		"manual/" + id + ".globex_crm/2026/iso-cert.pdf":    {Data: variantPDF(t), UploadedAt: goldenUploadedAt},
	}
	entry := manual.CatalogEntry{
		EvidenceID: id, Cadence: "annual", TemporalRule: "retrospective", GracePeriod: 30 * 24 * time.Hour,
		FanOut: manual.FanOutVendors,
		Instances: []manual.Instance{
			{ID: "acme_cloud", Name: "Acme Cloud Platform", Tier: "critical", Required: true, AssurancePeriodEnd: "2026-03-31"},
			{ID: "globex_crm", Name: "Globex CRM", Tier: "high", Required: true},
			{ID: "initech_mail", Name: "Initech Mail", Tier: "high", Required: true},
			{ID: "zeta_news", Name: "Zeta Newsletter", Tier: "low", Required: false,
				ExemptionReason: "No customer data.", ApprovedBy: "Security lead"},
		},
	}
	recs := collectManualPeriod(t, files, &entry, "2026",
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC))
	return goldenVector{name: "fanout", records: stripAttachments(recs), attachments: allAttachments(recs)}
}

func collectManual(t *testing.T, files map[string]manual.InMemoryFile, entry *manual.CatalogEntry) []core.EvidenceRecord {
	t.Helper()
	return collectManualPeriod(t, files, entry, "2026-Q1",
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC))
}

func collectManualPeriod(t *testing.T, files map[string]manual.InMemoryFile, entry *manual.CatalogEntry, periodID string, start, end time.Time) []core.EvidenceRecord {
	t.Helper()
	p := manual.New(manual.Options{
		Reader:  &manual.InMemoryReader{Files: files},
		Bucket:  "acme-evidence",
		Prefix:  "manual/",
		Scheme:  "s3",
		Catalog: map[string]manual.CatalogEntry{entry.EvidenceID: *entry},
	})
	recs, err := p.Collect(context.Background(), core.SlotRequest{
		PolicyID:      "golden." + entry.EvidenceID,
		SlotName:      "_manual",
		AcceptedTypes: []string{manual.EvidenceTypeID},
		Params: map[string]any{
			"catalog_id":   entry.EvidenceID,
			"period_id":    periodID,
			"period_start": start,
			"period_end":   end,
			"now":          goldenCollectedAt,
		},
	})
	if err != nil {
		t.Fatalf("collect %s: %v", entry.EvidenceID, err)
	}
	if len(recs) != 1 {
		t.Fatalf("collect %s: %d records; want 1", entry.EvidenceID, len(recs))
	}
	return recs
}

func stripAttachments(recs []core.EvidenceRecord) []core.EvidenceRecord {
	out := make([]core.EvidenceRecord, len(recs))
	copy(out, recs)
	for i := range out {
		out[i].Attachments = nil
	}
	return out
}

func allAttachments(recs []core.EvidenceRecord) []core.Attachment {
	var out []core.Attachment
	for i := range recs {
		out = append(out, recs[i].Attachments...)
	}
	return out
}

func fixturePDF(t *testing.T) []byte {
	t.Helper()
	return fixtureFile(t, "e2e_doc_single", "policy.pdf")
}

// variantPDF is the fixture PDF with a trailing comment, so a second
// fan-out member has different bytes and a different hash.
func variantPDF(t *testing.T) []byte {
	t.Helper()
	return append(fixturePDF(t), []byte("% second member\n")...)
}

func fixtureFile(t *testing.T, folder, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "sources", "manual", "testdata", "store", "manual", folder, "2026-Q1", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeGoldenDir(t *testing.T, want map[string][]byte) {
	t.Helper()
	existing, err := filepath.Glob(filepath.Join(spaGoldenDir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range existing {
		if filepath.Base(f) == "README.md" {
			continue
		}
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range want {
		if err := os.WriteFile(filepath.Join(spaGoldenDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// assertGoldenDir fails when a regenerated vector differs from the
// committed one, or a file was added or removed: the SPA copy would then
// be stale.
func assertGoldenDir(t *testing.T, want map[string][]byte) {
	t.Helper()
	entries, err := os.ReadDir(spaGoldenDir)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []string
	for _, e := range entries {
		if e.Name() != "README.md" {
			onDisk = append(onDisk, e.Name())
		}
	}
	expected := make([]string, 0, len(want))
	for name := range want {
		expected = append(expected, name)
	}
	sort.Strings(onDisk)
	sort.Strings(expected)
	if strings.Join(onDisk, ",") != strings.Join(expected, ",") {
		t.Fatalf("%s holds %v; generator produces %v (rerun with -update)", spaGoldenDir, onDisk, expected)
	}
	for _, name := range expected {
		got, err := os.ReadFile(filepath.Join(spaGoldenDir, name)) //nolint:gosec // #nosec G304 -- fixed testdata dir
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want[name]) {
			t.Errorf("%s/%s is stale; rerun with -update and copy the folder to the SPA", spaGoldenDir, name)
		}
	}
}

// verifyGoldenEnvelope re-verifies a committed envelope the way the SPA
// does: parse the file, check the signature, and match each merged PDF
// it ships against the hash the signed record carries.
func verifyGoldenEnvelope(t *testing.T, name string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(spaGoldenDir, name)) //nolint:gosec // #nosec G304 -- fixed testdata dir
	if err != nil {
		t.Fatal(err)
	}
	var env core.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if err := sign.VerifyEnvelope(&env); err != nil {
		t.Errorf("%s does not verify: %v", name, err)
	}
	base := strings.TrimSuffix(name, ".json")
	for i := range env.Records {
		for file, hash := range manualHashes(t, &env.Records[i]) {
			pdf, err := os.ReadFile(filepath.Join(spaGoldenDir, base+"."+file)) //nolint:gosec // #nosec G304 -- fixed testdata dir
			if err != nil {
				t.Errorf("%s: PDF for %s: %v", name, file, err)
				continue
			}
			sum := sha256.Sum256(pdf)
			if got := "sha256:" + hex.EncodeToString(sum[:]); got != hash {
				t.Errorf("%s: %s hashes to %s; the signed record says %s", name, file, got, hash)
			}
		}
	}
}

// manualHashes maps each attachment name a manual record implies to the
// file_hash it signs: {evidence_id}.pdf, or {evidence_id}.{member}.pdf
// per fan-out member.
func manualHashes(t *testing.T, rec *core.EvidenceRecord) map[string]string {
	t.Helper()
	if rec.Type != manual.EvidenceTypeID {
		return nil
	}
	var p struct {
		EvidenceID string `json:"evidence_id"`
		FileHash   string `json:"file_hash"`
		Instances  []struct {
			ID       string `json:"id"`
			FileHash string `json:"file_hash"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(rec.Payload, &p); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	if p.FileHash != "" {
		out[p.EvidenceID+".pdf"] = p.FileHash
	}
	for _, in := range p.Instances {
		if in.FileHash != "" {
			out[p.EvidenceID+"."+in.ID+".pdf"] = in.FileHash
		}
	}
	if len(out) == 0 {
		t.Errorf("manual record %s carries no file_hash", rec.ID)
	}
	return out
}
