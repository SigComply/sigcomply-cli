// Package manual implements the manual.pdf source plugin: a project-
// level singleton that reads customer-uploaded PDFs from the project's
// configured manual-evidence backend and emits a small signed_document
// manifest record for each. The PDF itself is mirrored as a sibling
// attachment by the collector (L4); this plugin is responsible only
// for resolving the path, hashing the bytes, and emitting the record.
//
// See docs/architecture/04-source-plugins.md §The manual.pdf plugin.
//
// Test injection: the Reader interface lets unit tests substitute an
// in-memory backend without touching real storage, matching the
// pattern used by internal/vault/s3 (API interface).
package manual

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the single evidence type this plugin emits.
const EvidenceTypeID = "signed_document"

// SourceID is the registered ID for the manual.pdf singleton.
const SourceID = "manual.pdf"

// Reader is the package-internal interface the plugin uses to fetch
// PDF bytes. The concrete adapter wraps a configured backend (local
// filesystem, S3, GCS, Azure Blob) and is injected at construction
// time; tests inject an in-memory map.
type Reader interface {
	// Get returns the bytes at uri and the upload time if the backend
	// records it. A missing file returns (nil, time.Time{}, ErrNotFound)
	// so callers can distinguish missing-but-expected (the policy fails
	// with a structured message) from a transport error (the policy
	// becomes status=error).
	Get(ctx context.Context, uri string) (data []byte, uploadedAt time.Time, err error)
}

// ErrNotFound is the sentinel a Reader returns when the requested URI
// does not exist. Other errors are treated as transport failures.
var ErrNotFound = errors.New("manual: pdf not found at expected path")

// CatalogEntry is the descriptive metadata for one manual-evidence
// path. It's the small subset of the full manual-catalog YAML the
// plugin needs at collection time; the rest of the catalog (display
// names, descriptions) is for the optional Evidence SPA helper.
type CatalogEntry struct {
	EvidenceID   string
	Filename     string
	Cadence      string
	TemporalRule string
	GracePeriod  time.Duration
}

// Plugin is the in-process manual.pdf source. One instance per
// project (singleton); enforced by config validation in
// internal/spec/project_config.go.
type Plugin struct {
	reader  Reader
	bucket  string
	prefix  string
	scheme  string // "s3" | "gs" | "azure" | "file"
	catalog map[string]CatalogEntry
}

// Options is the constructor input. The reader handles backend I/O;
// the scheme drives only the expected-URI text in the emitted record.
type Options struct {
	Reader  Reader
	Bucket  string
	Prefix  string
	Scheme  string
	Catalog map[string]CatalogEntry
}

// New constructs a Plugin. The catalog maps evidence_catalog_id to
// the descriptive fields used at collection time.
func New(opts Options) *Plugin {
	if opts.Prefix == "" {
		opts.Prefix = "manual/"
	}
	if opts.Scheme == "" {
		opts.Scheme = "file"
	}
	return &Plugin{
		reader:  opts.Reader,
		bucket:  opts.Bucket,
		prefix:  opts.Prefix,
		scheme:  opts.Scheme,
		catalog: opts.Catalog,
	}
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the single evidence type this plugin produces.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op for this plugin — configuration is fixed at New.
// The interface signature is preserved for symmetry with API plugins.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// Collect resolves the catalog entry referenced by req.Params and
// produces exactly one signed_document record. The collector wraps the
// record in an envelope; the PDF mirroring is handled by L4 alongside
// the envelope write.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("manual.pdf: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	catalogID := stringParam(req.Params, "catalog_id")
	if catalogID == "" {
		return nil, fmt.Errorf("manual.pdf: policy %q slot %q: catalog_id missing from slot_params", req.PolicyID, req.SlotName)
	}
	entry, ok := p.catalog[catalogID]
	if !ok {
		return nil, fmt.Errorf("manual.pdf: catalog entry %q not declared", catalogID)
	}
	periodID := stringParam(req.Params, "period_id")
	if periodID == "" {
		return nil, fmt.Errorf("manual.pdf: catalog %q: period_id missing from slot_params", catalogID)
	}
	periodStart := timeParam(req.Params, "period_start")
	periodEnd := timeParam(req.Params, "period_end")
	now := timeParam(req.Params, "now")
	if now.IsZero() {
		now = time.Now().UTC()
	}

	filename := entry.Filename
	if filename == "" {
		filename = "evidence.pdf"
	}

	relPath := fmt.Sprintf("%s%s/%s/%s", p.prefix, entry.EvidenceID, periodID, filename)
	expectedURI := p.buildURI(relPath)

	data, uploadedAt, err := p.reader.Get(ctx, relPath)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			rec, encodeErr := buildRecord(entry.EvidenceID, periodID, expectedURI, "", 0, time.Time{}, false, false, now)
			if encodeErr != nil {
				return nil, encodeErr
			}
			return []core.EvidenceRecord{rec}, nil
		}
		return nil, fmt.Errorf("manual.pdf: read %s: %w", relPath, err)
	}

	hash := sha256.Sum256(data)
	hashStr := "sha256:" + hex.EncodeToString(hash[:])
	inWindow := isInTemporalWindow(uploadedAt, periodStart, periodEnd, entry.GracePeriod)

	rec, err := buildRecord(entry.EvidenceID, periodID, expectedURI, hashStr, len(data), uploadedAt, true, inWindow, now)
	if err != nil {
		return nil, err
	}
	return []core.EvidenceRecord{rec}, nil
}

func (p *Plugin) buildURI(relPath string) string {
	switch p.scheme {
	case "s3":
		return fmt.Sprintf("s3://%s/%s", p.bucket, relPath)
	case "gs":
		return fmt.Sprintf("gs://%s/%s", p.bucket, relPath)
	case "azure":
		return fmt.Sprintf("azure://%s/%s", p.bucket, relPath)
	default:
		if p.bucket == "" {
			return relPath
		}
		return fmt.Sprintf("file://%s/%s", p.bucket, relPath)
	}
}

func isInTemporalWindow(uploadedAt, start, end time.Time, grace time.Duration) bool {
	if uploadedAt.IsZero() || start.IsZero() || end.IsZero() {
		return false
	}
	windowEnd := end.Add(grace)
	return !uploadedAt.Before(start) && !uploadedAt.After(windowEnd)
}

// manualManifest is the JSON payload embedded inside the
// signed_document record. Kept small on purpose — auditors should be
// able to read it without a schema in hand.
type manualManifest struct {
	EvidenceID       string    `json:"evidence_id"`
	PeriodID         string    `json:"period_id"`
	FilePresent      bool      `json:"file_present"`
	FileHash         string    `json:"file_hash,omitempty"`
	FileSize         int       `json:"file_size,omitempty"`
	UploadedAt       time.Time `json:"uploaded_at,omitempty"`
	InTemporalWindow bool      `json:"in_temporal_window"`
	ExpectedURI      string    `json:"expected_uri"`
}

func buildRecord(evidenceID, periodID, uri, hash string, size int, uploadedAt time.Time, present, inWindow bool, now time.Time) (core.EvidenceRecord, error) {
	manifest := manualManifest{
		EvidenceID:       evidenceID,
		PeriodID:         periodID,
		FilePresent:      present,
		FileHash:         hash,
		FileSize:         size,
		UploadedAt:       uploadedAt,
		InTemporalWindow: inWindow,
		ExpectedURI:      uri,
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("manual.pdf: marshal manifest: %w", err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeID,
		ID:          fmt.Sprintf("%s/%s", evidenceID, periodID),
		IdentityKey: "",
		Payload:     payload,
		SourceID:    SourceID,
		CollectedAt: now,
	}, nil
}

// InMemoryReader is a Reader backed by an in-memory map; used by tests
// and by the orchestrator's e2e fixture. Stable iteration order is not
// required — callers fetch by exact URI.
type InMemoryReader struct {
	Files map[string]InMemoryFile
}

// InMemoryFile pairs the file bytes with its recorded upload time.
type InMemoryFile struct {
	Data       []byte
	UploadedAt time.Time
}

// Get returns the recorded file, or ErrNotFound.
func (r *InMemoryReader) Get(_ context.Context, uri string) ([]byte, time.Time, error) {
	f, ok := r.Files[uri]
	if !ok {
		return nil, time.Time{}, ErrNotFound
	}
	return f.Data, f.UploadedAt, nil
}

// stringParam reads a string-typed slot parameter, returning "" when
// missing or the wrong type. Slot params are map[string]any by design.
func stringParam(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// timeParam reads a time.Time slot parameter, returning the zero value
// when missing or the wrong type.
func timeParam(m map[string]any, key string) time.Time {
	if v, ok := m[key].(time.Time); ok {
		return v
	}
	return time.Time{}
}

// SortedCatalogIDs returns the catalog IDs in lexicographic order;
// callers needing deterministic iteration over the catalog use this.
func SortedCatalogIDs(catalog map[string]CatalogEntry) []string {
	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

var _ core.SourcePlugin = (*Plugin)(nil)
