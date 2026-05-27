// Package manual implements the manual.pdf source plugin: a project-
// level singleton that reads customer-uploaded evidence files from the
// project's configured manual-evidence backend and emits a single
// signed_document manifest record per catalog entry. Supported input
// formats are PDF (pass-through), JPEG, PNG, GIF, TIFF, WebP, and BMP;
// images are converted to PDF and all files found in the folder are
// merged into one PDF before signing.
//
// Multi-file folder model: the plugin lists all files under
//
//	{prefix}{evidence_catalog_id}/{period_id}/
//
// converts images to PDF, merges everything into one combined PDF, and
// records per-file metadata in SourceFiles for auditor transparency.
// Files with unsupported extensions are surfaced as validation_failures
// with an explicit error message so CI operators know exactly what to fix.
//
// See docs/architecture/04-source-plugins.md §The manual.pdf plugin.
//
// Test injection: the Reader interface lets unit tests substitute an
// in-memory backend without touching real storage, matching the
// pattern used by internal/vault/s3 (API interface).
package manual

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/fileconv"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/pdfmerge"
)

// minPDFBytes is the lower bound below which a payload cannot be a
// real-world compliance PDF. A theoretical minimum-valid PDF is ~67
// bytes, but any document with real content (a signed acknowledgement,
// an access-review export, a training certificate) is comfortably
// above 100 bytes. The check is meant to catch 0-byte uploads and
// trivially corrupt payloads, not to validate PDF correctness.
const minPDFBytes = 100

// pdfMagic is the PDF file signature. A payload that does not start
// with these bytes is not a PDF.
var pdfMagic = []byte("%PDF-")

// pdfPageMarker appears in the object dictionary of every PDF that has
// at least one page.
var pdfPageMarker = []byte("/Page")

// validatePDF runs cheap, stdlib-only sanity checks on the merged PDF
// and returns the list of failed checks (empty = valid). These are NOT
// a content audit — they only detect "this isn't a usable PDF at all"
// categories of upload mistake.
func validatePDF(data []byte) []string {
	var failures []string
	if len(data) < minPDFBytes {
		failures = append(failures, fmt.Sprintf("file_too_small (got %d bytes, want >=%d)", len(data), minPDFBytes))
	}
	if !bytes.HasPrefix(data, pdfMagic) {
		failures = append(failures, "missing_pdf_header (file does not start with %PDF-)")
	}
	if !bytes.Contains(data, pdfPageMarker) {
		failures = append(failures, "no_pages (PDF contains no /Page object — header-only or truncated)")
	}
	return failures
}

// EvidenceTypeID is the single evidence type this plugin emits.
const EvidenceTypeID = "signed_document"

// SourceID is the registered ID for the manual.pdf singleton.
const SourceID = "manual.pdf"

// FileInfo describes one file returned by a List operation.
type FileInfo struct {
	// Key is the full path as passed to Get (prefix-relative, not
	// filename-only). List consumers pass Key directly to Get.
	Key        string
	UploadedAt time.Time
}

// Reader is the package-internal interface the plugin uses to fetch
// evidence files. The concrete adapter wraps a configured backend (local
// filesystem, S3, GCS, Azure Blob) and is injected at construction
// time; tests inject an in-memory map.
type Reader interface {
	// Get returns the bytes at key and the upload time if the backend
	// records it. A missing file returns (nil, time.Time{}, ErrNotFound)
	// so callers can distinguish missing-but-expected (the policy fails
	// with a structured message) from a transport error (the policy
	// becomes status=error).
	Get(ctx context.Context, key string) (data []byte, uploadedAt time.Time, err error)

	// List returns all files whose key begins with prefix, sorted
	// lexicographically by key. An empty result (no files) is not an
	// error — the caller decides how to handle an empty folder.
	List(ctx context.Context, prefix string) ([]FileInfo, error)
}

// ErrNotFound is the sentinel a Reader returns when the requested key
// does not exist. Other errors are treated as transport failures.
var ErrNotFound = errors.New("manual: file not found at expected path")

// CatalogEntry is the descriptive metadata for one manual-evidence
// path. It's the small subset of the full manual-catalog YAML the
// plugin needs at collection time; the rest of the catalog (display
// names, descriptions) is for the optional Evidence SPA helper.
//
// The Filename field is kept for backward compatibility but is no
// longer used in collection logic — all files in the period folder
// are collected regardless of name.
type CatalogEntry struct {
	EvidenceID   string
	Filename     string // kept for compat; ignored in collection
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

// Collect lists all evidence files in the catalog-entry folder for
// the given period, converts images to PDF, merges everything into a
// single PDF, and produces one signed_document record. Unsupported
// file types are surfaced as validation_failures so the CI operator
// sees an actionable error message.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	entry, periodID, now, err := p.parseCollectParams(req)
	if err != nil {
		return nil, err
	}
	periodStart := timeParam(req.Params, "period_start")
	periodEnd := timeParam(req.Params, "period_end")

	folderPrefix := fmt.Sprintf("%s%s/%s/", p.prefix, entry.EvidenceID, periodID)
	folderURI := p.buildURI(folderPrefix)

	items, err := p.reader.List(ctx, folderPrefix)
	if err != nil {
		return nil, fmt.Errorf("manual.pdf: list %s: %w", folderPrefix, err)
	}
	if len(items) == 0 {
		rec, encErr := buildRecord(entry.EvidenceID, periodID, folderURI, "", 0, time.Time{}, false, false, nil, nil, now)
		if encErr != nil {
			return nil, encErr
		}
		return []core.EvidenceRecord{rec}, nil
	}

	pdfParts, sourceFiles, validationFailures, latestAt, fetchErr := p.fetchAndConvert(ctx, items)
	if fetchErr != nil {
		return nil, fetchErr
	}
	if len(pdfParts) == 0 {
		rec, encErr := buildRecord(entry.EvidenceID, periodID, folderURI, "", 0, latestAt, true, false, validationFailures, nil, now)
		if encErr != nil {
			return nil, encErr
		}
		return []core.EvidenceRecord{rec}, nil
	}

	mergedHash, mergedSize, mergeFailures := mergeAndValidate(pdfParts)
	validationFailures = append(validationFailures, mergeFailures...)

	inWindow := isInTemporalWindow(latestAt, periodStart, periodEnd, entry.GracePeriod)

	if len(mergeFailures) == 0 && len(validationFailures) == 0 {
		if priorID := stringParam(req.Params, "prior_period_id"); priorID != "" {
			priorFolder := fmt.Sprintf("%s%s/%s/", p.prefix, entry.EvidenceID, priorID)
			if f := p.checkPriorPeriod(ctx, sourceFiles, priorFolder, priorID); f != "" {
				validationFailures = append(validationFailures, f)
			}
		}
	}

	rec, encErr := buildRecord(entry.EvidenceID, periodID, folderURI, mergedHash, mergedSize, latestAt, true, inWindow, validationFailures, sourceFiles, now)
	if encErr != nil {
		return nil, encErr
	}
	return []core.EvidenceRecord{rec}, nil
}

// parseCollectParams validates the slot request and returns the resolved
// catalog entry, periodID, and the effective "now" time.
func (p *Plugin) parseCollectParams(req core.SlotRequest) (CatalogEntry, string, time.Time, error) {
	if !req.Accepts(EvidenceTypeID) {
		return CatalogEntry{}, "", time.Time{}, fmt.Errorf("manual.pdf: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	catalogID := stringParam(req.Params, "catalog_id")
	if catalogID == "" {
		return CatalogEntry{}, "", time.Time{}, fmt.Errorf("manual.pdf: policy %q slot %q: catalog_id missing from slot_params", req.PolicyID, req.SlotName)
	}
	entry, ok := p.catalog[catalogID]
	if !ok {
		return CatalogEntry{}, "", time.Time{}, fmt.Errorf("manual.pdf: catalog entry %q not declared", catalogID)
	}
	periodID := stringParam(req.Params, "period_id")
	if periodID == "" {
		return CatalogEntry{}, "", time.Time{}, fmt.Errorf("manual.pdf: catalog %q: period_id missing from slot_params", catalogID)
	}
	now := timeParam(req.Params, "now")
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return entry, periodID, now, nil
}

// mergeAndValidate merges pdfParts into one PDF and validates the result.
// It returns the hex-encoded SHA-256 hash of the merged PDF, its byte size,
// and any validation failures (merge errors or structural PDF failures).
func mergeAndValidate(pdfParts [][]byte) (mergedHash string, mergedSize int, failures []string) {
	merged, err := pdfmerge.Merge(pdfParts)
	if err != nil {
		return "", 0, []string{fmt.Sprintf("merge_failed: %v", err)}
	}
	failures = validatePDF(merged)
	h := sha256.Sum256(merged)
	return "sha256:" + hex.EncodeToString(h[:]), len(merged), failures
}

// fetchAndConvert lists all items, separates supported from unsupported
// extensions, fetches each supported file, hashes the original bytes, and
// converts images to PDF. It returns the PDF parts, the per-file audit
// records, any validation failures so far, and the latest upload time seen.
func (p *Plugin) fetchAndConvert(ctx context.Context, items []FileInfo) (pdfParts [][]byte, sourceFiles []sourceFile, validationFailures []string, latestAt time.Time, err error) {
	for _, item := range items {
		ext := fileconv.NormalizeExt(item.Key)
		if !fileconv.SupportedExt(ext) {
			validationFailures = append(validationFailures, fmt.Sprintf(
				"unsupported_file_type: %q (extension %q not supported; supported: %s)",
				filepath.Base(item.Key), ext, fileconv.SupportedExtsList(),
			))
			continue
		}
		data, uploadedAt, fetchErr := p.reader.Get(ctx, item.Key)
		if fetchErr != nil {
			return nil, nil, nil, time.Time{}, fmt.Errorf("manual.pdf: fetch %s: %w", item.Key, fetchErr)
		}
		if uploadedAt.After(latestAt) {
			latestAt = uploadedAt
		}
		rawHash := sha256.Sum256(data)
		filename := filepath.Base(item.Key)
		pdfData, converted, convErr := fileconv.ToPDF(filename, ext, data)
		if convErr != nil {
			validationFailures = append(validationFailures, fmt.Sprintf("conversion_failed: %q: %v", filename, convErr))
			continue
		}
		pdfParts = append(pdfParts, pdfData)
		sourceFiles = append(sourceFiles, sourceFile{
			Filename:   filename,
			Type:       extToTypeName(ext),
			SHA256:     "sha256:" + hex.EncodeToString(rawHash[:]),
			UploadedAt: uploadedAt,
			Converted:  converted,
		})
	}
	return pdfParts, sourceFiles, validationFailures, latestAt, nil
}

// checkPriorPeriod fetches the files in priorFolder and compares their
// source fingerprint against the current period's. It returns a non-empty
// failure string when the two sets are byte-identical, and "" otherwise
// (including when the prior folder is missing or empty).
func (p *Plugin) checkPriorPeriod(ctx context.Context, currentFiles []sourceFile, priorFolder, priorID string) string {
	priorItems, listErr := p.reader.List(ctx, priorFolder)
	if listErr != nil || len(priorItems) == 0 {
		return ""
	}
	var priorFiles []sourceFile
	for _, pi := range priorItems {
		ext := fileconv.NormalizeExt(pi.Key)
		if !fileconv.SupportedExt(ext) {
			continue
		}
		pd, _, getErr := p.reader.Get(ctx, pi.Key)
		if getErr != nil {
			continue
		}
		ph := sha256.Sum256(pd)
		priorFiles = append(priorFiles, sourceFile{
			Filename: filepath.Base(pi.Key),
			SHA256:   "sha256:" + hex.EncodeToString(ph[:]),
		})
	}
	if len(priorFiles) > 0 && sourceFingerprint(currentFiles) == sourceFingerprint(priorFiles) {
		return fmt.Sprintf("copy_paste_of_prior_period (all source files byte-identical to %s)", priorID)
	}
	return ""
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

// sourceFile is the per-file audit record embedded in the manifest.
// Auditors can verify each original file independently from the merged PDF.
type sourceFile struct {
	Filename   string    `json:"filename"`
	Type       string    `json:"type"`   // "pdf", "jpeg", "png", etc.
	SHA256     string    `json:"sha256"` // of the original bytes, before conversion
	UploadedAt time.Time `json:"uploaded_at,omitempty"`
	Converted  bool      `json:"converted,omitempty"` // true if image was converted to PDF
}

// manualManifest is the JSON payload embedded inside the
// signed_document record.
//
// FileHash is the SHA-256 of the merged PDF (all source files combined).
// SourceFiles lists each original file with its own hash so auditors
// can trace back from the combined evidence to individual uploads.
// FileValid + ValidationFailures report sanity-check results: empty
// ValidationFailures and FileValid=true means the evidence passed all
// structural checks. Unsupported file types and conversion failures
// also land here so CI operators see an actionable message.
type manualManifest struct {
	EvidenceID         string       `json:"evidence_id"`
	PeriodID           string       `json:"period_id"`
	FilePresent        bool         `json:"file_present"`
	FileHash           string       `json:"file_hash,omitempty"`   // SHA-256 of merged PDF
	FileSize           int          `json:"file_size,omitempty"`   // bytes of merged PDF
	UploadedAt         time.Time    `json:"uploaded_at,omitempty"` // latest file upload time
	InTemporalWindow   bool         `json:"in_temporal_window"`
	FileValid          bool         `json:"file_valid"`
	ValidationFailures []string     `json:"validation_failures,omitempty"`
	ExpectedURI        string       `json:"expected_uri"`           // folder URI
	SourceFiles        []sourceFile `json:"source_files,omitempty"` // per-file audit trail
}

func buildRecord(evidenceID, periodID, uri, hash string, size int, uploadedAt time.Time, present, inWindow bool, validationFailures []string, sourceFiles []sourceFile, now time.Time) (core.EvidenceRecord, error) {
	manifest := manualManifest{
		EvidenceID:         evidenceID,
		PeriodID:           periodID,
		FilePresent:        present,
		FileHash:           hash,
		FileSize:           size,
		UploadedAt:         uploadedAt,
		InTemporalWindow:   inWindow,
		FileValid:          present && len(validationFailures) == 0,
		ValidationFailures: validationFailures,
		ExpectedURI:        uri,
		SourceFiles:        sourceFiles,
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

// sourceFingerprint produces a stable hash over a set of sourceFile
// records by sorting on filename before hashing. This lets the
// prior-period check compare two unordered sets deterministically.
func sourceFingerprint(files []sourceFile) string {
	parts := make([]string, 0, len(files))
	for _, f := range files {
		parts = append(parts, f.Filename+":"+f.SHA256)
	}
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(h[:])
}

// extToTypeName maps a normalised extension to a human-readable type
// name for the SourceFiles audit trail.
func extToTypeName(ext string) string {
	switch ext {
	case ".pdf":
		return "pdf"
	case ".jpg", ".jpeg":
		return "jpeg"
	case ".png":
		return "png"
	case ".gif":
		return "gif"
	case ".tif", ".tiff":
		return "tiff"
	case ".webp":
		return "webp"
	case ".bmp":
		return "bmp"
	default:
		return strings.TrimPrefix(ext, ".")
	}
}

// InMemoryReader is a Reader backed by an in-memory map; used by tests
// and by the orchestrator's e2e fixture. Stable iteration order is not
// required — callers fetch by exact key.
type InMemoryReader struct {
	Files map[string]InMemoryFile
}

// InMemoryFile pairs the file bytes with its recorded upload time.
type InMemoryFile struct {
	Data       []byte
	UploadedAt time.Time
}

// Get returns the recorded file, or ErrNotFound.
func (r *InMemoryReader) Get(_ context.Context, key string) ([]byte, time.Time, error) {
	f, ok := r.Files[key]
	if !ok {
		return nil, time.Time{}, ErrNotFound
	}
	return f.Data, f.UploadedAt, nil
}

// List returns all keys that begin with prefix, sorted lexicographically.
func (r *InMemoryReader) List(_ context.Context, prefix string) ([]FileInfo, error) {
	var items []FileInfo
	for key, f := range r.Files {
		if strings.HasPrefix(key, prefix) {
			items = append(items, FileInfo{Key: key, UploadedAt: f.UploadedAt})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	return items, nil
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
