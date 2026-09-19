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

	// FanOut names the set this entry multiplies over ("" for none).
	// It is declared by the framework; the members are resolved from
	// project config at wiring time. See the FanOut* constants.
	FanOut string

	// Instances turns this entry into a fan-out: instead of one folder
	// at {prefix}{evidence_id}/{period}/, the plugin scans one folder
	// per instance at {prefix}{evidence_id}.{instance_id}/{period}/ and
	// emits a single record carrying every instance's verdict plus the
	// counts. Empty (the default) keeps the original single-folder
	// behavior exactly.
	//
	// This field is deliberately on the runtime entry only. The
	// SPA-facing manualcatalog.Entry stays a flat 15-field contract —
	// fan-out instances come from the project's config, which the
	// framework-static catalog export cannot see.
	Instances []Instance
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
	priorID := stringParam(req.Params, "prior_period_id")

	// Fan-out entry: one folder per instance, one record out. Checked
	// first so the single-folder path below stays byte-identical for
	// every entry that is not a fan-out.
	if len(entry.Instances) > 0 {
		return p.collectInstances(ctx, &entry, periodID, priorID, periodStart, periodEnd, now)
	}

	scan := p.scanFolder(ctx, entry.EvidenceID, periodID, priorID, periodStart, periodEnd, entry.GracePeriod)
	if scan.err != nil {
		return nil, scan.err
	}
	rec, encErr := buildRecord(entry.EvidenceID, periodID, scan.uri, scan.hash, scan.size, scan.uploadedAt,
		scan.present, scan.inWindow, scan.failures, scan.sourceFiles, now)
	if encErr != nil {
		return nil, encErr
	}
	return []core.EvidenceRecord{rec}, nil
}

// folderScan is the result of examining one period folder. It is the
// unit both the single-entry and the fan-out paths are built from, so
// the two cannot drift in how they hash, merge or window-check.
type folderScan struct {
	uri         string
	hash        string
	size        int
	uploadedAt  time.Time
	present     bool
	inWindow    bool
	failures    []string
	sourceFiles []sourceFile
	err         error
}

// scanFolder performs the v1 manual-evidence algorithm against a single
// folder: list, classify, fetch/hash/convert, merge, validate, window,
// prior-period fingerprint.
func (p *Plugin) scanFolder(ctx context.Context, folderID, periodID, priorID string, periodStart, periodEnd time.Time, grace time.Duration) folderScan {
	folderPrefix := FolderPrefix(p.prefix, folderID, periodID)
	out := folderScan{uri: p.buildURI(folderPrefix)}

	items, err := p.reader.List(ctx, folderPrefix)
	if err != nil {
		out.err = fmt.Errorf("manual.pdf: list %s: %w", folderPrefix, err)
		return out
	}
	if len(items) == 0 {
		return out
	}

	pdfParts, sourceFiles, validationFailures, latestAt, fetchErr := p.fetchAndConvert(ctx, items)
	if fetchErr != nil {
		out.err = fetchErr
		return out
	}
	out.present = true
	out.uploadedAt = latestAt
	out.sourceFiles = sourceFiles
	out.failures = validationFailures
	if len(pdfParts) == 0 {
		return out
	}

	mergedHash, mergedSize, mergeFailures := mergeAndValidate(pdfParts)
	out.hash, out.size = mergedHash, mergedSize
	out.failures = append(out.failures, mergeFailures...)
	out.inWindow = isInTemporalWindow(latestAt, periodStart, periodEnd, grace)

	if len(out.failures) == 0 && priorID != "" {
		priorFolder := FolderPrefix(p.prefix, folderID, priorID)
		if f := p.checkPriorPeriod(ctx, sourceFiles, priorFolder, priorID); f != "" {
			out.failures = append(out.failures, f)
		}
	}
	return out
}

// collectInstances scans one folder per declared instance and reduces
// them to a single signed record. Instance order follows the catalog
// entry, which the config loader already sorted, so the record is
// deterministic across runs (Core Principle #7 — auditors diff runs).
func (p *Plugin) collectInstances(ctx context.Context, entry *CatalogEntry, periodID, priorID string, periodStart, periodEnd, now time.Time) ([]core.EvidenceRecord, error) {
	instances := make([]instanceManifest, 0, len(entry.Instances))
	satisfied := 0

	for i := range entry.Instances {
		inst := &entry.Instances[i]
		im := instanceManifest{
			ID:                 inst.ID,
			Name:               inst.Name,
			Tier:               inst.Tier,
			Required:           inst.Required,
			ExemptionReason:    inst.ExemptionReason,
			ApprovedBy:         inst.ApprovedBy,
			AssurancePeriodEnd: inst.AssurancePeriodEnd,
		}

		// A non-required instance owes a justification rather than an
		// artifact. Record it and move on without a LIST call — there
		// is no folder to scan and inventing one would report it as
		// perpetually overdue.
		if !inst.Required {
			im.ExpectedURI = ""
			im.Satisfied = true
			satisfied++
			instances = append(instances, im)
			continue
		}

		scan := p.scanFolder(ctx, inst.FolderID(entry.EvidenceID), periodID, priorID, periodStart, periodEnd, entry.GracePeriod)
		if scan.err != nil {
			return nil, scan.err
		}
		im.ExpectedURI = scan.uri
		im.FilePresent = scan.present
		im.FileHash = scan.hash
		im.FileSize = scan.size
		im.UploadedAt = scan.uploadedAt
		im.InTemporalWindow = scan.inWindow
		im.ValidationFailures = scan.failures
		im.SourceFiles = scan.sourceFiles

		if stale, reason := assuranceStale(inst.AssurancePeriodEnd, periodStart); stale {
			im.ValidationFailures = append(im.ValidationFailures, reason)
		}
		im.FileValid = scan.present && len(im.ValidationFailures) == 0
		im.Satisfied = im.FilePresent && im.InTemporalWindow && im.FileValid
		if im.Satisfied {
			satisfied++
		}
		instances = append(instances, im)
	}

	rec, err := buildInstanceRecord(entry.EvidenceID, periodID,
		p.buildURI(FolderPrefix(p.prefix, entry.EvidenceID, periodID)), instances, satisfied, now)
	if err != nil {
		return nil, err
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
	priorFiles := make([]sourceFile, 0, len(priorItems))
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

// buildURI renders an already-built object-key prefix as a display URI.
// The scheme/bucket switch lives in FolderURI so that read-only callers
// outside this package render byte-identical paths.
func (p *Plugin) buildURI(relPath string) string {
	return uriForScheme(p.scheme, p.bucket, relPath)
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

	// Instances is populated only for a fan-out entry. When present it
	// is the authoritative breakdown and the scalar fields above are
	// the conjunction over the *required* instances, so a consumer that
	// predates fan-out still reads a truthful summary rather than a
	// blank one.
	Instances          []instanceManifest `json:"instances,omitempty"`
	InstancesTotal     int                `json:"instances_total,omitempty"`
	InstancesSatisfied int                `json:"instances_satisfied,omitempty"`
}

// instanceManifest is one fan-out member's verdict inside the signed
// record — the per-vendor detail an auditor needs, kept vault-side.
// None of it crosses the aggregation boundary: the evaluator reduces
// these to two counts before anything is submitted.
type instanceManifest struct {
	ID                 string       `json:"id"`
	Name               string       `json:"name,omitempty"`
	Tier               string       `json:"tier,omitempty"`
	Required           bool         `json:"required"`
	FilePresent        bool         `json:"file_present"`
	FileHash           string       `json:"file_hash,omitempty"`
	FileSize           int          `json:"file_size,omitempty"`
	UploadedAt         time.Time    `json:"uploaded_at,omitempty"`
	InTemporalWindow   bool         `json:"in_temporal_window"`
	FileValid          bool         `json:"file_valid"`
	ValidationFailures []string     `json:"validation_failures,omitempty"`
	ExpectedURI        string       `json:"expected_uri,omitempty"`
	SourceFiles        []sourceFile `json:"source_files,omitempty"`

	// Satisfied is the single verdict for this instance: the artifact
	// is present, in-window and valid — or the instance is an approved
	// exemption, in which case ExemptionReason and ApprovedBy say so.
	Satisfied          bool   `json:"satisfied"`
	ExemptionReason    string `json:"exemption_reason,omitempty"`
	ApprovedBy         string `json:"approved_by,omitempty"`
	AssurancePeriodEnd string `json:"assurance_period_end,omitempty"`
}

// buildInstanceRecord reduces a fan-out entry's per-instance scans to
// one signed_document record.
func buildInstanceRecord(evidenceID, periodID, parentURI string, instances []instanceManifest, satisfied int, now time.Time) (core.EvidenceRecord, error) {
	manifest := manualManifest{
		EvidenceID:         evidenceID,
		PeriodID:           periodID,
		ExpectedURI:        parentURI,
		Instances:          instances,
		InstancesTotal:     len(instances),
		InstancesSatisfied: satisfied,
	}

	// The scalar fields are the conjunction over required instances.
	// Vacuously true when nothing is required, which is correct: a
	// register whose every member is an approved exemption has nothing
	// outstanding.
	allPresent, allInWindow, allValid := true, true, true
	var failures []string
	for i := range instances {
		im := &instances[i]
		if !im.Required {
			continue
		}
		if !im.FilePresent {
			allPresent = false
		}
		if !im.InTemporalWindow {
			allInWindow = false
		}
		if !im.FileValid {
			allValid = false
		}
		for _, f := range im.ValidationFailures {
			failures = append(failures, im.ID+": "+f)
		}
	}
	manifest.FilePresent = allPresent
	manifest.InTemporalWindow = allInWindow
	manifest.FileValid = allValid
	manifest.ValidationFailures = failures

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
