package plugin

import (
	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
)

// ---------------------------------------------------------------------
// Axis C — source plugins
//
// See docs/architecture/04-source-plugins.md §The plugin contract and
// docs/architecture/07-extensibility.md §Authoring a custom source plugin.
// ---------------------------------------------------------------------

// SourcePlugin is the interface a source plugin implements: ID, Emits,
// Init, Collect. Implementations must sort emitted records by ID, set
// IdentityKey where the evidence type has a cross-source identity, and
// leave fetch time to EvidenceRecord.CollectedAt — the full contract is
// documented on core.SourcePlugin.
type SourcePlugin = core.SourcePlugin

// SlotRequest is the per-binding call into Collect. AcceptedTypes is the
// intersection of the slot's accepts list with this plugin's Emits(), so
// a plugin emitting several types dispatches on it (via its Accepts
// method) rather than on PolicyID, which is diagnostics only.
type SlotRequest = core.SlotRequest

// EvidenceRecord is one observation a plugin returns from Collect. The
// Payload is validated against the registered JSON Schema of Type before
// it is wrapped in a signed envelope; the first non-conforming record
// fails the binding.
type EvidenceRecord = core.EvidenceRecord

// RecordScope is the account/region/project an EvidenceRecord was
// collected from — provenance for an auditor reading a single envelope,
// not a dimension of record identity. Optional; most records leave it nil.
type RecordScope = core.RecordScope

// SourceCaveat is a plugin's own declaration that a field it emits is a
// safe default rather than a measurement — the vendor publishes no API
// for it, or the configured credential cannot reach the one that exists.
// It is advisory: a caveat never changes a status, a count, or the wire
// payload.
type SourceCaveat = core.SourceCaveat

// CaveatedSource is the optional interface a SourcePlugin implements to
// declare its SourceCaveats. A plugin that implements nothing declares
// no caveats, which is the correct default.
type CaveatedSource = core.CaveatedSource

// Env carries everything a SourceFactory needs: Config is the raw map
// from the project config's `sources:` entry for this plugin, and
// FrameworkExtras is the escape hatch for framework-supplied data (the
// manual catalog, for instance). There is deliberately no Vault field —
// a plugin that needs storage configures its own backend rather than
// borrowing the run's evidence vault.
type Env = sources.Env

// SourceFactory builds a configured plugin instance. It runs once per
// registered source ID at the start of every `sigcomply check`; an error
// here is a configuration error (exit code 3).
type SourceFactory = sources.Factory

// RegisterSource registers a source-plugin factory under id, to be
// called from the extension package's init(). Duplicate IDs panic at
// process start: an in-tree duplicate is a programming error, and a
// project-local plugin claiming a reserved ID is a misconfiguration the
// build should not let through.
//
// configKeys names every key the factory reads out of Env.Config. It is
// optional and fail-open — a factory that declares none is never warned
// about — but declaring them is what lets the planner report a typo in
// `sources:` instead of silently collecting nothing, because the inner
// config bag is an untyped map the config loader cannot check.
func RegisterSource(id string, factory SourceFactory, configKeys ...string) {
	sources.RegisterFactory(id, factory, configKeys...)
}

// ---------------------------------------------------------------------
// Axis B — vault backends
//
// See docs/architecture/00-three-plugin-axes.md §Axis B and
// docs/architecture/07-extensibility.md §Custom vault backends.
// ---------------------------------------------------------------------

// Vault is the customer-side persistence layer a backend implements:
// append-only per run, written by the CLI and read by auditors and
// dashboards. The CLI never reads back from the vault during the same run.
type Vault = core.Vault

// Envelope is the signed wrapper around a batch of EvidenceRecords that
// a Vault's PutEnvelope receives. It is self-contained — public key and
// signature travel inside it — so an auditor holding one file can verify
// it offline; a backend stores the bytes and must not rewrite them.
type Envelope = core.Envelope

// VaultConfig is the project config's `vault:` section: Backend selects
// the registered backend ID and Config carries every other key through
// untouched, so a new backend reads its own settings with no typed field
// and no central validation switch to edit. Str and Bool read Config.
type VaultConfig = spec.VaultConfig

// VaultFactory builds a fully Init'd Vault from the project's vault
// config. Backends translate VaultConfig into their own options, then
// construct and initialize before returning.
type VaultFactory = vault.Factory

// RegisterVaultBackend registers a vault backend under id, to be called
// from the extension package's init(). Duplicate IDs panic at process
// start, for the same reason RegisterSource's do.
func RegisterVaultBackend(id string, factory VaultFactory) {
	vault.RegisterBackend(id, factory)
}

// ---------------------------------------------------------------------
// Axis A — manual-evidence backends
//
// See docs/architecture/00-three-plugin-axes.md §Axis A and
// docs/architecture/07-extensibility.md §Custom manual-evidence backends.
// ---------------------------------------------------------------------

// ManualReader is the read-only interface the manual.pdf source uses to
// fetch customer-uploaded evidence files. It is named ManualReader
// rather than Reader because this package holds all three axes at once,
// and an unqualified Reader beside a Vault and a SourcePlugin would not
// say which storage it reads.
type ManualReader = manual.Reader

// ManualFileInfo describes one file returned by ManualReader.List. Key
// is the full path as passed to Get — prefix-relative, not a bare
// filename — so a List result feeds straight back into Get.
type ManualFileInfo = manual.FileInfo

// ManualReaderFactory builds a ManualReader from the raw `manual.pdf`
// config map, returning the reader plus the (scheme, bucket, prefix)
// triple used to build the URI recorded in emitted evidence records.
type ManualReaderFactory = manual.ReaderFactory

// RegisterManualReader registers a manual-evidence backend under id, to
// be called from the extension package's init(). Duplicate IDs panic at
// process start, for the same reason RegisterSource's do.
func RegisterManualReader(id string, factory ManualReaderFactory) {
	manual.RegisterReader(id, factory)
}

// ErrManualNotFound is the sentinel a ManualReader returns when the
// requested key does not exist. Returning it is not optional: it is what
// separates missing-but-expected evidence (the policy fails with a
// structured message telling the operator which folder is empty) from a
// transport failure (the policy becomes status=error). Any other error
// is read as transport.
//
// It is a variable rather than a constant only because Go has no error
// constants; it is the same value as the sentinel the manual.pdf source
// compares against, so errors.Is works across the seam. Do not reassign it.
var ErrManualNotFound = manual.ErrNotFound
