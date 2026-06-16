// Package firestore implements the gcp.firestore source plugin: lists
// Cloud Firestore databases in one GCP project and emits one nosql_table
// evidence record per database, carrying the encryption, point-in-time-
// recovery, and deletion-protection attributes the nosql_table policies
// evaluate — the same cloud-neutral type aws.dynamodb emits, so those
// policies span both clouds with zero changes (Invariant #4,
// substitutability).
//
// One list call covers the project: Projects.Databases.List accepts the
// parent "projects/{project}/databases" and returns every database (the
// "(default)" one plus any named databases) in a single, non-paginated
// response. The response also carries Unreachable locations; the real
// adapter treats any unreachable location as an error rather than
// silently dropping databases — a partial list could make an
// all-quantifier policy ("every database has PITR on") falsely pass.
//
// Field mapping (all three required booleans are emitted unconditionally —
// the evaluator errors on any payload that omits a field a policy clause
// references):
//   - encryption_enabled ← always true. Firestore encrypts all data at
//     rest unconditionally — Google-managed keys by default, or a customer
//     Cloud KMS key (CMEK); there is no unencrypted state. This matches
//     aws.dynamodb (which reports true when no explicit SSE config is
//     present) and gcp.artifactregistry. The CMEK-vs-default distinction
//     rides in the is_customer_managed / kms_key_name extras, NOT in
//     encryption_enabled.
//   - point_in_time_recovery_enabled ← PointInTimeRecoveryEnablement ==
//     "POINT_IN_TIME_RECOVERY_ENABLED" (a nil/UNSPECIFIED/DISABLED value →
//     false). The raw enum rides in the pitr_state extra.
//   - deletion_protection ← DeleteProtectionState ==
//     "DELETE_PROTECTION_ENABLED" (UNSPECIFIED/DISABLED → false). The raw
//     enum rides in the deletion_protection_state extra.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Auth: Application Default Credentials with the Datastore scope (Cloud
// Firestore exposes no dedicated read-only scope); restrict access at the
// IAM layer with roles/datastore.viewer (grants firestore.databases.list).
// See docs/configuration.md §GCP. The real adapter wraps *firestore.Service
// and unit tests inject an in-memory fake via the API interface seam.
package firestore

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	firestore "google.golang.org/api/firestore/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "nosql_table"

// SourceID is the registered ID for the gcp.firestore plugin instance.
const SourceID = "gcp.firestore"

// pitrEnabled is the PointInTimeRecoveryEnablement value that means PITR
// is on.
const pitrEnabled = "POINT_IN_TIME_RECOVERY_ENABLED"

// deleteProtectionEnabled is the DeleteProtectionState value that means
// deletion protection is on.
const deleteProtectionEnabled = "DELETE_PROTECTION_ENABLED"

// API is the subset of the Firestore Admin client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// GCP; the real adapter wraps *firestore.Service and lists every database
// in the project in one call.
type API interface {
	// ListDatabases returns every Firestore database in the project (the
	// "(default)" one plus any named databases) in one non-paginated
	// response.
	ListDatabases(ctx context.Context, project string) ([]*firestore.GoogleFirestoreAdminV1Database, error)
}

// Plugin is the in-process gcp.firestore source.
type Plugin struct {
	api       API
	projectID string
	now       func() time.Time
}

// Options is the constructor input.
type Options struct {
	API       API
	ProjectID string
	// Now is injected so tests can produce deterministic CollectedAt values.
	// Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers
// using the real GCP SDK should use NewFromGCP.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:       opts.API,
		projectID: opts.ProjectID,
		now:       now,
	}
}

// NewFromGCP constructs a Plugin backed by the real Firestore Admin API
// using Application Default Credentials with the Datastore scope (there is
// no narrower read-only scope). Restrict access at the IAM layer with
// roles/datastore.viewer.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := firestore.NewService(ctx, option.WithScopes(firestore.DatastoreScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.firestore: new service: %w", err)
	}
	return New(Options{
		API:       &realFirestore{svc: svc},
		ProjectID: projectID,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op for this plugin — configuration is fixed at New.
// Preserved for symmetry with other plugins.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// databasePayload is the cross-vendor nosql_table shape (see
// internal/evidence_types/schemas/nosql_table.v1.json). The three required
// booleans are always emitted — the evaluator errors on any payload that
// omits a field a policy clause references.
type databasePayload struct {
	ID                         string `json:"id"`
	Name                       string `json:"name"`
	Provider                   string `json:"provider"`
	EncryptionEnabled          bool   `json:"encryption_enabled"`
	PointInTimeRecoveryEnabled bool   `json:"point_in_time_recovery_enabled"`
	DeletionProtection         bool   `json:"deletion_protection"`
	// GCP-specific extras (additionalProperties). location and
	// database_type identify the database; is_customer_managed + kms_key_name
	// make the always-true encryption_enabled auditable (false/absent ⇒
	// Google-managed default keys, true ⇒ a customer CMEK key); pitr_state
	// and deletion_protection_state carry the raw enums so an UNSPECIFIED
	// (never configured) is distinguishable from an explicit DISABLED.
	Location                string `json:"location,omitempty"`
	DatabaseType            string `json:"database_type,omitempty"`
	IsCustomerManaged       bool   `json:"is_customer_managed,omitempty"`
	KMSKeyName              string `json:"kms_key_name,omitempty"`
	PITRState               string `json:"pitr_state,omitempty"`
	DeletionProtectionState string `json:"deletion_protection_state,omitempty"`
}

// Collect lists Firestore databases in the configured project and returns
// one nosql_table record per database. Records are sorted by ID before
// return so envelope bytes are stable across runs against stable project
// state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.firestore: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	databases, err := p.api.ListDatabases(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.firestore: list databases: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(databases))
	for _, db := range databases {
		if db == nil {
			continue
		}
		payload := buildPayload(db)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.firestore: marshal payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          payload.ID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// buildPayload maps one Firestore database into the cross-vendor
// nosql_table shape.
func buildPayload(db *firestore.GoogleFirestoreAdminV1Database) databasePayload {
	cmek, keyName := cmekConfig(db)
	return databasePayload{
		ID:                         db.Name,
		Name:                       databaseShortName(db.Name),
		Provider:                   "gcp",
		EncryptionEnabled:          true, // Firestore always encrypts at rest.
		PointInTimeRecoveryEnabled: db.PointInTimeRecoveryEnablement == pitrEnabled,
		DeletionProtection:         db.DeleteProtectionState == deleteProtectionEnabled,
		Location:                   db.LocationId,
		DatabaseType:               db.Type,
		IsCustomerManaged:          cmek,
		KMSKeyName:                 keyName,
		PITRState:                  db.PointInTimeRecoveryEnablement,
		DeletionProtectionState:    db.DeleteProtectionState,
	}
}

// cmekConfig reports whether the database uses a customer-managed (CMEK)
// key, along with the key name. A nil CmekConfig means Google-managed
// default encryption.
func cmekConfig(db *firestore.GoogleFirestoreAdminV1Database) (customerManaged bool, keyName string) {
	if db.CmekConfig == nil {
		return false, ""
	}
	return true, db.CmekConfig.KmsKeyName
}

// databaseShortName returns the trailing database id from a resource name
// of the form "projects/{project}/databases/{database}" (the "(default)"
// database keeps that literal id). It falls back to the full name when the
// name does not contain the "/databases/" segment.
func databaseShortName(name string) string {
	if i := strings.Index(name, "/databases/"); i >= 0 {
		return name[i+len("/databases/"):]
	}
	return path.Base(name)
}

// realFirestore is the production implementation of API. It wraps
// *firestore.Service and lists every database in the project in one call.
type realFirestore struct {
	svc *firestore.Service
}

func (r *realFirestore) ListDatabases(ctx context.Context, project string) ([]*firestore.GoogleFirestoreAdminV1Database, error) {
	parent := fmt.Sprintf("projects/%s/databases", project)
	resp, err := r.svc.Projects.Databases.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	// A location Firestore couldn't reach means its databases are missing
	// from the list. Surfacing this as an error (rather than returning a
	// partial set) keeps all-quantifier policies honest.
	if len(resp.Unreachable) > 0 {
		return nil, fmt.Errorf("unreachable locations: %s", strings.Join(resp.Unreachable, ", "))
	}
	return resp.Databases, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
