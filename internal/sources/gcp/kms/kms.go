// Package kms implements the gcp.kms source plugin: lists Cloud KMS
// crypto keys across every location in one GCP project and emits one
// kms_key evidence record per key, carrying the rotation and
// manager attributes key-rotation policies evaluate — the same neutral
// type aws.kms emits, so those policies span both clouds with zero
// changes (Invariant #4, substitutability).
//
// Cloud KMS keys are organized project → location → keyRing → cryptoKey,
// so the real adapter walks all three levels and returns a flat list. The
// "global" location is returned by ListLocations like any other, so the
// same walk covers it.
//
// Every key returned by cryptoKeys.list is customer-managed (CMEK) —
// Google-managed default encryption keys are not surfaced by the API — so
// is_customer_managed is always true (matching aws.kms's CUSTOMER manager
// value). Automatic rotation is enabled iff a rotation period is set; only
// ENCRYPT_DECRYPT keys support it, and for other purposes the field is
// always empty, so rotation_enabled=false needs no purpose special-casing.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Auth: Application Default Credentials with the cloudkms scope. See
// docs/configuration.md §GCP. The real adapter wraps *cloudkms.Service and
// unit tests inject an in-memory fake via the API interface seam.
package kms

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "kms_key"

// SourceID is the registered ID for the gcp.kms plugin instance.
const SourceID = "gcp.kms"

// keyManagerCustomer is the cross-vendor key_manager value for a
// customer-managed key. It matches the string aws.kms emits for AWS
// KeyManagerType "CUSTOMER", so the is-customer-managed policies read the
// same value across clouds.
const keyManagerCustomer = "CUSTOMER"

// stateEnabled is the CryptoKeyVersion state for an active primary version.
const stateEnabled = "ENABLED"

const secondsPerDay = 86400

// API is the subset of the Cloud KMS client this plugin uses. Defining it
// as an interface lets tests inject a fake without hitting GCP; the real
// adapter wraps *cloudkms.Service and walks the location/keyRing/cryptoKey
// hierarchy transparently.
type API interface {
	// ListCryptoKeys returns every crypto key across all locations in the
	// project, flattened into one slice.
	ListCryptoKeys(ctx context.Context, project string) ([]*cloudkms.CryptoKey, error)
}

// Plugin is the in-process gcp.kms source.
type Plugin struct {
	api       API
	projectID string
	now       func() time.Time
}

// Options is the constructor input.
type Options struct {
	API       API
	ProjectID string
	// Now is injected so tests can produce deterministic CollectedAt
	// values. Production callers leave it nil → time.Now().UTC().
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

// NewFromGCP constructs a Plugin backed by the real Cloud KMS API using
// Application Default Credentials with the cloudkms scope (Cloud KMS has
// no narrower read-only scope).
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := cloudkms.NewService(ctx, option.WithScopes(cloudkms.CloudkmsScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.kms: new service: %w", err)
	}
	return New(Options{
		API:       &realKMS{svc: svc},
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

// keyPayload is the cross-vendor kms_key shape (see
// internal/evidence_types/schemas/kms_key.v1.json). The two required
// fields (key_id, rotation_enabled) are always emitted — the evaluator
// errors on any payload that omits a field a policy clause references, and
// the rotation policies also read is_customer_managed.
type keyPayload struct {
	KeyID             string `json:"key_id"`
	KeyManager        string `json:"key_manager"`
	IsCustomerManaged bool   `json:"is_customer_managed"`
	Enabled           bool   `json:"enabled"`
	RotationEnabled   bool   `json:"rotation_enabled"`
	// GCP-specific extras (additionalProperties). purpose distinguishes
	// ENCRYPT_DECRYPT (rotatable) from asymmetric/MAC keys; protection_level
	// surfaces SOFTWARE/HSM/EXTERNAL; rotation_period_days makes the
	// rotation cadence auditable; primary_state mirrors the symmetric key's
	// primary version state.
	Provider           string `json:"provider"`
	Purpose            string `json:"purpose,omitempty"`
	ProtectionLevel    string `json:"protection_level,omitempty"`
	RotationPeriodDays int    `json:"rotation_period_days"`
	PrimaryState       string `json:"primary_state,omitempty"`
}

// Collect lists Cloud KMS keys in the configured project and returns one
// kms_key record per key. Records are sorted by ID before return so
// envelope bytes are stable across runs against stable project state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.kms: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	keys, err := p.api.ListCryptoKeys(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.kms: list crypto keys: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(keys))
	for _, key := range keys {
		if key == nil {
			continue
		}
		payload := buildPayload(key)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.kms: marshal payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          payload.KeyID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// buildPayload maps one Cloud KMS crypto key into the cross-vendor
// kms_key shape. Every key listed by cryptoKeys.list is customer-managed
// (CMEK), so is_customer_managed is always true.
func buildPayload(key *cloudkms.CryptoKey) keyPayload {
	protectionLevel := ""
	if key.VersionTemplate != nil {
		protectionLevel = key.VersionTemplate.ProtectionLevel
	}
	// State has no key-level analog in GCP; the primary version state is the
	// closest signal and is only present for ENCRYPT_DECRYPT keys. For other
	// purposes (no primary) enabled is best-effort true — the key exists and
	// is listable. No shipped policy reads enabled, so the asymmetric-key
	// imperfection cannot cause a false result.
	enabled := true
	primaryState := ""
	if key.Primary != nil {
		primaryState = key.Primary.State
		enabled = key.Primary.State == stateEnabled
	}
	return keyPayload{
		KeyID:              key.Name,
		KeyManager:         keyManagerCustomer,
		IsCustomerManaged:  true,
		Enabled:            enabled,
		RotationEnabled:    key.RotationPeriod != "",
		Provider:           "gcp",
		Purpose:            key.Purpose,
		ProtectionLevel:    protectionLevel,
		RotationPeriodDays: rotationPeriodDays(key.RotationPeriod),
		PrimaryState:       primaryState,
	}
}

// rotationPeriodDays parses a Cloud KMS rotation period ("7776000s") into
// whole days (90). Returns 0 when unset or unparseable.
func rotationPeriodDays(rp string) int {
	if rp == "" {
		return 0
	}
	secs, err := strconv.Atoi(strings.TrimSuffix(rp, "s"))
	if err != nil {
		return 0
	}
	return secs / secondsPerDay
}

// realKMS is the production implementation of API. It wraps
// *cloudkms.Service and walks the project's locations → keyRings →
// cryptoKeys, paging at each level, returning a flat list of keys.
type realKMS struct {
	svc *cloudkms.Service
}

func (r *realKMS) ListCryptoKeys(ctx context.Context, project string) ([]*cloudkms.CryptoKey, error) {
	var out []*cloudkms.CryptoKey
	locParent := fmt.Sprintf("projects/%s", project)
	err := r.svc.Projects.Locations.List(locParent).Pages(ctx, func(lp *cloudkms.ListLocationsResponse) error {
		for _, loc := range lp.Locations {
			krParent := fmt.Sprintf("projects/%s/locations/%s", project, loc.LocationId)
			if err := r.svc.Projects.Locations.KeyRings.List(krParent).Pages(ctx, func(kp *cloudkms.ListKeyRingsResponse) error {
				for _, kr := range kp.KeyRings {
					// kr.Name is already projects/*/locations/*/keyRings/*.
					if err := r.svc.Projects.Locations.KeyRings.CryptoKeys.List(kr.Name).Pages(ctx, func(ck *cloudkms.ListCryptoKeysResponse) error {
						out = append(out, ck.CryptoKeys...)
						return nil
					}); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
