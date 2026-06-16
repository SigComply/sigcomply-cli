// Package certs implements the gcp.certs source plugin: lists Certificate
// Manager certificates across every location in one GCP project and emits
// one tls_certificate evidence record per certificate, carrying the
// expiry, managed-status, and auto-renewal attributes the tls_certificate
// policies evaluate — the same cloud-neutral type aws.acm emits, so those
// policies span both clouds with zero changes (Invariant #4,
// substitutability).
//
// Certificate Manager is GCP's managed-TLS surface and the direct analog
// of AWS ACM. A certificate is either managed (Google provisions and
// auto-renews it — Certificate.Managed set) or self-managed (the customer
// uploaded the PEM — Certificate.SelfManaged set); is_managed discriminates
// by which is non-nil.
//
// One list call covers the project: Projects.Locations.Certificates.List
// accepts the all-locations wildcard (locations/-), returning certificates
// from every region. The response carries Unreachable locations; the real
// adapter errors on any unreachable location rather than silently dropping
// certificates — a partial list could make an all-quantifier expiry policy
// falsely pass.
//
// Field mapping (the required fields are emitted unconditionally — the
// evaluator errors on any payload that omits a field a policy clause
// references):
//   - not_after ← ExpireTime (the durable, replay-safe field), normalized
//     to RFC3339 UTC. days_until_expiry is derived from it at collect time,
//     rounded toward zero so an already-expired cert reads negative.
//   - is_managed ← Managed != nil. auto_renew is a pointer set to true only
//     for managed certificates (Google auto-renews them); omitted for
//     self-managed certs, which have no auto-renewal concept — matching
//     aws.acm, where the auto-renew policy guards on is_managed.
//   - status ← an honest enum mapping: an expired cert is EXPIRED; otherwise
//     a managed cert maps its ManagedCertificate.State (ACTIVE→ISSUED,
//     PROVISIONING→PENDING_VALIDATION, FAILED→FAILED, else INACTIVE) and a
//     present self-managed cert is ISSUED. No shipped policy reads status,
//     but the schema requires a valid enum value.
//   - domain ← the first Subject Alternative Name (SanDnsnames, populated
//     from managed.domains for not-yet-provisioned managed certs).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md §The
// plugin contract), the plugin caches nothing across Collect calls. N
// policies bound to this plugin → N invocations of Collect.
//
// Auth: Application Default Credentials with the cloud-platform scope
// (Certificate Manager exposes no dedicated read-only scope); restrict
// access at the IAM layer with roles/certificatemanager.viewer (grants
// certificatemanager.certs.list/get). See docs/configuration.md §GCP. The
// real adapter wraps *certificatemanager.Service and unit tests inject an
// in-memory fake via the API interface seam.
package certs

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	certificatemanager "google.golang.org/api/certificatemanager/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "tls_certificate"

// SourceID is the registered ID for the gcp.certs plugin instance.
const SourceID = "gcp.certs"

// hoursPerDay converts an expiry duration to whole days.
const hoursPerDay = 24

// API is the subset of the Certificate Manager client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting GCP;
// the real adapter wraps *certificatemanager.Service and lists certificates
// across all locations.
type API interface {
	// ListCertificates returns every certificate across all locations in the
	// project (the locations/- wildcard), paginated into one slice.
	ListCertificates(ctx context.Context, project string) ([]*certificatemanager.Certificate, error)
}

// Plugin is the in-process gcp.certs source.
type Plugin struct {
	api       API
	projectID string
	now       func() time.Time
}

// Options is the constructor input.
type Options struct {
	API       API
	ProjectID string
	// Now is injected so tests can produce deterministic timestamps and
	// expiry math. Production callers leave it nil → time.Now().UTC().
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

// NewFromGCP constructs a Plugin backed by the real Certificate Manager API
// using Application Default Credentials with the cloud-platform scope (there
// is no narrower read-only scope). Restrict access at the IAM layer with
// roles/certificatemanager.viewer.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := certificatemanager.NewService(ctx, option.WithScopes(certificatemanager.CloudPlatformScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.certs: new service: %w", err)
	}
	return New(Options{
		API:       &realCertManager{svc: svc},
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

// certPayload is the cross-vendor tls_certificate shape (see
// internal/evidence_types/schemas/tls_certificate.v1.json). The required
// fields are always emitted — the evaluator errors on any payload that omits
// a field a policy clause references. auto_renew is a pointer so it is
// omitted (not false) for self-managed certs, which have no renewal concept.
type certPayload struct {
	ID              string `json:"id"`
	Domain          string `json:"domain"`
	Provider        string `json:"provider"`
	Status          string `json:"status"`
	NotAfter        string `json:"not_after"`
	DaysUntilExpiry int    `json:"days_until_expiry"`
	IsManaged       bool   `json:"is_managed"`
	AutoRenew       *bool  `json:"auto_renew,omitempty"`
	// GCP-specific extras (additionalProperties). location is parsed from the
	// resource name; san_dns_names lists every covered domain; managed_state
	// carries the raw managed-cert state so a PROVISIONING/FAILED is
	// distinguishable; scope records the certificate's intended use.
	Location     string   `json:"location,omitempty"`
	SanDNSNames  []string `json:"san_dns_names,omitempty"`
	ManagedState string   `json:"managed_state,omitempty"`
	Scope        string   `json:"scope,omitempty"`
}

// Collect lists Certificate Manager certificates in the configured project
// and returns one tls_certificate record per certificate. Records are sorted
// by ID before return so envelope bytes are stable across runs against
// stable project state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.certs: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	certs, err := p.api.ListCertificates(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.certs: list certificates: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(certs))
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		payload := buildPayload(cert, now)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.certs: marshal payload: %w", err)
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

// buildPayload maps one Certificate Manager certificate into the
// cross-vendor tls_certificate shape.
func buildPayload(cert *certificatemanager.Certificate, now time.Time) certPayload {
	notAfter, days, expired := expiry(cert.ExpireTime, now)
	isManaged := cert.Managed != nil
	p := certPayload{
		ID:              cert.Name,
		Domain:          primaryDomain(cert),
		Provider:        "gcp",
		Status:          mapStatus(cert, expired),
		NotAfter:        notAfter,
		DaysUntilExpiry: days,
		IsManaged:       isManaged,
		Location:        locationFromName(cert.Name),
		SanDNSNames:     cert.SanDnsnames,
		Scope:           cert.Scope,
	}
	if isManaged {
		// Google auto-renews managed certificates; self-managed certs omit
		// the field entirely (the auto-renew policy guards on is_managed).
		t := true
		p.AutoRenew = &t
		p.ManagedState = cert.Managed.State
	}
	return p
}

// expiry parses the certificate's RFC3339 expiry timestamp and returns it
// normalized to RFC3339 UTC, the whole days remaining (rounded toward zero;
// negative once expired), and whether it has already expired. An empty
// timestamp (e.g. a managed cert still provisioning) yields zero values; an
// unparseable timestamp is passed through verbatim with no derivation.
func expiry(expireTime string, now time.Time) (notAfter string, days int, expired bool) {
	if expireTime == "" {
		return "", 0, false
	}
	t, err := time.Parse(time.RFC3339, expireTime)
	if err != nil {
		return expireTime, 0, false
	}
	t = t.UTC()
	days = int(math.Trunc(t.Sub(now).Hours() / hoursPerDay))
	return t.Format(time.RFC3339), days, t.Before(now)
}

// mapStatus translates GCP certificate state into the tls_certificate status
// enum. Expiry takes precedence; otherwise a managed certificate maps its
// ManagedCertificate.State and a self-managed certificate (no lifecycle
// state) that is present and unexpired is treated as ISSUED.
func mapStatus(cert *certificatemanager.Certificate, expired bool) string {
	if expired {
		return "EXPIRED"
	}
	if cert.Managed != nil {
		switch cert.Managed.State {
		case "ACTIVE":
			return "ISSUED"
		case "PROVISIONING":
			return "PENDING_VALIDATION"
		case "FAILED":
			return "FAILED"
		default: // STATE_UNSPECIFIED or empty
			return "INACTIVE"
		}
	}
	return "ISSUED"
}

// primaryDomain returns the certificate's first Subject Alternative Name,
// falling back to the first configured managed domain when SANs are not yet
// populated (a managed cert mid-provisioning).
func primaryDomain(cert *certificatemanager.Certificate) string {
	if len(cert.SanDnsnames) > 0 {
		return cert.SanDnsnames[0]
	}
	if cert.Managed != nil && len(cert.Managed.Domains) > 0 {
		return cert.Managed.Domains[0]
	}
	return ""
}

// locationFromName extracts the location segment from a certificate resource
// name of the form "projects/{p}/locations/{loc}/certificates/{c}". Empty
// when the name does not contain a "/locations/" segment.
func locationFromName(name string) string {
	const marker = "/locations/"
	i := strings.Index(name, marker)
	if i < 0 {
		return ""
	}
	rest := name[i+len(marker):]
	if j := strings.Index(rest, "/"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// realCertManager is the production implementation of API. It wraps
// *certificatemanager.Service and lists every certificate in the project
// across all locations, paginating the response.
type realCertManager struct {
	svc *certificatemanager.Service
}

func (r *realCertManager) ListCertificates(ctx context.Context, project string) ([]*certificatemanager.Certificate, error) {
	parent := fmt.Sprintf("projects/%s/locations/-", project)
	var certs []*certificatemanager.Certificate
	var unreachable []string
	err := r.svc.Projects.Locations.Certificates.List(parent).Pages(ctx,
		func(resp *certificatemanager.ListCertificatesResponse) error {
			certs = append(certs, resp.Certificates...)
			unreachable = append(unreachable, resp.Unreachable...)
			return nil
		})
	if err != nil {
		return nil, err
	}
	// A location Certificate Manager couldn't reach means its certificates
	// are missing from the list. Surfacing this as an error (rather than
	// returning a partial set) keeps quantifier expiry policies honest.
	if len(unreachable) > 0 {
		return nil, fmt.Errorf("unreachable locations: %s", strings.Join(unreachable, ", "))
	}
	return certs, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
