// Package cloudidentity implements the gcp.cloud_identity source plugin:
// it reads the Google Workspace / Cloud Identity password policies
// through the Cloud Identity Policy API and emits password_policy.v2
// records, so the six password controls (SOC 2 CC6.1 ×4, ISO 27001 8.5
// ×2) evaluate automatically on a Google-backed estate instead of
// skipping.
//
// # Why the plugin is named for the API and not for the setting
//
// gcp.cloud_identity, not gcp.password_policy. The repo names a GCP
// plugin after the API surface it reads — gcp.directory is the Admin SDK
// Directory API, gcp.scc is Security Command Center — and reserves the
// resource-shaped name for AWS, where aws.password_policy reads one IAM
// call that returns exactly one thing. The Cloud Identity Policy API is
// not that: `settings/security.password` is one of dozens of setting
// types it serves (gmail.*, drive.*, security.*), all through the same
// list endpoint, the same super-admin delegation and the same 1 QPS
// budget. A second setting type therefore belongs in THIS plugin, reusing
// this credential and this listing, and gcp.password_policy would have
// made that impossible to do without either a misnamed plugin or a second
// one paying the quota twice.
//
// # What it emits
//
// One password_policy.v2 record per policy the API returns for
// `settings/security.password`, ranked and resolved — see reduce.go for
// the ordering (Google's sortOrder runs the opposite way from the
// schema's precedence) and for the field-by-field reduction the API
// leaves to the caller.
//
// Complexity is emitted as complexity_model "strength_enum" with
// password_strength strong|weak, never as the four per-class booleans.
// Google states in its own administrator documentation that a strong
// password "doesn't need to have a specific number of characters of a
// specific type" — STRONG is entropy plus breach and common-password
// screening, explicitly not a character-class rule — so mapping STRONG to
// four trues would fabricate a claim the vendor itself disclaims.
//
// # Zero policies is a real answer, and it is not synthesized
//
// Whether a tenant is guaranteed to have at least one `security.password`
// policy is unverified. If the listing contains none, this plugin emits
// NO records. It does not invent a record out of Google's documented
// defaults: with nothing returned there is no evidence that the API was
// even answering about a password policy, and the defaults would then be
// read out of a manual and signed into an envelope — the category error
// password_policy.v2 exists to prevent. Every consuming clause is
// is_set-guarded, so zero records lands as an out-of-scope, vacuous
// clause ("nothing here was examined") rather than as a false verdict.
//
// # No L2 cassette — deliberately, and here is what closes it
//
// Every other source in this repo owes an L2 cassette. This one does not
// have one, and the absence is a decision rather than an omission: Google
// publishes no sample response body for `settings/security.password`, so
// a hand-authored cassette would be a recording of our own guesses,
// asserted against the code that made them. It would pass forever and
// prove nothing, while looking exactly like coverage.
//
// What is tested instead is the property that makes the guesses
// harmless: the decoders accept EVERY shape the unverified details could
// take (setting.go), a shape outside that set is a hard error rather than
// a zero, and the ranking and reduction are exercised through the API
// seam with fakes. Pointing cloudidentity_live_test.go
// (//go:build live) at a real tenant records the truth; recording a
// cassette from that same tenant is what closes this gap for good. See
// docs/architecture/12-multicloud-sources.md.
//
// # Test injection
//
// The API interface is the single seam; the real adapter wraps
// *ciapi.Service, pages the listing and paces itself against the 1 QPS
// per-customer quota, which Google does not raise on request.
package cloudidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	ciapi "google.golang.org/api/cloudidentity/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
// v2 only, never v1 and never both: every record a binding returns lands
// in the same slot, so emitting two versions of one policy would double
// resources_evaluated on the wire and write two signed envelopes for one
// fact. v1 could not be filled here anyway — it requires four
// character-class booleans Google does not have.
const EvidenceTypeID = "password_policy.v2"

// SourceID is the registered ID for the gcp.cloud_identity plugin.
const SourceID = "gcp.cloud_identity"

// customerPrefix is the resource-name prefix on Policy.Customer
// ("customers/C03abc123"), stripped before the id is stamped as the
// record's scope.
const customerPrefix = "customers/"

// API is the subset of the Cloud Identity Policy API this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// Google; the real adapter wraps *ciapi.Service and handles pagination
// and pacing.
type API interface {
	ListPolicies(ctx context.Context) ([]*ciapi.Policy, error)
}

// Plugin is the in-process gcp.cloud_identity source.
type Plugin struct {
	api API
	now func() time.Time
}

// Options is the constructor input.
type Options struct {
	API API
	// Now is injected so tests can produce deterministic CollectedAt
	// values. Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers
// using the real Google SDK should use NewFromGCP.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{api: opts.API, now: now}
}

// NewFromGCP constructs a Plugin backed by the real Cloud Identity Policy
// API with the read-only policies scope, authenticating per auth (see
// AuthConfig). Credentials are resolved here, not at first use.
func NewFromGCP(ctx context.Context, auth AuthConfig) (*Plugin, error) {
	opts, err := clientOptions(ctx, auth)
	if err != nil {
		return nil, err
	}
	svc, err := ciapi.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcp.cloud_identity: new service: %w", err)
	}
	return New(Options{API: &realPolicies{svc: svc, pageInterval: minPageInterval}}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op for this plugin — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// passwordPolicyPayload is the canonical password_policy.v2 shape as the
// Cloud Identity Policy API can fill it. The json tags match the AWS,
// Okta and Entra emitters' exactly — policies bind to the evidence type,
// never to a vendor.
//
// # Why nothing here is a pointer, and why that is safe
//
// The other emitters use pointers to keep "absent" distinguishable from
// zero. This one does not need to, because after the reduction in
// reduce.go EVERY field has an answer: either an administrator set it
// somewhere in the policy order, or Google's documented default is in
// force. No value reaches this struct as a Go zero by accident — each one
// is either a decoded pointer that was non-nil or a named default
// constant, and TestNoFieldIsAnAccidentalZero pins that.
//
// The two exceptions carry omitempty and mean it: ComplexityModel and
// PasswordStrength are omitted together when Google reported an
// allowedStrength this plugin does not recognize (see mapStrength), which
// is the one case where the source genuinely cannot answer.
//
// # `defaulted`, and why it is not the Entra category error
//
// Google's API returns ONLY explicitly-set values, and its own contract
// defines an omitted field as "the documented default applies". So when
// `minimumLength` is absent from every policy, `8` is not a number read
// out of a manual and asserted about a tenant nobody asked — the API WAS
// asked, it returned this tenant's policy resource, and the omission is
// this tenant's answer. That is the difference from Entra, where no call
// says anything at all about minimum length and the number would be
// invented wholesale; azure.entra therefore reports not_configurable and
// no value, which is right there and would be wrong here.
//
// The marker is what keeps it honest: the auditor reading the envelope
// sees both the value in force AND that it came from Google's default
// rather than from an administrator's decision. Reporting absence instead
// would be MORE misleading in effect, not less — every consuming clause
// guards its reads with is_set, so a never-configured tenant would
// produce six vacuous passes and this collector would fail to close the
// exact gap it was written to close.
//
// not_configurable is absent by construction: every attribute here IS
// configurable in Google, which is what makes `defaulted` the right
// marker and not that one.
type passwordPolicyPayload struct {
	ID               string   `json:"id"`
	Provider         string   `json:"provider"`
	Scope            string   `json:"scope"`
	Precedence       int      `json:"precedence"`
	MinLength        int64    `json:"min_length"`
	MaxAgeDays       int64    `json:"max_age_days"`
	ReusePrevented   bool     `json:"reuse_prevented"`
	ComplexityModel  string   `json:"complexity_model,omitempty"`
	PasswordStrength string   `json:"password_strength,omitempty"`
	Defaulted        []string `json:"defaulted,omitempty"`
}

// Collect lists every policy the customer has for this setting type,
// keeps the password ones, ranks them and emits one record each.
//
// reuse_prevention_count is never emitted: Google exposes allowReuse as a
// bare boolean and documents no history depth at all, so the depth clause
// filters these records out of scope (a vacuous pass, visible as such)
// rather than being answered with a guess. max/min-length ceilings and
// enforceRequirementsAtLogin are read but not emitted — password_policy.v2
// has no field for them and no clause asks.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.cloud_identity: slot AcceptedTypes %v does not include %q",
			req.AcceptedTypes, EvidenceTypeID)
	}
	policies, err := p.api.ListPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.cloud_identity: list policies: %w", err)
	}
	ranked, err := matchPasswordPolicies(policies)
	if err != nil {
		return nil, err
	}
	// Zero matched policies → zero records. See the package doc: a
	// synthesized record would be the fabrication this schema exists to
	// prevent, and the is_set-guarded clauses report the absence honestly.
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(ranked))
	for i := range ranked {
		body, err := json.Marshal(payloadFor(ranked, i))
		if err != nil {
			return nil, fmt.Errorf("gcp.cloud_identity: marshal password policy payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          ranked[i].id,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
			Scope:       recordScope(ranked[i].customer),
		})
	}
	// Payloads are built in RANK order because the reduction reads
	// downward through it, but records are returned in ID order like every
	// other plugin's: envelope bytes must be stable across runs, and the
	// rank is not lost by sorting — it is in each payload's `precedence`,
	// which is where a consumer can actually read it.
	sort.SliceStable(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// payloadFor builds the record for the policy at index i of the ranked
// list.
func payloadFor(ranked []rankedPolicy, i int) passwordPolicyPayload {
	eff := resolve(ranked, i)
	out := passwordPolicyPayload{
		ID:       ranked[i].id,
		Provider: providerGoogle,
		Scope:    ranked[i].scope,
		// precedence is the 1-based position in the sortOrder-descending
		// order: 1 wins. See reduce.go for why the inversion is needed.
		Precedence:     i + 1,
		MinLength:      eff.minLength,
		MaxAgeDays:     eff.maxAgeDays,
		ReusePrevented: eff.reusePrevented,
		Defaulted:      eff.defaulted,
	}
	if eff.strengthKnown {
		out.ComplexityModel = complexityStrengthEnum
		out.PasswordStrength = eff.passwordStrength
	}
	return out
}

// recordScope stamps the customer the policy was read from, which is the
// account boundary for a directory. It comes from the API's own
// Policy.Customer rather than from config: an operator-declared customer
// id could disagree with the credential's, and a provenance stamp that
// might be wrong is worse than none. Nothing is stamped when the API
// reported no customer.
func recordScope(customer string) *core.RecordScope {
	id := strings.TrimPrefix(strings.TrimSpace(customer), customerPrefix)
	if id == "" {
		return nil
	}
	return &core.RecordScope{Account: id}
}

// minPageInterval paces the listing. The Policy API's quota is 1 QPS PER
// CUSTOMER and Google does not raise it on request, so two pages fetched
// back-to-back are already over budget. A daily-cadence collector reading
// at most a handful of pages can simply wait, which is cheaper than
// discovering the limit as a 429 and spending the collector's retry
// budget on it.
const minPageInterval = time.Second

// listPageSize is the API maximum (values above 100 are clamped to 100).
// Fewer pages is the only lever that helps under a per-second quota.
const listPageSize = 100

// realPolicies is the production implementation of API.
type realPolicies struct {
	svc          *ciapi.Service
	pageInterval time.Duration
}

// ListPolicies pages the full policy listing, with NO server-side filter
// — see matchPasswordPolicies for why the filter is not used even though
// the API offers one.
func (r *realPolicies) ListPolicies(ctx context.Context) ([]*ciapi.Policy, error) {
	var out []*ciapi.Policy
	call := r.svc.Policies.List().PageSize(listPageSize)
	for page := 0; ; page++ {
		if page > 0 {
			if err := wait(ctx, r.pageInterval); err != nil {
				return nil, err
			}
		}
		resp, err := call.Context(ctx).Do()
		if err != nil {
			return nil, err
		}
		out = append(out, resp.Policies...)
		if resp.NextPageToken == "" {
			return out, nil
		}
		call = call.PageToken(resp.NextPageToken)
	}
}

// wait sleeps for d, or returns early if the run is canceled — a
// collector that ignores cancellation during a paced listing holds the
// whole run open for as many seconds as the tenant has pages.
func wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

var _ core.SourcePlugin = (*Plugin)(nil)
