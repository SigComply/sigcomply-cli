// Package defender implements the azure.defender source plugin: it reads
// Microsoft Defender for Cloud (Azure Security Center) in a subscription and
// emits three cross-vendor types — threat_detection_service (one per Defender
// plan), security_service (one CSPM record for Defender for Cloud itself), and
// vulnerability_finding (one per vulnerability recommendation) — so threat-detection,
// security-service-enablement, and unaddressed-finding policies evaluate against
// Azure exactly as they do against AWS (GuardDuty / SecurityHub-Macie-Inspector
// / Inspector findings) and GCP (Security Command Center) — zero policy changes
// (Invariant #4).
//
// threat_detection_service (from Defender plans / "Pricings"):
//
//   - One record per Defender plan (VirtualMachines, StorageAccounts,
//     SqlServers, Containers, …). is_enabled is true when the plan's pricing
//     tier is Standard (the paid tier with advanced threat detection); the Free
//     tier reads false. This mirrors aws.guardduty's one-record-per-detector
//     (per region) granularity: the "all threat detection enabled" policy then
//     expects every Defender plan on Standard, and customers scope out plans for
//     resource types they do not use via a `.sigcomply.yaml` exception.
//
// security_service (from the same Pricings read):
//
//   - One record representing Microsoft Defender for Cloud itself, mapped to
//     service_type "cspm" (Cloud Security Posture Management — what Defender for
//     Cloud is; it is not a SIEM or DLP). is_enabled is true when at least one
//     Defender plan is on the Standard tier (i.e. the enhanced security service
//     is actively protecting resources). The legacy auto-provisioning toggle is
//     deprecated by Microsoft and is deliberately NOT used as the signal — a
//     modern estate using agentless scanning + Defender plans would read a false
//     auto-provisioning value while being fully protected.
//
// vulnerability_finding (from individual recommendations):
//
//   - One record per Defender for Cloud individual recommendation in a
//     vulnerability category (vulnerabilityCategories: a vulnerable software
//     package, a missing system update, a code, IaC or API finding), read
//     subscription-wide through Azure Resource Graph. Microsoft retired the
//     grouped model these used to come from (security sub-assessments, which
//     now answer 404 SubAssessmentsDeprecated) on 2026-07-31; misconfiguration
//     and exposed-secret recommendations are not vulnerabilities and are not
//     read. severity maps the recommendation's metadata severity
//     (Critical/High/Medium/Low → CRITICAL/HIGH/MEDIUM/LOW; anything else →
//     INFORMATIONAL). status maps the status code (Unhealthy → ACTIVE, Healthy
//     → RESOLVED, NotApplicable → SUPPRESSED); a missing status is treated as
//     ACTIVE so a finding is never silently hidden from the "no active critical
//     findings" policies. cve_id is the first CVE in CvesDetails, cve_ids all
//     of them; remediation_available is true when a fixed version is named.
//
// A list failure (e.g. a missing-permission 403) is surfaced as an error
// (tagging only the azure.defender-bound policies `error`) rather than returning
// a partial or insecure-default result.
//
// Test injection: the API interface is the single seam and returns raw vendor
// values (SDK types; Resource Graph columns as strings) so 100% of the
// vendor→canonical mapping stays in Collect under fakeAPI unit tests; the real
// adapter (realDefender) wraps the armsecurity and Resource Graph clients.
package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armsecurity "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// vulnerabilityCategories are the Defender for Cloud recommendation categories
// whose recommendations are vulnerability findings (Microsoft's "Vulnerabilities"
// view plus missing system updates, which the grouped model also reported).
var vulnerabilityCategories = []string{
	"SoftwareUpdate", "ServiceUpgrade", "SystemUpdate",
	"CodeVulnerabilities", "IacVulnerabilities", "ApiVulnerabilities",
}

// vulnerabilityQuery reads every vulnerability recommendation in the queried
// subscriptions, projected to the Assessment columns. resourceDetails spells
// its keys differently by source (Azure: Id; connectors: ResourceId), hence the
// coalesce.
var vulnerabilityQuery = `securityresources
| where type =~ 'microsoft.security/assessments'
| extend category = tostring(properties.metadata.recommendationCategory)
| where category in~ ('` + strings.Join(vulnerabilityCategories, "', '") + `')
| project id,
    resourceId = tostring(coalesce(properties.resourceDetails.Id, properties.resourceDetails.id, properties.resourceDetails.ResourceId)),
    resourceType = tostring(coalesce(properties.resourceDetails.ResourceType, properties.resourceDetails.resourceType)),
    displayName = tostring(properties.displayName),
    severity = tostring(properties.metadata.severity),
    status = tostring(properties.status.code),
    category,
    cves = tostring(properties.additionalData.CvesDetails),
    fixedVersion = tostring(properties.additionalData.FixedVersion)`

// Assessment is one Defender for Cloud individual recommendation as the
// vulnerability query projects it: raw vendor strings, mapped in Collect.
type Assessment struct {
	ID           string
	ResourceID   string
	ResourceType string
	DisplayName  string
	Severity     string // properties.metadata.severity
	StatusCode   string // properties.status.code
	Category     string // properties.metadata.recommendationCategory
	CvesDetails  string // properties.additionalData.CvesDetails: a JSON array, as a string
	FixedVersion string // properties.additionalData.FixedVersion; empty when no fix exists
}

// Evidence type IDs this plugin emits.
const (
	EvidenceTypeThreatService   = "threat_detection_service"
	EvidenceTypeSecurityService = "security_service"
	EvidenceTypeVulnFinding     = "vulnerability_finding"
)

// SourceID is the registered ID for the azure.defender plugin instance.
const SourceID = "azure.defender"

// resourceTypeFallback is used when an affected resource's ARM type can't be
// parsed from its id or read from the recommendation (e.g. an on-premise
// resource).
const resourceTypeFallback = "azure_resource"

// providerAzure is the cloud-provider name stamped on every emitted record.
const providerAzure = "azure"

// API is the subset of the Defender for Cloud management plane this plugin uses.
// It returns raw SDK types so the vendor→canonical mapping is exercised by
// fakeAPI unit tests; the real adapter (realDefender) wraps the armsecurity
// clients.
type API interface {
	// ListPricings returns the subscription's Defender plan configurations.
	ListPricings(ctx context.Context) ([]*armsecurity.Pricing, error)
	// ListVulnerabilityAssessments returns every individual recommendation in a
	// vulnerability category in the subscription.
	ListVulnerabilityAssessments(ctx context.Context) ([]Assessment, error)
}

// Plugin is the in-process azure.defender source.
type Plugin struct {
	api            API
	subscriptionID string
	now            func() time.Time
}

// Options is the constructor input.
type Options struct {
	API            API
	SubscriptionID string
	// Now is injected so tests can produce deterministic CollectedAt values.
	// Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers using
// the real Azure SDK should use NewFromAzure.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:            opts.API,
		subscriptionID: opts.SubscriptionID,
		now:            now,
	}
}

// NewFromAzure constructs a Plugin backed by the real Azure SDK using the
// given credential (a DefaultAzureCredential) scoped to cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealDefender(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return New(Options{API: adapter, SubscriptionID: cfg.SubscriptionID}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string {
	return []string{EvidenceTypeThreatService, EvidenceTypeSecurityService, EvidenceTypeVulnFinding}
}

// Init is a no-op — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// threatServicePayload is the cross-vendor threat_detection_service shape. The
// required fields (id, name, is_enabled) are always present.
type threatServicePayload struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	IsEnabled bool   `json:"is_enabled"`
	// Auditable extras (additionalProperties): the raw tier (so the is_enabled
	// derivation is auditable) and the selected sub-plan.
	PricingTier string `json:"pricing_tier"`
	SubPlan     string `json:"sub_plan,omitempty"`
}

// securityServicePayload is the cross-vendor security_service shape.
type securityServicePayload struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	ServiceType string `json:"service_type"`
	IsEnabled   bool   `json:"is_enabled"`
	// Auditable extras (additionalProperties): how is_enabled was derived.
	EnabledPlanCount int `json:"enabled_plan_count"`
	TotalPlanCount   int `json:"total_plan_count"`
}

// vulnFindingPayload is the cross-vendor vulnerability_finding shape. The
// required fields (id, resource_id, resource_type, severity, status) are always
// emitted — the evaluator errors on a referenced-but-absent field.
type vulnFindingPayload struct {
	ID                   string `json:"id"`
	ResourceID           string `json:"resource_id"`
	ResourceType         string `json:"resource_type"`
	Title                string `json:"title,omitempty"`
	Severity             string `json:"severity"`
	Status               string `json:"status"`
	CVEID                string `json:"cve_id,omitempty"`
	RemediationAvailable bool   `json:"remediation_available"`
	// Extras (additionalProperties). A recommendation is per software package,
	// so it can carry several CVEs; cve_id holds the first.
	CVEIDs   []string `json:"cve_ids,omitempty"`
	Provider string   `json:"provider"`
	Category string   `json:"category,omitempty"`
}

// Collect dispatches on which of the three emitted types the slot accepts,
// returning the union of the requested records (each group sorted by ID, grouped
// in Emits() order). The Pricings read is shared by threat_detection_service and
// security_service so it is performed at most once.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	wantThreat := req.Accepts(EvidenceTypeThreatService)
	wantSecurity := req.Accepts(EvidenceTypeSecurityService)
	wantVuln := req.Accepts(EvidenceTypeVulnFinding)
	if !wantThreat && !wantSecurity && !wantVuln {
		return nil, fmt.Errorf("azure.defender: slot AcceptedTypes %v does not include emitted types %q, %q, %q",
			req.AcceptedTypes, EvidenceTypeThreatService, EvidenceTypeSecurityService, EvidenceTypeVulnFinding)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()

	var records []core.EvidenceRecord
	if wantThreat || wantSecurity {
		pricings, err := p.api.ListPricings(ctx)
		if err != nil {
			return nil, fmt.Errorf("azure.defender: list pricings: %w", err)
		}
		if wantThreat {
			recs, err := threatRecords(pricings, now, scope)
			if err != nil {
				return nil, err
			}
			records = append(records, recs...)
		}
		if wantSecurity {
			rec, err := securityRecord(pricings, now, scope)
			if err != nil {
				return nil, err
			}
			records = append(records, rec)
		}
	}
	if wantVuln {
		recs, err := p.collectFindings(ctx, now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, recs...)
	}
	return records, nil
}

// threatRecords maps each Defender plan to a threat_detection_service record,
// sorted by ID.
func threatRecords(pricings []*armsecurity.Pricing, now time.Time, scope *core.RecordScope) ([]core.EvidenceRecord, error) {
	records := make([]core.EvidenceRecord, 0, len(pricings))
	for _, pr := range pricings {
		if pr == nil {
			continue
		}
		name := deref(pr.Name)
		payload := threatServicePayload{
			ID:          planID(pr),
			Name:        name,
			Provider:    providerAzure,
			IsEnabled:   planEnabled(pr),
			PricingTier: pricingTier(pr),
			SubPlan:     subPlan(pr),
		}
		rec, err := record(EvidenceTypeThreatService, payload, payload.ID, now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// securityRecord emits the single Defender-for-Cloud security_service record
// (service_type "cspm"); it is enabled when any Defender plan is on Standard.
func securityRecord(pricings []*armsecurity.Pricing, now time.Time, scope *core.RecordScope) (core.EvidenceRecord, error) {
	enabled := 0
	total := 0
	for _, pr := range pricings {
		if pr == nil {
			continue
		}
		total++
		if planEnabled(pr) {
			enabled++
		}
	}
	payload := securityServicePayload{
		ID:               "azure-defender-for-cloud",
		Name:             "Microsoft Defender for Cloud",
		Provider:         providerAzure,
		ServiceType:      "cspm",
		IsEnabled:        enabled > 0,
		EnabledPlanCount: enabled,
		TotalPlanCount:   total,
	}
	return record(EvidenceTypeSecurityService, payload, payload.ID, now, scope)
}

// collectFindings lists the vulnerability recommendations and emits one
// vulnerability_finding record each, sorted by ID.
func (p *Plugin) collectFindings(ctx context.Context, now time.Time, scope *core.RecordScope) ([]core.EvidenceRecord, error) {
	found, err := p.api.ListVulnerabilityAssessments(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.defender: list vulnerability assessments: %w", err)
	}
	records := make([]core.EvidenceRecord, 0, len(found))
	for i := range found {
		a := &found[i]
		cves := cveIDs(a.CvesDetails)
		payload := vulnFindingPayload{
			ID:                   a.ID,
			ResourceID:           a.ResourceID,
			ResourceType:         resourceType(a),
			Title:                a.DisplayName,
			Severity:             mapSeverity(a.Severity),
			Status:               mapStatus(a.StatusCode),
			RemediationAvailable: strings.TrimSpace(a.FixedVersion) != "",
			CVEIDs:               cves,
			Provider:             providerAzure,
			Category:             a.Category,
		}
		if len(cves) > 0 {
			payload.CVEID = cves[0]
		}
		rec, err := record(EvidenceTypeVulnFinding, payload, payload.ID, now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// record marshals a payload into an EvidenceRecord. id is the stable sort key.
func record(typeID string, payload any, id string, now time.Time, scope *core.RecordScope) (core.EvidenceRecord, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("azure.defender: marshal %s payload for %q: %w", typeID, id, err)
	}
	return core.EvidenceRecord{
		Type:        typeID,
		ID:          id,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
		Scope:       scope,
	}, nil
}

// --- pure mapping helpers (unit-tested via table tests) ---

// planID returns a stable id for a Defender plan: its ARM id when present, else
// a synthetic id built from the plan name.
func planID(pr *armsecurity.Pricing) string {
	if id := deref(pr.ID); id != "" {
		return id
	}
	return "azure.defender/pricings/" + deref(pr.Name)
}

// planEnabled reports whether a Defender plan is on the Standard (paid) tier.
func planEnabled(pr *armsecurity.Pricing) bool {
	if pr == nil || pr.Properties == nil || pr.Properties.PricingTier == nil {
		return false
	}
	return *pr.Properties.PricingTier == armsecurity.PricingTierStandard
}

func pricingTier(pr *armsecurity.Pricing) string {
	if pr == nil || pr.Properties == nil || pr.Properties.PricingTier == nil {
		return ""
	}
	return string(*pr.Properties.PricingTier)
}

func subPlan(pr *armsecurity.Pricing) string {
	if pr == nil || pr.Properties == nil {
		return ""
	}
	return deref(pr.Properties.SubPlan)
}

// mapSeverity maps a recommendation severity to the vulnerability_finding
// enum. Anything outside Critical/High/Medium/Low maps to INFORMATIONAL.
func mapSeverity(s string) string {
	switch {
	case strings.EqualFold(s, string(armsecurity.SeverityCritical)):
		return "CRITICAL"
	case strings.EqualFold(s, string(armsecurity.SeverityHigh)):
		return "HIGH"
	case strings.EqualFold(s, string(armsecurity.SeverityMedium)):
		return "MEDIUM"
	case strings.EqualFold(s, string(armsecurity.SeverityLow)):
		return "LOW"
	default:
		return "INFORMATIONAL"
	}
}

// mapStatus maps a recommendation status code to the schema status enum. A
// missing/unknown code is treated as ACTIVE so a finding is never silently
// hidden from the "no active critical findings" policies.
func mapStatus(c string) string {
	switch {
	case strings.EqualFold(c, string(armsecurity.AssessmentStatusCodeHealthy)):
		return "RESOLVED"
	case strings.EqualFold(c, string(armsecurity.AssessmentStatusCodeNotApplicable)):
		return "SUPPRESSED"
	default:
		return "ACTIVE"
	}
}

// resourceType is the ARM type parsed from the assessed resource id (e.g.
// "Microsoft.Compute/virtualMachines"), else the type the recommendation
// names (a connector resource such as an EC2 instance has no ARM id), else a
// generic marker.
func resourceType(a *Assessment) string {
	if t := resourceTypeFromID(a.ResourceID); t != "" {
		return t
	}
	if a.ResourceType != "" {
		return a.ResourceType
	}
	return resourceTypeFallback
}

// resourceTypeFromID parses "{namespace}/{type}" out of an ARM resource id. It
// reads the segment after "providers" as the namespace and the next as the
// type. Returns "" when no providers segment is present.
func resourceTypeFromID(id string) string {
	parts := strings.Split(id, "/")
	for i := 0; i+2 < len(parts); i++ {
		if strings.EqualFold(parts[i], "providers") {
			ns, typ := parts[i+1], parts[i+2]
			if ns != "" && typ != "" {
				return ns + "/" + typ
			}
		}
	}
	return ""
}

// cveIDs returns the CVE identifiers in a CvesDetails value (a JSON array of
// {"CveId": ...} objects, as a string), in order, once each. Ids that are not
// CVEs, and a value that is not that JSON, yield nothing: the finding is still
// reported, only without CVE ids.
func cveIDs(details string) []string {
	var entries []struct {
		CveID string `json:"CveId"`
	}
	if err := json.Unmarshal([]byte(details), &entries); err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, e := range entries {
		if strings.HasPrefix(strings.ToUpper(e.CveID), "CVE-") && !seen[e.CveID] {
			seen[e.CveID] = true
			out = append(out, e.CveID)
		}
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// --- real Azure adapter ---

// realDefender is the production implementation of API. It wraps the armsecurity
// PricingsClient (Defender plans, a single subscription-scoped List) and an
// Azure Resource Graph query (vulnerability recommendations, paged).
type realDefender struct {
	pricings       *armsecurity.PricingsClient
	cred           azcore.TokenCredential
	opts           *arm.ClientOptions
	subscriptionID string
}

// newRealDefender builds the armsecurity client. opts is nil in production;
// tests pass a *arm.ClientOptions pointing the clients at an httptest server.
func newRealDefender(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realDefender, error) {
	pricings, err := armsecurity.NewPricingsClient(cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.defender: pricings client: %w", err)
	}
	return &realDefender{pricings: pricings, cred: cred, opts: opts, subscriptionID: subscriptionID}, nil
}

func (r *realDefender) scope() string {
	return "/subscriptions/" + r.subscriptionID
}

func (r *realDefender) ListPricings(ctx context.Context) ([]*armsecurity.Pricing, error) {
	resp, err := r.pricings.List(ctx, r.scope(), nil)
	if err != nil {
		return nil, err
	}
	return resp.Value, nil
}

func (r *realDefender) ListVulnerabilityAssessments(ctx context.Context) ([]Assessment, error) {
	rows, err := azcommon.QueryResourceGraphWithOptions(ctx, r.cred, r.opts, vulnerabilityQuery, []string{r.subscriptionID})
	if err != nil {
		return nil, err
	}
	out := make([]Assessment, 0, len(rows))
	for _, row := range rows {
		out = append(out, Assessment{
			ID:           column(row, "id"),
			ResourceID:   column(row, "resourceId"),
			ResourceType: column(row, "resourceType"),
			DisplayName:  column(row, "displayName"),
			Severity:     column(row, "severity"),
			StatusCode:   column(row, "status"),
			Category:     column(row, "category"),
			CvesDetails:  column(row, "cves"),
			FixedVersion: column(row, "fixedVersion"),
		})
	}
	return out, nil
}

// column reads a projected string column; the query tostring()s every column,
// so anything else (absent, null) reads as empty.
func column(row map[string]any, name string) string {
	if s, ok := row[name].(string); ok {
		return s
	}
	return ""
}

var _ core.SourcePlugin = (*Plugin)(nil)
