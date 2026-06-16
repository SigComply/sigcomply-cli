// Package network implements the gcp.network source plugin: lists VPC
// Networks in one GCP project and emits one network evidence record per
// VPC, carrying the cross-vendor flow-logging / default-network
// attributes policies evaluate — the same neutral type aws.vpc emits, so
// flow-log and default-VPC-removal policies span both clouds with zero
// changes (Invariant #4, substitutability).
//
// VPC Flow Logs in GCP are a *subnetwork* property, not a network one: a
// network spans many regional subnetworks, each with its own
// LogConfig.Enable. The network-level flow_logs_enabled bool is therefore
// aggregated conservatively — true only when the network has at least one
// subnetwork and *every* subnetwork has flow logs on. The compliance
// intent ("all network traffic is logged") makes a single un-logged
// subnet a gap, so ALL-must-be-on is the correct semantics; a network
// with no subnetworks (legacy, or custom-mode with none added) reports
// false rather than vacuously true.
//
// GCP networks are global, so there is no region field. The "default"
// network is identified by convention — a network literally named
// "default" (auto-created with new projects); GCP exposes no isDefault
// boolean.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Auth: Application Default Credentials with the read-only Compute scope.
// See docs/configuration.md §GCP. The real adapter wraps *compute.Service
// and unit tests inject an in-memory fake via the API interface seam.
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	gce "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "network"

// SourceID is the registered ID for the gcp.network plugin instance.
const SourceID = "gcp.network"

// defaultNetworkName is the name GCP gives the auto-created default VPC.
// GCP exposes no isDefault flag, so the default network is identified by
// this conventional name.
const defaultNetworkName = "default"

// API is the subset of the Compute Engine client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// GCP; the real adapter wraps *compute.Service and pages transparently.
type API interface {
	// ListNetworks returns every VPC network in the project. Networks are
	// global, so a single List call covers them all.
	ListNetworks(ctx context.Context, project string) ([]*gce.Network, error)
	// AggregatedListSubnetworks returns every subnetwork across all regions
	// in the project. Flow-logs state lives on subnetworks, so the plugin
	// reads them once and buckets by owning network.
	AggregatedListSubnetworks(ctx context.Context, project string) ([]*gce.Subnetwork, error)
}

// Plugin is the in-process gcp.network source.
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

// NewFromGCP constructs a Plugin backed by the real Compute Engine API
// using Application Default Credentials with the read-only Compute scope.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := gce.NewService(ctx, option.WithScopes(gce.ComputeReadonlyScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.network: new service: %w", err)
	}
	return New(Options{
		API:       &realNetwork{svc: svc},
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

// networkPayload is the cross-vendor network shape (see
// internal/evidence_types/schemas/network.v1.json). The four required
// fields (id, name, flow_logs_enabled, is_default) are always emitted —
// the evaluator errors on any payload that omits a field a policy clause
// references. GCP networks are global, so region is intentionally absent.
type networkPayload struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Provider        string `json:"provider"`
	FlowLogsEnabled bool   `json:"flow_logs_enabled"`
	IsDefault       bool   `json:"is_default"`
	CIDRBlock       string `json:"cidr_block,omitempty"`
	// GCP-specific extras (additionalProperties). auto_create_subnetworks
	// distinguishes auto-mode from custom-mode VPCs; is_legacy flags the
	// deprecated legacy networks (which predate flow logs and have no
	// subnetworks); subnet_count makes the flow_logs aggregation auditable
	// (0 ⇒ flow_logs_enabled is false because nothing is logged).
	AutoCreateSubnetworks bool   `json:"auto_create_subnetworks"`
	RoutingMode           string `json:"routing_mode,omitempty"`
	IsLegacy              bool   `json:"is_legacy"`
	SubnetCount           int    `json:"subnet_count"`
}

// Collect lists VPC networks in the configured project and returns one
// network record per VPC. Records are sorted by ID before return so
// envelope bytes are stable across runs against stable project state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.network: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	networks, err := p.api.ListNetworks(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.network: list networks: %w", err)
	}
	subnets, err := p.api.AggregatedListSubnetworks(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.network: list subnetworks: %w", err)
	}
	byNetwork := bucketSubnetworks(subnets)

	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(networks))
	for _, net := range networks {
		if net == nil {
			continue
		}
		payload := buildPayload(net, byNetwork[net.Name])
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.network: marshal payload: %w", err)
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

// buildPayload maps one GCP network plus its subnetworks into the
// cross-vendor network shape.
func buildPayload(net *gce.Network, subnets []*gce.Subnetwork) networkPayload {
	routingMode := ""
	if net.RoutingConfig != nil {
		routingMode = net.RoutingConfig.RoutingMode
	}
	return networkPayload{
		ID:                    net.Name,
		Name:                  net.Name,
		Provider:              "gcp",
		FlowLogsEnabled:       allSubnetsLogged(subnets),
		IsDefault:             net.Name == defaultNetworkName,
		CIDRBlock:             net.IPv4Range, // non-empty only for legacy networks; omitempty otherwise
		AutoCreateSubnetworks: net.AutoCreateSubnetworks,
		RoutingMode:           routingMode,
		IsLegacy:              net.IPv4Range != "",
		SubnetCount:           len(subnets),
	}
}

// bucketSubnetworks groups subnetworks by the short name of their owning
// network. Subnetwork.Network and Network.SelfLink are both fully
// qualified URLs whose trailing segment is the (project-unique) network
// name, so matching on the short name is robust to host-prefix differences.
func bucketSubnetworks(subnets []*gce.Subnetwork) map[string][]*gce.Subnetwork {
	out := make(map[string][]*gce.Subnetwork)
	for _, sub := range subnets {
		if sub == nil {
			continue
		}
		name := shortName(sub.Network)
		out[name] = append(out[name], sub)
	}
	return out
}

// allSubnetsLogged reports whether the network's traffic is fully logged:
// true only when there is at least one subnetwork and every subnetwork has
// flow logs enabled. A network with no subnetworks (legacy, or custom-mode
// with none added) is not vacuously compliant — nothing is being logged.
func allSubnetsLogged(subnets []*gce.Subnetwork) bool {
	if len(subnets) == 0 {
		return false
	}
	for _, sub := range subnets {
		if !subnetFlowLogsOn(sub) {
			return false
		}
	}
	return true
}

// subnetFlowLogsOn reads a subnetwork's flow-logs flag, preferring the
// modern LogConfig.Enable and falling back to the legacy EnableFlowLogs
// bool when LogConfig is absent (it does not appear in listings if never
// set).
func subnetFlowLogsOn(sub *gce.Subnetwork) bool {
	if sub.LogConfig != nil {
		return sub.LogConfig.Enable
	}
	return sub.EnableFlowLogs
}

// shortName strips the GCE URL prefix from a self-link, returning the
// trailing path segment:
//
//	"projects/p/global/networks/default" → "default".
func shortName(url string) string {
	if url == "" {
		return ""
	}
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '/' {
			return url[i+1:]
		}
	}
	return url
}

// realNetwork is the production implementation of API. It wraps
// *compute.Service and pages through the project's networks and
// subnetworks.
type realNetwork struct {
	svc *gce.Service
}

func (r *realNetwork) ListNetworks(ctx context.Context, project string) ([]*gce.Network, error) {
	var out []*gce.Network
	err := r.svc.Networks.List(project).Pages(ctx, func(page *gce.NetworkList) error {
		out = append(out, page.Items...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *realNetwork) AggregatedListSubnetworks(ctx context.Context, project string) ([]*gce.Subnetwork, error) {
	var out []*gce.Subnetwork
	err := r.svc.Subnetworks.AggregatedList(project).Pages(ctx, func(page *gce.SubnetworkAggregatedList) error {
		for _, scoped := range page.Items {
			out = append(out, scoped.Subnetworks...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
