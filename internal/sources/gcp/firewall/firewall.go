// Package firewall implements the gcp.firewall source plugin: lists VPC
// firewall rules in one GCP project and emits one firewall_rule evidence
// record per protocol/port-range within each firewall, carrying the
// cross-vendor direction / protocol / port-range / unrestricted-source
// attributes that network-exposure policies evaluate — the same neutral
// type aws.security_group emits, so those policies span both clouds with
// zero changes (Invariant #4, substitutability).
//
// A single GCP firewall can carry several allowed/denied protocol entries,
// each with several port ranges; the firewall_rule schema is one rule =
// one protocol + one port range, so each firewall is flattened into one
// record per (protocol, port-range) — mirroring how aws.security_group
// flattens an IpPermission set.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Auth: Application Default Credentials with the read-only Compute scope.
// See docs/configuration.md §GCP. The real adapter wraps *compute.Service
// and unit tests inject an in-memory fake via the API interface seam.
package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	gce "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "firewall_rule"

// SourceID is the registered ID for the gcp.firewall plugin instance.
const SourceID = "gcp.firewall"

// allPortsSentinel is the cross-vendor convention for "all ports" — a
// GCP rule with no port list means every port for that protocol; policies
// detect this by matching from_port == -1 (matches aws.security_group).
const allPortsSentinel = -1

// Cross-vendor lowercase direction values emitted in the payload.
const (
	directionIngress = "ingress"
	directionEgress  = "egress"
)

// API is the subset of the Compute Engine client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// GCP; the real adapter wraps *compute.Service and pages transparently.
type API interface {
	// ListFirewalls returns every firewall rule in the project. Firewalls
	// are VPC-global, so a single List call covers them all (no zonal or
	// regional aggregation needed, unlike instances).
	ListFirewalls(ctx context.Context, project string) ([]*gce.Firewall, error)
}

// Plugin is the in-process gcp.firewall source.
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
		return nil, fmt.Errorf("gcp.firewall: new service: %w", err)
	}
	return New(Options{
		API:       &realFirewall{svc: svc},
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

// rulePayload is the cross-vendor firewall_rule shape. Every required
// field is always emitted (never omitempty): the evaluator errors on any
// payload that omits a field a policy clause references, and the network
// clauses read direction/protocol/from_port/to_port/is_unrestricted_ipv4.
type rulePayload struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Provider           string `json:"provider"`
	GroupID            string `json:"group_id"`
	Direction          string `json:"direction"`
	Protocol           string `json:"protocol"`
	FromPort           int    `json:"from_port"`
	ToPort             int    `json:"to_port"`
	IsUnrestrictedIPv4 bool   `json:"is_unrestricted_ipv4"`
	IsUnrestrictedIPv6 bool   `json:"is_unrestricted_ipv6"`
	SourceCIDR         string `json:"source_cidr,omitempty"`
	DestCIDR           string `json:"dest_cidr,omitempty"`
	// GCP-specific extras (additionalProperties). action distinguishes
	// allow vs deny — GCP supports deny rules, which AWS security groups
	// do not; a firewall populates either Allowed or Denied, never both.
	Action   string `json:"action,omitempty"`
	Network  string `json:"network,omitempty"`
	Priority int64  `json:"priority,omitempty"`
	Disabled bool   `json:"disabled"`
}

// protoPort is the normalized (protocol, ports) shape shared by the
// Allowed and Denied lists, which are distinct SDK types with the same
// fields. Flattening through it keeps the allow/deny paths identical.
type protoPort struct {
	protocol string
	ports    []string
}

// Collect lists firewalls in the configured project and returns one
// firewall_rule record per (protocol, port-range). Records are sorted by
// ID before return so envelope bytes are stable across runs against
// stable project state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.firewall: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	firewalls, err := p.api.ListFirewalls(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.firewall: list firewalls: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(firewalls))
	for _, fw := range firewalls {
		if fw == nil {
			continue
		}
		rules := flattenFirewall(fw)
		for i := range rules {
			payload := &rules[i]
			body, err := json.Marshal(payload)
			if err != nil {
				return nil, fmt.Errorf("gcp.firewall: marshal payload: %w", err)
			}
			records = append(records, core.EvidenceRecord{
				Type:        EvidenceTypeID,
				ID:          payload.ID,
				Payload:     body,
				SourceID:    SourceID,
				CollectedAt: now,
			})
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// flattenFirewall expands one GCP firewall into one rulePayload per
// (protocol, port-range). An empty port list means "all ports" for that
// protocol (from_port/to_port == -1), matching the cross-vendor sentinel.
func flattenFirewall(fw *gce.Firewall) []rulePayload {
	direction := normalizeDirection(fw.Direction)
	action, entries := actionAndEntries(fw)

	// Unrestricted-source / first-CIDR are read from the range list
	// relevant to the rule's direction: SourceRanges for ingress,
	// DestinationRanges for egress.
	ranges := fw.SourceRanges
	if direction == directionEgress {
		ranges = fw.DestinationRanges
	}
	unrestrictedV4 := containsCIDR(ranges, "0.0.0.0/0")
	unrestrictedV6 := containsCIDR(ranges, "::/0")
	firstCIDR := ""
	if len(ranges) > 0 {
		firstCIDR = ranges[0]
	}

	out := make([]rulePayload, 0, len(entries))
	index := 0
	for _, pp := range entries {
		protocol := strings.ToLower(pp.protocol)
		portStrings := pp.ports
		if len(portStrings) == 0 {
			// No ports listed → all ports for this protocol.
			portStrings = []string{""}
		}
		for _, ps := range portStrings {
			from, to := parsePortRange(ps)
			payload := rulePayload{
				ID:                 fmt.Sprintf("%s:%s:%d", fw.Name, direction, index),
				Name:               fmt.Sprintf("%s %s rule", fw.Name, direction),
				Provider:           "gcp",
				GroupID:            fw.Name,
				Direction:          direction,
				Protocol:           protocol,
				FromPort:           from,
				ToPort:             to,
				IsUnrestrictedIPv4: unrestrictedV4,
				IsUnrestrictedIPv6: unrestrictedV6,
				Action:             action,
				Network:            shortName(fw.Network),
				Priority:           fw.Priority,
				Disabled:           fw.Disabled,
			}
			if direction == directionEgress {
				payload.DestCIDR = firstCIDR
			} else {
				payload.SourceCIDR = firstCIDR
			}
			out = append(out, payload)
			index++
		}
	}
	return out
}

// actionAndEntries reports whether the firewall allows or denies traffic
// and returns its protocol/port entries normalized to protoPort. A GCP
// firewall populates either Allowed or Denied, never both.
func actionAndEntries(fw *gce.Firewall) (string, []protoPort) {
	if len(fw.Denied) > 0 {
		entries := make([]protoPort, 0, len(fw.Denied))
		for _, d := range fw.Denied {
			if d == nil {
				continue
			}
			entries = append(entries, protoPort{protocol: d.IPProtocol, ports: d.Ports})
		}
		return "deny", entries
	}
	entries := make([]protoPort, 0, len(fw.Allowed))
	for _, a := range fw.Allowed {
		if a == nil {
			continue
		}
		entries = append(entries, protoPort{protocol: a.IPProtocol, ports: a.Ports})
	}
	return "allow", entries
}

// normalizeDirection maps GCP's INGRESS/EGRESS to the cross-vendor
// lowercase form. GCP defaults to INGRESS when the field is empty.
func normalizeDirection(d string) string {
	if strings.EqualFold(d, "EGRESS") {
		return directionEgress
	}
	return directionIngress
}

// parsePortRange maps a GCP port string to a [from, to] pair. "22" →
// (22, 22); "80-443" → (80, 443); "" or unparseable → the all-ports
// sentinel (-1, -1).
func parsePortRange(s string) (from, to int) {
	if s == "" {
		return allPortsSentinel, allPortsSentinel
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		from, errF := strconv.Atoi(s[:i])
		to, errT := strconv.Atoi(s[i+1:])
		if errF != nil || errT != nil {
			return allPortsSentinel, allPortsSentinel
		}
		return from, to
	}
	port, err := strconv.Atoi(s)
	if err != nil {
		return allPortsSentinel, allPortsSentinel
	}
	return port, port
}

func containsCIDR(ranges []string, want string) bool {
	for _, r := range ranges {
		if r == want {
			return true
		}
	}
	return false
}

// shortName strips the GCE URL prefix from a network URL:
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

// realFirewall is the production implementation of API. It wraps
// *compute.Service and pages through the project's firewall list.
type realFirewall struct {
	svc *gce.Service
}

func (r *realFirewall) ListFirewalls(ctx context.Context, project string) ([]*gce.Firewall, error) {
	var out []*gce.Firewall
	err := r.svc.Firewalls.List(project).Pages(ctx, func(page *gce.FirewallList) error {
		out = append(out, page.Items...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
