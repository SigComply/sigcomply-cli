// Package network implements the azure.network source plugin: it reads Azure
// Network Security Groups and Virtual Networks in a subscription and emits two
// cross-vendor types — firewall_rule (one per NSG rule, flattened) and network
// (one per VNet) — so network-exposure and flow-logging policies evaluate
// against Azure exactly as they do against AWS (security groups + VPCs) and GCP
// (firewall rules + VPC networks) — zero policy changes (Invariant #4).
//
// firewall_rule (from NSGs):
//
//   - Only **Allow** custom rules are emitted. An NSG Deny rule is the opposite
//     of an exposure, and the unrestricted-SSH / all-traffic policies do not
//     filter on action — so emitting a Deny rule open to "*"/Internet would
//     false-fail those policies. Azure estates routinely carry explicit Deny
//     rules (unlike GCP, which relies on implied deny), so this filter is
//     load-bearing for correctness, not cosmetic. The platform
//     DefaultSecurityRules are also excluded (they are not customer config).
//   - Each rule is flattened to one record per destination port range (the
//     NSG's filtered service port), mirroring the AWS/GCP flatteners. The
//     all-ports value "*" maps to the (-1, -1) sentinel.
//   - is_unrestricted_ipv4/_ipv6 are computed from the direction-relevant
//     address prefixes; the NSG values that mean "open to the internet" are
//     "*", "0.0.0.0/0" (v4) / "::/0" (v6), the "Internet" service tag, and
//     "Any". Both the singular and plural prefix fields are checked.
//
// network (from VNets):
//
//   - is_default is **always false** — Azure has no provider-created default
//     VNet concept (unlike an AWS default VPC), so the no-default-network policy
//     is vacuously satisfied for Azure.
//   - flow_logs_enabled reflects **VNet flow logs** (the modern signal that
//     supersedes NSG flow logs): true when an inline FlowLog on the VNet is
//     enabled. NSG-flow-log-only setups (the legacy model) are a documented v1
//     gap and read false (a conservative mapping — absence is treated as "not
//     enabled" rather than guessed true).
//
// A list failure (e.g. a missing-permission 403) is surfaced as an error
// (tagging only the azure.network-bound policies `error`) rather than returning
// a partial or insecure-default result.
//
// Test injection: the API interface is the single seam and returns raw SDK
// types so 100% of the vendor→canonical mapping stays in Collect under fakeAPI
// unit tests; the real adapter (realNetwork) wraps the armnetwork SDK clients.
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v9"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// Evidence type IDs this plugin emits.
const (
	EvidenceTypeFirewallRule = "firewall_rule"
	EvidenceTypeNetwork      = "network"
)

// SourceID is the registered ID for the azure.network plugin instance.
const SourceID = "azure.network"

// allPortsSentinel is the firewall_rule schema's "all ports" marker.
const allPortsSentinel = -1

// Traffic directions in the firewall_rule schema's vocabulary.
const (
	directionIngress = "ingress"
	directionEgress  = "egress"
)

// API is the subset of the Azure network management plane this plugin uses. It
// returns raw SDK types so the vendor→canonical mapping is exercised by fakeAPI
// unit tests; the real adapter (realNetwork) wraps the armnetwork clients.
type API interface {
	// ListSecurityGroups returns every NSG in the subscription.
	ListSecurityGroups(ctx context.Context) ([]*armnetwork.SecurityGroup, error)
	// ListVirtualNetworks returns every VNet in the subscription.
	ListVirtualNetworks(ctx context.Context) ([]*armnetwork.VirtualNetwork, error)
}

// Plugin is the in-process azure.network source.
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

// NewFromAzure constructs a Plugin backed by the real armnetwork SDK using the
// given credential (a DefaultAzureCredential) scoped to cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealNetwork(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return New(Options{API: adapter, SubscriptionID: cfg.SubscriptionID}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeFirewallRule, EvidenceTypeNetwork} }

// Init is a no-op — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// rulePayload is the firewall_rule shape this plugin emits. The required fields
// (id, name, direction, protocol, from_port, to_port, is_unrestricted_ipv4/_ipv6)
// are always present; source/dest CIDR + the Azure priority extra carry context.
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

	// Auditable Azure extras (additionalProperties).
	Access   string `json:"access,omitempty"`
	Priority int32  `json:"priority,omitempty"`
}

// networkPayload is the network shape this plugin emits. id, name,
// flow_logs_enabled, and is_default are always present.
type networkPayload struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Provider        string `json:"provider"`
	Region          string `json:"region,omitempty"`
	FlowLogsEnabled bool   `json:"flow_logs_enabled"`
	IsDefault       bool   `json:"is_default"`
	CIDRBlock       string `json:"cidr_block,omitempty"`

	// Auditable Azure extra (additionalProperties).
	SubnetCount int `json:"subnet_count"`
}

// Collect emits firewall_rule records (from NSGs) and/or network records (from
// VNets), per the slot's accepted types, grouped in Emits() order and each
// group sorted by ID so envelope bytes are stable across runs.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	wantFW := req.Accepts(EvidenceTypeFirewallRule)
	wantNet := req.Accepts(EvidenceTypeNetwork)
	if !wantFW && !wantNet {
		return nil, fmt.Errorf("azure.network: slot AcceptedTypes %v does not include emitted types %q, %q",
			req.AcceptedTypes, EvidenceTypeFirewallRule, EvidenceTypeNetwork)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()

	var records []core.EvidenceRecord
	if wantFW {
		fwRecs, err := p.collectFirewallRules(ctx, now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, fwRecs...)
	}
	if wantNet {
		netRecs, err := p.collectNetworks(ctx, now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, netRecs...)
	}
	return records, nil
}

// collectFirewallRules lists NSGs and flattens their Allow custom rules into
// firewall_rule records, sorted by ID.
func (p *Plugin) collectFirewallRules(ctx context.Context, now time.Time, scope *core.RecordScope) ([]core.EvidenceRecord, error) {
	nsgs, err := p.api.ListSecurityGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.network: list security groups: %w", err)
	}
	var records []core.EvidenceRecord
	for _, nsg := range nsgs {
		if nsg == nil || nsg.Properties == nil {
			continue
		}
		nsgName := deref(nsg.Name)
		rg, err := resourceGroupFromID(deref(nsg.ID))
		if err != nil {
			return nil, fmt.Errorf("azure.network: NSG %q: %w", nsgName, err)
		}
		index := 0
		for _, rule := range nsg.Properties.SecurityRules {
			if rule == nil || rule.Properties == nil {
				continue
			}
			rp := rule.Properties
			if rp.Access == nil || *rp.Access != armnetwork.SecurityRuleAccessAllow {
				continue // only Allow rules are firewall exposures
			}
			direction := mapDirection(rp.Direction)
			prefixes := directionPrefixes(rp, direction)
			v4, v6 := unrestricted(prefixes)
			firstCIDR := firstPrefix(prefixes)
			for _, pr := range destinationPortRanges(rp) {
				from, to := parsePortRange(pr)
				payload := rulePayload{
					ID:                 fmt.Sprintf("%s/%s:%s:%d", rg, nsgName, direction, index),
					Name:               fmt.Sprintf("%s %s rule", nsgName, direction),
					Provider:           "azure",
					GroupID:            nsgName,
					Direction:          direction,
					Protocol:           mapProtocol(rp.Protocol),
					FromPort:           from,
					ToPort:             to,
					IsUnrestrictedIPv4: v4,
					IsUnrestrictedIPv6: v6,
					Access:             "allow",
					Priority:           derefInt32(rp.Priority),
				}
				if direction == directionEgress {
					payload.DestCIDR = firstCIDR
				} else {
					payload.SourceCIDR = firstCIDR
				}
				rec, err := record(EvidenceTypeFirewallRule, payload, payload.ID, now, scope)
				if err != nil {
					return nil, err
				}
				records = append(records, rec)
				index++
			}
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// collectNetworks lists VNets and emits one network record each, sorted by ID.
func (p *Plugin) collectNetworks(ctx context.Context, now time.Time, scope *core.RecordScope) ([]core.EvidenceRecord, error) {
	vnets, err := p.api.ListVirtualNetworks(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.network: list virtual networks: %w", err)
	}
	records := make([]core.EvidenceRecord, 0, len(vnets))
	for _, vnet := range vnets {
		if vnet == nil {
			continue
		}
		payload := networkPayload{
			ID:              deref(vnet.ID),
			Name:            deref(vnet.Name),
			Provider:        "azure",
			Region:          deref(vnet.Location),
			FlowLogsEnabled: vnetFlowLogsEnabled(vnet),
			IsDefault:       false, // Azure has no default-VNet concept.
			CIDRBlock:       firstAddressPrefix(vnet),
			SubnetCount:     subnetCount(vnet),
		}
		rec, err := record(EvidenceTypeNetwork, payload, payload.ID, now, scope)
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
		return core.EvidenceRecord{}, fmt.Errorf("azure.network: marshal %s payload for %q: %w", typeID, id, err)
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

// resourceGroupFromID extracts the resource group from an ARM resource id,
// case-insensitively (ARM sometimes returns "resourcegroups").
func resourceGroupFromID(id string) (string, error) {
	parts := strings.Split(id, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			if rg := parts[i+1]; rg != "" {
				return rg, nil
			}
		}
	}
	return "", fmt.Errorf("no resourceGroups segment in id %q", id)
}

func mapDirection(d *armnetwork.SecurityRuleDirection) string {
	if d != nil && *d == armnetwork.SecurityRuleDirectionOutbound {
		return directionEgress
	}
	return directionIngress
}

// mapProtocol maps an NSG protocol to the firewall_rule enum (tcp/udp/icmp/all).
func mapProtocol(p *armnetwork.SecurityRuleProtocol) string {
	if p == nil {
		return "all"
	}
	switch *p {
	case armnetwork.SecurityRuleProtocolAsterisk:
		return "all"
	case armnetwork.SecurityRuleProtocolTCP:
		return "tcp"
	case armnetwork.SecurityRuleProtocolUDP:
		return "udp"
	case armnetwork.SecurityRuleProtocolIcmp:
		return "icmp"
	default:
		return strings.ToLower(string(*p))
	}
}

// directionPrefixes returns the address prefixes that govern who the rule opens
// traffic to/from: source prefixes for ingress, destination prefixes for egress.
// Both the singular and plural NSG fields are merged.
func directionPrefixes(rp *armnetwork.SecurityRulePropertiesFormat, direction string) []string {
	if direction == directionEgress {
		return mergePrefixes(rp.DestinationAddressPrefix, rp.DestinationAddressPrefixes)
	}
	return mergePrefixes(rp.SourceAddressPrefix, rp.SourceAddressPrefixes)
}

func mergePrefixes(single *string, multi []*string) []string {
	out := make([]string, 0, len(multi)+1)
	if s := deref(single); s != "" {
		out = append(out, s)
	}
	for _, m := range multi {
		if s := deref(m); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// unrestricted reports whether the prefix set opens the rule to all IPv4 / all
// IPv6. "*", "Internet", and "Any" open both families; "0.0.0.0/0" is v4-only
// and "::/0" is v6-only.
func unrestricted(prefixes []string) (v4, v6 bool) {
	for _, p := range prefixes {
		switch p {
		case "*", "Internet", "Any":
			v4, v6 = true, true
		case "0.0.0.0/0":
			v4 = true
		case "::/0":
			v6 = true
		}
	}
	return v4, v6
}

// firstPrefix returns a representative CIDR for the rule, or "" when none.
func firstPrefix(prefixes []string) string {
	if len(prefixes) == 0 {
		return ""
	}
	return prefixes[0]
}

// destinationPortRanges returns the rule's destination port range strings
// (the merged singular + plural fields); an empty set yields one "*" entry so
// every rule produces at least one record (all-ports).
func destinationPortRanges(rp *armnetwork.SecurityRulePropertiesFormat) []string {
	ranges := make([]string, 0, len(rp.DestinationPortRanges)+1)
	if s := deref(rp.DestinationPortRange); s != "" {
		ranges = append(ranges, s)
	}
	for _, m := range rp.DestinationPortRanges {
		if s := deref(m); s != "" {
			ranges = append(ranges, s)
		}
	}
	if len(ranges) == 0 {
		return []string{"*"}
	}
	return ranges
}

// parsePortRange maps an NSG port string to a [from, to] pair. "*" or
// unparseable → the all-ports sentinel (-1, -1); "22" → (22, 22); "80-443" →
// (80, 443).
func parsePortRange(s string) (from, to int) {
	if s == "" || s == "*" {
		return allPortsSentinel, allPortsSentinel
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		f, errF := strconv.Atoi(strings.TrimSpace(s[:i]))
		t, errT := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if errF != nil || errT != nil {
			return allPortsSentinel, allPortsSentinel
		}
		return f, t
	}
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return allPortsSentinel, allPortsSentinel
	}
	return port, port
}

// vnetFlowLogsEnabled reports whether an inline VNet flow log is enabled.
func vnetFlowLogsEnabled(vnet *armnetwork.VirtualNetwork) bool {
	if vnet == nil || vnet.Properties == nil {
		return false
	}
	for _, fl := range vnet.Properties.FlowLogs {
		if fl != nil && fl.Properties != nil && fl.Properties.Enabled != nil && *fl.Properties.Enabled {
			return true
		}
	}
	return false
}

func firstAddressPrefix(vnet *armnetwork.VirtualNetwork) string {
	if vnet == nil || vnet.Properties == nil || vnet.Properties.AddressSpace == nil {
		return ""
	}
	for _, p := range vnet.Properties.AddressSpace.AddressPrefixes {
		if s := deref(p); s != "" {
			return s
		}
	}
	return ""
}

func subnetCount(vnet *armnetwork.VirtualNetwork) int {
	if vnet == nil || vnet.Properties == nil {
		return 0
	}
	return len(vnet.Properties.Subnets)
}

func derefInt32(i *int32) int32 {
	if i == nil {
		return 0
	}
	return *i
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// --- real Azure adapter ---

// realNetwork is the production implementation of API. It wraps the armnetwork
// SecurityGroupsClient (NSGs) and VirtualNetworksClient (VNets), both listed
// subscription-wide.
type realNetwork struct {
	nsgs  *armnetwork.SecurityGroupsClient
	vnets *armnetwork.VirtualNetworksClient
}

// newRealNetwork builds the armnetwork clients. opts is nil in production; tests
// pass a *arm.ClientOptions pointing the clients at an httptest server.
func newRealNetwork(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realNetwork, error) {
	nsgs, err := armnetwork.NewSecurityGroupsClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.network: security groups client: %w", err)
	}
	vnets, err := armnetwork.NewVirtualNetworksClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.network: virtual networks client: %w", err)
	}
	return &realNetwork{nsgs: nsgs, vnets: vnets}, nil
}

func (r *realNetwork) ListSecurityGroups(ctx context.Context) ([]*armnetwork.SecurityGroup, error) {
	var out []*armnetwork.SecurityGroup
	pager := r.nsgs.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realNetwork) ListVirtualNetworks(ctx context.Context) ([]*armnetwork.VirtualNetwork, error) {
	var out []*armnetwork.VirtualNetwork
	pager := r.vnets.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
