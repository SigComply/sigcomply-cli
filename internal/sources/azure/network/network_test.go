package network

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v9"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

var fixedNow = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

// allProto is the firewall_rule "all protocols" value, asserted in several tests.
const allProto = "all"

func mustUnmarshal(t *testing.T, raw json.RawMessage, dst any) {
	t.Helper()
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

type fakeAPI struct {
	nsgs      []*armnetwork.SecurityGroup
	vnets     []*armnetwork.VirtualNetwork
	nsgErr    error
	vnetErr   error
	nsgCalls  int
	vnetCalls int
}

func (f *fakeAPI) ListSecurityGroups(context.Context) ([]*armnetwork.SecurityGroup, error) {
	f.nsgCalls++
	if f.nsgErr != nil {
		return nil, f.nsgErr
	}
	return f.nsgs, nil
}

func (f *fakeAPI) ListVirtualNetworks(context.Context) ([]*armnetwork.VirtualNetwork, error) {
	f.vnetCalls++
	if f.vnetErr != nil {
		return nil, f.vnetErr
	}
	return f.vnets, nil
}

func bothReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeFirewallRule, EvidenceTypeNetwork}}
}

func nsgID(rg, name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/" + rg + "/providers/Microsoft.Network/networkSecurityGroups/" + name)
}

func vnetID(rg, name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/" + rg + "/providers/Microsoft.Network/virtualNetworks/" + name)
}

// allowRule builds an Allow security rule. The address prefix is placed on the
// direction-appropriate field (source for inbound, destination for outbound),
// matching how the plugin reads "who the rule opens traffic to/from".
func allowRule(name string, dir armnetwork.SecurityRuleDirection, proto armnetwork.SecurityRuleProtocol, port, prefix string, priority int32) *armnetwork.SecurityRule {
	props := &armnetwork.SecurityRulePropertiesFormat{
		Access:               to.Ptr(armnetwork.SecurityRuleAccessAllow),
		Direction:            to.Ptr(dir),
		Protocol:             to.Ptr(proto),
		Priority:             to.Ptr(priority),
		DestinationPortRange: to.Ptr(port),
	}
	if dir == armnetwork.SecurityRuleDirectionOutbound {
		props.DestinationAddressPrefix = to.Ptr(prefix)
	} else {
		props.SourceAddressPrefix = to.Ptr(prefix)
	}
	return &armnetwork.SecurityRule{Name: to.Ptr(name), Properties: props}
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if got := p.ID(); got != "azure.network" {
		t.Errorf("ID() = %q, want azure.network", got)
	}
	got := p.Emits()
	if len(got) != 2 || got[0] != EvidenceTypeFirewallRule || got[1] != EvidenceTypeNetwork {
		t.Errorf("Emits() = %v, want [firewall_rule network]", got)
	}
}

func TestCollect_RejectsWhenNoEmittedTypeAccepted(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "emitted types") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestCollect_BothTypes_MapsSortsAndFullPayload(t *testing.T) {
	f := &fakeAPI{
		nsgs: []*armnetwork.SecurityGroup{{
			Name: to.Ptr("web-nsg"),
			ID:   nsgID("rg-net", "web-nsg"),
			Properties: &armnetwork.SecurityGroupPropertiesFormat{
				SecurityRules: []*armnetwork.SecurityRule{
					allowRule("ssh", armnetwork.SecurityRuleDirectionInbound, armnetwork.SecurityRuleProtocolTCP, "22", "*", 100),
					// Deny rule must be skipped.
					{Name: to.Ptr("deny-all"), Properties: &armnetwork.SecurityRulePropertiesFormat{
						Access:               to.Ptr(armnetwork.SecurityRuleAccessDeny),
						Direction:            to.Ptr(armnetwork.SecurityRuleDirectionInbound),
						Protocol:             to.Ptr(armnetwork.SecurityRuleProtocolAsterisk),
						DestinationPortRange: to.Ptr("*"),
						SourceAddressPrefix:  to.Ptr("*"),
					}},
				},
			},
		}},
		vnets: []*armnetwork.VirtualNetwork{{
			Name:     to.Ptr("prod-vnet"),
			ID:       vnetID("rg-net", "prod-vnet"),
			Location: to.Ptr("eastus"),
			Properties: &armnetwork.VirtualNetworkPropertiesFormat{
				AddressSpace: &armnetwork.AddressSpace{AddressPrefixes: []*string{to.Ptr("10.0.0.0/16")}},
				Subnets:      []*armnetwork.Subnet{{Name: to.Ptr("default")}},
				FlowLogs:     []*armnetwork.FlowLog{{Properties: &armnetwork.FlowLogPropertiesFormat{Enabled: to.Ptr(true)}}},
			},
		}},
	}
	p := New(Options{API: f, SubscriptionID: "sub-1", Now: func() time.Time { return fixedNow }})

	recs, err := p.Collect(context.Background(), bothReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (one Allow rule + one VNet; Deny skipped)", len(recs))
	}
	// firewall_rule group comes first (Emits() order), then network.
	if recs[0].Type != EvidenceTypeFirewallRule || recs[1].Type != EvidenceTypeNetwork {
		t.Fatalf("type order wrong: %s, %s", recs[0].Type, recs[1].Type)
	}
	for _, r := range recs {
		if r.SourceID != SourceID || !r.CollectedAt.Equal(fixedNow) {
			t.Errorf("record %s: SourceID/CollectedAt = %s/%v", r.ID, r.SourceID, r.CollectedAt)
		}
		if r.Scope == nil || r.Scope.Account != "sub-1" {
			t.Errorf("record %s: scope = %+v", r.ID, r.Scope)
		}
		if r.IdentityKey != "" {
			t.Errorf("record %s: unexpected IdentityKey %q", r.ID, r.IdentityKey)
		}
	}

	var gotRule rulePayload
	if err := json.Unmarshal(recs[0].Payload, &gotRule); err != nil {
		t.Fatalf("unmarshal rule: %v", err)
	}
	wantRule := rulePayload{
		ID:                 "rg-net/web-nsg:ingress:0",
		Name:               "web-nsg ingress rule",
		Provider:           "azure",
		GroupID:            "web-nsg",
		Direction:          "ingress",
		Protocol:           "tcp",
		FromPort:           22,
		ToPort:             22,
		IsUnrestrictedIPv4: true,
		IsUnrestrictedIPv6: true,
		SourceCIDR:         "*",
		Access:             "allow",
		Priority:           100,
	}
	if !reflect.DeepEqual(gotRule, wantRule) {
		t.Errorf("rule payload mismatch:\n got  %+v\n want %+v", gotRule, wantRule)
	}

	var gotNet networkPayload
	if err := json.Unmarshal(recs[1].Payload, &gotNet); err != nil {
		t.Fatalf("unmarshal network: %v", err)
	}
	wantNet := networkPayload{
		ID:              *vnetID("rg-net", "prod-vnet"),
		Name:            "prod-vnet",
		Provider:        "azure",
		Region:          "eastus",
		FlowLogsEnabled: true,
		IsDefault:       false,
		CIDRBlock:       "10.0.0.0/16",
		SubnetCount:     1,
	}
	if !reflect.DeepEqual(gotNet, wantNet) {
		t.Errorf("network payload mismatch:\n got  %+v\n want %+v", gotNet, wantNet)
	}
}

func TestCollect_OnlyFirewall_SkipsVNetList(t *testing.T) {
	f := &fakeAPI{
		nsgs: []*armnetwork.SecurityGroup{{
			Name:       to.Ptr("n"),
			ID:         nsgID("rg", "n"),
			Properties: &armnetwork.SecurityGroupPropertiesFormat{SecurityRules: []*armnetwork.SecurityRule{allowRule("r", armnetwork.SecurityRuleDirectionInbound, armnetwork.SecurityRuleProtocolTCP, "443", "10.0.0.0/8", 100)}},
		}},
	}
	recs, err := New(Options{API: f}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeFirewallRule}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 || recs[0].Type != EvidenceTypeFirewallRule {
		t.Fatalf("expected one firewall_rule record, got %+v", recs)
	}
	if f.vnetCalls != 0 {
		t.Errorf("VNet list should not be called when only firewall_rule is requested, got %d", f.vnetCalls)
	}
	// A restricted source should not be flagged unrestricted.
	var got rulePayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.IsUnrestrictedIPv4 || got.IsUnrestrictedIPv6 {
		t.Errorf("10.0.0.0/8 source should not be unrestricted, got %+v", got)
	}
}

func TestCollect_OnlyNetwork_SkipsNSGList(t *testing.T) {
	f := &fakeAPI{vnets: []*armnetwork.VirtualNetwork{{Name: to.Ptr("v"), ID: vnetID("rg", "v"), Properties: &armnetwork.VirtualNetworkPropertiesFormat{}}}}
	recs, err := New(Options{API: f}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeNetwork}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 || recs[0].Type != EvidenceTypeNetwork {
		t.Fatalf("expected one network record, got %+v", recs)
	}
	if f.nsgCalls != 0 {
		t.Errorf("NSG list should not be called when only network is requested, got %d", f.nsgCalls)
	}
	// No flow logs → flow_logs_enabled false (conservative).
	var got networkPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.FlowLogsEnabled {
		t.Errorf("absent flow logs should be false, got %+v", got)
	}
}

func TestCollect_MultiPortRange_FlattensAndSorts(t *testing.T) {
	rule := &armnetwork.SecurityRule{
		Name: to.Ptr("multi"),
		Properties: &armnetwork.SecurityRulePropertiesFormat{
			Access:                to.Ptr(armnetwork.SecurityRuleAccessAllow),
			Direction:             to.Ptr(armnetwork.SecurityRuleDirectionInbound),
			Protocol:              to.Ptr(armnetwork.SecurityRuleProtocolAsterisk),
			DestinationPortRanges: []*string{to.Ptr("80"), to.Ptr("443-444")},
			SourceAddressPrefix:   to.Ptr("Internet"),
		},
	}
	f := &fakeAPI{nsgs: []*armnetwork.SecurityGroup{{Name: to.Ptr("nsg"), ID: nsgID("rg", "nsg"), Properties: &armnetwork.SecurityGroupPropertiesFormat{SecurityRules: []*armnetwork.SecurityRule{rule}}}}}
	recs, err := New(Options{API: f}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeFirewallRule}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 flattened records (one per port range), got %d", len(recs))
	}
	if recs[0].ID != "rg/nsg:ingress:0" || recs[1].ID != "rg/nsg:ingress:1" {
		t.Fatalf("unexpected flattened IDs: %s, %s", recs[0].ID, recs[1].ID)
	}
	var r0, r1 rulePayload
	mustUnmarshal(t, recs[0].Payload, &r0)
	mustUnmarshal(t, recs[1].Payload, &r1)
	if r0.Protocol != allProto || r0.FromPort != 80 || r0.ToPort != 80 || !r0.IsUnrestrictedIPv4 {
		t.Errorf("record 0 = %+v", r0)
	}
	if r1.FromPort != 443 || r1.ToPort != 444 {
		t.Errorf("record 1 ports = (%d,%d), want (443,444)", r1.FromPort, r1.ToPort)
	}
}

func TestCollect_EgressRule_SetsDestCIDR(t *testing.T) {
	f := &fakeAPI{nsgs: []*armnetwork.SecurityGroup{{
		Name:       to.Ptr("eg-nsg"),
		ID:         nsgID("rg", "eg-nsg"),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{SecurityRules: []*armnetwork.SecurityRule{allowRule("out", armnetwork.SecurityRuleDirectionOutbound, armnetwork.SecurityRuleProtocolUDP, "53", "0.0.0.0/0", 200)}},
	}}}
	recs, err := New(Options{API: f}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeFirewallRule}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got rulePayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.Direction != "egress" {
		t.Errorf("direction = %q, want egress", got.Direction)
	}
	if got.DestCIDR != "0.0.0.0/0" || got.SourceCIDR != "" {
		t.Errorf("egress rule should set dest_cidr (not source_cidr), got %+v", got)
	}
	if !got.IsUnrestrictedIPv4 || got.IsUnrestrictedIPv6 {
		t.Errorf("0.0.0.0/0 should be v4-unrestricted only, got v4=%v v6=%v", got.IsUnrestrictedIPv4, got.IsUnrestrictedIPv6)
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{
		nsgs: []*armnetwork.SecurityGroup{
			nil,
			{Name: to.Ptr("no-props"), ID: nsgID("rg", "no-props")}, // nil Properties
			{Name: to.Ptr("n"), ID: nsgID("rg", "n"), Properties: &armnetwork.SecurityGroupPropertiesFormat{SecurityRules: []*armnetwork.SecurityRule{nil, allowRule("r", armnetwork.SecurityRuleDirectionInbound, armnetwork.SecurityRuleProtocolTCP, "22", "10.0.0.0/8", 100)}}},
		},
		vnets: []*armnetwork.VirtualNetwork{nil, {Name: to.Ptr("v"), ID: vnetID("rg", "v"), Properties: &armnetwork.VirtualNetworkPropertiesFormat{}}},
	}
	recs, err := New(Options{API: f}).Collect(context.Background(), bothReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 1 rule + 1 network, got %d records", len(recs))
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	t.Run("nsg-list", func(t *testing.T) {
		_, err := New(Options{API: &fakeAPI{nsgErr: errors.New("nsg boom")}}).Collect(context.Background(), bothReq())
		if err == nil || !strings.Contains(err.Error(), "nsg boom") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("vnet-list", func(t *testing.T) {
		_, err := New(Options{API: &fakeAPI{vnetErr: errors.New("vnet boom")}}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeNetwork}})
		if err == nil || !strings.Contains(err.Error(), "vnet boom") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestCollect_BadNSGResourceGroupID(t *testing.T) {
	f := &fakeAPI{nsgs: []*armnetwork.SecurityGroup{{Name: to.Ptr("n"), ID: to.Ptr("/subscriptions/s/providers/x"), Properties: &armnetwork.SecurityGroupPropertiesFormat{SecurityRules: []*armnetwork.SecurityRule{allowRule("r", armnetwork.SecurityRuleDirectionInbound, armnetwork.SecurityRuleProtocolTCP, "22", "*", 100)}}}}}
	_, err := New(Options{API: f}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeFirewallRule}})
	if err == nil || !strings.Contains(err.Error(), "resourceGroups") {
		t.Fatalf("expected resource-group parse error, got %v", err)
	}
}

func TestCollect_KISSNoDRY_RefetchesEachCollect(t *testing.T) {
	f := &fakeAPI{
		nsgs:  []*armnetwork.SecurityGroup{{Name: to.Ptr("n"), ID: nsgID("rg", "n"), Properties: &armnetwork.SecurityGroupPropertiesFormat{}}},
		vnets: []*armnetwork.VirtualNetwork{{Name: to.Ptr("v"), ID: vnetID("rg", "v"), Properties: &armnetwork.VirtualNetworkPropertiesFormat{}}},
	}
	p := New(Options{API: f})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), bothReq()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if f.nsgCalls != 3 || f.vnetCalls != 3 {
		t.Errorf("expected 3 nsg + 3 vnet calls, got %d + %d", f.nsgCalls, f.vnetCalls)
	}
}

func TestUnrestricted_Table(t *testing.T) {
	cases := []struct {
		name     string
		prefixes []string
		wantV4   bool
		wantV6   bool
	}{
		{"empty", nil, false, false},
		{"asterisk-both", []string{"*"}, true, true},
		{"internet-both", []string{"Internet"}, true, true},
		{"any-both", []string{"Any"}, true, true},
		{"v4-only", []string{"0.0.0.0/0"}, true, false},
		{"v6-only", []string{"::/0"}, false, true},
		{"restricted", []string{"10.0.0.0/8", "VirtualNetwork"}, false, false},
		{"mixed", []string{"10.0.0.0/8", "::/0"}, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v4, v6 := unrestricted(c.prefixes)
			if v4 != c.wantV4 || v6 != c.wantV6 {
				t.Errorf("unrestricted(%v) = (%v,%v), want (%v,%v)", c.prefixes, v4, v6, c.wantV4, c.wantV6)
			}
		})
	}
}

func TestParsePortRange_Table(t *testing.T) {
	cases := []struct {
		in       string
		from, to int
	}{
		{"*", -1, -1},
		{"", -1, -1},
		{"22", 22, 22},
		{"80-443", 80, 443},
		{"bad", -1, -1},
		{"1-bad", -1, -1},
	}
	for _, c := range cases {
		gotFrom, gotTo := parsePortRange(c.in)
		if gotFrom != c.from || gotTo != c.to {
			t.Errorf("parsePortRange(%q) = (%d,%d), want (%d,%d)", c.in, gotFrom, gotTo, c.from, c.to)
		}
	}
}

func TestMapProtocol_Table(t *testing.T) {
	cases := []struct {
		in   *armnetwork.SecurityRuleProtocol
		want string
	}{
		{nil, allProto},
		{to.Ptr(armnetwork.SecurityRuleProtocolAsterisk), allProto},
		{to.Ptr(armnetwork.SecurityRuleProtocolTCP), "tcp"},
		{to.Ptr(armnetwork.SecurityRuleProtocolUDP), "udp"},
		{to.Ptr(armnetwork.SecurityRuleProtocolIcmp), "icmp"},
		{to.Ptr(armnetwork.SecurityRuleProtocolEsp), "esp"},
	}
	for _, c := range cases {
		if got := mapProtocol(c.in); got != c.want {
			t.Errorf("mapProtocol = %q, want %q", got, c.want)
		}
	}
}

func TestVNetFlowLogsEnabled_NilSafe(t *testing.T) {
	if vnetFlowLogsEnabled(nil) || vnetFlowLogsEnabled(&armnetwork.VirtualNetwork{}) {
		t.Error("nil-safe vnetFlowLogsEnabled should be false")
	}
	disabled := &armnetwork.VirtualNetwork{Properties: &armnetwork.VirtualNetworkPropertiesFormat{FlowLogs: []*armnetwork.FlowLog{{Properties: &armnetwork.FlowLogPropertiesFormat{Enabled: to.Ptr(false)}}}}}
	if vnetFlowLogsEnabled(disabled) {
		t.Error("disabled flow log should be false")
	}
}

func TestResourceGroupFromID_Table(t *testing.T) {
	cases := []struct {
		id      string
		want    string
		wantErr bool
	}{
		{"/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.Network/networkSecurityGroups/n", "my-rg", false},
		{"/subscriptions/s/resourcegroups/lower/providers/x", "lower", false},
		{"/subscriptions/s/providers/x", "", true},
	}
	for _, c := range cases {
		got, err := resourceGroupFromID(c.id)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("resourceGroupFromID(%q) = (%q,%v), want (%q,err=%v)", c.id, got, err, c.want, c.wantErr)
		}
	}
}

func TestBuild_RequiresSubscriptionID(t *testing.T) {
	_, err := sources.Build(context.Background(), SourceID, sources.Env{Config: map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), "subscription_id") {
		t.Fatalf("expected subscription_id required error, got %v", err)
	}
}

// --- real adapter (httptest) ---

type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func realNetworkPointedAt(t *testing.T, srv *httptest.Server) *realNetwork {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rn, err := newRealNetwork("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealNetwork: %v", err)
	}
	return rn
}

func TestRealNetwork_ListNSGsAndVNets_HappyPath(t *testing.T) {
	nsgBody := mustMarshal(t, armnetwork.SecurityGroupListResult{Value: []*armnetwork.SecurityGroup{
		{Name: to.Ptr("nsg1"), ID: nsgID("rg", "nsg1")},
	}})
	vnetBody := mustMarshal(t, armnetwork.VirtualNetworkListResult{Value: []*armnetwork.VirtualNetwork{
		{Name: to.Ptr("vnet1"), ID: vnetID("rg", "vnet1")},
	}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/networkSecurityGroups"):
			_, _ = w.Write(nsgBody) //nolint:errcheck // test handler
		case strings.Contains(r.URL.Path, "/virtualNetworks"):
			_, _ = w.Write(vnetBody) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rn := realNetworkPointedAt(t, srv)
	t.Run("nsgs", func(t *testing.T) {
		nsgs, err := rn.ListSecurityGroups(context.Background())
		if err != nil || len(nsgs) != 1 || deref(nsgs[0].Name) != "nsg1" {
			t.Fatalf("ListSecurityGroups = %+v, err %v", nsgs, err)
		}
	})
	t.Run("vnets", func(t *testing.T) {
		vnets, err := rn.ListVirtualNetworks(context.Background())
		if err != nil || len(vnets) != 1 || deref(vnets[0].Name) != "vnet1" {
			t.Fatalf("ListVirtualNetworks = %+v, err %v", vnets, err)
		}
	})
}

func TestRealNetwork_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rn := realNetworkPointedAt(t, srv)
	if _, err := rn.ListSecurityGroups(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}
