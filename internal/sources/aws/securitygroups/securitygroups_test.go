package securitygroups

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

const (
	cidrAllIPv4 = "0.0.0.0/0"
	protoAll    = "all"
)

type fakeAPI struct {
	groups    []ec2types.SecurityGroup
	descErr   error
	descCount int
}

func (f *fakeAPI) DescribeSecurityGroups(_ context.Context, _ *awsec2.DescribeSecurityGroupsInput, _ ...func(*awsec2.Options)) (*awsec2.DescribeSecurityGroupsOutput, error) {
	f.descCount++
	if f.descErr != nil {
		return nil, f.descErr
	}
	return &awsec2.DescribeSecurityGroupsOutput{SecurityGroups: f.groups}, nil
}

func ptr[T any](v T) *T { return &v }

func unmarshal(t *testing.T, rec *core.EvidenceRecord) *rulePayload {
	t.Helper()
	var p rulePayload
	if err := json.Unmarshal(rec.Payload, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &p
}

func byID(records []core.EvidenceRecord, id string) *core.EvidenceRecord {
	for i := range records {
		if records[i].ID == id {
			return &records[i]
		}
	}
	return nil
}

func TestPlugin_IDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	em := p.Emits()
	if len(em) != 1 || em[0] != EvidenceTypeID {
		t.Errorf("Emits = %v; want [%s]", em, EvidenceTypeID)
	}
}

func TestPlugin_InitNoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// A security group with: an open-to-world SSH ingress rule, a restricted
// ingress rule, an all-ports/all-protocol (-1) ingress rule, and an egress
// rule — flattened into one record each.
func TestCollect_FlattensRulesDirectionPortsAndUnrestricted(t *testing.T) {
	fake := &fakeAPI{
		groups: []ec2types.SecurityGroup{
			{
				GroupId:   ptr("sg-1"),
				GroupName: ptr("web"),
				IpPermissions: []ec2types.IpPermission{
					{ // 0: open SSH to the world
						IpProtocol: ptr("tcp"),
						FromPort:   ptr(int32(22)),
						ToPort:     ptr(int32(22)),
						IpRanges:   []ec2types.IpRange{{CidrIp: ptr(cidrAllIPv4)}},
					},
					{ // 1: restricted HTTPS
						IpProtocol: ptr("tcp"),
						FromPort:   ptr(int32(443)),
						ToPort:     ptr(int32(443)),
						IpRanges:   []ec2types.IpRange{{CidrIp: ptr("10.0.0.0/8")}},
					},
					{ // 2: all ports, all protocols, IPv6 unrestricted
						IpProtocol: ptr("-1"),
						Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: ptr("::/0")}},
					},
				},
				IpPermissionsEgress: []ec2types.IpPermission{
					{ // 0: egress all
						IpProtocol: ptr("-1"),
						IpRanges:   []ec2types.IpRange{{CidrIp: ptr(cidrAllIPv4)}},
					},
				},
			},
		},
	}
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Region: "us-east-1", Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("len(records) = %d; want 4", len(records))
	}

	assertRecordMeta(t, records, now)
	assertRuleSSH(t, unmarshal(t, byID(records, "sg-1:ingress:0")))
	assertRuleHTTPS(t, unmarshal(t, byID(records, "sg-1:ingress:1")))
	assertRuleAll(t, unmarshal(t, byID(records, "sg-1:ingress:2")))
	assertRuleEgress(t, unmarshal(t, byID(records, "sg-1:egress:0")))
}

// assertRecordMeta verifies deterministic ordering and per-record metadata.
func assertRecordMeta(t *testing.T, records []core.EvidenceRecord, now time.Time) {
	t.Helper()
	wantOrder := []string{"sg-1:egress:0", "sg-1:ingress:0", "sg-1:ingress:1", "sg-1:ingress:2"}
	for i, want := range wantOrder {
		if records[i].ID != want {
			t.Errorf("records[%d].ID = %q; want %q", i, records[i].ID, want)
		}
		if records[i].CollectedAt != now {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].Type != EvidenceTypeID {
			t.Errorf("records[%d].Type = %q; want %q", i, records[i].Type, EvidenceTypeID)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("records[%d].SourceID = %q; want %q", i, records[i].SourceID, SourceID)
		}
	}
}

// assertRuleSSH checks the open-to-world SSH ingress rule.
func assertRuleSSH(t *testing.T, ssh *rulePayload) {
	t.Helper()
	checks := []struct {
		name      string
		got, want any
	}{
		{"Direction", ssh.Direction, "ingress"},
		{"Protocol", ssh.Protocol, "tcp"},
		{"FromPort", ssh.FromPort, 22},
		{"ToPort", ssh.ToPort, 22},
		{"IsUnrestrictedIPv4", ssh.IsUnrestrictedIPv4, true},
		{"IsUnrestrictedIPv6", ssh.IsUnrestrictedIPv6, false},
		{"SourceCIDR", ssh.SourceCIDR, cidrAllIPv4},
		{"DestCIDR", ssh.DestCIDR, ""},
		{"Provider", ssh.Provider, "aws"},
		{"GroupID", ssh.GroupID, "sg-1"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("ssh.%s = %v; want %v", c.name, c.got, c.want)
		}
	}
	if !strings.Contains(ssh.Name, "web") {
		t.Errorf("ssh.Name = %q; want to include group name 'web'", ssh.Name)
	}
}

// assertRuleHTTPS checks the restricted HTTPS ingress rule.
func assertRuleHTTPS(t *testing.T, https *rulePayload) {
	t.Helper()
	if https.IsUnrestrictedIPv4 {
		t.Errorf("https.IsUnrestrictedIPv4 = true; want false")
	}
	if https.SourceCIDR != "10.0.0.0/8" {
		t.Errorf("https.SourceCIDR = %q; want 10.0.0.0/8", https.SourceCIDR)
	}
}

// assertRuleAll checks the all-ports/all-protocols (-1) IPv6-unrestricted rule.
func assertRuleAll(t *testing.T, all *rulePayload) {
	t.Helper()
	checks := []struct {
		name      string
		got, want any
	}{
		{"Protocol", all.Protocol, protoAll},
		{"FromPort", all.FromPort, -1},
		{"ToPort", all.ToPort, -1},
		{"IsUnrestrictedIPv4", all.IsUnrestrictedIPv4, false},
		{"IsUnrestrictedIPv6", all.IsUnrestrictedIPv6, true},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("all.%s = %v; want %v", c.name, c.got, c.want)
		}
	}
}

// assertRuleEgress checks the egress-all rule.
func assertRuleEgress(t *testing.T, egress *rulePayload) {
	t.Helper()
	checks := []struct {
		name      string
		got, want any
	}{
		{"Direction", egress.Direction, "egress"},
		{"Protocol", egress.Protocol, protoAll},
		{"FromPort", egress.FromPort, -1},
		{"ToPort", egress.ToPort, -1},
		{"IsUnrestrictedIPv4", egress.IsUnrestrictedIPv4, true},
		{"DestCIDR", egress.DestCIDR, cidrAllIPv4},
		{"SourceCIDR", egress.SourceCIDR, ""},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("egress.%s = %v; want %v", c.name, c.got, c.want)
		}
	}
}

// Every required schema field must be present in the raw JSON of every
// record — the evaluator errors on any omitted referenced field.
func TestCollect_AllRequiredFieldsPresentInJSON(t *testing.T) {
	fake := &fakeAPI{groups: []ec2types.SecurityGroup{{
		GroupId:   ptr("sg-x"),
		GroupName: ptr("g"),
		IpPermissions: []ec2types.IpPermission{
			{IpProtocol: ptr("-1")}, // minimal rule, no ranges, no ports
		},
	}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(records[0].Payload, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	for _, field := range []string{"id", "name", "direction", "protocol", "from_port", "to_port", "is_unrestricted_ipv4", "is_unrestricted_ipv6"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("required field %q missing from payload JSON", field)
		}
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"kms_key"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want reject error; got %v", err)
	}
}

func TestCollect_DescribeError(t *testing.T) {
	p := New(Options{API: &fakeAPI{descErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "describe security groups") {
		t.Errorf("want describe error; got %v", err)
	}
}

func TestCollect_SkipsGroupWithEmptyID(t *testing.T) {
	fake := &fakeAPI{groups: []ec2types.SecurityGroup{
		{IpPermissions: []ec2types.IpPermission{{IpProtocol: ptr("tcp")}}}, // no GroupId
		{GroupId: ptr("sg-ok"), IpPermissions: []ec2types.IpPermission{{IpProtocol: ptr("tcp")}}},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "sg-ok:ingress:0" {
		t.Errorf("records = %v", records)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{groups: []ec2types.SecurityGroup{{GroupId: ptr("sg-1"), IpPermissions: []ec2types.IpPermission{{IpProtocol: ptr("tcp")}}}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{groups: []ec2types.SecurityGroup{{GroupId: ptr("sg-1"), IpPermissions: []ec2types.IpPermission{{IpProtocol: ptr("tcp")}}}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.descCount != 3 {
		t.Errorf("descCount = %d; want 3", fake.descCount)
	}
}

func TestNormalizeProtocol(t *testing.T) {
	if got := normalizeProtocol("-1"); got != "all" {
		t.Errorf("normalizeProtocol(-1) = %q; want all", got)
	}
	for _, p := range []string{"tcp", "udp", "icmp"} {
		if got := normalizeProtocol(p); got != p {
			t.Errorf("normalizeProtocol(%q) = %q; want unchanged", p, got)
		}
	}
}

func TestNewFromAWS_SmokeTest(t *testing.T) {
	p, err := NewFromAWS(context.Background(), "us-east-1")
	if err != nil {
		t.Logf("NewFromAWS errored (acceptable in CI): %v", err)
		return
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}
