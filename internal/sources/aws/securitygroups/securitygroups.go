// Package securitygroups implements the aws.security_group source plugin:
// lists EC2 security groups in one AWS account and emits one firewall_rule
// evidence record per ingress/egress rule, carrying the cross-vendor
// direction / protocol / port-range / unrestricted-source attributes that
// network-exposure policies evaluate.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract) the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
package securitygroups

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "firewall_rule"

// SourceID is the registered ID for the aws.security_group plugin instance.
const SourceID = "aws.security_group"

// allPortsSentinel is the documented cross-vendor convention for "all
// ports" — AWS uses a nil FromPort/ToPort (typically with protocol "-1");
// policies detect this by matching from_port == -1.
const allPortsSentinel = -1

// API is the subset of the EC2 client this plugin uses.
type API interface {
	DescribeSecurityGroups(ctx context.Context, params *awsec2.DescribeSecurityGroupsInput, optFns ...func(*awsec2.Options)) (*awsec2.DescribeSecurityGroupsOutput, error)
}

// Plugin is the in-process aws.security_group source.
type Plugin struct {
	api    API
	region string
	now    func() time.Time
}

// Options is the constructor input.
type Options struct {
	API    API
	Region string
	Now    func() time.Time
}

// New constructs a Plugin around an explicit API implementation.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:    opts.API,
		region: opts.Region,
		now:    now,
	}
}

// NewFromAWS constructs a Plugin backed by the real AWS SDK.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.security_group: load AWS config: %w", err)
	}
	return New(Options{
		API:    awsec2.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
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
}

// Collect lists security groups and returns one firewall_rule record per
// ingress/egress rule (flattening every group's IpPermissions and
// IpPermissionsEgress into individual rule records).
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.security_group: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	groups, err := p.listAllGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.security_group: describe security groups: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0)
	for i := range groups {
		g := &groups[i]
		groupID := safeString(g.GroupId)
		if groupID == "" {
			continue
		}
		groupName := safeString(g.GroupName)
		for idx := range g.IpPermissions {
			payload := buildPayload(groupID, groupName, "ingress", idx, &g.IpPermissions[idx])
			rec, err := toRecord(&payload, now)
			if err != nil {
				return nil, err
			}
			records = append(records, rec)
		}
		for idx := range g.IpPermissionsEgress {
			payload := buildPayload(groupID, groupName, "egress", idx, &g.IpPermissionsEgress[idx])
			rec, err := toRecord(&payload, now)
			if err != nil {
				return nil, err
			}
			records = append(records, rec)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// buildPayload maps a single AWS IpPermission to the firewall_rule shape.
func buildPayload(groupID, groupName, direction string, index int, perm *ec2types.IpPermission) rulePayload {
	fromPort, toPort := allPortsSentinel, allPortsSentinel
	if perm.FromPort != nil {
		fromPort = int(*perm.FromPort)
	}
	if perm.ToPort != nil {
		toPort = int(*perm.ToPort)
	}
	payload := rulePayload{
		ID:                 fmt.Sprintf("%s:%s:%d", groupID, direction, index),
		Name:               fmt.Sprintf("%s %s rule", groupName, direction),
		Provider:           "aws",
		GroupID:            groupID,
		Direction:          direction,
		Protocol:           normalizeProtocol(safeString(perm.IpProtocol)),
		FromPort:           fromPort,
		ToPort:             toPort,
		IsUnrestrictedIPv4: hasUnrestrictedIPv4(perm),
		IsUnrestrictedIPv6: hasUnrestrictedIPv6(perm),
	}
	cidr := firstIPv4CIDR(perm)
	if direction == "ingress" {
		payload.SourceCIDR = cidr
	} else {
		payload.DestCIDR = cidr
	}
	return payload
}

func toRecord(payload *rulePayload, now time.Time) (core.EvidenceRecord, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("aws.security_group: marshal payload: %w", err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeID,
		ID:          payload.ID,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
	}, nil
}

func (p *Plugin) listAllGroups(ctx context.Context) ([]ec2types.SecurityGroup, error) {
	var (
		out       []ec2types.SecurityGroup
		nextToken *string
	)
	for {
		page, err := p.api.DescribeSecurityGroups(ctx, &awsec2.DescribeSecurityGroupsInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		out = append(out, page.SecurityGroups...)
		if page.NextToken != nil && *page.NextToken != "" {
			nextToken = page.NextToken
			continue
		}
		return out, nil
	}
}

// normalizeProtocol maps the AWS "-1" all-protocols marker to the
// cross-vendor "all"; tcp/udp/icmp pass through unchanged.
func normalizeProtocol(p string) string {
	if p == "-1" {
		return "all"
	}
	return p
}

func hasUnrestrictedIPv4(perm *ec2types.IpPermission) bool {
	for i := range perm.IpRanges {
		if safeString(perm.IpRanges[i].CidrIp) == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

func hasUnrestrictedIPv6(perm *ec2types.IpPermission) bool {
	for i := range perm.Ipv6Ranges {
		if safeString(perm.Ipv6Ranges[i].CidrIpv6) == "::/0" {
			return true
		}
	}
	return false
}

func firstIPv4CIDR(perm *ec2types.IpPermission) string {
	for i := range perm.IpRanges {
		if c := safeString(perm.IpRanges[i].CidrIp); c != "" {
			return c
		}
	}
	return ""
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ core.SourcePlugin = (*Plugin)(nil)
