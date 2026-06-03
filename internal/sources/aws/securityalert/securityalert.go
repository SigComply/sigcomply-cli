// Package securityalert implements the aws.security_alert source plugin.
//
// It emits vendor-neutral security_alert evidence records. AWS-specific
// detection is expressed as CloudWatch Logs metric filters (a filter
// pattern over CloudTrail events) wired to CloudWatch metric alarms. The
// vendor-specific knowledge of which filter pattern means which kind of
// security event lives HERE, in the plugin: each metric filter is
// classified into a normalized event_class enum. Policies then check
// "an active alert exists for event class X" without ever touching an
// AWS filter pattern.
package securityalert

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	cw "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the single evidence type this plugin emits.
const EvidenceTypeID = "security_alert"

// SourceID is the registered ID for the aws.security_alert plugin instance.
const SourceID = "aws.security_alert"

const providerAWS = "aws"

// Event-class enum values. These MUST match the security_alert.v1.json
// schema enum and the consuming policies' pass_when clauses exactly.
const (
	classUnauthorizedAPICalls    = "unauthorized_api_calls"
	classRootAccountUsage        = "root_account_usage"
	classIAMPolicyChanges        = "iam_policy_changes"
	classCloudTrailConfigChanges = "cloudtrail_config_changes"
	classConsoleLoginNoMFA       = "console_login_no_mfa"
	classSecurityGroupChanges    = "security_group_changes"
	classVPCChanges              = "vpc_changes"
	classKMSKeyDeletion          = "kms_key_deletion"
	classOther                   = "other"
)

// API is the subset of AWS clients this plugin uses.
type API interface {
	DescribeMetricFilters(ctx context.Context, params *cwl.DescribeMetricFiltersInput, optFns ...func(*cwl.Options)) (*cwl.DescribeMetricFiltersOutput, error)
	DescribeAlarms(ctx context.Context, params *cw.DescribeAlarmsInput, optFns ...func(*cw.Options)) (*cw.DescribeAlarmsOutput, error)
}

// awsAPI adapts the two concrete AWS SDK clients to the API interface.
type awsAPI struct {
	logs   *cwl.Client
	alarms *cw.Client
}

func (a *awsAPI) DescribeMetricFilters(ctx context.Context, params *cwl.DescribeMetricFiltersInput, optFns ...func(*cwl.Options)) (*cwl.DescribeMetricFiltersOutput, error) {
	return a.logs.DescribeMetricFilters(ctx, params, optFns...)
}

func (a *awsAPI) DescribeAlarms(ctx context.Context, params *cw.DescribeAlarmsInput, optFns ...func(*cw.Options)) (*cw.DescribeAlarmsOutput, error) {
	return a.alarms.DescribeAlarms(ctx, params, optFns...)
}

// Plugin is the in-process aws.security_alert source.
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

// NewFromAWS constructs a Plugin backed by the real AWS SDK clients.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.security_alert: load AWS config: %w", err)
	}
	return New(Options{
		API: &awsAPI{
			logs:   cwl.NewFromConfig(cfg),
			alarms: cw.NewFromConfig(cfg),
		},
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// securityAlertPayload is the cross-vendor security_alert shape.
type securityAlertPayload struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	Provider              string `json:"provider"`
	EventClass            string `json:"event_class"`
	IsEnabled             bool   `json:"is_enabled"`
	HasNotificationTarget bool   `json:"has_notification_target"`
}

// alarmInfo summarizes an alarm relevant to alert wiring.
type alarmInfo struct {
	hasNotificationTarget bool
}

// Collect lists CloudWatch metric filters and alarms, classifies each
// metric filter into a normalized event_class, and emits one
// security_alert record per metric filter that maps to a recognized
// event class.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.security_alert: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	filters, err := p.listAllFilters(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.security_alert: describe metric filters: %w", err)
	}
	alarmsByMetric, err := p.listAlarmsByMetric(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.security_alert: describe alarms: %w", err)
	}

	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(filters))
	for i := range filters {
		rec, ok, err := buildRecord(&filters[i], alarmsByMetric, now)
		if err != nil {
			return nil, err
		}
		if ok {
			records = append(records, rec)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// buildRecord classifies one metric filter and, when it maps to a
// recognized event class, returns the corresponding evidence record.
func buildRecord(f *cwltypes.MetricFilter, alarmsByMetric map[string]alarmInfo, now time.Time) (core.EvidenceRecord, bool, error) {
	class := classify(safeStr(f.FilterPattern))
	if class == classOther {
		return core.EvidenceRecord{}, false, nil
	}
	name := safeStr(f.FilterName)
	enabled, info := alarmFor(f.MetricTransformations, alarmsByMetric)
	payload := securityAlertPayload{
		ID:                    class + ":" + name,
		Name:                  name,
		Provider:              providerAWS,
		EventClass:            class,
		IsEnabled:             enabled,
		HasNotificationTarget: enabled && info.hasNotificationTarget,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, false, fmt.Errorf("aws.security_alert: marshal payload: %w", err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeID,
		ID:          payload.ID,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
	}, true, nil
}

// alarmFor reports whether any of the filter's metric names is referenced
// by an alarm, and returns that alarm's info.
func alarmFor(transforms []cwltypes.MetricTransformation, alarmsByMetric map[string]alarmInfo) (bool, alarmInfo) {
	for i := range transforms {
		metric := safeStr(transforms[i].MetricName)
		if metric == "" {
			continue
		}
		if info, ok := alarmsByMetric[metric]; ok {
			return true, info
		}
	}
	return false, alarmInfo{}
}

// classify maps an AWS CloudWatch Logs metric filter pattern to a
// normalized event_class. This is the vendor-specific knowledge that the
// security_alert type deliberately hides from policies.
func classify(pattern string) string {
	switch {
	case strings.Contains(pattern, "Unauthorized"):
		return classUnauthorizedAPICalls
	case strings.Contains(pattern, "RootAccount") || strings.Contains(pattern, "userIdentity.type"):
		return classRootAccountUsage
	case containsAny(pattern, "DeleteGroupPolicy", "PutGroupPolicy", "AttachUserPolicy", "DetachUserPolicy"):
		return classIAMPolicyChanges
	case containsAny(pattern, "StopLogging", "DeleteTrail", "UpdateTrail"):
		return classCloudTrailConfigChanges
	case strings.Contains(pattern, "ConsoleLogin") && strings.Contains(pattern, "MFAUsed"):
		return classConsoleLoginNoMFA
	case containsAny(pattern, "CreateSecurityGroup", "DeleteSecurityGroup", "AuthorizeSecurityGroup"):
		return classSecurityGroupChanges
	case containsAny(pattern, "CreateVpc", "DeleteVpc", "ModifyVpc"):
		return classVPCChanges
	case containsAny(pattern, "DisableKey", "ScheduleKeyDeletion"):
		return classKMSKeyDeletion
	default:
		return classOther
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// listAllFilters pages through all CloudWatch Logs metric filters.
func (p *Plugin) listAllFilters(ctx context.Context) ([]cwltypes.MetricFilter, error) {
	var (
		out   []cwltypes.MetricFilter
		token *string
	)
	for {
		page, err := p.api.DescribeMetricFilters(ctx, &cwl.DescribeMetricFiltersInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		out = append(out, page.MetricFilters...)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

// listAlarmsByMetric pages through all metric alarms and indexes them by
// the metric name they watch.
func (p *Plugin) listAlarmsByMetric(ctx context.Context) (map[string]alarmInfo, error) {
	out := map[string]alarmInfo{}
	var token *string
	for {
		page, err := p.api.DescribeAlarms(ctx, &cw.DescribeAlarmsInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		indexAlarms(out, page.MetricAlarms)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

func indexAlarms(out map[string]alarmInfo, alarms []cwtypes.MetricAlarm) {
	for i := range alarms {
		metric := safeStr(alarms[i].MetricName)
		if metric == "" {
			continue
		}
		out[metric] = alarmInfo{hasNotificationTarget: len(alarms[i].AlarmActions) > 0}
	}
}

func safeStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ core.SourcePlugin = (*Plugin)(nil)
