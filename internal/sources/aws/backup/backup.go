// Package backup implements the aws.backup source plugin: lists AWS Backup
// plans and emits backup_plan evidence records with cross-vendor activeness
// and retention attributes.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsbackup "github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "backup_plan"

// SourceID is the registered ID for the aws.backup plugin instance.
const SourceID = "aws.backup"

// API is the subset of the AWS Backup client this plugin uses.
type API interface {
	ListBackupPlans(ctx context.Context, params *awsbackup.ListBackupPlansInput, optFns ...func(*awsbackup.Options)) (*awsbackup.ListBackupPlansOutput, error)
	GetBackupPlan(ctx context.Context, params *awsbackup.GetBackupPlanInput, optFns ...func(*awsbackup.Options)) (*awsbackup.GetBackupPlanOutput, error)
}

// Plugin is the in-process aws.backup source.
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
		return nil, fmt.Errorf("aws.backup: load AWS config: %w", err)
	}
	return New(Options{
		API:    awsbackup.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// planPayload is the cross-vendor backup_plan shape. retention_days is a
// pointer so it is omitted (not emitted as a 0 sentinel) when the plan has
// no rule defining a retention period; has_retention_rule is the
// authoritative boolean.
type planPayload struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Provider         string `json:"provider"`
	IsActive         bool   `json:"is_active"`
	HasRetentionRule bool   `json:"has_retention_rule"`
	RetentionDays    *int64 `json:"retention_days,omitempty"`
}

// Collect lists backup plans and returns one backup_plan record per plan.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.backup: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	plans, err := p.listAllPlans(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.backup: list backup plans: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(plans))
	for i := range plans {
		plan := &plans[i]
		id := safeString(plan.BackupPlanId)
		if id == "" {
			continue
		}
		hasRetention, maxDays, err := p.retention(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("aws.backup: get backup plan %s: %w", id, err)
		}
		payload := planPayload{
			ID:       id,
			Name:     safeString(plan.BackupPlanName),
			Provider: "aws",
			// A listed plan is active; AWS Backup has no per-plan disabled
			// flag, so listed == active.
			IsActive:         true,
			HasRetentionRule: hasRetention,
		}
		if hasRetention {
			payload.RetentionDays = &maxDays
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.backup: marshal payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          id,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func (p *Plugin) listAllPlans(ctx context.Context) ([]backuptypes.BackupPlansListMember, error) {
	var (
		out   []backuptypes.BackupPlansListMember
		token *string
	)
	for {
		page, err := p.api.ListBackupPlans(ctx, &awsbackup.ListBackupPlansInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		out = append(out, page.BackupPlansList...)
		if page.NextToken != nil && *page.NextToken != "" {
			token = page.NextToken
			continue
		}
		return out, nil
	}
}

// retention reads a plan's rules and reports whether any rule defines a
// retention period (Lifecycle.DeleteAfterDays) and the max such value.
func (p *Plugin) retention(ctx context.Context, id string) (hasRetention bool, maxDays int64, err error) {
	out, err := p.api.GetBackupPlan(ctx, &awsbackup.GetBackupPlanInput{BackupPlanId: &id})
	if err != nil {
		return false, 0, err
	}
	if out.BackupPlan == nil {
		return false, 0, nil
	}
	for i := range out.BackupPlan.Rules {
		lc := out.BackupPlan.Rules[i].Lifecycle
		if lc == nil || lc.DeleteAfterDays == nil {
			continue
		}
		if !hasRetention || *lc.DeleteAfterDays > maxDays {
			maxDays = *lc.DeleteAfterDays
		}
		hasRetention = true
	}
	return hasRetention, maxDays, nil
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ core.SourcePlugin = (*Plugin)(nil)
