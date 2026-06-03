// Package dynamodb implements the aws.dynamodb source plugin: lists
// DynamoDB tables and emits nosql_table evidence records with cross-vendor
// encryption, point-in-time-recovery, and deletion-protection attributes.
package dynamodb

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "nosql_table"

// SourceID is the registered ID for the aws.dynamodb plugin instance.
const SourceID = "aws.dynamodb"

// providerAWS is the provider short name stamped on every record.
const providerAWS = "aws"

// API is the subset of the DynamoDB client this plugin uses.
type API interface {
	ListTables(ctx context.Context, params *awsdynamodb.ListTablesInput, optFns ...func(*awsdynamodb.Options)) (*awsdynamodb.ListTablesOutput, error)
	DescribeTable(ctx context.Context, params *awsdynamodb.DescribeTableInput, optFns ...func(*awsdynamodb.Options)) (*awsdynamodb.DescribeTableOutput, error)
	DescribeContinuousBackups(ctx context.Context, params *awsdynamodb.DescribeContinuousBackupsInput, optFns ...func(*awsdynamodb.Options)) (*awsdynamodb.DescribeContinuousBackupsOutput, error)
}

// Plugin is the in-process aws.dynamodb source.
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
		return nil, fmt.Errorf("aws.dynamodb: load AWS config: %w", err)
	}
	return New(Options{
		API:    awsdynamodb.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// tablePayload is the cross-vendor nosql_table shape. Every field a
// consuming policy reads is always emitted (no omitempty on the
// policy-read booleans) — the evaluator errors on an absent referenced
// field, so a missing key is never silently treated as false.
type tablePayload struct {
	ID                         string `json:"id"`
	Name                       string `json:"name"`
	Provider                   string `json:"provider"`
	EncryptionEnabled          bool   `json:"encryption_enabled"`
	PointInTimeRecoveryEnabled bool   `json:"point_in_time_recovery_enabled"`
	DeletionProtection         bool   `json:"deletion_protection"`
}

// Collect lists DynamoDB tables and returns one nosql_table record per table.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.dynamodb: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	names, err := p.listAllTables(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.dynamodb: list tables: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		payload, perr := p.tablePayload(ctx, name)
		if perr != nil {
			return nil, perr
		}
		body, merr := json.Marshal(payload)
		if merr != nil {
			return nil, fmt.Errorf("aws.dynamodb: marshal payload: %w", merr)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          name,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// tablePayload assembles the nosql_table payload for one table by combining
// DescribeTable (encryption + deletion protection) and
// DescribeContinuousBackups (point-in-time recovery).
func (p *Plugin) tablePayload(ctx context.Context, name string) (tablePayload, error) {
	dt, err := p.api.DescribeTable(ctx, &awsdynamodb.DescribeTableInput{TableName: &name})
	if err != nil {
		return tablePayload{}, fmt.Errorf("aws.dynamodb: describe table %q: %w", name, err)
	}
	cb, err := p.api.DescribeContinuousBackups(ctx, &awsdynamodb.DescribeContinuousBackupsInput{TableName: &name})
	if err != nil {
		return tablePayload{}, fmt.Errorf("aws.dynamodb: describe continuous backups %q: %w", name, err)
	}
	return tablePayload{
		ID:                         name,
		Name:                       name,
		Provider:                   providerAWS,
		EncryptionEnabled:          encryptionEnabled(dt.Table),
		PointInTimeRecoveryEnabled: pitrEnabled(cb.ContinuousBackupsDescription),
		DeletionProtection:         deletionProtection(dt.Table),
	}, nil
}

func (p *Plugin) listAllTables(ctx context.Context) ([]string, error) {
	var (
		out   []string
		start *string
	)
	for {
		page, err := p.api.ListTables(ctx, &awsdynamodb.ListTablesInput{ExclusiveStartTableName: start})
		if err != nil {
			return nil, err
		}
		out = append(out, page.TableNames...)
		if page.LastEvaluatedTableName != nil && *page.LastEvaluatedTableName != "" {
			start = page.LastEvaluatedTableName
			continue
		}
		return out, nil
	}
}

// encryptionEnabled reports whether the table is encrypted at rest.
// DynamoDB encrypts every table at rest by default; SSEDescription is only
// populated when a non-default (KMS/managed) key is configured. So an
// honest reading is: present => use its status; absent => true (default
// AWS-owned-key encryption is always on and cannot be disabled).
func encryptionEnabled(t *ddbtypes.TableDescription) bool {
	if t == nil {
		return true
	}
	if t.SSEDescription == nil {
		return true
	}
	return t.SSEDescription.Status == ddbtypes.SSEStatusEnabled
}

func deletionProtection(t *ddbtypes.TableDescription) bool {
	if t == nil || t.DeletionProtectionEnabled == nil {
		return false
	}
	return *t.DeletionProtectionEnabled
}

func pitrEnabled(cb *ddbtypes.ContinuousBackupsDescription) bool {
	if cb == nil || cb.PointInTimeRecoveryDescription == nil {
		return false
	}
	return cb.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == ddbtypes.PointInTimeRecoveryStatusEnabled
}

var _ core.SourcePlugin = (*Plugin)(nil)
