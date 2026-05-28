// Package rds implements the aws.rds source plugin: lists RDS DB instances
// and emits managed_database_instance evidence records with cross-vendor
// encryption, access, backup, and redundancy attributes.
package rds

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsrds "github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "managed_database_instance"

// SourceID is the registered ID for the aws.rds plugin instance.
const SourceID = "aws.rds"

// API is the subset of the RDS client this plugin uses.
type API interface {
	DescribeDBInstances(ctx context.Context, params *awsrds.DescribeDBInstancesInput, optFns ...func(*awsrds.Options)) (*awsrds.DescribeDBInstancesOutput, error)
}

// Plugin is the in-process aws.rds source.
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
		return nil, fmt.Errorf("aws.rds: load AWS config: %w", err)
	}
	return New(Options{
		API:    awsrds.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// instancePayload is the cross-vendor managed_database_instance shape.
type instancePayload struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Provider           string `json:"provider"`
	Engine             string `json:"engine,omitempty"`
	EngineVersion      string `json:"engine_version,omitempty"`
	StorageEncrypted   bool   `json:"storage_encrypted"`
	PubliclyAccessible bool   `json:"publicly_accessible"`
	BackupEnabled      bool   `json:"backup_enabled"`
	SSLRequired        bool   `json:"ssl_required"`
	MultiAZ            bool   `json:"multi_az"`
	DeletionProtection bool   `json:"deletion_protection"`
	KMSKeyID           string `json:"kms_key_id,omitempty"`
	// AWS-specific extras
	ARN    string `json:"arn,omitempty"`
	Status string `json:"status,omitempty"`
}

// Collect lists DB instances and returns one managed_database_instance record per instance.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.rds: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	instances, err := p.listAllInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.rds: describe db instances: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(instances))
	for i := range instances {
		inst := &instances[i]
		id := safeIdentifier(inst)
		if id == "" {
			continue
		}
		payload := instancePayload{
			ID:                 id,
			Name:               id,
			Provider:           "aws",
			Engine:             safeString(inst.Engine),
			EngineVersion:      safeString(inst.EngineVersion),
			StorageEncrypted:   safeBool(inst.StorageEncrypted),
			PubliclyAccessible: safeBool(inst.PubliclyAccessible),
			BackupEnabled:      safeBackupEnabled(inst),
			SSLRequired:        false, // RDS SSL is enforced via parameter groups; conservative default
			MultiAZ:            safeBool(inst.MultiAZ),
			DeletionProtection: safeBool(inst.DeletionProtection),
			KMSKeyID:           safeString(inst.KmsKeyId),
			ARN:                safeString(inst.DBInstanceArn),
			Status:             safeString(inst.DBInstanceStatus),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.rds: marshal payload: %w", err)
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

func (p *Plugin) listAllInstances(ctx context.Context) ([]rdstypes.DBInstance, error) {
	var (
		out    []rdstypes.DBInstance
		marker *string
	)
	for {
		page, err := p.api.DescribeDBInstances(ctx, &awsrds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.DBInstances...)
		if page.Marker != nil && *page.Marker != "" {
			marker = page.Marker
			continue
		}
		return out, nil
	}
}

func safeBackupEnabled(inst *rdstypes.DBInstance) bool {
	if inst == nil {
		return false
	}
	return inst.BackupRetentionPeriod != nil && *inst.BackupRetentionPeriod > 0
}

func safeIdentifier(inst *rdstypes.DBInstance) string {
	if inst == nil || inst.DBInstanceIdentifier == nil {
		return ""
	}
	return *inst.DBInstanceIdentifier
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func safeBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

var _ core.SourcePlugin = (*Plugin)(nil)
