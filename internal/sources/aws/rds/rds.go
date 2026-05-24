// Package rds implements the aws.rds source plugin: lists RDS DB
// instances in one AWS account and emits rds_instance evidence records
// carrying encryption and engine attributes that SOC 2 CC6.7 policies
// consume.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract) the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by the
// aws.iam plugin — the concrete *rds.Client satisfies it, and unit tests
// inject an in-memory fake.
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
const EvidenceTypeID = "rds_instance"

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
	// Now is injected so tests can produce deterministic CollectedAt
	// values. Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
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

// instancePayload is the shape of the JSON payload inside each
// rds_instance record.
type instancePayload struct {
	DBInstanceIdentifier string `json:"db_instance_identifier"`
	ARN                  string `json:"arn,omitempty"`
	Engine               string `json:"engine,omitempty"`
	EngineVersion        string `json:"engine_version,omitempty"`
	StorageEncrypted     bool   `json:"storage_encrypted"`
	KMSKeyID             string `json:"kms_key_id,omitempty"`
	PubliclyAccessible   bool   `json:"publicly_accessible"`
	DBInstanceStatus     string `json:"db_instance_status,omitempty"`
}

// Collect lists DB instances in the configured account and returns one
// rds_instance record per instance.
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
			DBInstanceIdentifier: id,
			ARN:                  safeString(inst.DBInstanceArn),
			Engine:               safeString(inst.Engine),
			EngineVersion:        safeString(inst.EngineVersion),
			StorageEncrypted:     inst.StorageEncrypted != nil && *inst.StorageEncrypted,
			KMSKeyID:             safeString(inst.KmsKeyId),
			PubliclyAccessible:   inst.PubliclyAccessible != nil && *inst.PubliclyAccessible,
			DBInstanceStatus:     safeString(inst.DBInstanceStatus),
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

var _ core.SourcePlugin = (*Plugin)(nil)
