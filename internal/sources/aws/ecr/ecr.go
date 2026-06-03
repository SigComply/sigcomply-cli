// Package ecr implements the aws.ecr source plugin: lists ECR
// repositories in the private registry and emits container_registry
// evidence records with cross-vendor scan-on-push, public-exposure,
// immutability, and encryption attributes.
package ecr

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "container_registry"

// SourceID is the registered ID for the aws.ecr plugin instance.
const SourceID = "aws.ecr"

// immutableTagSetting is the ImageTagMutability value that means image
// tags cannot be overwritten.
const immutableTagSetting = "IMMUTABLE"

// providerName is the cloud provider short name emitted on every record.
const providerName = "aws"

// API is the subset of the ECR client this plugin uses.
type API interface {
	DescribeRepositories(ctx context.Context, params *awsecr.DescribeRepositoriesInput, optFns ...func(*awsecr.Options)) (*awsecr.DescribeRepositoriesOutput, error)
}

// Plugin is the in-process aws.ecr source.
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
		return nil, fmt.Errorf("aws.ecr: load AWS config: %w", err)
	}
	return New(Options{
		API:    awsecr.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// registryPayload is the cross-vendor container_registry shape.
type registryPayload struct {
	ID                       string `json:"id"`
	Name                     string `json:"name"`
	Provider                 string `json:"provider"`
	ScanOnPushEnabled        bool   `json:"scan_on_push_enabled"`
	ImageImmutabilityEnabled bool   `json:"image_immutability_enabled"`
	IsPublic                 bool   `json:"is_public"`
	EncryptionEnabled        bool   `json:"encryption_enabled"`
	// AWS-specific extras.
	ARN string `json:"arn,omitempty"`
	URI string `json:"uri,omitempty"`
}

// Collect lists ECR repositories and returns one container_registry record per repository.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.ecr: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	repos, err := p.listAllRepositories(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.ecr: describe repositories: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(repos))
	for i := range repos {
		repo := &repos[i]
		id := safeRepositoryName(repo)
		if id == "" {
			continue
		}
		payload := registryPayload{
			ID:                       id,
			Name:                     id,
			Provider:                 providerName,
			ScanOnPushEnabled:        scanOnPushEnabled(repo),
			ImageImmutabilityEnabled: string(repo.ImageTagMutability) == immutableTagSetting,
			// ECR is a private registry; DescribeRepositories never returns
			// public repositories (those live behind a separate ECR Public API).
			IsPublic: false,
			// ECR always encrypts images at rest (AES256 by default, or KMS);
			// EncryptionConfiguration is always populated, so presence == encrypted.
			EncryptionEnabled: repo.EncryptionConfiguration != nil,
			ARN:               safeString(repo.RepositoryArn),
			URI:               safeString(repo.RepositoryUri),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.ecr: marshal payload: %w", err)
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

func (p *Plugin) listAllRepositories(ctx context.Context) ([]ecrtypes.Repository, error) {
	var (
		out       []ecrtypes.Repository
		nextToken *string
	)
	for {
		page, err := p.api.DescribeRepositories(ctx, &awsecr.DescribeRepositoriesInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Repositories...)
		if page.NextToken != nil && *page.NextToken != "" {
			nextToken = page.NextToken
			continue
		}
		return out, nil
	}
}

// scanOnPushEnabled reports whether the repository scans images on push.
// ImageScanningConfiguration is a pointer; when absent ECR defaults to off.
func scanOnPushEnabled(repo *ecrtypes.Repository) bool {
	return repo.ImageScanningConfiguration != nil && repo.ImageScanningConfiguration.ScanOnPush
}

func safeRepositoryName(repo *ecrtypes.Repository) string {
	if repo == nil || repo.RepositoryName == nil {
		return ""
	}
	return *repo.RepositoryName
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ core.SourcePlugin = (*Plugin)(nil)
