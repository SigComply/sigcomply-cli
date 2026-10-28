// Package ecr implements the aws.ecr source plugin: lists ECR
// repositories in the private registry and emits container_registry
// evidence records with cross-vendor scan-on-push, public-exposure,
// immutability, and encryption attributes.
package ecr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awscfg"
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
	GetRepositoryPolicy(ctx context.Context, params *awsecr.GetRepositoryPolicyInput, optFns ...func(*awsecr.Options)) (*awsecr.GetRepositoryPolicyOutput, error)
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
// The variadic opts carry per-instance credential settings (see
// internal/sources/aws/awscfg). Omitting them keeps the previous
// behavior: the ambient credential chain, scoped to region.
func NewFromAWS(ctx context.Context, region string, opts ...awscfg.Options) (*Plugin, error) {
	o := awscfg.Options{Region: region}
	if len(opts) > 0 {
		o = opts[0]
		if o.Region == "" {
			o.Region = region
		}
	}
	cfg, region, err := awscfg.Load(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("aws.ecr: %w", err)
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
		public, err := p.repositoryIsPublic(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("aws.ecr: repository policy for %s: %w", id, err)
		}
		payload := registryPayload{
			ID:                       id,
			Name:                     id,
			Provider:                 providerName,
			ScanOnPushEnabled:        scanOnPushEnabled(repo),
			ImageImmutabilityEnabled: string(repo.ImageTagMutability) == immutableTagSetting,
			// DescribeRepositories lists private repositories (ECR Public is
			// a separate API), but a repository policy can still let anyone
			// pull from one.
			IsPublic: public,
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

// repositoryIsPublic reports whether the repository policy lets anyone
// in: an Allow statement whose principal is "*" (or {"AWS": "*"}) with no
// Condition. A statement with a Condition is treated as restricted, since
// conditions such as aws:PrincipalOrgID or aws:SourceIp narrow it. No
// policy (RepositoryPolicyNotFoundException) means private.
func (p *Plugin) repositoryIsPublic(ctx context.Context, name string) (bool, error) {
	out, err := p.api.GetRepositoryPolicy(ctx, &awsecr.GetRepositoryPolicyInput{RepositoryName: &name})
	if err != nil {
		var notFound *ecrtypes.RepositoryPolicyNotFoundException
		if errors.As(err, &notFound) {
			return false, nil
		}
		return false, err
	}
	if out == nil || out.PolicyText == nil {
		return false, nil
	}
	return policyAllowsAnyone(*out.PolicyText)
}

// policyDoc is the subset of an IAM-style resource policy this plugin
// reads. Statement and Principal each come in more than one JSON shape.
type policyDoc struct {
	Statement json.RawMessage `json:"Statement"`
}

type policyStatement struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Condition json.RawMessage `json:"Condition"`
}

func policyAllowsAnyone(text string) (bool, error) {
	var doc policyDoc
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return false, fmt.Errorf("parse repository policy: %w", err)
	}
	var stmts []policyStatement
	if err := json.Unmarshal(doc.Statement, &stmts); err != nil {
		var one policyStatement
		if err := json.Unmarshal(doc.Statement, &one); err != nil {
			return false, fmt.Errorf("parse repository policy statements: %w", err)
		}
		stmts = []policyStatement{one}
	}
	for i := range stmts {
		st := &stmts[i]
		if st.Effect != "Allow" || hasCondition(st.Condition) {
			continue
		}
		if principalIsAnyone(st.Principal) {
			return true, nil
		}
	}
	return false, nil
}

func hasCondition(raw json.RawMessage) bool {
	c := string(raw)
	return c != "" && c != "null" && c != "{}"
}

// principalIsAnyone accepts "*", {"AWS": "*"} and {"AWS": ["*", ...]}.
func principalIsAnyone(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "*"
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	aws, ok := m["AWS"]
	if !ok {
		return false
	}
	if json.Unmarshal(aws, &s) == nil {
		return s == "*"
	}
	var list []string
	if json.Unmarshal(aws, &list) == nil {
		for _, v := range list {
			if v == "*" {
				return true
			}
		}
	}
	return false
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
