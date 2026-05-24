// Package eks implements the aws.eks source plugin: lists EKS clusters
// in one AWS account and emits eks_cluster evidence records carrying
// the secrets-envelope-encryption attributes that SOC 2 CC6.7 policies
// consume.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract) the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by the
// aws.iam plugin — the concrete *eks.Client satisfies it, and unit tests
// inject an in-memory fake.
package eks

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "eks_cluster"

// SourceID is the registered ID for the aws.eks plugin instance.
const SourceID = "aws.eks"

// secretsResource is the only documented EncryptionConfig.Resources
// value for EKS envelope encryption today.
const secretsResource = "secrets"

// API is the subset of the EKS client this plugin uses.
type API interface {
	ListClusters(ctx context.Context, params *awseks.ListClustersInput, optFns ...func(*awseks.Options)) (*awseks.ListClustersOutput, error)
	DescribeCluster(ctx context.Context, params *awseks.DescribeClusterInput, optFns ...func(*awseks.Options)) (*awseks.DescribeClusterOutput, error)
}

// Plugin is the in-process aws.eks source.
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
		return nil, fmt.Errorf("aws.eks: load AWS config: %w", err)
	}
	return New(Options{
		API:    awseks.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// clusterPayload is the shape of the JSON payload inside each
// eks_cluster record.
type clusterPayload struct {
	Name                       string `json:"name"`
	ARN                        string `json:"arn,omitempty"`
	Status                     string `json:"status,omitempty"`
	Version                    string `json:"version,omitempty"`
	SecretsEncryptionEnabled   bool   `json:"secrets_encryption_enabled"`
	SecretsEncryptionKMSKeyARN string `json:"secrets_encryption_kms_key_arn,omitempty"`
}

// Collect lists EKS clusters in the configured region and returns one
// eks_cluster record per cluster.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.eks: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	names, err := p.listAllClusterNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.eks: list clusters: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		nameVar := name
		desc, err := p.api.DescribeCluster(ctx, &awseks.DescribeClusterInput{Name: &nameVar})
		if err != nil {
			return nil, fmt.Errorf("aws.eks: describe cluster %s: %w", name, err)
		}
		c := safeCluster(desc)
		enabled, keyARN := secretsEncryption(c)
		payload := clusterPayload{
			Name:                       name,
			ARN:                        safeARN(c),
			Status:                     safeStatus(c),
			Version:                    safeVersion(c),
			SecretsEncryptionEnabled:   enabled,
			SecretsEncryptionKMSKeyARN: keyARN,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.eks: marshal payload: %w", err)
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

func (p *Plugin) listAllClusterNames(ctx context.Context) ([]string, error) {
	var (
		out       []string
		nextToken *string
	)
	for {
		page, err := p.api.ListClusters(ctx, &awseks.ListClustersInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Clusters...)
		if page.NextToken != nil && *page.NextToken != "" {
			nextToken = page.NextToken
			continue
		}
		return out, nil
	}
}

func secretsEncryption(c *ekstypes.Cluster) (enabled bool, kmsKeyARN string) {
	if c == nil {
		return false, ""
	}
	for i := range c.EncryptionConfig {
		cfg := &c.EncryptionConfig[i]
		if !containsSecrets(cfg.Resources) {
			continue
		}
		if cfg.Provider == nil || cfg.Provider.KeyArn == nil || *cfg.Provider.KeyArn == "" {
			continue
		}
		return true, *cfg.Provider.KeyArn
	}
	return false, ""
}

func containsSecrets(resources []string) bool {
	for _, r := range resources {
		if r == secretsResource {
			return true
		}
	}
	return false
}

func safeCluster(out *awseks.DescribeClusterOutput) *ekstypes.Cluster {
	if out == nil {
		return nil
	}
	return out.Cluster
}

func safeARN(c *ekstypes.Cluster) string {
	if c == nil || c.Arn == nil {
		return ""
	}
	return *c.Arn
}

func safeStatus(c *ekstypes.Cluster) string {
	if c == nil {
		return ""
	}
	return string(c.Status)
}

func safeVersion(c *ekstypes.Cluster) string {
	if c == nil || c.Version == nil {
		return ""
	}
	return *c.Version
}

var _ core.SourcePlugin = (*Plugin)(nil)
