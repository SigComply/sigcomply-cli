// Package aws provides evidence collection from AWS services.
package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// STSClient defines the interface for STS operations we use.
type STSClient interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// CollectorStatus represents the current state of the AWS collector.
type CollectorStatus struct {
	Connected bool   `json:"connected"`
	AccountID string `json:"account_id,omitempty"`
	Region    string `json:"region,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Collector gathers evidence from AWS services.
type Collector struct {
	stsClient STSClient
	region    string
	accountID string // Cached after first retrieval
}

// New creates a new AWS Collector with auto-detected credentials.
func New() *Collector {
	return &Collector{}
}

// WithRegion sets the AWS region for the collector.
func (c *Collector) WithRegion(region string) *Collector {
	c.region = region
	return c
}

// Init initializes the AWS clients with auto-detected credentials.
func (c *Collector) Init(ctx context.Context) error {
	opts := []func(*config.LoadOptions) error{}

	if c.region != "" {
		opts = append(opts, config.WithRegion(c.region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Store the resolved region
	if c.region == "" {
		c.region = cfg.Region
	}

	c.stsClient = sts.NewFromConfig(cfg)

	return nil
}

// GetAccountID retrieves the AWS account ID using STS GetCallerIdentity.
func (c *Collector) GetAccountID(ctx context.Context) (string, error) {
	// Return cached value if available
	if c.accountID != "" {
		return c.accountID, nil
	}

	if c.stsClient == nil {
		return "", errors.New("collector not initialized: call Init() first")
	}

	result, err := c.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}

	if result.Account == nil {
		return "", errors.New("account ID not returned from STS")
	}

	c.accountID = *result.Account
	return c.accountID, nil
}

// Status returns the current connection status of the collector.
// Note: This method intentionally returns nil error even when connection fails,
// because connection failure is a valid status (not an execution error).
func (c *Collector) Status(ctx context.Context) CollectorStatus {
	status := CollectorStatus{
		Region: c.region,
	}

	accountID, err := c.GetAccountID(ctx)
	if err != nil {
		status.Connected = false
		status.Error = err.Error()
		return status
	}

	status.Connected = true
	status.AccountID = accountID
	return status
}

// Region returns the configured region.
func (c *Collector) Region() string {
	return c.region
}
