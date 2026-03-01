// Package gcp provides evidence collection from Google Cloud Platform services.
package gcp

import (
	"context"
	"fmt"
	"os"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1beta4"
	"google.golang.org/api/storage/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// CollectorStatus represents the current state of the GCP collector.
type CollectorStatus struct {
	Connected bool   `json:"connected"`
	ProjectID string `json:"project_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// CollectionResult represents the result of collecting evidence from GCP.
type CollectionResult struct {
	Evidence []evidence.Evidence `json:"evidence"`
	Errors   []CollectionError   `json:"errors,omitempty"`
}

// CollectionError represents an error during collection from a specific service.
type CollectionError struct {
	Service string `json:"service"`
	Error   string `json:"error"`
}

// HasErrors returns true if there were any collection errors.
func (r *CollectionResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// Collector gathers evidence from GCP services.
type Collector struct {
	projectID  string
	iamService *iam.Service
	crmService *cloudresourcemanager.Service
	gcsService *storage.Service
	gceService *compute.Service
	sqlService *sqladmin.Service
}

// New creates a new GCP Collector.
func New() *Collector {
	return &Collector{}
}

// WithProjectID sets the GCP project ID for the collector.
func (c *Collector) WithProjectID(projectID string) *Collector {
	c.projectID = projectID
	return c
}

// Init initializes all GCP service clients with auto-detected credentials.
func (c *Collector) Init(ctx context.Context) error {
	if c.projectID == "" {
		c.projectID = os.Getenv("GOOGLE_PROJECT_ID")
		if c.projectID == "" {
			c.projectID = os.Getenv("GCLOUD_PROJECT")
			if c.projectID == "" {
				c.projectID = os.Getenv("GCP_PROJECT")
			}
		}
	}

	if c.projectID == "" {
		return fmt.Errorf("GCP project ID not set: use WithProjectID() or set GOOGLE_PROJECT_ID environment variable")
	}

	opts := []option.ClientOption{}

	var err error

	c.iamService, err = iam.NewService(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create IAM service: %w", err)
	}

	c.crmService, err = cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create Cloud Resource Manager service: %w", err)
	}

	c.gcsService, err = storage.NewService(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create Cloud Storage service: %w", err)
	}

	c.gceService, err = compute.NewService(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create Compute Engine service: %w", err)
	}

	c.sqlService, err = sqladmin.NewService(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create Cloud SQL service: %w", err)
	}

	return nil
}

// Status returns the current connection status of the collector.
func (c *Collector) Status(ctx context.Context) CollectorStatus {
	status := CollectorStatus{
		ProjectID: c.projectID,
	}

	if c.crmService == nil {
		status.Connected = false
		status.Error = "collector not initialized"
		return status
	}

	// Verify we can access the project
	_, err := c.crmService.Projects.Get(c.projectID).Context(ctx).Do()
	if err != nil {
		status.Connected = false
		status.Error = err.Error()
		return status
	}

	status.Connected = true
	return status
}

// ProjectID returns the configured project ID.
func (c *Collector) ProjectID() string {
	return c.projectID
}

// Collect gathers evidence from all GCP services using fail-safe pattern.
func (c *Collector) Collect(ctx context.Context) (*CollectionResult, error) {
	result := &CollectionResult{
		Evidence: []evidence.Evidence{},
		Errors:   []CollectionError{},
	}

	// Collect IAM service accounts
	c.collectIAM(ctx, result)

	// Collect Cloud Storage buckets
	c.collectStorage(ctx, result)

	// Collect Compute Engine resources
	c.collectCompute(ctx, result)

	// Collect Cloud SQL instances
	c.collectSQL(ctx, result)

	return result, nil
}

// collectIAM collects IAM evidence with fail-safe pattern.
func (c *Collector) collectIAM(ctx context.Context, result *CollectionResult) {
	iamCollector := NewIAMCollector(c.iamService, c.crmService)
	ev, err := iamCollector.CollectEvidence(ctx, c.projectID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "iam",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectStorage collects Cloud Storage evidence with fail-safe pattern.
func (c *Collector) collectStorage(ctx context.Context, result *CollectionResult) {
	storageCollector := NewStorageCollector(c.gcsService)
	ev, err := storageCollector.CollectEvidence(ctx, c.projectID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "storage",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectCompute collects Compute Engine evidence with fail-safe pattern.
func (c *Collector) collectCompute(ctx context.Context, result *CollectionResult) {
	computeCollector := NewComputeCollector(c.gceService)
	ev, err := computeCollector.CollectEvidence(ctx, c.projectID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "compute",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectSQL collects Cloud SQL evidence with fail-safe pattern.
func (c *Collector) collectSQL(ctx context.Context, result *CollectionResult) {
	sqlCollector := NewSQLCollector(c.sqlService)
	ev, err := sqlCollector.CollectEvidence(ctx, c.projectID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "cloudsql",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}
