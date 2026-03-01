package gcp

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/api/storage/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// GCSBucket represents a Cloud Storage bucket with security configuration.
type GCSBucket struct {
	Name                   string `json:"name"`
	Location               string `json:"location"`
	StorageClass           string `json:"storage_class"`
	EncryptionEnabled      bool   `json:"encryption_enabled"`
	DefaultKMSKeyName      string `json:"default_kms_key_name,omitempty"`
	VersioningEnabled      bool   `json:"versioning_enabled"`
	UniformBucketAccess    bool   `json:"uniform_bucket_access"`
	PublicAccessPrevention string `json:"public_access_prevention"`
	AllUsersAccess         bool   `json:"all_users_access"`
	AllAuthenticatedAccess bool   `json:"all_authenticated_access"`
}

// ToEvidence converts a GCSBucket to Evidence.
func (b *GCSBucket) ToEvidence(projectID string) evidence.Evidence {
	data, _ := json.Marshal(b) //nolint:errcheck
	resourceID := fmt.Sprintf("projects/%s/buckets/%s", projectID, b.Name)
	ev := evidence.New("gcp", "gcp:storage:bucket", resourceID, data)
	ev.Metadata = evidence.Metadata{
		AccountID: projectID,
	}
	return ev
}

// StorageCollector collects Cloud Storage bucket data.
type StorageCollector struct {
	service *storage.Service
}

// NewStorageCollector creates a new Cloud Storage collector.
func NewStorageCollector(service *storage.Service) *StorageCollector {
	return &StorageCollector{service: service}
}

// CollectBuckets retrieves all Cloud Storage buckets with security configuration.
func (c *StorageCollector) CollectBuckets(ctx context.Context, projectID string) ([]GCSBucket, error) {
	resp, err := c.service.Buckets.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	var buckets []GCSBucket
	for _, b := range resp.Items {
		bucket := GCSBucket{
			Name:         b.Name,
			Location:     b.Location,
			StorageClass: b.StorageClass,
		}

		// All GCS buckets have Google-managed encryption by default
		bucket.EncryptionEnabled = true
		if b.Encryption != nil && b.Encryption.DefaultKmsKeyName != "" {
			bucket.DefaultKMSKeyName = b.Encryption.DefaultKmsKeyName
		}

		// Versioning
		if b.Versioning != nil {
			bucket.VersioningEnabled = b.Versioning.Enabled
		}

		// Uniform bucket-level access
		if b.IamConfiguration != nil {
			if b.IamConfiguration.UniformBucketLevelAccess != nil {
				bucket.UniformBucketAccess = b.IamConfiguration.UniformBucketLevelAccess.Enabled
			}
			bucket.PublicAccessPrevention = b.IamConfiguration.PublicAccessPrevention
		}

		// Check for public access via ACLs
		c.enrichPublicAccess(ctx, &bucket)

		buckets = append(buckets, bucket)
	}

	return buckets, nil
}

// enrichPublicAccess checks if a bucket has allUsers or allAuthenticatedUsers access.
func (c *StorageCollector) enrichPublicAccess(ctx context.Context, bucket *GCSBucket) {
	policy, err := c.service.Buckets.GetIamPolicy(bucket.Name).Context(ctx).Do()
	if err != nil {
		// Fail-safe: assume potentially public
		return
	}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if member == "allUsers" {
				bucket.AllUsersAccess = true
			}
			if member == "allAuthenticatedUsers" {
				bucket.AllAuthenticatedAccess = true
			}
		}
	}
}

// CollectEvidence collects Cloud Storage buckets as evidence.
func (c *StorageCollector) CollectEvidence(ctx context.Context, projectID string) ([]evidence.Evidence, error) {
	buckets, err := c.CollectBuckets(ctx, projectID)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(buckets))
	for i := range buckets {
		evidenceList = append(evidenceList, buckets[i].ToEvidence(projectID))
	}

	return evidenceList, nil
}
