package gcp

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/api/sqladmin/v1beta4"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// SQLInstance represents a Cloud SQL instance.
type SQLInstance struct {
	Name              string `json:"name"`
	DatabaseVersion   string `json:"database_version"`
	Region            string `json:"region"`
	Tier              string `json:"tier"`
	State             string `json:"state"`
	EncryptionEnabled bool   `json:"encryption_enabled"`
	KMSKeyName        string `json:"kms_key_name,omitempty"`
	PublicIPEnabled   bool   `json:"public_ip_enabled"`
	RequireSSL        bool   `json:"require_ssl"`
	BackupEnabled     bool   `json:"backup_enabled"`
	PITREnabled       bool   `json:"pitr_enabled"`
	BackupLocation    string `json:"backup_location,omitempty"`
}

// ToEvidence converts a SQLInstance to Evidence.
func (s *SQLInstance) ToEvidence(projectID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("projects/%s/instances/%s", projectID, s.Name)
	ev := evidence.New("gcp", "gcp:sql:instance", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: projectID}
	return ev
}

// SQLCollector collects Cloud SQL instance data.
type SQLCollector struct {
	service *sqladmin.Service
}

// NewSQLCollector creates a new Cloud SQL collector.
func NewSQLCollector(service *sqladmin.Service) *SQLCollector {
	return &SQLCollector{service: service}
}

// CollectInstances retrieves all Cloud SQL instances.
func (c *SQLCollector) CollectInstances(ctx context.Context, projectID string) ([]SQLInstance, error) {
	resp, err := c.service.Instances.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list Cloud SQL instances: %w", err)
	}

	var instances []SQLInstance
	for _, inst := range resp.Items {
		instance := SQLInstance{
			Name:            inst.Name,
			DatabaseVersion: inst.DatabaseVersion,
			Region:          inst.Region,
			Tier:            inst.Settings.Tier,
			State:           inst.State,
		}

		// All Cloud SQL instances are encrypted at rest by default (Google-managed)
		instance.EncryptionEnabled = true
		if inst.DiskEncryptionConfiguration != nil && inst.DiskEncryptionConfiguration.KmsKeyName != "" {
			instance.KMSKeyName = inst.DiskEncryptionConfiguration.KmsKeyName
		}

		// Check for public IP
		if inst.Settings != nil && inst.Settings.IpConfiguration != nil {
			ipConfig := inst.Settings.IpConfiguration
			// Ipv4Enabled being true means public IP is enabled
			instance.PublicIPEnabled = ipConfig.Ipv4Enabled
			instance.RequireSSL = ipConfig.RequireSsl
		}

		// Check backup configuration
		if inst.Settings != nil && inst.Settings.BackupConfiguration != nil {
			bc := inst.Settings.BackupConfiguration
			instance.BackupEnabled = bc.Enabled
			instance.PITREnabled = bc.PointInTimeRecoveryEnabled
			instance.BackupLocation = bc.Location
		}

		instances = append(instances, instance)
	}

	return instances, nil
}

// CollectEvidence collects Cloud SQL instances as evidence.
func (c *SQLCollector) CollectEvidence(ctx context.Context, projectID string) ([]evidence.Evidence, error) {
	instances, err := c.CollectInstances(ctx, projectID)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(instances))
	for i := range instances {
		evidenceList = append(evidenceList, instances[i].ToEvidence(projectID))
	}

	return evidenceList, nil
}
