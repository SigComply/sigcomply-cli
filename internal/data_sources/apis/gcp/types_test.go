package gcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServiceAccount_ToEvidence(t *testing.T) {
	sa := &ServiceAccount{
		Email:       "test@project.iam.gserviceaccount.com",
		Name:        "projects/project/serviceAccounts/test@project.iam.gserviceaccount.com",
		DisplayName: "Test SA",
		UniqueID:    "12345",
		KeyCount:    2,
		OldestKeyAge: 120,
	}

	ev := sa.ToEvidence("my-project")
	assert.Equal(t, "gcp", ev.Collector)
	assert.Equal(t, "gcp:iam:service-account", ev.ResourceType)
	assert.Equal(t, "test@project.iam.gserviceaccount.com", ev.ResourceID)
	assert.Equal(t, "my-project", ev.Metadata.AccountID)
	assert.NotEmpty(t, ev.Hash)
}

func TestProjectIAMPolicy_ToEvidence(t *testing.T) {
	policy := &ProjectIAMPolicy{
		ProjectID: "my-project",
		Bindings: []IAMBinding{
			{Role: "roles/owner", Members: []string{"user:admin@example.com"}},
		},
	}

	ev := policy.ToEvidence()
	assert.Equal(t, "gcp", ev.Collector)
	assert.Equal(t, "gcp:iam:policy", ev.ResourceType)
	assert.Equal(t, "my-project", ev.ResourceID)
	assert.NotEmpty(t, ev.Hash)
}

func TestGCSBucket_ToEvidence(t *testing.T) {
	bucket := &GCSBucket{
		Name:                "test-bucket",
		Location:            "US",
		StorageClass:        "STANDARD",
		EncryptionEnabled:   true,
		VersioningEnabled:   true,
		UniformBucketAccess: true,
	}

	ev := bucket.ToEvidence("my-project")
	assert.Equal(t, "gcp", ev.Collector)
	assert.Equal(t, "gcp:storage:bucket", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "test-bucket")
	assert.NotEmpty(t, ev.Hash)
}

func TestFirewallRule_ToEvidence(t *testing.T) {
	rule := &FirewallRule{
		Name:           "allow-ssh",
		Network:        "default",
		Direction:      "INGRESS",
		SourceRanges:   []string{"0.0.0.0/0"},
		OpenSSH:        true,
		OpenToInternet: true,
	}

	ev := rule.ToEvidence("my-project")
	assert.Equal(t, "gcp", ev.Collector)
	assert.Equal(t, "gcp:compute:firewall", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "allow-ssh")
	assert.NotEmpty(t, ev.Hash)
}

func TestSubnet_ToEvidence(t *testing.T) {
	subnet := &Subnet{
		Name:            "subnet-1",
		Region:          "us-central1",
		Network:         "default",
		IPCIDRRange:     "10.0.0.0/24",
		FlowLogsEnabled: true,
	}

	ev := subnet.ToEvidence("my-project")
	assert.Equal(t, "gcp", ev.Collector)
	assert.Equal(t, "gcp:compute:subnet", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "subnet-1")
}

func TestDisk_ToEvidence(t *testing.T) {
	disk := &Disk{
		Name:              "disk-1",
		Zone:              "us-central1-a",
		SizeGb:            100,
		EncryptionEnabled: true,
		EncryptionType:    "google-managed",
	}

	ev := disk.ToEvidence("my-project")
	assert.Equal(t, "gcp", ev.Collector)
	assert.Equal(t, "gcp:compute:disk", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "disk-1")
}

func TestNetwork_ToEvidence(t *testing.T) {
	network := &Network{
		Name:      "default",
		IsDefault: true,
	}

	ev := network.ToEvidence("my-project")
	assert.Equal(t, "gcp", ev.Collector)
	assert.Equal(t, "gcp:compute:network", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "default")
}

func TestSQLInstance_ToEvidence(t *testing.T) {
	inst := &SQLInstance{
		Name:              "db-1",
		DatabaseVersion:   "POSTGRES_15",
		Region:            "us-central1",
		EncryptionEnabled: true,
		PublicIPEnabled:   false,
		RequireSSL:        true,
		BackupEnabled:     true,
		PITREnabled:       true,
	}

	ev := inst.ToEvidence("my-project")
	assert.Equal(t, "gcp", ev.Collector)
	assert.Equal(t, "gcp:sql:instance", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "db-1")
}

func TestContainsPort(t *testing.T) {
	assert.True(t, containsPort("20-25", 22))
	assert.True(t, containsPort("3389-3390", 3389))
	assert.False(t, containsPort("80-443", 22))
	assert.False(t, containsPort("invalid", 22))
	assert.False(t, containsPort("22", 22), "single port not a range")
	assert.False(t, containsPort("abc-def", 22))
}

func TestCollectionResult_HasErrors(t *testing.T) {
	result := &CollectionResult{}
	assert.False(t, result.HasErrors())

	result.Errors = append(result.Errors, CollectionError{Service: "iam", Error: "access denied"})
	assert.True(t, result.HasErrors())
}

func TestCollector_WithProjectID(t *testing.T) {
	c := New()
	result := c.WithProjectID("my-project")
	assert.Equal(t, c, result)
	assert.Equal(t, "my-project", c.ProjectID())
}

// --- Negative Tests ---

func TestServiceAccount_ToEvidence_EmptyFields(t *testing.T) {
	sa := &ServiceAccount{
		Email:       "",
		Name:        "",
		DisplayName: "",
		UniqueID:    "",
		KeyCount:    0,
		OldestKeyAge: 0,
	}

	ev := sa.ToEvidence("")
	assert.Equal(t, "gcp", ev.Collector)
	assert.Equal(t, "gcp:iam:service-account", ev.ResourceType)
	assert.Equal(t, "", ev.ResourceID)
	assert.NotEmpty(t, ev.Hash, "hash should still be computed even with empty data")
}

func TestGCSBucket_ToEvidence_EmptyFields(t *testing.T) {
	bucket := &GCSBucket{
		Name: "",
	}

	ev := bucket.ToEvidence("")
	assert.Equal(t, "gcp:storage:bucket", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}

func TestFirewallRule_ToEvidence_EmptyFields(t *testing.T) {
	rule := &FirewallRule{
		Name:         "",
		Network:      "",
		Direction:    "",
		SourceRanges: nil,
	}

	ev := rule.ToEvidence("")
	assert.Equal(t, "gcp:compute:firewall", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}

func TestSQLInstance_ToEvidence_EmptyFields(t *testing.T) {
	inst := &SQLInstance{
		Name:            "",
		DatabaseVersion: "",
		Region:          "",
	}

	ev := inst.ToEvidence("")
	assert.Equal(t, "gcp:sql:instance", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}

func TestContainsPort_EdgeCases(t *testing.T) {
	assert.False(t, containsPort("", 22), "empty string")
	assert.False(t, containsPort("-", 22), "just a dash")
	assert.True(t, containsPort("0-65535", 22), "full range")
	assert.True(t, containsPort("0-65535", 0), "full range includes 0")
	assert.True(t, containsPort("0-65535", 65535), "full range includes 65535")
	assert.True(t, containsPort("22-22", 22), "single-port range")
	assert.False(t, containsPort("23-21", 22), "inverted range")
}

func TestCollectionResult_HasErrors_MultipleErrors(t *testing.T) {
	result := &CollectionResult{
		Errors: []CollectionError{
			{Service: "iam", Error: "error 1"},
			{Service: "storage", Error: "error 2"},
		},
	}
	assert.True(t, result.HasErrors())
}

func TestCollectionResult_EmptyEvidence(t *testing.T) {
	result := &CollectionResult{
		Evidence: nil,
	}
	assert.False(t, result.HasErrors())
	assert.Nil(t, result.Evidence)
}

func TestCollector_DefaultProjectID(t *testing.T) {
	c := New()
	assert.Equal(t, "", c.ProjectID(), "default project ID should be empty")
}

func TestCollector_Status_NotInitialized(t *testing.T) {
	c := New()
	status := c.Status(context.Background())
	assert.Equal(t, "", status.ProjectID, "project ID should be empty when not set")
}

func TestProjectIAMPolicy_ToEvidence_EmptyBindings(t *testing.T) {
	policy := &ProjectIAMPolicy{
		ProjectID: "my-project",
		Bindings:  nil,
	}

	ev := policy.ToEvidence()
	assert.Equal(t, "gcp:iam:policy", ev.ResourceType)
	assert.Equal(t, "my-project", ev.ResourceID)
	assert.NotEmpty(t, ev.Hash)
}

func TestDisk_ToEvidence_EmptyFields(t *testing.T) {
	disk := &Disk{
		Name:              "",
		Zone:              "",
		SizeGb:            0,
		EncryptionEnabled: false,
		EncryptionType:    "",
	}

	ev := disk.ToEvidence("")
	assert.Equal(t, "gcp:compute:disk", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}

func TestSubnet_ToEvidence_EmptyFields(t *testing.T) {
	subnet := &Subnet{
		Name:            "",
		Region:          "",
		Network:         "",
		IPCIDRRange:     "",
		FlowLogsEnabled: false,
	}

	ev := subnet.ToEvidence("")
	assert.Equal(t, "gcp:compute:subnet", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}

func TestNetwork_ToEvidence_NonDefault(t *testing.T) {
	network := &Network{
		Name:      "custom-vpc",
		IsDefault: false,
	}

	ev := network.ToEvidence("my-project")
	assert.Equal(t, "gcp:compute:network", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "custom-vpc")
}
