package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// BackupClient defines the interface for Backup operations.
type BackupClient interface {
	ListBackupPlans(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error)
	GetBackupPlan(ctx context.Context, params *backup.GetBackupPlanInput, optFns ...func(*backup.Options)) (*backup.GetBackupPlanOutput, error)
	ListBackupVaults(ctx context.Context, params *backup.ListBackupVaultsInput, optFns ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error)
	DescribeBackupVault(ctx context.Context, params *backup.DescribeBackupVaultInput, optFns ...func(*backup.Options)) (*backup.DescribeBackupVaultOutput, error)
	ListRecoveryPointsByBackupVault(ctx context.Context, params *backup.ListRecoveryPointsByBackupVaultInput, optFns ...func(*backup.Options)) (*backup.ListRecoveryPointsByBackupVaultOutput, error)
}

// BackupStatus represents the Backup status.
type BackupStatus struct {
	HasBackupPlans   bool   `json:"has_backup_plans"`
	PlanCount        int    `json:"plan_count"`
	Region           string `json:"region"`
	VaultLockEnabled bool   `json:"vault_lock_enabled"`
}

// ToEvidence converts a BackupStatus to Evidence.
func (s *BackupStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // marshalling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:backup:%s:%s:status", s.Region, accountID)
	ev := evidence.New("aws", "aws:backup:status", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// BackupPlan represents an AWS Backup plan with cross-region copy info.
type BackupPlan struct {
	PlanID           string `json:"plan_id"`
	PlanName         string `json:"plan_name"`
	HasCrossRegionCopy bool `json:"has_cross_region_copy"`
}

// ToEvidence converts a BackupPlan to Evidence.
func (p *BackupPlan) ToEvidence(accountID, region string) evidence.Evidence {
	data, _ := json.Marshal(p) //nolint:errcheck // marshalling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:backup:%s:%s:backup-plan:%s", region, accountID, p.PlanID)
	ev := evidence.New("aws", "aws:backup:plan", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// BackupVault represents an AWS Backup vault with encryption info.
type BackupVault struct {
	VaultName        string `json:"vault_name"`
	VaultARN         string `json:"vault_arn"`
	EncryptionEnabled bool  `json:"encryption_enabled"`
	KMSKeyConfigured bool   `json:"kms_key_configured"`
}

// ToEvidence converts a BackupVault to Evidence.
func (v *BackupVault) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(v) //nolint:errcheck
	ev := evidence.New("aws", "aws:backup:vault", v.VaultARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// BackupRecoveryPoint represents an AWS Backup recovery point.
type BackupRecoveryPoint struct {
	RecoveryPointARN string `json:"recovery_point_arn"`
	VaultName        string `json:"vault_name"`
	Encrypted        bool   `json:"encrypted"`
}

// ToEvidence converts a BackupRecoveryPoint to Evidence.
func (rp *BackupRecoveryPoint) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(rp) //nolint:errcheck
	ev := evidence.New("aws", "aws:backup:recovery-point", rp.RecoveryPointARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// BackupCollector collects Backup status.
type BackupCollector struct {
	client BackupClient
	region string
}

// NewBackupCollector creates a new Backup collector.
func NewBackupCollector(client BackupClient, region string) *BackupCollector {
	return &BackupCollector{client: client, region: region}
}

// CollectStatus retrieves Backup status.
func (c *BackupCollector) CollectStatus(ctx context.Context) (*BackupStatus, error) {
	status := &BackupStatus{Region: c.region}

	output, err := c.client.ListBackupPlans(ctx, &backup.ListBackupPlansInput{})
	if err != nil {
		return status, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	status.PlanCount = len(output.BackupPlansList)
	status.HasBackupPlans = status.PlanCount > 0

	// Check vault lock
	c.enrichVaultLock(ctx, status)

	return status, nil
}

// enrichVaultLock checks if any backup vault has vault lock enabled.
func (c *BackupCollector) enrichVaultLock(ctx context.Context, status *BackupStatus) {
	output, err := c.client.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})
	if err != nil {
		return
	}
	for i := range output.BackupVaultList {
		vault := &output.BackupVaultList[i]
		if vault.Locked != nil && *vault.Locked {
			status.VaultLockEnabled = true
			return
		}
	}
}

// CollectPlans retrieves backup plans and checks for cross-region copy rules.
func (c *BackupCollector) CollectPlans(ctx context.Context) ([]BackupPlan, error) {
	output, err := c.client.ListBackupPlans(ctx, &backup.ListBackupPlansInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list backup plans: %w", err)
	}

	var plans []BackupPlan
	for i := range output.BackupPlansList {
		p := &output.BackupPlansList[i]
		plan := BackupPlan{
			PlanID:   awssdk.ToString(p.BackupPlanId),
			PlanName: awssdk.ToString(p.BackupPlanName),
		}

		// Get plan details to check for cross-region copy
		if p.BackupPlanId != nil {
			detail, err := c.client.GetBackupPlan(ctx, &backup.GetBackupPlanInput{
				BackupPlanId: p.BackupPlanId,
			})
			if err == nil && detail.BackupPlan != nil {
				for _, rule := range detail.BackupPlan.Rules {
					if len(rule.CopyActions) > 0 {
						plan.HasCrossRegionCopy = true
						break
					}
				}
			}
		}

		plans = append(plans, plan)
	}

	return plans, nil
}

// CollectVaults retrieves backup vaults with encryption details.
func (c *BackupCollector) CollectVaults(ctx context.Context) ([]BackupVault, error) {
	output, err := c.client.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list backup vaults: %w", err)
	}

	var vaults []BackupVault
	for i := range output.BackupVaultList {
		v := &output.BackupVaultList[i]
		vaultName := awssdk.ToString(v.BackupVaultName)
		vault := BackupVault{
			VaultName: vaultName,
			VaultARN:  awssdk.ToString(v.BackupVaultArn),
		}

		// Get vault details for encryption info
		detail, err := c.client.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{
			BackupVaultName: awssdk.String(vaultName),
		})
		if err == nil {
			keyArn := awssdk.ToString(detail.EncryptionKeyArn)
			vault.EncryptionEnabled = keyArn != ""
			vault.KMSKeyConfigured = keyArn != "" && !strings.Contains(keyArn, "aws/backup")
		}

		vaults = append(vaults, vault)
	}

	return vaults, nil
}

// CollectRecoveryPoints retrieves recovery points across all vaults.
func (c *BackupCollector) CollectRecoveryPoints(ctx context.Context) ([]BackupRecoveryPoint, error) {
	vaultsOutput, err := c.client.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list backup vaults: %w", err)
	}

	var points []BackupRecoveryPoint
	for i := range vaultsOutput.BackupVaultList {
		v := &vaultsOutput.BackupVaultList[i]
		vaultName := awssdk.ToString(v.BackupVaultName)
		rpOutput, err := c.client.ListRecoveryPointsByBackupVault(ctx, &backup.ListRecoveryPointsByBackupVaultInput{
			BackupVaultName: awssdk.String(vaultName),
		})
		if err != nil {
			continue // Fail-safe per vault
		}

		for j := range rpOutput.RecoveryPoints {
			rp := &rpOutput.RecoveryPoints[j]
			points = append(points, BackupRecoveryPoint{
				RecoveryPointARN: awssdk.ToString(rp.RecoveryPointArn),
				VaultName:        vaultName,
				Encrypted:        rp.IsEncrypted,
			})
		}
	}

	return points, nil
}

// CollectEvidence collects Backup status and plans as evidence.
func (c *BackupCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	status, err := c.CollectStatus(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := []evidence.Evidence{status.ToEvidence(accountID)}

	// Collect backup plans (fail-safe)
	plans, err := c.CollectPlans(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range plans {
			evidenceList = append(evidenceList, plans[i].ToEvidence(accountID, c.region))
		}
	}

	// Collect vaults (fail-safe)
	vaults, err := c.CollectVaults(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range vaults {
			evidenceList = append(evidenceList, vaults[i].ToEvidence(accountID))
		}
	}

	// Collect recovery points (fail-safe)
	recoveryPoints, err := c.CollectRecoveryPoints(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range recoveryPoints {
			evidenceList = append(evidenceList, recoveryPoints[i].ToEvidence(accountID))
		}
	}

	return evidenceList, nil
}
