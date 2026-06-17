package backup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservices"
	armbackup "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicesbackup/v4"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

var fixedNow = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

func mustUnmarshal(t *testing.T, raw json.RawMessage, dst any) {
	t.Helper()
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// fakeAPI records calls and returns staged vaults + per-vault policies.
type fakeAPI struct {
	vaults     []*armrecoveryservices.Vault
	policies   map[string][]*armbackup.ProtectionPolicyResource // keyed by vault name
	vaultErr   error
	policyErr  error
	vaultCalls int
	polCalls   int
}

func (f *fakeAPI) ListVaults(context.Context) ([]*armrecoveryservices.Vault, error) {
	f.vaultCalls++
	if f.vaultErr != nil {
		return nil, f.vaultErr
	}
	return f.vaults, nil
}

func (f *fakeAPI) ListPolicies(_ context.Context, vaultName, _ string) ([]*armbackup.ProtectionPolicyResource, error) {
	f.polCalls++
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	return f.policies[vaultName], nil
}

func req() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}
}

func vaultID(name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/" + name)
}

func policyID(vault, name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/" + vault + "/backupPolicies/" + name)
}

func dailyDuration(count int32) *armbackup.RetentionDuration {
	return &armbackup.RetentionDuration{Count: to.Ptr(count), DurationType: to.Ptr(armbackup.RetentionDurationTypeDays)}
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if got := p.ID(); got != "azure.backup" {
		t.Errorf("ID() = %q, want azure.backup", got)
	}
	got := p.Emits()
	if len(got) != 1 || got[0] != EvidenceTypeID {
		t.Errorf("Emits() = %v, want [backup_plan]", got)
	}
}

func TestCollect_RejectsNonEmittedType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "backup_plan") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestCollect_MapsSortsAndFullPayload(t *testing.T) {
	// Two vaults (out of order to prove cross-vault sort): a prod vault with an
	// active IaaS-VM policy (weekly retention, 5 protected items) and an inactive
	// SQL policy (0 protected items); a dev vault with one active file-share
	// policy.
	f := &fakeAPI{
		vaults: []*armrecoveryservices.Vault{
			{ID: vaultID("z-prod"), Name: to.Ptr("z-prod"), Location: to.Ptr("eastus")},
			{ID: vaultID("a-dev"), Name: to.Ptr("a-dev"), Location: to.Ptr("westus")},
		},
		policies: map[string][]*armbackup.ProtectionPolicyResource{
			"z-prod": {
				{
					ID:       policyID("z-prod", "vm-weekly"),
					Name:     to.Ptr("vm-weekly"),
					Location: to.Ptr("eastus"),
					Properties: &armbackup.AzureIaaSVMProtectionPolicy{
						BackupManagementType: to.Ptr("AzureIaasVM"),
						ProtectedItemsCount:  to.Ptr[int32](5),
						RetentionPolicy: &armbackup.LongTermRetentionPolicy{
							DailySchedule:  &armbackup.DailyRetentionSchedule{RetentionDuration: dailyDuration(30)},
							WeeklySchedule: &armbackup.WeeklyRetentionSchedule{RetentionDuration: &armbackup.RetentionDuration{Count: to.Ptr[int32](12), DurationType: to.Ptr(armbackup.RetentionDurationTypeWeeks)}},
						},
					},
				},
				{
					ID:       policyID("z-prod", "sql-unused"),
					Name:     to.Ptr("sql-unused"),
					Location: to.Ptr("eastus"),
					Properties: &armbackup.AzureSQLProtectionPolicy{
						BackupManagementType: to.Ptr("AzureSql"),
						ProtectedItemsCount:  to.Ptr[int32](0),
						RetentionPolicy: &armbackup.SimpleRetentionPolicy{
							RetentionDuration: dailyDuration(15),
						},
					},
				},
			},
			"a-dev": {
				{
					ID:       policyID("a-dev", "files-daily"),
					Name:     to.Ptr("files-daily"),
					Location: to.Ptr("westus"),
					Properties: &armbackup.AzureFileShareProtectionPolicy{
						BackupManagementType: to.Ptr("AzureStorage"),
						ProtectedItemsCount:  to.Ptr[int32](2),
						RetentionPolicy: &armbackup.LongTermRetentionPolicy{
							DailySchedule: &armbackup.DailyRetentionSchedule{RetentionDuration: dailyDuration(45)},
						},
					},
				},
			},
		},
	}
	p := New(Options{API: f, SubscriptionID: "sub-1", Now: func() time.Time { return fixedNow }})

	recs, err := p.Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	// Sorted by ID across vaults: a-dev/files-daily, z-prod/sql-unused, z-prod/vm-weekly.
	wantOrder := []string{*policyID("a-dev", "files-daily"), *policyID("z-prod", "sql-unused"), *policyID("z-prod", "vm-weekly")}
	for i, want := range wantOrder {
		if recs[i].ID != want {
			t.Fatalf("record %d ID = %s, want %s", i, recs[i].ID, want)
		}
	}
	for _, r := range recs {
		if r.Type != EvidenceTypeID || r.SourceID != SourceID || !r.CollectedAt.Equal(fixedNow) {
			t.Errorf("record %s: Type/SourceID/CollectedAt = %s/%s/%v", r.ID, r.Type, r.SourceID, r.CollectedAt)
		}
		if r.Scope == nil || r.Scope.Account != "sub-1" {
			t.Errorf("record %s: scope = %+v", r.ID, r.Scope)
		}
		if r.IdentityKey != "" {
			t.Errorf("record %s: unexpected IdentityKey %q", r.ID, r.IdentityKey)
		}
	}

	// files-daily: active, daily 45-day retention.
	var files policyPayload
	mustUnmarshal(t, recs[0].Payload, &files)
	wantFiles := policyPayload{
		ID:                  *policyID("a-dev", "files-daily"),
		Name:                "files-daily",
		Provider:            "azure",
		IsActive:            true,
		HasRetentionRule:    true,
		RetentionDays:       to.Ptr[int64](45),
		CoversResourceTypes: []string{"AzureStorage"},
		Location:            "westus",
		ResourceGroup:       "rg",
		VaultName:           "a-dev",
		ProtectedItemsCount: 2,
	}
	if !reflect.DeepEqual(files, wantFiles) {
		t.Errorf("files payload mismatch:\n got  %+v\n want %+v", files, wantFiles)
	}

	// sql-unused: inactive (0 protected items), 15-day retention still reported.
	var sql policyPayload
	mustUnmarshal(t, recs[1].Payload, &sql)
	wantSQL := policyPayload{
		ID:                  *policyID("z-prod", "sql-unused"),
		Name:                "sql-unused",
		Provider:            "azure",
		IsActive:            false,
		HasRetentionRule:    true,
		RetentionDays:       to.Ptr[int64](15),
		CoversResourceTypes: []string{"AzureSql"},
		Location:            "eastus",
		ResourceGroup:       "rg",
		VaultName:           "z-prod",
		ProtectedItemsCount: 0,
	}
	if !reflect.DeepEqual(sql, wantSQL) {
		t.Errorf("sql payload mismatch:\n got  %+v\n want %+v", sql, wantSQL)
	}

	// vm-weekly: active, max(daily 30, weekly 12×7=84) = 84.
	var vm policyPayload
	mustUnmarshal(t, recs[2].Payload, &vm)
	wantVM := policyPayload{
		ID:                  *policyID("z-prod", "vm-weekly"),
		Name:                "vm-weekly",
		Provider:            "azure",
		IsActive:            true,
		HasRetentionRule:    true,
		RetentionDays:       to.Ptr[int64](84),
		CoversResourceTypes: []string{"AzureIaasVM"},
		Location:            "eastus",
		ResourceGroup:       "rg",
		VaultName:           "z-prod",
		ProtectedItemsCount: 5,
	}
	if !reflect.DeepEqual(vm, wantVM) {
		t.Errorf("vm payload mismatch:\n got  %+v\n want %+v", vm, wantVM)
	}
}

// TestCollect_NoRetentionRule proves a policy with no resolvable retention emits
// has_retention_rule=false and omits retention_days from the JSON entirely.
func TestCollect_NoRetentionRule(t *testing.T) {
	f := &fakeAPI{
		vaults: []*armrecoveryservices.Vault{{ID: vaultID("v"), Name: to.Ptr("v")}},
		policies: map[string][]*armbackup.ProtectionPolicyResource{
			"v": {{
				ID:   policyID("v", "no-retention"),
				Name: to.Ptr("no-retention"),
				Properties: &armbackup.AzureIaaSVMProtectionPolicy{
					BackupManagementType: to.Ptr("AzureIaasVM"),
					ProtectedItemsCount:  to.Ptr[int32](1),
				},
			}},
		},
	}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got policyPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.HasRetentionRule || got.RetentionDays != nil {
		t.Errorf("want has_retention_rule=false + nil retention_days, got %+v", got)
	}
	if strings.Contains(string(recs[0].Payload), "retention_days") {
		t.Errorf("retention_days should be omitted from JSON: %s", recs[0].Payload)
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{
		vaults: []*armrecoveryservices.Vault{
			nil,
			{ID: vaultID("v"), Name: to.Ptr("v")},
		},
		policies: map[string][]*armbackup.ProtectionPolicyResource{
			"v": {
				nil,
				{ID: policyID("v", "nilprops"), Name: to.Ptr("nilprops")}, // nil Properties
				{ID: policyID("v", "ok"), Name: to.Ptr("ok"), Properties: &armbackup.AzureIaaSVMProtectionPolicy{ProtectedItemsCount: to.Ptr[int32](1)}},
			},
		},
	}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != *policyID("v", "ok") {
		t.Fatalf("expected 1 record (nils skipped), got %d: %+v", len(recs), recs)
	}
}

func TestCollect_VaultListError(t *testing.T) {
	_, err := New(Options{API: &fakeAPI{vaultErr: errors.New("vault boom")}}).Collect(context.Background(), req())
	if err == nil || !strings.Contains(err.Error(), "vault boom") {
		t.Fatalf("vault error should surface, got %v", err)
	}
}

func TestCollect_PolicyListError(t *testing.T) {
	f := &fakeAPI{
		vaults:    []*armrecoveryservices.Vault{{ID: vaultID("v"), Name: to.Ptr("v")}},
		policyErr: errors.New("policy boom"),
	}
	_, err := New(Options{API: f}).Collect(context.Background(), req())
	if err == nil || !strings.Contains(err.Error(), "policy boom") {
		t.Fatalf("policy error should surface, got %v", err)
	}
}

// TestCollect_MalformedVaultID_Errors proves a vault whose ARM id has no
// resourceGroups segment errors (the RG is required to list its policies) rather
// than silently dropping the vault.
func TestCollect_MalformedVaultID_Errors(t *testing.T) {
	f := &fakeAPI{vaults: []*armrecoveryservices.Vault{
		{ID: to.Ptr("/subscriptions/s/providers/x/vaults/odd"), Name: to.Ptr("odd")},
	}}
	_, err := New(Options{API: f}).Collect(context.Background(), req())
	if err == nil || !strings.Contains(err.Error(), "resourceGroups") {
		t.Fatalf("malformed vault id should error, got %v", err)
	}
}

func TestCollect_KISSNoDRY_RefetchesEachCollect(t *testing.T) {
	f := &fakeAPI{
		vaults: []*armrecoveryservices.Vault{{ID: vaultID("v"), Name: to.Ptr("v")}},
		policies: map[string][]*armbackup.ProtectionPolicyResource{
			"v": {{ID: policyID("v", "p"), Name: to.Ptr("p"), Properties: &armbackup.AzureIaaSVMProtectionPolicy{ProtectedItemsCount: to.Ptr[int32](1)}}},
		},
	}
	p := New(Options{API: f})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), req()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if f.vaultCalls != 3 || f.polCalls != 3 {
		t.Errorf("expected 3 vault + 3 policy calls, got %d/%d", f.vaultCalls, f.polCalls)
	}
}

func TestPolicyRetentionDays_Table(t *testing.T) {
	ltr := func(d *armbackup.RetentionDuration) *armbackup.LongTermRetentionPolicy {
		return &armbackup.LongTermRetentionPolicy{MonthlySchedule: &armbackup.MonthlyRetentionSchedule{RetentionDuration: d}}
	}
	cases := []struct {
		name string
		p    armbackup.ProtectionPolicyClassification
		want int
	}{
		{"iaasvm-longterm-monthly", &armbackup.AzureIaaSVMProtectionPolicy{RetentionPolicy: ltr(&armbackup.RetentionDuration{Count: to.Ptr[int32](6), DurationType: to.Ptr(armbackup.RetentionDurationTypeMonths)})}, 180},
		{"sql-simple", &armbackup.AzureSQLProtectionPolicy{RetentionPolicy: &armbackup.SimpleRetentionPolicy{RetentionDuration: dailyDuration(35)}}, 35},
		{"fileshare-yearly", &armbackup.AzureFileShareProtectionPolicy{RetentionPolicy: &armbackup.LongTermRetentionPolicy{YearlySchedule: &armbackup.YearlyRetentionSchedule{RetentionDuration: &armbackup.RetentionDuration{Count: to.Ptr[int32](2), DurationType: to.Ptr(armbackup.RetentionDurationTypeYears)}}}}, 730},
		{"vmworkload-subpolicy-max", &armbackup.AzureVMWorkloadProtectionPolicy{SubProtectionPolicy: []*armbackup.SubProtectionPolicy{
			nil,
			{RetentionPolicy: &armbackup.SimpleRetentionPolicy{RetentionDuration: dailyDuration(7)}},
			{RetentionPolicy: &armbackup.SimpleRetentionPolicy{RetentionDuration: dailyDuration(90)}},
		}}, 90},
		{"iaasvm-no-retention", &armbackup.AzureIaaSVMProtectionPolicy{}, 0},
		{"unknown-type", &armbackup.GenericProtectionPolicy{}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := policyRetentionDays(c.p); got != c.want {
				t.Errorf("policyRetentionDays = %d, want %d", got, c.want)
			}
		})
	}
}

func TestDurationToDays_Table(t *testing.T) {
	cases := []struct {
		name string
		d    *armbackup.RetentionDuration
		want int
	}{
		{"days", &armbackup.RetentionDuration{Count: to.Ptr[int32](10), DurationType: to.Ptr(armbackup.RetentionDurationTypeDays)}, 10},
		{"weeks", &armbackup.RetentionDuration{Count: to.Ptr[int32](4), DurationType: to.Ptr(armbackup.RetentionDurationTypeWeeks)}, 28},
		{"months", &armbackup.RetentionDuration{Count: to.Ptr[int32](3), DurationType: to.Ptr(armbackup.RetentionDurationTypeMonths)}, 90},
		{"years", &armbackup.RetentionDuration{Count: to.Ptr[int32](1), DurationType: to.Ptr(armbackup.RetentionDurationTypeYears)}, 365},
		{"nil", nil, 0},
		{"nil-count", &armbackup.RetentionDuration{DurationType: to.Ptr(armbackup.RetentionDurationTypeDays)}, 0},
		{"nil-type", &armbackup.RetentionDuration{Count: to.Ptr[int32](5)}, 0},
		{"invalid-type", &armbackup.RetentionDuration{Count: to.Ptr[int32](5), DurationType: to.Ptr(armbackup.RetentionDurationTypeInvalid)}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := durationToDays(c.d); got != c.want {
				t.Errorf("durationToDays = %d, want %d", got, c.want)
			}
		})
	}
}

func TestProtectedItemsCountAndCovers_NilSafe(t *testing.T) {
	if protectedItemsCount(nil) != 0 {
		t.Error("nil base → 0")
	}
	if protectedItemsCount(&armbackup.ProtectionPolicy{}) != 0 {
		t.Error("nil count → 0")
	}
	if protectedItemsCount(&armbackup.ProtectionPolicy{ProtectedItemsCount: to.Ptr[int32](7)}) != 7 {
		t.Error("count set → 7")
	}
	if coversResourceTypes(nil) != nil {
		t.Error("nil base → nil")
	}
	if coversResourceTypes(&armbackup.ProtectionPolicy{BackupManagementType: to.Ptr("")}) != nil {
		t.Error("empty mgmt type → nil")
	}
	got := coversResourceTypes(&armbackup.ProtectionPolicy{BackupManagementType: to.Ptr("AzureIaasVM")})
	if len(got) != 1 || got[0] != "AzureIaasVM" {
		t.Errorf("mgmt type set → %v", got)
	}
}

func TestResourceGroupFromID_Table(t *testing.T) {
	cases := []struct {
		id      string
		want    string
		wantErr bool
	}{
		{"/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.RecoveryServices/vaults/v", "my-rg", false},
		{"/subscriptions/s/resourcegroups/lower/providers/x", "lower", false},
		{"/subscriptions/s/providers/x", "", true},
	}
	for _, c := range cases {
		got, err := resourceGroupFromID(c.id)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("resourceGroupFromID(%q) = (%q,%v), want (%q,err=%v)", c.id, got, err, c.want, c.wantErr)
		}
	}
}

func TestBuild_RequiresSubscriptionID(t *testing.T) {
	_, err := sources.Build(context.Background(), SourceID, sources.Env{Config: map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), "subscription_id") {
		t.Fatalf("expected subscription_id required error, got %v", err)
	}
}

// --- real adapter (httptest) ---

type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func realBackupPointedAt(t *testing.T, srv *httptest.Server) *realBackup {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rb, err := newRealBackup("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealBackup: %v", err)
	}
	return rb
}

func TestRealBackup_ListVaultsAndPolicies_HappyPath(t *testing.T) {
	vaultsBody := mustMarshal(t, armrecoveryservices.VaultList{Value: []*armrecoveryservices.Vault{
		{ID: vaultID("v1"), Name: to.Ptr("v1"), Location: to.Ptr("eastus")},
	}})
	policiesBody := mustMarshal(t, armbackup.ProtectionPolicyResourceList{Value: []*armbackup.ProtectionPolicyResource{
		{ID: policyID("v1", "p1"), Name: to.Ptr("p1"), Properties: &armbackup.AzureIaaSVMProtectionPolicy{
			ProtectedItemsCount: to.Ptr[int32](3),
			RetentionPolicy: &armbackup.LongTermRetentionPolicy{
				DailySchedule: &armbackup.DailyRetentionSchedule{RetentionDuration: dailyDuration(30)},
			},
		}},
	}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/backupPolicies"):
			_, _ = w.Write(policiesBody) //nolint:errcheck // test handler
		case strings.Contains(r.URL.Path, "/vaults"):
			_, _ = w.Write(vaultsBody) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rb := realBackupPointedAt(t, srv)

	vaults, err := rb.ListVaults(context.Background())
	if err != nil || len(vaults) != 1 || deref(vaults[0].Name) != "v1" {
		t.Fatalf("ListVaults = %+v, err %v", vaults, err)
	}
	pols, err := rb.ListPolicies(context.Background(), "v1", "rg")
	if err != nil || len(pols) != 1 || deref(pols[0].Name) != "p1" {
		t.Fatalf("ListPolicies = %+v, err %v", pols, err)
	}
	// Retention round-trips through the polymorphic union.
	if got := policyRetentionDays(pols[0].Properties); got != 30 {
		t.Errorf("expected 30-day retention to round-trip, got %d", got)
	}
}

func TestRealBackup_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rb := realBackupPointedAt(t, srv)
	if _, err := rb.ListVaults(context.Background()); err == nil {
		t.Fatal("expected error on 403 (vaults), got nil")
	}
	if _, err := rb.ListPolicies(context.Background(), "v1", "rg"); err == nil {
		t.Fatal("expected error on 403 (policies), got nil")
	}
}
