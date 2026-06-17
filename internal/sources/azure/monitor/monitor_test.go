package monitor

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
	armmonitor "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	armoi "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v2"

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

type fakeAPI struct {
	workspaces []*armoi.Workspace
	settings   []*armmonitor.DiagnosticSettingsResource
	wsErr      error
	dsErr      error
	wsCalls    int
	dsCalls    int
}

func (f *fakeAPI) ListWorkspaces(context.Context) ([]*armoi.Workspace, error) {
	f.wsCalls++
	if f.wsErr != nil {
		return nil, f.wsErr
	}
	return f.workspaces, nil
}

func (f *fakeAPI) ListSubscriptionDiagnosticSettings(context.Context) ([]*armmonitor.DiagnosticSettingsResource, error) {
	f.dsCalls++
	if f.dsErr != nil {
		return nil, f.dsErr
	}
	return f.settings, nil
}

func bothReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeLogGroup, EvidenceTypeAuditLogTrail}}
}

func workspaceID(rg, name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/" + rg + "/providers/Microsoft.OperationalInsights/workspaces/" + name)
}

func workspace(rg, name, location string, retention int32) *armoi.Workspace {
	return &armoi.Workspace{
		ID:       workspaceID(rg, name),
		Name:     to.Ptr(name),
		Location: to.Ptr(location),
		Properties: &armoi.WorkspaceProperties{
			RetentionInDays: to.Ptr(retention),
			SKU:             &armoi.WorkspaceSKU{Name: to.Ptr(armoi.WorkspaceSKUNameEnumPerGB2018)},
		},
	}
}

// logSetting builds an enabled/disabled log category setting.
func logSetting(category string, enabled bool) *armmonitor.LogSettings {
	return &armmonitor.LogSettings{Category: to.Ptr(category), Enabled: to.Ptr(enabled)}
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if got := p.ID(); got != "azure.monitor" {
		t.Errorf("ID() = %q, want azure.monitor", got)
	}
	got := p.Emits()
	if len(got) != 2 || got[0] != EvidenceTypeLogGroup || got[1] != EvidenceTypeAuditLogTrail {
		t.Errorf("Emits() = %v, want [log_group audit_log_trail]", got)
	}
}

func TestCollect_RejectsWhenNoEmittedTypeAccepted(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "emitted types") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestCollect_BothTypes_MapsSortsAndFullPayload(t *testing.T) {
	f := &fakeAPI{
		// Out of order so the sort-by-ID is exercised (zworkspace > aworkspace).
		workspaces: []*armoi.Workspace{
			workspace("rg-logs", "zworkspace", "westus", 30),
			workspace("rg-logs", "aworkspace", "eastus", 365),
		},
		settings: []*armmonitor.DiagnosticSettingsResource{{
			Name: to.Ptr("activity-to-law"),
			Properties: &armmonitor.DiagnosticSettings{
				WorkspaceID: workspaceID("rg-logs", "aworkspace"),
				Logs: []*armmonitor.LogSettings{
					logSetting("Security", true),
					logSetting("Administrative", true),
					logSetting("Alert", false), // disabled → not counted
				},
			},
		}},
	}
	p := New(Options{API: f, SubscriptionID: "sub-1", Now: func() time.Time { return fixedNow }})

	recs, err := p.Collect(context.Background(), bothReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3 (2 workspaces + 1 activity log)", len(recs))
	}
	// log_group group comes first (Emits() order), then audit_log_trail.
	if recs[0].Type != EvidenceTypeLogGroup || recs[1].Type != EvidenceTypeLogGroup || recs[2].Type != EvidenceTypeAuditLogTrail {
		t.Fatalf("type order wrong: %s, %s, %s", recs[0].Type, recs[1].Type, recs[2].Type)
	}
	for _, r := range recs {
		if r.SourceID != SourceID || !r.CollectedAt.Equal(fixedNow) {
			t.Errorf("record %s: SourceID/CollectedAt = %s/%v", r.ID, r.SourceID, r.CollectedAt)
		}
		if r.Scope == nil || r.Scope.Account != "sub-1" {
			t.Errorf("record %s: scope = %+v", r.ID, r.Scope)
		}
		if r.IdentityKey != "" {
			t.Errorf("record %s: unexpected IdentityKey %q", r.ID, r.IdentityKey)
		}
	}

	// log_group records are sorted by ID — aworkspace before zworkspace.
	var gotLog0 logGroupPayload
	mustUnmarshal(t, recs[0].Payload, &gotLog0)
	wantLog0 := logGroupPayload{
		ID:            *workspaceID("rg-logs", "aworkspace"),
		Name:          "aworkspace",
		Provider:      "azure",
		RetentionSet:  true,
		RetentionDays: 365,
		Location:      "eastus",
		SKU:           "PerGB2018",
		ResourceGroup: "rg-logs",
	}
	if !reflect.DeepEqual(gotLog0, wantLog0) {
		t.Errorf("log_group[0] payload mismatch:\n got  %+v\n want %+v", gotLog0, wantLog0)
	}

	var gotAudit auditTrailPayload
	mustUnmarshal(t, recs[2].Payload, &gotAudit)
	wantAudit := auditTrailPayload{
		ID:                       "/subscriptions/sub-1/providers/Microsoft.Insights/activityLog",
		Name:                     "Azure Activity Log",
		Provider:                 "azure",
		IsEnabled:                true,
		IsMultiRegion:            true,
		LogFileValidationEnabled: true,
		KMSEncrypted:             false,
		Exported:                 true,
		DiagnosticSettingCount:   1,
		EnabledCategories:        []string{"Administrative", "Security"}, // sorted, disabled Alert excluded
		DestinationWorkspaceID:   *workspaceID("rg-logs", "aworkspace"),
	}
	if !reflect.DeepEqual(gotAudit, wantAudit) {
		t.Errorf("audit_log_trail payload mismatch:\n got  %+v\n want %+v", gotAudit, wantAudit)
	}
}

func TestCollect_OnlyLogGroups_SkipsDiagnostics(t *testing.T) {
	f := &fakeAPI{workspaces: []*armoi.Workspace{workspace("rg", "w", "eastus", 0)}}
	recs, err := New(Options{API: f}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeLogGroup}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 || recs[0].Type != EvidenceTypeLogGroup {
		t.Fatalf("expected one log_group record, got %+v", recs)
	}
	if f.dsCalls != 0 {
		t.Errorf("diagnostic settings should not be listed when only log_group is requested, got %d", f.dsCalls)
	}
	// retention 0 → retention_set false.
	var got logGroupPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.RetentionSet || got.RetentionDays != 0 {
		t.Errorf("zero retention should be retention_set=false days=0, got %+v", got)
	}
}

func TestCollect_OnlyAudit_SkipsWorkspaces_NoSettings(t *testing.T) {
	f := &fakeAPI{} // no diagnostic settings configured
	recs, err := New(Options{API: f, SubscriptionID: "sub-9"}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeAuditLogTrail}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 || recs[0].Type != EvidenceTypeAuditLogTrail {
		t.Fatalf("expected one audit_log_trail record, got %+v", recs)
	}
	if f.wsCalls != 0 {
		t.Errorf("workspaces should not be listed when only audit_log_trail is requested, got %d", f.wsCalls)
	}
	// Activity Log is always-on even with no diagnostic settings; just not exported.
	var got auditTrailPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if !got.IsEnabled || !got.IsMultiRegion || !got.LogFileValidationEnabled {
		t.Errorf("Activity Log platform constants should all be true, got %+v", got)
	}
	if got.Exported || got.DiagnosticSettingCount != 0 || got.EnabledCategories != nil {
		t.Errorf("no diagnostic settings should be exported=false count=0 no categories, got %+v", got)
	}
	if got.KMSEncrypted {
		t.Errorf("native Activity Log should report kms_encrypted=false, got %+v", got)
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{
		workspaces: []*armoi.Workspace{nil, workspace("rg", "w", "eastus", 90)},
		settings: []*armmonitor.DiagnosticSettingsResource{
			nil,
			{Name: to.Ptr("no-props")}, // nil Properties
			{Properties: &armmonitor.DiagnosticSettings{Logs: []*armmonitor.LogSettings{nil}}},
		},
	}
	recs, err := New(Options{API: f, SubscriptionID: "sub-1"}).Collect(context.Background(), bothReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 1 workspace + 1 activity log, got %d records", len(recs))
	}
	var got auditTrailPayload
	mustUnmarshal(t, recs[1].Payload, &got)
	if got.Exported {
		t.Errorf("settings with no enabled routed logs should not be exported, got %+v", got)
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	t.Run("workspaces", func(t *testing.T) {
		_, err := New(Options{API: &fakeAPI{wsErr: errors.New("ws boom")}}).Collect(context.Background(), bothReq())
		if err == nil || !strings.Contains(err.Error(), "ws boom") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("diagnostic-settings", func(t *testing.T) {
		_, err := New(Options{API: &fakeAPI{dsErr: errors.New("ds boom")}}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeAuditLogTrail}})
		if err == nil || !strings.Contains(err.Error(), "ds boom") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestCollect_KISSNoDRY_RefetchesEachCollect(t *testing.T) {
	f := &fakeAPI{
		workspaces: []*armoi.Workspace{workspace("rg", "w", "eastus", 30)},
	}
	p := New(Options{API: f, SubscriptionID: "sub-1"})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), bothReq()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if f.wsCalls != 3 || f.dsCalls != 3 {
		t.Errorf("expected 3 workspace + 3 diagnostic-settings calls, got %d + %d", f.wsCalls, f.dsCalls)
	}
}

func TestRetentionDays_Table(t *testing.T) {
	cases := []struct {
		name string
		ws   *armoi.Workspace
		want int
	}{
		{"nil", nil, 0},
		{"nil-props", &armoi.Workspace{}, 0},
		{"nil-retention", &armoi.Workspace{Properties: &armoi.WorkspaceProperties{}}, 0},
		{"zero", &armoi.Workspace{Properties: &armoi.WorkspaceProperties{RetentionInDays: to.Ptr[int32](0)}}, 0},
		{"negative", &armoi.Workspace{Properties: &armoi.WorkspaceProperties{RetentionInDays: to.Ptr[int32](-1)}}, 0},
		{"positive", &armoi.Workspace{Properties: &armoi.WorkspaceProperties{RetentionInDays: to.Ptr[int32](730)}}, 730},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := retentionDays(c.ws); got != c.want {
				t.Errorf("retentionDays = %d, want %d", got, c.want)
			}
		})
	}
}

func TestWorkspaceSKU_NilSafe(t *testing.T) {
	if workspaceSKU(nil) != "" || workspaceSKU(&armoi.Workspace{}) != "" {
		t.Error("nil-safe workspaceSKU should be empty")
	}
	if workspaceSKU(&armoi.Workspace{Properties: &armoi.WorkspaceProperties{SKU: &armoi.WorkspaceSKU{}}}) != "" {
		t.Error("nil SKU name should be empty")
	}
}

func TestSummarizeDiagnosticSettings(t *testing.T) {
	t.Run("storage-destination-exported", func(t *testing.T) {
		exported, _, ws, st := summarizeDiagnosticSettings([]*armmonitor.DiagnosticSettingsResource{{
			Properties: &armmonitor.DiagnosticSettings{
				StorageAccountID: to.Ptr("/subscriptions/s/.../storageAccounts/audit"),
				Logs:             []*armmonitor.LogSettings{logSetting("Administrative", true)},
			},
		}})
		if !exported || ws != "" || st != "/subscriptions/s/.../storageAccounts/audit" {
			t.Errorf("storage route: exported=%v ws=%q st=%q", exported, ws, st)
		}
	})
	t.Run("eventhub-destination-exported", func(t *testing.T) {
		exported, _, _, _ := summarizeDiagnosticSettings([]*armmonitor.DiagnosticSettingsResource{{
			Properties: &armmonitor.DiagnosticSettings{
				EventHubName: to.Ptr("hub"),
				Logs:         []*armmonitor.LogSettings{logSetting("Security", true)},
			},
		}})
		if !exported {
			t.Errorf("event hub route should be exported")
		}
	})
	t.Run("enabled-but-no-destination-not-exported", func(t *testing.T) {
		exported, cats, _, _ := summarizeDiagnosticSettings([]*armmonitor.DiagnosticSettingsResource{{
			Properties: &armmonitor.DiagnosticSettings{Logs: []*armmonitor.LogSettings{logSetting("Policy", true)}},
		}})
		if exported {
			t.Errorf("an enabled log with no destination should not be exported")
		}
		if len(cats) != 1 || cats[0] != "Policy" {
			t.Errorf("category should still be collected, got %v", cats)
		}
	})
	t.Run("category-dedup-sort-and-group-fallback", func(t *testing.T) {
		_, cats, _, _ := summarizeDiagnosticSettings([]*armmonitor.DiagnosticSettingsResource{
			{Properties: &armmonitor.DiagnosticSettings{
				StorageAccountID: to.Ptr("/sa"),
				Logs: []*armmonitor.LogSettings{
					logSetting("Security", true),
					logSetting("Administrative", true),
					{CategoryGroup: to.Ptr("audit"), Enabled: to.Ptr(true)}, // group fallback
				},
			}},
			{Properties: &armmonitor.DiagnosticSettings{
				StorageAccountID: to.Ptr("/sa2"),
				Logs:             []*armmonitor.LogSettings{logSetting("Security", true)}, // dup
			}},
		})
		want := []string{"Administrative", "Security", "audit"}
		if !reflect.DeepEqual(cats, want) {
			t.Errorf("categories = %v, want %v (deduped+sorted, group fallback)", cats, want)
		}
	})
	t.Run("first-workspace-wins", func(t *testing.T) {
		_, _, ws, _ := summarizeDiagnosticSettings([]*armmonitor.DiagnosticSettingsResource{
			{Properties: &armmonitor.DiagnosticSettings{WorkspaceID: to.Ptr("/ws-a"), Logs: []*armmonitor.LogSettings{logSetting("X", true)}}},
			{Properties: &armmonitor.DiagnosticSettings{WorkspaceID: to.Ptr("/ws-b"), Logs: []*armmonitor.LogSettings{logSetting("Y", true)}}},
		})
		if ws != "/ws-a" {
			t.Errorf("first workspace destination should win, got %q", ws)
		}
	})
}

func TestResourceGroupFromID_Table(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.OperationalInsights/workspaces/w", "my-rg"},
		{"/subscriptions/s/resourcegroups/lower/providers/x", "lower"},
		{"/subscriptions/s/providers/x", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := resourceGroupFromID(c.id); got != c.want {
			t.Errorf("resourceGroupFromID(%q) = %q, want %q", c.id, got, c.want)
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

func realMonitorPointedAt(t *testing.T, srv *httptest.Server) *realMonitor {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rm, err := newRealMonitor("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealMonitor: %v", err)
	}
	return rm
}

func TestRealMonitor_ListWorkspacesAndDiagnostics_HappyPath(t *testing.T) {
	wsBody := mustMarshal(t, armoi.WorkspaceListResult{Value: []*armoi.Workspace{
		{Name: to.Ptr("ws1"), ID: workspaceID("rg", "ws1")},
	}})
	dsBody := mustMarshal(t, armmonitor.DiagnosticSettingsResourceCollection{Value: []*armmonitor.DiagnosticSettingsResource{
		{Name: to.Ptr("ds1"), Properties: &armmonitor.DiagnosticSettings{StorageAccountID: to.Ptr("/sa")}},
	}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/workspaces"):
			_, _ = w.Write(wsBody) //nolint:errcheck // test handler
		case strings.Contains(r.URL.Path, "/diagnosticSettings"):
			_, _ = w.Write(dsBody) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rm := realMonitorPointedAt(t, srv)
	t.Run("workspaces", func(t *testing.T) {
		ws, err := rm.ListWorkspaces(context.Background())
		if err != nil || len(ws) != 1 || deref(ws[0].Name) != "ws1" {
			t.Fatalf("ListWorkspaces = %+v, err %v", ws, err)
		}
	})
	t.Run("diagnostic-settings", func(t *testing.T) {
		ds, err := rm.ListSubscriptionDiagnosticSettings(context.Background())
		if err != nil || len(ds) != 1 || deref(ds[0].Name) != "ds1" {
			t.Fatalf("ListSubscriptionDiagnosticSettings = %+v, err %v", ds, err)
		}
	})
}

func TestRealMonitor_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rm := realMonitorPointedAt(t, srv)
	if _, err := rm.ListWorkspaces(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}
