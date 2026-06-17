package sql

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
	armmysql "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	armpg "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

var fixedNow = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

// fakeAPI is the in-memory API seam used by the Collect unit tests.
type fakeAPI struct {
	sqlServers   []*armsql.Server
	sqlDBs       map[string][]*armsql.Database                     // keyed by server name
	tde          map[string]*armsql.TransparentDataEncryptionState // keyed by database name
	pgServers    []*armpg.Server
	mysqlServers []*armmysql.Server

	sqlListErr error
	dbListErr  error
	tdeErr     error
	pgErr      error
	myErr      error

	sqlListCalls int
	dbListCalls  int
	tdeCalls     int
	pgCalls      int
	myCalls      int
}

func (f *fakeAPI) ListSQLServers(context.Context) ([]*armsql.Server, error) {
	f.sqlListCalls++
	if f.sqlListErr != nil {
		return nil, f.sqlListErr
	}
	return f.sqlServers, nil
}

func (f *fakeAPI) ListSQLDatabases(_ context.Context, _, server string) ([]*armsql.Database, error) {
	f.dbListCalls++
	if f.dbListErr != nil {
		return nil, f.dbListErr
	}
	return f.sqlDBs[server], nil
}

func (f *fakeAPI) GetSQLDatabaseTDEState(_ context.Context, _, _, database string) (*armsql.TransparentDataEncryptionState, error) {
	f.tdeCalls++
	if f.tdeErr != nil {
		return nil, f.tdeErr
	}
	return f.tde[database], nil
}

func (f *fakeAPI) ListPostgresServers(context.Context) ([]*armpg.Server, error) {
	f.pgCalls++
	if f.pgErr != nil {
		return nil, f.pgErr
	}
	return f.pgServers, nil
}

func (f *fakeAPI) ListMySQLServers(context.Context) ([]*armmysql.Server, error) {
	f.myCalls++
	if f.myErr != nil {
		return nil, f.myErr
	}
	return f.mysqlServers, nil
}

func acceptReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}
}

func sqlServerID(sub, rg, server string) *string {
	return to.Ptr("/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.Sql/servers/" + server)
}

func sqlDatabaseID(sub, rg, server, db string) *string {
	return to.Ptr("/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.Sql/servers/" + server + "/databases/" + db)
}

func pgServerID(sub, rg, server string) *string {
	return to.Ptr("/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.DBforPostgreSQL/flexibleServers/" + server)
}

func mysqlServerID() *string {
	// The MySQL fixture is a single fixed server (sub-1 / rg-my / mysqlsrv).
	return to.Ptr("/subscriptions/sub-1/resourceGroups/rg-my/providers/Microsoft.DBforMySQL/flexibleServers/mysqlsrv")
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if got := p.ID(); got != "azure.sql" {
		t.Errorf("ID() = %q, want azure.sql", got)
	}
	if got := p.Emits(); len(got) != 1 || got[0] != EvidenceTypeID {
		t.Errorf("Emits() = %v, want [%s]", got, EvidenceTypeID)
	}
}

func TestCollect_RejectsNonEmittedType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), EvidenceTypeID) {
		t.Fatalf("expected rejection error mentioning %s, got %v", EvidenceTypeID, err)
	}
}

func TestCollect_MapsSortsAndFullPayload(t *testing.T) {
	f := &fakeAPI{
		sqlServers: []*armsql.Server{{
			Name:     to.Ptr("sqlsrv"),
			ID:       sqlServerID("sub-1", "rg-sql", "sqlsrv"),
			Location: to.Ptr("eastus"),
			Properties: &armsql.ServerProperties{
				Version:             to.Ptr("12.0"),
				State:               to.Ptr("Ready"),
				MinimalTLSVersion:   to.Ptr("1.2"),
				PublicNetworkAccess: to.Ptr(armsql.ServerNetworkAccessFlagEnabled),
			},
		}},
		sqlDBs: map[string][]*armsql.Database{
			"sqlsrv": {
				{Name: to.Ptr("master"), ID: sqlDatabaseID("sub-1", "rg-sql", "sqlsrv", "master")}, // system DB, skipped
				{Name: to.Ptr("appdb"), ID: sqlDatabaseID("sub-1", "rg-sql", "sqlsrv", "appdb"),
					Properties: &armsql.DatabaseProperties{ZoneRedundant: to.Ptr(true)}},
			},
		},
		tde: map[string]*armsql.TransparentDataEncryptionState{
			"appdb": to.Ptr(armsql.TransparentDataEncryptionStateEnabled),
		},
		pgServers: []*armpg.Server{{
			Name:     to.Ptr("pgsrv"),
			ID:       pgServerID("sub-1", "rg-pg", "pgsrv"),
			Location: to.Ptr("westus"),
			Properties: &armpg.ServerProperties{
				Version:          to.Ptr(armpg.PostgresMajorVersionSixteen),
				Network:          &armpg.Network{PublicNetworkAccess: to.Ptr(armpg.ServerPublicNetworkAccessStateDisabled)},
				HighAvailability: &armpg.HighAvailability{Mode: to.Ptr(armpg.HighAvailabilityModeZoneRedundant)},
				Backup:           &armpg.Backup{BackupRetentionDays: to.Ptr[int32](14)},
				DataEncryption:   &armpg.DataEncryption{Type: to.Ptr(armpg.DataEncryptionTypeAzureKeyVault)},
			},
		}},
		mysqlServers: []*armmysql.Server{{
			Name:     to.Ptr("mysqlsrv"),
			ID:       mysqlServerID(),
			Location: to.Ptr("centralus"),
			Properties: &armmysql.ServerProperties{
				Version:          to.Ptr(armmysql.ServerVersionEight021),
				Network:          &armmysql.Network{PublicNetworkAccess: to.Ptr(armmysql.EnableStatusEnumEnabled)},
				HighAvailability: &armmysql.HighAvailability{Mode: to.Ptr(armmysql.HighAvailabilityModeDisabled)},
				Backup:           &armmysql.Backup{BackupRetentionDays: to.Ptr[int32](7)},
				DataEncryption:   &armmysql.DataEncryption{Type: to.Ptr(armmysql.DataEncryptionTypeSystemManaged)},
			},
		}},
	}
	p := New(Options{API: f, SubscriptionID: "sub-1", Now: func() time.Time { return fixedNow }})

	recs, err := p.Collect(context.Background(), acceptReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3 (master DB must be skipped)", len(recs))
	}
	// Sorted by ARM resource id: rg-my (mysql) < rg-pg (postgres) < rg-sql (sql).
	if recs[0].ID != *mysqlServerID() ||
		recs[1].ID != *pgServerID("sub-1", "rg-pg", "pgsrv") ||
		recs[2].ID != *sqlDatabaseID("sub-1", "rg-sql", "sqlsrv", "appdb") {
		t.Fatalf("records not sorted by ID: %s, %s, %s", recs[0].ID, recs[1].ID, recs[2].ID)
	}
	for _, r := range recs {
		if r.Type != EvidenceTypeID || r.SourceID != SourceID {
			t.Errorf("record %s: Type/SourceID = %s/%s", r.ID, r.Type, r.SourceID)
		}
		if !r.CollectedAt.Equal(fixedNow) {
			t.Errorf("record %s: CollectedAt = %v", r.ID, r.CollectedAt)
		}
		if r.Scope == nil || r.Scope.Account != "sub-1" {
			t.Errorf("record %s: scope = %+v", r.ID, r.Scope)
		}
		if r.IdentityKey != "" {
			t.Errorf("record %s: unexpected IdentityKey %q", r.ID, r.IdentityKey)
		}
	}

	wantMySQL := instancePayload{
		ID:                  *mysqlServerID(),
		Name:                "mysqlsrv",
		Provider:            "azure",
		Engine:              "mysql",
		EngineVersion:       "8.0.21",
		StorageEncrypted:    true,
		PubliclyAccessible:  true,
		BackupEnabled:       true,
		MultiAZ:             false,
		DeletionProtection:  false,
		Location:            "centralus",
		PublicNetworkAccess: "Enabled",
		BackupRetentionDays: 7,
	}
	wantPG := instancePayload{
		ID:                  *pgServerID("sub-1", "rg-pg", "pgsrv"),
		Name:                "pgsrv",
		Provider:            "azure",
		Engine:              "postgres",
		EngineVersion:       "16",
		StorageEncrypted:    true,
		PubliclyAccessible:  false,
		BackupEnabled:       true,
		MultiAZ:             true,
		DeletionProtection:  false,
		Location:            "westus",
		PublicNetworkAccess: "Disabled",
		BackupRetentionDays: 14,
		CMEKEnabled:         true,
	}
	wantSQL := instancePayload{
		ID:                  *sqlDatabaseID("sub-1", "rg-sql", "sqlsrv", "appdb"),
		Name:                "sqlsrv/appdb",
		Provider:            "azure",
		Engine:              "sqlserver",
		EngineVersion:       "12.0",
		StorageEncrypted:    true,
		PubliclyAccessible:  true,
		BackupEnabled:       true,
		SSLRequired:         to.Ptr(true),
		MultiAZ:             true,
		DeletionProtection:  false,
		Location:            "eastus",
		State:               "Ready",
		PublicNetworkAccess: "Enabled",
		MinimumTLSVersion:   "1.2",
	}
	assertPayload(t, recs[0].Payload, &wantMySQL)
	assertPayload(t, recs[1].Payload, &wantPG)
	assertPayload(t, recs[2].Payload, &wantSQL)
}

func assertPayload(t *testing.T, raw json.RawMessage, want *instancePayload) {
	t.Helper()
	var got instancePayload
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if !reflect.DeepEqual(got, *want) {
		t.Errorf("payload mismatch:\n got  %+v\n want %+v", got, *want)
	}
}

func TestCollect_SQLDisabledTDE_StorageNotEncrypted(t *testing.T) {
	f := &fakeAPI{
		sqlServers: []*armsql.Server{{Name: to.Ptr("s"), ID: sqlServerID("sub", "rg", "s"), Properties: &armsql.ServerProperties{}}},
		sqlDBs:     map[string][]*armsql.Database{"s": {{Name: to.Ptr("db"), ID: sqlDatabaseID("sub", "rg", "s", "db")}}},
		tde:        map[string]*armsql.TransparentDataEncryptionState{"db": to.Ptr(armsql.TransparentDataEncryptionStateDisabled)},
	}
	recs, err := New(Options{API: f}).Collect(context.Background(), acceptReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got instancePayload
	if err := json.Unmarshal(recs[0].Payload, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.StorageEncrypted {
		t.Error("disabled TDE should yield storage_encrypted=false")
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{
		sqlServers:   []*armsql.Server{nil},
		pgServers:    []*armpg.Server{nil, {Name: to.Ptr("pg"), ID: pgServerID("s", "rg", "pg"), Properties: &armpg.ServerProperties{}}},
		mysqlServers: []*armmysql.Server{nil},
	}
	recs, err := New(Options{API: f}).Collect(context.Background(), acceptReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != *pgServerID("s", "rg", "pg") {
		t.Fatalf("expected one pg record, got %+v", recs)
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	sqlSrv := []*armsql.Server{{Name: to.Ptr("s"), ID: sqlServerID("sub", "rg", "s"), Properties: &armsql.ServerProperties{}}}
	sqlDBs := map[string][]*armsql.Database{"s": {{Name: to.Ptr("db"), ID: sqlDatabaseID("sub", "rg", "s", "db")}}}
	cases := []struct {
		name string
		f    *fakeAPI
	}{
		{"sql-list", &fakeAPI{sqlListErr: errors.New("sql boom")}},
		{"db-list", &fakeAPI{sqlServers: sqlSrv, dbListErr: errors.New("db boom")}},
		{"tde", &fakeAPI{sqlServers: sqlSrv, sqlDBs: sqlDBs, tdeErr: errors.New("tde boom")}},
		{"pg-list", &fakeAPI{pgErr: errors.New("pg boom")}},
		{"mysql-list", &fakeAPI{myErr: errors.New("mysql boom")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(Options{API: c.f}).Collect(context.Background(), acceptReq())
			if err == nil || !strings.Contains(err.Error(), "boom") {
				t.Fatalf("expected error to propagate, got %v", err)
			}
		})
	}
}

func TestCollect_BadResourceGroupID(t *testing.T) {
	f := &fakeAPI{sqlServers: []*armsql.Server{{Name: to.Ptr("s"), ID: to.Ptr("/subscriptions/s/providers/x")}}}
	_, err := New(Options{API: f}).Collect(context.Background(), acceptReq())
	if err == nil || !strings.Contains(err.Error(), "resourceGroups") {
		t.Fatalf("expected resource-group parse error, got %v", err)
	}
}

func TestCollect_KISSNoDRY_RefetchesEachCollect(t *testing.T) {
	f := &fakeAPI{
		sqlServers: []*armsql.Server{{Name: to.Ptr("s"), ID: sqlServerID("sub", "rg", "s"), Properties: &armsql.ServerProperties{}}},
		sqlDBs:     map[string][]*armsql.Database{"s": {{Name: to.Ptr("db"), ID: sqlDatabaseID("sub", "rg", "s", "db")}}},
		tde:        map[string]*armsql.TransparentDataEncryptionState{"db": to.Ptr(armsql.TransparentDataEncryptionStateEnabled)},
	}
	p := New(Options{API: f})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), acceptReq()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if f.sqlListCalls != 3 || f.dbListCalls != 3 || f.tdeCalls != 3 || f.pgCalls != 3 || f.myCalls != 3 {
		t.Errorf("expected 3 calls each, got sql=%d db=%d tde=%d pg=%d my=%d",
			f.sqlListCalls, f.dbListCalls, f.tdeCalls, f.pgCalls, f.myCalls)
	}
}

func TestTDEEnabled_Table(t *testing.T) {
	cases := []struct {
		name string
		in   *armsql.TransparentDataEncryptionState
		want bool
	}{
		{"nil", nil, false},
		{"enabled", to.Ptr(armsql.TransparentDataEncryptionStateEnabled), true},
		{"disabled", to.Ptr(armsql.TransparentDataEncryptionStateDisabled), false},
	}
	for _, c := range cases {
		if got := tdeEnabled(c.in); got != c.want {
			t.Errorf("%s: tdeEnabled = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSQLPublicAccess_Table(t *testing.T) {
	cases := []struct {
		name       string
		srv        *armsql.Server
		wantAccess bool
		wantRaw    string
	}{
		{"nil-server", nil, false, ""},
		{"nil-props", &armsql.Server{}, false, ""},
		{"enabled", &armsql.Server{Properties: &armsql.ServerProperties{PublicNetworkAccess: to.Ptr(armsql.ServerNetworkAccessFlagEnabled)}}, true, "Enabled"},
		{"disabled", &armsql.Server{Properties: &armsql.ServerProperties{PublicNetworkAccess: to.Ptr(armsql.ServerNetworkAccessFlagDisabled)}}, false, "Disabled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			access, raw := sqlPublicAccess(c.srv)
			if access != c.wantAccess || raw != c.wantRaw {
				t.Errorf("sqlPublicAccess = (%v,%q), want (%v,%q)", access, raw, c.wantAccess, c.wantRaw)
			}
		})
	}
}

func TestZoneRedundancyAndCMEK_NilSafe(t *testing.T) {
	if sqlZoneRedundant(nil) || sqlZoneRedundant(&armsql.Database{}) {
		t.Error("nil-safe sqlZoneRedundant should be false")
	}
	if pgZoneRedundant(nil) || pgZoneRedundant(&armpg.Server{}) || pgCMEK(nil) || pgCMEK(&armpg.Server{}) {
		t.Error("nil-safe pg helpers should be false")
	}
	if mysqlZoneRedundant(nil) || mysqlZoneRedundant(&armmysql.Server{}) || mysqlCMEK(nil) || mysqlCMEK(&armmysql.Server{}) {
		t.Error("nil-safe mysql helpers should be false")
	}
	if pgBackupRetention(&armpg.Server{}) != 0 || mysqlBackupRetention(&armmysql.Server{}) != 0 {
		t.Error("nil-safe backup-retention should be 0")
	}
	if pgVersion(&armpg.Server{}) != "" || mysqlVersion(&armmysql.Server{}) != "" {
		t.Error("nil-safe version should be empty")
	}
}

func TestResourceGroupFromID_Table(t *testing.T) {
	cases := []struct {
		id      string
		want    string
		wantErr bool
	}{
		{"/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.Sql/servers/x", "my-rg", false},
		{"/subscriptions/s/resourcegroups/lower-rg/providers/x", "lower-rg", false}, // case-insensitive
		{"/subscriptions/s/providers/x", "", true},
		{"", "", true},
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

func realSQLPointedAt(t *testing.T, srv *httptest.Server) *realSQL {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rs, err := newRealSQL("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealSQL: %v", err)
	}
	return rs
}

func TestRealSQL_AllServices_HappyPath(t *testing.T) {
	sqlServersBody := mustMarshal(t, armsql.ServerListResult{Value: []*armsql.Server{
		{Name: to.Ptr("sqlsrv"), ID: sqlServerID("sub-1", "rg-sql", "sqlsrv")},
	}})
	dbsBody := mustMarshal(t, armsql.DatabaseListResult{Value: []*armsql.Database{
		{Name: to.Ptr("appdb"), ID: sqlDatabaseID("sub-1", "rg-sql", "sqlsrv", "appdb")},
	}})
	tdeBody := mustMarshal(t, armsql.LogicalDatabaseTransparentDataEncryption{
		Properties: &armsql.TransparentDataEncryptionProperties{State: to.Ptr(armsql.TransparentDataEncryptionStateEnabled)},
	})
	pgBody := mustMarshal(t, armpg.ServerList{Value: []*armpg.Server{
		{Name: to.Ptr("pgsrv"), ID: pgServerID("sub-1", "rg-pg", "pgsrv")},
	}})
	myBody := mustMarshal(t, armmysql.ServerListResult{Value: []*armmysql.Server{
		{Name: to.Ptr("mysqlsrv"), ID: mysqlServerID()},
	}})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.Contains(path, "/transparentDataEncryption"):
			_, _ = w.Write(tdeBody) //nolint:errcheck // test handler
		case strings.Contains(path, "/databases"):
			_, _ = w.Write(dbsBody) //nolint:errcheck // test handler
		case strings.Contains(path, "Microsoft.Sql/servers"):
			_, _ = w.Write(sqlServersBody) //nolint:errcheck // test handler
		case strings.Contains(path, "Microsoft.DBforPostgreSQL"):
			_, _ = w.Write(pgBody) //nolint:errcheck // test handler
		case strings.Contains(path, "Microsoft.DBforMySQL"):
			_, _ = w.Write(myBody) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected path: %s", path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rs := realSQLPointedAt(t, srv)
	ctx := context.Background()

	// assertSingle fails unless exactly one name was returned and it matches.
	assertSingle := func(t *testing.T, want string, got []string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("call error: %v", err)
		}
		if len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, want [%s]", got, want)
		}
	}

	t.Run("sql-servers", func(t *testing.T) {
		v, err := rs.ListSQLServers(ctx)
		got := make([]string, len(v))
		for i := range v {
			got[i] = deref(v[i].Name)
		}
		assertSingle(t, "sqlsrv", got, err)
	})
	t.Run("sql-databases", func(t *testing.T) {
		v, err := rs.ListSQLDatabases(ctx, "rg-sql", "sqlsrv")
		got := make([]string, len(v))
		for i := range v {
			got[i] = deref(v[i].Name)
		}
		assertSingle(t, "appdb", got, err)
	})
	t.Run("pg-servers", func(t *testing.T) {
		v, err := rs.ListPostgresServers(ctx)
		got := make([]string, len(v))
		for i := range v {
			got[i] = deref(v[i].Name)
		}
		assertSingle(t, "pgsrv", got, err)
	})
	t.Run("mysql-servers", func(t *testing.T) {
		v, err := rs.ListMySQLServers(ctx)
		got := make([]string, len(v))
		for i := range v {
			got[i] = deref(v[i].Name)
		}
		assertSingle(t, "mysqlsrv", got, err)
	})
	t.Run("tde", func(t *testing.T) {
		state, err := rs.GetSQLDatabaseTDEState(ctx, "rg-sql", "sqlsrv", "appdb")
		if err != nil || !tdeEnabled(state) {
			t.Fatalf("GetSQLDatabaseTDEState = %v, err %v", state, err)
		}
	})
}

func TestRealSQL_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rs := realSQLPointedAt(t, srv)
	if _, err := rs.ListSQLServers(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}
