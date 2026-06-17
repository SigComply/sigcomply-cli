// Package sql implements the azure.sql source plugin: it enumerates Azure's
// three managed relational-database services in a subscription and emits one
// cross-vendor managed_database_instance record per database/server, so
// encryption-at-rest, public-access, backup, SSL, and multi-AZ policies
// evaluate against Azure exactly as they do against AWS RDS and GCP Cloud SQL —
// zero policy changes (Invariant #4, substitutability).
//
// Three families, one plugin (mirrors aws.rds covering every engine):
//
//   - Azure SQL (armsql): one record per database, excluding the `master`
//     system database. Transparent Data Encryption (TDE) is per-database, so
//     this family is an N+1+1 walk — list servers, list databases per server,
//     GET TDE state per database.
//   - PostgreSQL Flexible Server (armpostgresqlflexibleservers): one record per
//     server.
//   - MySQL Flexible Server (armmysqlflexibleservers): one record per server.
//
// Honest mappings (the plugin owns 100% of the vendor→canonical translation):
//
//   - storage_encrypted: a REAL toggle for Azure SQL (TDE can be disabled per
//     database), but a platform CONSTANT true for the flexible servers (their
//     at-rest encryption is always-on and cannot be disabled — Microsoft-
//     managed by default, optionally CMEK; the cmek_enabled extra carries that
//     distinction).
//   - backup_enabled: true for all three — Azure SQL Database always retains
//     automated point-in-time backups (cannot be disabled), and the flexible
//     servers always run automated backups (BackupRetentionDays has a 7-day
//     floor). The backup_retention_days extra makes that auditable.
//   - publicly_accessible: from the SERVER-level public-network-access flag
//     (it gates every database on an Azure SQL logical server).
//   - ssl_required: emitted as true ONLY for Azure SQL, which enforces
//     encrypted connections unconditionally. For the flexible servers SSL
//     enforcement is a server PARAMETER (require_secure_transport / ssl), not a
//     ServerProperties field; rather than fabricate a value the field is
//     OMITTED, so the is_set-guarded SSL policy skips those records instead of
//     false-failing them.
//   - deletion_protection: false for every Azure managed database — none expose
//     a deletion-protection property. The Azure mechanism is an ARM resource
//     lock (CanNotDelete), which is not a database property and is not read
//     here; customers cover that control via a resource lock + an exception or
//     manual evidence.
//
// A list/GET failure (e.g. a missing-permission 403) is surfaced as an error
// rather than silently reporting an insecure default, which would be misleading
// false-fail evidence; the error tags only the azure.sql-bound policies
// `error`, not a run crash.
//
// Test injection: the API interface is the single seam and returns raw SDK
// types so 100% of the vendor→canonical mapping stays in Collect under fakeAPI
// unit tests; the real adapter (realSQL) wraps the armsql / armpostgresql /
// armmysql SDK clients. Real-adapter HTTP behavior is covered with httptest;
// deeper integration coverage is deferred to the testing strategy revamp.
package sql

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armmysql "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	armpg "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// EvidenceTypeID is the cross-vendor managed_database_instance shape. Azure's
// managed databases are substitutable sources alongside AWS RDS and GCP Cloud
// SQL.
const EvidenceTypeID = "managed_database_instance"

// SourceID is the registered ID for the azure.sql plugin instance.
const SourceID = "azure.sql"

// API is the subset of the Azure management plane this plugin uses across the
// three managed-database services. It returns raw SDK types so the
// vendor→canonical mapping is exercised by fakeAPI unit tests; the real adapter
// (realSQL) wraps the armsql / armpostgresql / armmysql clients.
type API interface {
	// ListSQLServers returns every Azure SQL logical server in the subscription.
	ListSQLServers(ctx context.Context) ([]*armsql.Server, error)
	// ListSQLDatabases returns the databases on one Azure SQL server (includes
	// the `master` system database; the caller filters it out).
	ListSQLDatabases(ctx context.Context, resourceGroup, server string) ([]*armsql.Database, error)
	// GetSQLDatabaseTDEState returns the current Transparent Data Encryption
	// state for one database, nil when unavailable.
	GetSQLDatabaseTDEState(ctx context.Context, resourceGroup, server, database string) (*armsql.TransparentDataEncryptionState, error)
	// ListPostgresServers returns every PostgreSQL Flexible Server in the subscription.
	ListPostgresServers(ctx context.Context) ([]*armpg.Server, error)
	// ListMySQLServers returns every MySQL Flexible Server in the subscription.
	ListMySQLServers(ctx context.Context) ([]*armmysql.Server, error)
}

// Plugin is the in-process azure.sql source.
type Plugin struct {
	api            API
	subscriptionID string
	now            func() time.Time
}

// Options is the constructor input.
type Options struct {
	API            API
	SubscriptionID string
	// Now is injected so tests can produce deterministic CollectedAt values.
	// Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers using
// the real Azure SDK should use NewFromAzure.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:            opts.API,
		subscriptionID: opts.SubscriptionID,
		now:            now,
	}
}

// NewFromAzure constructs a Plugin backed by the real Azure SDK clients using
// the given credential (a DefaultAzureCredential) scoped to cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealSQL(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return New(Options{API: adapter, SubscriptionID: cfg.SubscriptionID}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// instancePayload is the managed_database_instance shape this plugin emits. The
// schema-required fields (id, name, storage_encrypted, publicly_accessible,
// backup_enabled) plus multi_az and deletion_protection (read by policies
// without an is_set guard) are always present. ssl_required is a pointer:
// omitted when the source cannot determine in-transit-encryption enforcement
// (the is_set-guarded policy then skips the record). The Azure posture fields
// are additionalProperties (the schema allows them) that make the derivations
// auditable.
type instancePayload struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Provider           string `json:"provider"`
	Engine             string `json:"engine,omitempty"`
	EngineVersion      string `json:"engine_version,omitempty"`
	StorageEncrypted   bool   `json:"storage_encrypted"`
	PubliclyAccessible bool   `json:"publicly_accessible"`
	BackupEnabled      bool   `json:"backup_enabled"`
	SSLRequired        *bool  `json:"ssl_required,omitempty"`
	MultiAZ            bool   `json:"multi_az"`
	DeletionProtection bool   `json:"deletion_protection"`
	KMSKeyID           string `json:"kms_key_id,omitempty"`

	// Auditable Azure extras (additionalProperties).
	Location            string `json:"location,omitempty"`
	State               string `json:"state,omitempty"`
	PublicNetworkAccess string `json:"public_network_access,omitempty"`
	BackupRetentionDays int32  `json:"backup_retention_days,omitempty"`
	CMEKEnabled         bool   `json:"cmek_enabled,omitempty"`
	MinimumTLSVersion   string `json:"minimum_tls_version,omitempty"`
}

// Collect enumerates Azure SQL databases plus PostgreSQL/MySQL flexible servers
// in the configured subscription and emits one managed_database_instance record
// each, sorted by ID (ARM resource id) so envelope bytes are stable across runs
// against stable state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("azure.sql: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()

	var records []core.EvidenceRecord
	sqlRecs, err := p.collectSQL(ctx, now, scope)
	if err != nil {
		return nil, err
	}
	records = append(records, sqlRecs...)
	pgRecs, err := p.collectPostgres(ctx, now, scope)
	if err != nil {
		return nil, err
	}
	records = append(records, pgRecs...)
	myRecs, err := p.collectMySQL(ctx, now, scope)
	if err != nil {
		return nil, err
	}
	records = append(records, myRecs...)

	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// collectSQL walks Azure SQL servers → databases → TDE, emitting one record per
// non-system database.
func (p *Plugin) collectSQL(ctx context.Context, now time.Time, scope *core.RecordScope) ([]core.EvidenceRecord, error) {
	servers, err := p.api.ListSQLServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.sql: list sql servers: %w", err)
	}
	var records []core.EvidenceRecord
	for _, srv := range servers {
		if srv == nil {
			continue
		}
		serverName := deref(srv.Name)
		rg, err := resourceGroupFromID(deref(srv.ID))
		if err != nil {
			return nil, fmt.Errorf("azure.sql: server %q: %w", serverName, err)
		}
		pubAccess, pubRaw := sqlPublicAccess(srv)
		dbs, err := p.api.ListSQLDatabases(ctx, rg, serverName)
		if err != nil {
			return nil, fmt.Errorf("azure.sql: list databases for %q: %w", serverName, err)
		}
		for _, db := range dbs {
			if db == nil {
				continue
			}
			dbName := deref(db.Name)
			if strings.EqualFold(dbName, "master") {
				continue // system database, not a customer workload
			}
			tde, err := p.api.GetSQLDatabaseTDEState(ctx, rg, serverName, dbName)
			if err != nil {
				return nil, fmt.Errorf("azure.sql: TDE for %q/%q: %w", serverName, dbName, err)
			}
			payload := instancePayload{
				ID:                  deref(db.ID),
				Name:                serverName + "/" + dbName,
				Provider:            "azure",
				Engine:              "sqlserver",
				EngineVersion:       sqlServerVersion(srv),
				StorageEncrypted:    tdeEnabled(tde),
				PubliclyAccessible:  pubAccess,
				BackupEnabled:       true,          // Azure SQL Database always retains automated PITR backups.
				SSLRequired:         boolPtr(true), // Azure SQL enforces encrypted connections unconditionally.
				MultiAZ:             sqlZoneRedundant(db),
				DeletionProtection:  false, // no DB-level property; ARM resource lock (not read here) is the mechanism.
				Location:            deref(srv.Location),
				State:               sqlServerState(srv),
				PublicNetworkAccess: pubRaw,
				MinimumTLSVersion:   sqlMinimumTLS(srv),
			}
			rec, err := record(&payload, deref(db.ID), now, scope)
			if err != nil {
				return nil, err
			}
			records = append(records, rec)
		}
	}
	return records, nil
}

// collectPostgres emits one record per PostgreSQL Flexible Server.
func (p *Plugin) collectPostgres(ctx context.Context, now time.Time, scope *core.RecordScope) ([]core.EvidenceRecord, error) {
	servers, err := p.api.ListPostgresServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.sql: list postgres servers: %w", err)
	}
	var records []core.EvidenceRecord
	for _, srv := range servers {
		if srv == nil {
			continue
		}
		pubAccess, pubRaw := pgPublicAccess(srv)
		payload := instancePayload{
			ID:                 deref(srv.ID),
			Name:               deref(srv.Name),
			Provider:           "azure",
			Engine:             "postgres",
			EngineVersion:      pgVersion(srv),
			StorageEncrypted:   true, // flexible-server at-rest encryption is always-on.
			PubliclyAccessible: pubAccess,
			BackupEnabled:      true, // flexible servers always run automated backups.
			// SSLRequired omitted: TLS enforcement is a server parameter, not a ServerProperties field.
			MultiAZ:             pgZoneRedundant(srv),
			DeletionProtection:  false, // no flexible-server deletion-protection property.
			Location:            deref(srv.Location),
			PublicNetworkAccess: pubRaw,
			BackupRetentionDays: pgBackupRetention(srv),
			CMEKEnabled:         pgCMEK(srv),
		}
		rec, err := record(&payload, deref(srv.ID), now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

// collectMySQL emits one record per MySQL Flexible Server.
func (p *Plugin) collectMySQL(ctx context.Context, now time.Time, scope *core.RecordScope) ([]core.EvidenceRecord, error) {
	servers, err := p.api.ListMySQLServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.sql: list mysql servers: %w", err)
	}
	var records []core.EvidenceRecord
	for _, srv := range servers {
		if srv == nil {
			continue
		}
		pubAccess, pubRaw := mysqlPublicAccess(srv)
		payload := instancePayload{
			ID:                 deref(srv.ID),
			Name:               deref(srv.Name),
			Provider:           "azure",
			Engine:             "mysql",
			EngineVersion:      mysqlVersion(srv),
			StorageEncrypted:   true, // flexible-server at-rest encryption is always-on.
			PubliclyAccessible: pubAccess,
			BackupEnabled:      true, // flexible servers always run automated backups.
			// SSLRequired omitted: TLS enforcement is a server parameter, not a ServerProperties field.
			MultiAZ:             mysqlZoneRedundant(srv),
			DeletionProtection:  false, // no flexible-server deletion-protection property.
			Location:            deref(srv.Location),
			PublicNetworkAccess: pubRaw,
			BackupRetentionDays: mysqlBackupRetention(srv),
			CMEKEnabled:         mysqlCMEK(srv),
		}
		rec, err := record(&payload, deref(srv.ID), now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

// record marshals a payload into an EvidenceRecord. id is the ARM resource id,
// used as the stable sort key.
func record(payload *instancePayload, id string, now time.Time, scope *core.RecordScope) (core.EvidenceRecord, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("azure.sql: marshal payload for %q: %w", id, err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeID,
		ID:          id,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
		Scope:       scope,
	}, nil
}

// --- pure mapping helpers (unit-tested via table tests) ---

// resourceGroupFromID extracts the resource group from an ARM resource id of
// the form /subscriptions/{sub}/resourceGroups/{rg}/providers/... . The match
// is case-insensitive because ARM sometimes returns "resourcegroups".
func resourceGroupFromID(id string) (string, error) {
	parts := strings.Split(id, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			if rg := parts[i+1]; rg != "" {
				return rg, nil
			}
		}
	}
	return "", fmt.Errorf("no resourceGroups segment in id %q", id)
}

// tdeEnabled reports whether a database's TDE state is Enabled, nil-safe.
func tdeEnabled(s *armsql.TransparentDataEncryptionState) bool {
	return s != nil && *s == armsql.TransparentDataEncryptionStateEnabled
}

// --- Azure SQL nil-safe accessors ---

func sqlPublicAccess(srv *armsql.Server) (blocked bool, raw string) {
	if srv == nil || srv.Properties == nil || srv.Properties.PublicNetworkAccess == nil {
		return false, ""
	}
	v := *srv.Properties.PublicNetworkAccess
	return v == armsql.ServerNetworkAccessFlagEnabled, string(v)
}

func sqlServerVersion(srv *armsql.Server) string {
	if srv == nil || srv.Properties == nil {
		return ""
	}
	return deref(srv.Properties.Version)
}

func sqlServerState(srv *armsql.Server) string {
	if srv == nil || srv.Properties == nil {
		return ""
	}
	return deref(srv.Properties.State)
}

func sqlMinimumTLS(srv *armsql.Server) string {
	if srv == nil || srv.Properties == nil {
		return ""
	}
	return deref(srv.Properties.MinimalTLSVersion)
}

func sqlZoneRedundant(db *armsql.Database) bool {
	if db == nil || db.Properties == nil || db.Properties.ZoneRedundant == nil {
		return false
	}
	return *db.Properties.ZoneRedundant
}

// --- PostgreSQL Flexible Server nil-safe accessors ---

func pgVersion(srv *armpg.Server) string {
	if srv == nil || srv.Properties == nil || srv.Properties.Version == nil {
		return ""
	}
	return string(*srv.Properties.Version)
}

func pgPublicAccess(srv *armpg.Server) (accessible bool, raw string) {
	if srv == nil || srv.Properties == nil || srv.Properties.Network == nil || srv.Properties.Network.PublicNetworkAccess == nil {
		return false, ""
	}
	v := *srv.Properties.Network.PublicNetworkAccess
	return v == armpg.ServerPublicNetworkAccessStateEnabled, string(v)
}

func pgZoneRedundant(srv *armpg.Server) bool {
	if srv == nil || srv.Properties == nil || srv.Properties.HighAvailability == nil || srv.Properties.HighAvailability.Mode == nil {
		return false
	}
	return *srv.Properties.HighAvailability.Mode == armpg.HighAvailabilityModeZoneRedundant
}

func pgBackupRetention(srv *armpg.Server) int32 {
	if srv == nil || srv.Properties == nil || srv.Properties.Backup == nil || srv.Properties.Backup.BackupRetentionDays == nil {
		return 0
	}
	return *srv.Properties.Backup.BackupRetentionDays
}

func pgCMEK(srv *armpg.Server) bool {
	if srv == nil || srv.Properties == nil || srv.Properties.DataEncryption == nil || srv.Properties.DataEncryption.Type == nil {
		return false
	}
	return *srv.Properties.DataEncryption.Type == armpg.DataEncryptionTypeAzureKeyVault
}

// --- MySQL Flexible Server nil-safe accessors ---

func mysqlVersion(srv *armmysql.Server) string {
	if srv == nil || srv.Properties == nil || srv.Properties.Version == nil {
		return ""
	}
	return string(*srv.Properties.Version)
}

func mysqlPublicAccess(srv *armmysql.Server) (accessible bool, raw string) {
	if srv == nil || srv.Properties == nil || srv.Properties.Network == nil || srv.Properties.Network.PublicNetworkAccess == nil {
		return false, ""
	}
	v := *srv.Properties.Network.PublicNetworkAccess
	return v == armmysql.EnableStatusEnumEnabled, string(v)
}

func mysqlZoneRedundant(srv *armmysql.Server) bool {
	if srv == nil || srv.Properties == nil || srv.Properties.HighAvailability == nil || srv.Properties.HighAvailability.Mode == nil {
		return false
	}
	return *srv.Properties.HighAvailability.Mode == armmysql.HighAvailabilityModeZoneRedundant
}

func mysqlBackupRetention(srv *armmysql.Server) int32 {
	if srv == nil || srv.Properties == nil || srv.Properties.Backup == nil || srv.Properties.Backup.BackupRetentionDays == nil {
		return 0
	}
	return *srv.Properties.Backup.BackupRetentionDays
}

func mysqlCMEK(srv *armmysql.Server) bool {
	if srv == nil || srv.Properties == nil || srv.Properties.DataEncryption == nil || srv.Properties.DataEncryption.Type == nil {
		return false
	}
	return *srv.Properties.DataEncryption.Type == armmysql.DataEncryptionTypeAzureKeyVault
}

func boolPtr(b bool) *bool { return &b }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// --- real Azure adapter ---

// realSQL is the production implementation of API. It wraps the subscription-
// wide list clients for the three managed-database services plus the Azure SQL
// per-database TDE client.
type realSQL struct {
	sqlServers   *armsql.ServersClient
	sqlDatabases *armsql.DatabasesClient
	sqlTDE       *armsql.TransparentDataEncryptionsClient
	pgServers    *armpg.ServersClient
	mysqlServers *armmysql.ServersClient
}

// newRealSQL builds the SDK clients. opts is nil in production; tests pass a
// *arm.ClientOptions pointing the clients at an httptest server.
func newRealSQL(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realSQL, error) {
	sqlServers, err := armsql.NewServersClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.sql: sql servers client: %w", err)
	}
	sqlDatabases, err := armsql.NewDatabasesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.sql: sql databases client: %w", err)
	}
	sqlTDE, err := armsql.NewTransparentDataEncryptionsClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.sql: sql tde client: %w", err)
	}
	pgServers, err := armpg.NewServersClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.sql: postgres servers client: %w", err)
	}
	mysqlServers, err := armmysql.NewServersClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.sql: mysql servers client: %w", err)
	}
	return &realSQL{
		sqlServers:   sqlServers,
		sqlDatabases: sqlDatabases,
		sqlTDE:       sqlTDE,
		pgServers:    pgServers,
		mysqlServers: mysqlServers,
	}, nil
}

func (r *realSQL) ListSQLServers(ctx context.Context) ([]*armsql.Server, error) {
	var out []*armsql.Server
	pager := r.sqlServers.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realSQL) ListSQLDatabases(ctx context.Context, resourceGroup, server string) ([]*armsql.Database, error) {
	var out []*armsql.Database
	pager := r.sqlDatabases.NewListByServerPager(resourceGroup, server, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realSQL) GetSQLDatabaseTDEState(ctx context.Context, resourceGroup, server, database string) (*armsql.TransparentDataEncryptionState, error) {
	resp, err := r.sqlTDE.Get(ctx, resourceGroup, server, database, armsql.TransparentDataEncryptionNameCurrent, nil)
	if err != nil {
		return nil, err
	}
	if resp.Properties == nil {
		return nil, nil
	}
	return resp.Properties.State, nil
}

func (r *realSQL) ListPostgresServers(ctx context.Context) ([]*armpg.Server, error) {
	var out []*armpg.Server
	// PostgreSQL's subscription-wide pager is NewListBySubscriptionPager (SQL
	// and MySQL both name the equivalent NewListPager — an SDK inconsistency).
	pager := r.pgServers.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realSQL) ListMySQLServers(ctx context.Context) ([]*armmysql.Server, error) {
	var out []*armmysql.Server
	pager := r.mysqlServers.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
