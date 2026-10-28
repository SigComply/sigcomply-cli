// Package rds implements the aws.rds source plugin: lists RDS DB instances
// and emits managed_database_instance evidence records with cross-vendor
// encryption, access, backup, and redundancy attributes.
package rds

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	awsrds "github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awscfg"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "managed_database_instance"

// SourceID is the registered ID for the aws.rds plugin instance.
const SourceID = "aws.rds"

// API is the subset of the RDS client this plugin uses.
type API interface {
	DescribeDBInstances(ctx context.Context, params *awsrds.DescribeDBInstancesInput, optFns ...func(*awsrds.Options)) (*awsrds.DescribeDBInstancesOutput, error)
	DescribeDBParameters(ctx context.Context, params *awsrds.DescribeDBParametersInput, optFns ...func(*awsrds.Options)) (*awsrds.DescribeDBParametersOutput, error)
	// Aurora instances belong to a DB cluster that owns their deletion
	// protection, Multi-AZ, backup, encryption and TLS settings.
	DescribeDBClusters(ctx context.Context, params *awsrds.DescribeDBClustersInput, optFns ...func(*awsrds.Options)) (*awsrds.DescribeDBClustersOutput, error)
	DescribeDBClusterParameters(ctx context.Context, params *awsrds.DescribeDBClusterParametersInput, optFns ...func(*awsrds.Options)) (*awsrds.DescribeDBClusterParametersOutput, error)
}

// Plugin is the in-process aws.rds source.
type Plugin struct {
	api    API
	region string
	now    func() time.Time
}

// Options is the constructor input.
type Options struct {
	API    API
	Region string
	Now    func() time.Time
}

// New constructs a Plugin around an explicit API implementation.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:    opts.API,
		region: opts.Region,
		now:    now,
	}
}

// NewFromAWS constructs a Plugin backed by the real AWS SDK.
// The variadic opts carry per-instance credential settings (see
// internal/sources/aws/awscfg). Omitting them keeps the previous
// behavior: the ambient credential chain, scoped to region.
func NewFromAWS(ctx context.Context, region string, opts ...awscfg.Options) (*Plugin, error) {
	o := awscfg.Options{Region: region}
	if len(opts) > 0 {
		o = opts[0]
		if o.Region == "" {
			o.Region = region
		}
	}
	cfg, region, err := awscfg.Load(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("aws.rds: %w", err)
	}
	return New(Options{
		API:    awsrds.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// instancePayload is the cross-vendor managed_database_instance shape.
type instancePayload struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Provider           string `json:"provider"`
	Engine             string `json:"engine,omitempty"`
	EngineVersion      string `json:"engine_version,omitempty"`
	StorageEncrypted   bool   `json:"storage_encrypted"`
	PubliclyAccessible bool   `json:"publicly_accessible"`
	BackupEnabled      bool   `json:"backup_enabled"`
	// SSLRequired is a pointer so it is omitted (not emitted as false)
	// when the engine's parameter group cannot be introspected for an
	// in-transit-encryption setting. A consuming policy guards with
	// is_set, so an undeterminable engine is skipped rather than
	// false-failed. Measured from the DB parameter group, never assumed.
	SSLRequired        *bool  `json:"ssl_required,omitempty"`
	MultiAZ            bool   `json:"multi_az"`
	DeletionProtection bool   `json:"deletion_protection"`
	KMSKeyID           string `json:"kms_key_id,omitempty"`
	// AWS-specific extras
	ARN    string `json:"arn,omitempty"`
	Status string `json:"status,omitempty"`
}

// Collect lists DB instances and returns one managed_database_instance record per instance.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.rds: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	instances, err := p.listAllInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.rds: describe db instances: %w", err)
	}
	now := p.now()
	// The caches memoize per-parameter-group SSL lookups and per-cluster
	// reads within this one Collect call: many instances share a group or
	// a cluster, and the plugin caches nothing across Collect calls
	// (KISS-no-DRY axiom).
	c := &collectCache{ssl: map[string]*bool{}, clusters: map[string]*rdstypes.DBCluster{}}
	records := make([]core.EvidenceRecord, 0, len(instances))
	for i := range instances {
		inst := &instances[i]
		id := safeIdentifier(inst)
		if id == "" {
			continue
		}
		payload, err := p.instancePayload(ctx, inst, c)
		if err != nil {
			return nil, fmt.Errorf("aws.rds: %s: %w", id, err)
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.rds: marshal payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          id,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

type collectCache struct {
	ssl      map[string]*bool
	clusters map[string]*rdstypes.DBCluster
}

// instancePayload maps one DB instance. An Aurora instance reports its
// cluster's settings: AWS returns cluster-managed values such as
// DeletionProtection and MultiAZ as false on the instance, and Aurora's
// TLS parameter lives in the DB cluster parameter group.
func (p *Plugin) instancePayload(ctx context.Context, inst *rdstypes.DBInstance, c *collectCache) (instancePayload, error) {
	id := safeIdentifier(inst)
	payload := instancePayload{
		ID:                 id,
		Name:               id,
		Provider:           "aws",
		Engine:             safeString(inst.Engine),
		EngineVersion:      safeString(inst.EngineVersion),
		StorageEncrypted:   safeBool(inst.StorageEncrypted),
		PubliclyAccessible: safeBool(inst.PubliclyAccessible),
		BackupEnabled:      safeBackupEnabled(inst),
		MultiAZ:            safeBool(inst.MultiAZ),
		DeletionProtection: safeBool(inst.DeletionProtection),
		KMSKeyID:           safeString(inst.KmsKeyId),
		ARN:                safeString(inst.DBInstanceArn),
		Status:             safeString(inst.DBInstanceStatus),
	}
	param, onValue := sslParamByEngine(payload.Engine)
	clusterID := safeString(inst.DBClusterIdentifier)
	if clusterID == "" {
		ssl, err := p.sslRequired(ctx, param, onValue, primaryParameterGroup(inst), false, c.ssl)
		if err != nil {
			return payload, err
		}
		payload.SSLRequired = ssl
		return payload, nil
	}
	cl, err := p.cluster(ctx, clusterID, c.clusters)
	if err != nil {
		return payload, fmt.Errorf("db cluster %s: %w", clusterID, err)
	}
	payload.DeletionProtection = safeBool(cl.DeletionProtection)
	payload.MultiAZ = safeBool(cl.MultiAZ)
	payload.StorageEncrypted = safeBool(cl.StorageEncrypted)
	payload.BackupEnabled = cl.BackupRetentionPeriod != nil && *cl.BackupRetentionPeriod > 0
	if k := safeString(cl.KmsKeyId); k != "" {
		payload.KMSKeyID = k
	}
	ssl, err := p.sslRequired(ctx, param, onValue, safeString(cl.DBClusterParameterGroup), true, c.ssl)
	if err != nil {
		return payload, err
	}
	payload.SSLRequired = ssl
	return payload, nil
}

// cluster reads one DB cluster, memoized per Collect.
func (p *Plugin) cluster(ctx context.Context, id string, cache map[string]*rdstypes.DBCluster) (*rdstypes.DBCluster, error) {
	if cl, ok := cache[id]; ok {
		return cl, nil
	}
	out, err := p.api.DescribeDBClusters(ctx, &awsrds.DescribeDBClustersInput{DBClusterIdentifier: &id})
	if err != nil {
		return nil, err
	}
	if out == nil || len(out.DBClusters) == 0 {
		return nil, fmt.Errorf("DescribeDBClusters returned no cluster")
	}
	cl := &out.DBClusters[0]
	cache[id] = cl
	return cl, nil
}

func (p *Plugin) listAllInstances(ctx context.Context) ([]rdstypes.DBInstance, error) {
	var (
		out    []rdstypes.DBInstance
		marker *string
	)
	for {
		page, err := p.api.DescribeDBInstances(ctx, &awsrds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.DBInstances...)
		if page.Marker != nil && *page.Marker != "" {
			marker = page.Marker
			continue
		}
		return out, nil
	}
}

// sslRequired determines whether the instance enforces in-transit
// encryption by inspecting the engine-appropriate parameter in its DB
// parameter group (cluster parameter group for Aurora). Returns nil
// (field omitted) when the engine is not introspectable this way (e.g.
// oracle/sqlserver use option groups) or the group does not carry the
// parameter, so the consuming policy skips rather than false-fails such
// instances. A failed read is an error: omitting the field would make
// the policy skip a database it could not judge.
func (p *Plugin) sslRequired(ctx context.Context, param, onValue, group string, clusterGroup bool, cache map[string]*bool) (*bool, error) {
	if param == "" || group == "" {
		return nil, nil
	}
	key := group
	if clusterGroup {
		key = "cluster:" + group
	}
	if v, ok := cache[key]; ok {
		return v, nil
	}
	lookup := p.lookupParameter
	if clusterGroup {
		lookup = p.lookupClusterParameter
	}
	val, found, err := lookup(ctx, group, param)
	if err != nil {
		return nil, fmt.Errorf("parameter group %s: %w", group, err)
	}
	var result *bool
	if found {
		on := strings.EqualFold(val, onValue)
		result = &on
	}
	cache[key] = result
	return result, nil
}

// sslParamByEngine maps an RDS engine to the parameter that enforces TLS
// and the value that means "enforced". Empty param => not introspectable.
func sslParamByEngine(engine string) (param, onValue string) {
	switch {
	case strings.Contains(engine, "postgres"):
		return "rds.force_ssl", "1"
	case strings.Contains(engine, "mysql"), strings.Contains(engine, "mariadb"):
		return "require_secure_transport", "ON"
	default:
		return "", ""
	}
}

func primaryParameterGroup(inst *rdstypes.DBInstance) string {
	if inst == nil || len(inst.DBParameterGroups) == 0 {
		return ""
	}
	return safeString(inst.DBParameterGroups[0].DBParameterGroupName)
}

// lookupParameter scans a DB parameter group (paged) for the named
// parameter. found=false when the group does not carry it.
func (p *Plugin) lookupParameter(ctx context.Context, group, name string) (value string, found bool, err error) {
	var marker *string
	for {
		page, err := p.api.DescribeDBParameters(ctx, &awsrds.DescribeDBParametersInput{
			DBParameterGroupName: &group,
			Marker:               marker,
		})
		if err != nil {
			return "", false, err
		}
		if v, ok := findParameter(page.Parameters, name); ok {
			return v, true, nil
		}
		if page.Marker == nil || *page.Marker == "" {
			return "", false, nil
		}
		marker = page.Marker
	}
}

// lookupClusterParameter is lookupParameter for a DB cluster parameter
// group.
func (p *Plugin) lookupClusterParameter(ctx context.Context, group, name string) (value string, found bool, err error) {
	var marker *string
	for {
		page, err := p.api.DescribeDBClusterParameters(ctx, &awsrds.DescribeDBClusterParametersInput{
			DBClusterParameterGroupName: &group,
			Marker:                      marker,
		})
		if err != nil {
			return "", false, err
		}
		if v, ok := findParameter(page.Parameters, name); ok {
			return v, true, nil
		}
		if page.Marker == nil || *page.Marker == "" {
			return "", false, nil
		}
		marker = page.Marker
	}
}

func findParameter(params []rdstypes.Parameter, name string) (string, bool) {
	for i := range params {
		pm := &params[i]
		if pm.ParameterName != nil && *pm.ParameterName == name {
			return safeString(pm.ParameterValue), true
		}
	}
	return "", false
}

func safeBackupEnabled(inst *rdstypes.DBInstance) bool {
	if inst == nil {
		return false
	}
	return inst.BackupRetentionPeriod != nil && *inst.BackupRetentionPeriod > 0
}

func safeIdentifier(inst *rdstypes.DBInstance) string {
	if inst == nil || inst.DBInstanceIdentifier == nil {
		return ""
	}
	return *inst.DBInstanceIdentifier
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func safeBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

var _ core.SourcePlugin = (*Plugin)(nil)
