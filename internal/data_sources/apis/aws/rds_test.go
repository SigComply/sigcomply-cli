package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockRDSClient implements RDSClient for testing.
type MockRDSClient struct {
	DescribeDBInstancesFunc       func(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBParameterGroupsFunc func(ctx context.Context, params *rds.DescribeDBParameterGroupsInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParameterGroupsOutput, error)
	DescribeDBParametersFunc      func(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error)
}

func (m *MockRDSClient) DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return m.DescribeDBInstancesFunc(ctx, params, optFns...)
}

func (m *MockRDSClient) DescribeDBParameterGroups(ctx context.Context, params *rds.DescribeDBParameterGroupsInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParameterGroupsOutput, error) {
	return m.DescribeDBParameterGroupsFunc(ctx, params, optFns...)
}

func (m *MockRDSClient) DescribeDBParameters(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
	return m.DescribeDBParametersFunc(ctx, params, optFns...)
}

func TestRDSCollector_CollectInstances(t *testing.T) {
	tests := []struct {
		name           string
		mockInstances  []rdstypes.DBInstance
		mockErr        error
		wantCount      int
		wantError      bool
	}{
		{
			name: "encrypted instance with backups",
			mockInstances: []rdstypes.DBInstance{
				{
					DBInstanceIdentifier: awssdk.String("prod-db"),
					DBInstanceArn:       awssdk.String("arn:aws:rds:us-east-1:123:db:prod-db"),
					Engine:              awssdk.String("postgres"),
					EngineVersion:       awssdk.String("15.3"),
					DBInstanceClass:     awssdk.String("db.r5.large"),
					StorageEncrypted:    awssdk.Bool(true),
					KmsKeyId:            awssdk.String("arn:aws:kms:us-east-1:123:key/abc"),
					PubliclyAccessible:  awssdk.Bool(false),
					MultiAZ:            awssdk.Bool(true),
					BackupRetentionPeriod: awssdk.Int32(7),
					DBParameterGroups: []rdstypes.DBParameterGroupStatus{
						{DBParameterGroupName: awssdk.String("default.postgres15")},
					},
				},
			},
			wantCount: 1,
		},
		{
			name: "unencrypted public instance without backups",
			mockInstances: []rdstypes.DBInstance{
				{
					DBInstanceIdentifier:  awssdk.String("dev-db"),
					DBInstanceArn:        awssdk.String("arn:aws:rds:us-east-1:123:db:dev-db"),
					Engine:               awssdk.String("mysql"),
					DBInstanceClass:      awssdk.String("db.t3.micro"),
					StorageEncrypted:     awssdk.Bool(false),
					PubliclyAccessible:   awssdk.Bool(true),
					MultiAZ:             awssdk.Bool(false),
					BackupRetentionPeriod: awssdk.Int32(0),
				},
			},
			wantCount: 1,
		},
		{
			name:          "no instances",
			mockInstances: []rdstypes.DBInstance{},
			wantCount:     0,
		},
		{
			name:      "API error",
			mockErr:   errors.New("access denied"),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockRDSClient{
				DescribeDBInstancesFunc: func(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}
					return &rds.DescribeDBInstancesOutput{DBInstances: tt.mockInstances}, nil
				},
				DescribeDBParametersFunc: func(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
					return &rds.DescribeDBParametersOutput{Parameters: []rdstypes.Parameter{}}, nil
				},
			}

			collector := NewRDSCollector(mock)
			instances, err := collector.CollectInstances(context.Background())

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, instances, tt.wantCount)

			if tt.name == "encrypted instance with backups" {
				inst := instances[0]
				assert.True(t, inst.StorageEncrypted)
				assert.False(t, inst.PubliclyAccessible)
				assert.True(t, inst.BackupEnabled)
				assert.True(t, inst.PITREnabled)
				assert.Equal(t, 7, inst.BackupRetentionPeriod)
				assert.Equal(t, "arn:aws:kms:us-east-1:123:key/abc", inst.KMSKeyID)
			}

			if tt.name == "unencrypted public instance without backups" {
				inst := instances[0]
				assert.False(t, inst.StorageEncrypted)
				assert.True(t, inst.PubliclyAccessible)
				assert.False(t, inst.BackupEnabled)
				assert.False(t, inst.PITREnabled)
			}
		})
	}
}

func TestRDSCollector_CollectInstances_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockRDSClient{
		DescribeDBInstancesFunc: func(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
			callCount++
			if callCount == 1 {
				return &rds.DescribeDBInstancesOutput{
					DBInstances: []rdstypes.DBInstance{
						{
							DBInstanceIdentifier: awssdk.String("db-1"),
							DBInstanceArn:       awssdk.String("arn:aws:rds:us-east-1:123:db:db-1"),
							Engine:              awssdk.String("postgres"),
						},
					},
					Marker: awssdk.String("page2"),
				}, nil
			}
			return &rds.DescribeDBInstancesOutput{
				DBInstances: []rdstypes.DBInstance{
					{
						DBInstanceIdentifier: awssdk.String("db-2"),
						DBInstanceArn:       awssdk.String("arn:aws:rds:us-east-1:123:db:db-2"),
						Engine:              awssdk.String("mysql"),
					},
				},
			}, nil
		},
		DescribeDBParametersFunc: func(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
			return &rds.DescribeDBParametersOutput{}, nil
		},
	}

	collector := NewRDSCollector(mock)
	instances, err := collector.CollectInstances(context.Background())

	require.NoError(t, err)
	assert.Len(t, instances, 2)
	assert.Equal(t, 2, callCount)
}

func TestRDSCollector_enrichSSLStatus(t *testing.T) {
	tests := []struct {
		name       string
		paramGroup string
		params     []rdstypes.Parameter
		paramErr   error
		wantSSL    bool
	}{
		{
			name:       "SSL forced via rds.force_ssl",
			paramGroup: "custom-pg",
			params: []rdstypes.Parameter{
				{ParameterName: awssdk.String("rds.force_ssl"), ParameterValue: awssdk.String("1")},
			},
			wantSSL: true,
		},
		{
			name:       "SSL via require_secure_transport",
			paramGroup: "custom-pg",
			params: []rdstypes.Parameter{
				{ParameterName: awssdk.String("require_secure_transport"), ParameterValue: awssdk.String("ON")},
			},
			wantSSL: true,
		},
		{
			name:       "SSL not forced",
			paramGroup: "custom-pg",
			params: []rdstypes.Parameter{
				{ParameterName: awssdk.String("rds.force_ssl"), ParameterValue: awssdk.String("0")},
			},
			wantSSL: false,
		},
		{
			name:       "no parameter group",
			paramGroup: "",
			wantSSL:    false,
		},
		{
			name:       "parameter query fails (fail-safe)",
			paramGroup: "custom-pg",
			paramErr:   errors.New("access denied"),
			wantSSL:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockRDSClient{
				DescribeDBParametersFunc: func(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
					if tt.paramErr != nil {
						return nil, tt.paramErr
					}
					return &rds.DescribeDBParametersOutput{Parameters: tt.params}, nil
				},
			}

			collector := NewRDSCollector(mock)
			instance := &RDSInstance{ParameterGroupName: tt.paramGroup}
			collector.enrichSSLStatus(context.Background(), instance)

			assert.Equal(t, tt.wantSSL, instance.ForceSSL)
		})
	}
}

func TestRDSInstance_ToEvidence(t *testing.T) {
	instance := &RDSInstance{
		DBInstanceID:     "prod-db",
		ARN:              "arn:aws:rds:us-east-1:123:db:prod-db",
		Engine:           "postgres",
		StorageEncrypted: true,
	}

	ev := instance.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:rds:instance", ev.ResourceType)
	assert.Equal(t, "arn:aws:rds:us-east-1:123:db:prod-db", ev.ResourceID)
	assert.NotEmpty(t, ev.Hash)
}

// --- Negative Tests ---

func TestRDSCollector_CollectInstances_PaginationErrorMidStream(t *testing.T) {
	callCount := 0
	mock := &MockRDSClient{
		DescribeDBInstancesFunc: func(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
			callCount++
			if callCount == 1 {
				return &rds.DescribeDBInstancesOutput{
					DBInstances: []rdstypes.DBInstance{
						{
							DBInstanceIdentifier: awssdk.String("db-1"),
							DBInstanceArn:       awssdk.String("arn:aws:rds:us-east-1:123:db:db-1"),
							Engine:              awssdk.String("postgres"),
						},
					},
					Marker: awssdk.String("page2"),
				}, nil
			}
			return nil, errors.New("internal service error on page 2")
		},
		DescribeDBParametersFunc: func(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
			return &rds.DescribeDBParametersOutput{}, nil
		},
	}

	collector := NewRDSCollector(mock)
	_, err := collector.CollectInstances(context.Background())

	assert.Error(t, err, "pagination error should propagate")
	assert.Contains(t, err.Error(), "failed to describe RDS instances")
}

func TestRDSCollector_CollectInstances_NilOptionalFields(t *testing.T) {
	mock := &MockRDSClient{
		DescribeDBInstancesFunc: func(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
			return &rds.DescribeDBInstancesOutput{
				DBInstances: []rdstypes.DBInstance{
					{
						// Minimal fields, everything else nil
						DBInstanceIdentifier:  awssdk.String("minimal-db"),
						DBInstanceArn:        awssdk.String("arn:aws:rds:us-east-1:123:db:minimal-db"),
						Engine:               awssdk.String("mysql"),
						DBInstanceClass:      awssdk.String("db.t3.micro"),
						StorageEncrypted:     nil,
						KmsKeyId:             nil,
						PubliclyAccessible:   nil,
						MultiAZ:             nil,
						BackupRetentionPeriod: nil,
						DBParameterGroups:    nil,
					},
				},
			}, nil
		},
		DescribeDBParametersFunc: func(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
			return &rds.DescribeDBParametersOutput{}, nil
		},
	}

	collector := NewRDSCollector(mock)
	instances, err := collector.CollectInstances(context.Background())

	require.NoError(t, err, "should handle nil optional fields")
	require.Len(t, instances, 1)

	inst := instances[0]
	assert.False(t, inst.StorageEncrypted, "nil StorageEncrypted should be false")
	assert.Empty(t, inst.KMSKeyID, "nil KmsKeyId should be empty")
	assert.False(t, inst.PubliclyAccessible, "nil PubliclyAccessible should be false")
	assert.False(t, inst.MultiAZ, "nil MultiAZ should be false")
	assert.Equal(t, 0, inst.BackupRetentionPeriod, "nil BackupRetentionPeriod should be 0")
	assert.False(t, inst.BackupEnabled, "should not be enabled with 0 retention")
	assert.False(t, inst.PITREnabled, "should not be enabled with 0 retention")
	assert.Empty(t, inst.ParameterGroupName, "nil param groups should be empty")
	assert.False(t, inst.ForceSSL, "no param group means no SSL check")
}

func TestRDSCollector_enrichSSLStatus_MultipleSslParams(t *testing.T) {
	// Test with multiple params, one of which is the SSL one with value "true"
	mock := &MockRDSClient{
		DescribeDBParametersFunc: func(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
			return &rds.DescribeDBParametersOutput{
				Parameters: []rdstypes.Parameter{
					{ParameterName: awssdk.String("max_connections"), ParameterValue: awssdk.String("100")},
					{ParameterName: awssdk.String("require_secure_transport"), ParameterValue: awssdk.String("true")},
					{ParameterName: awssdk.String("log_output"), ParameterValue: awssdk.String("FILE")},
				},
			}, nil
		},
	}

	collector := NewRDSCollector(mock)
	instance := &RDSInstance{ParameterGroupName: "custom-pg"}
	collector.enrichSSLStatus(context.Background(), instance)

	assert.True(t, instance.ForceSSL, "should detect SSL from mixed params")
}

func TestRDSCollector_enrichSSLStatus_NilParameterValue(t *testing.T) {
	mock := &MockRDSClient{
		DescribeDBParametersFunc: func(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
			return &rds.DescribeDBParametersOutput{
				Parameters: []rdstypes.Parameter{
					{ParameterName: awssdk.String("rds.force_ssl"), ParameterValue: nil},
				},
			}, nil
		},
	}

	collector := NewRDSCollector(mock)
	instance := &RDSInstance{ParameterGroupName: "pg"}
	collector.enrichSSLStatus(context.Background(), instance)

	assert.False(t, instance.ForceSSL, "nil parameter value should not enable SSL")
}

func TestRDSCollector_CollectEvidence_Error(t *testing.T) {
	mock := &MockRDSClient{
		DescribeDBInstancesFunc: func(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
			return nil, errors.New("service unavailable")
		},
		DescribeDBParametersFunc: func(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
			return &rds.DescribeDBParametersOutput{}, nil
		},
	}

	collector := NewRDSCollector(mock)
	_, err := collector.CollectEvidence(context.Background(), "123456789012")

	assert.Error(t, err, "CollectEvidence should propagate CollectInstances error")
}
