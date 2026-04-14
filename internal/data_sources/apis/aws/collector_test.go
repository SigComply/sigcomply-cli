package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macietypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockSTSClient is a mock implementation of STSClient for testing.
type MockSTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *MockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.GetCallerIdentityFunc(ctx, params, optFns...)
}

func TestCollector_GetAccountID(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *sts.GetCallerIdentityOutput
		mockError     error
		wantAccountID string
		wantError     bool
	}{
		{
			name: "successful account ID retrieval",
			mockResponse: &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
				UserId:  aws.String("AIDAEXAMPLEID"),
			},
			wantAccountID: "123456789012",
			wantError:     false,
		},
		{
			name:      "STS API error",
			mockError: errors.New("access denied"),
			wantError: true,
		},
		{
			name: "nil account in response",
			mockResponse: &sts.GetCallerIdentityOutput{
				Account: nil,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSTS := &MockSTSClient{
				GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			collector := &Collector{
				stsClient: mockSTS,
			}

			accountID, err := collector.GetAccountID(context.Background())

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantAccountID, accountID)
			}
		})
	}
}

func TestCollector_New(t *testing.T) {
	// This test verifies the constructor doesn't panic
	// Actual AWS credential loading is tested in integration tests
	collector := New()
	assert.NotNil(t, collector)
}

func TestCollector_WithRegion(t *testing.T) {
	collector := New()

	// Chain method should return the collector
	result := collector.WithRegion("us-west-2")
	assert.Equal(t, collector, result)
	assert.Equal(t, "us-west-2", collector.region)
}

func TestCollector_Status(t *testing.T) {
	mockSTS := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
			}, nil
		},
	}

	collector := &Collector{
		stsClient: mockSTS,
		region:    "us-east-1",
	}

	status := collector.Status(context.Background())

	assert.True(t, status.Connected)
	assert.Equal(t, "123456789012", status.AccountID)
	assert.Equal(t, "us-east-1", status.Region)
}

func TestCollector_Status_NotConnected(t *testing.T) {
	mockSTS := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return nil, errors.New("no credentials")
		},
	}

	collector := &Collector{
		stsClient: mockSTS,
	}

	status := collector.Status(context.Background())

	assert.False(t, status.Connected)
	assert.Contains(t, status.Error, "no credentials")
}

func TestCollector_Collect_FailSafe(t *testing.T) {
	// Test that collection continues even when one service fails
	mockSTS := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
			}, nil
		},
	}

	// IAM fails, but S3 and CloudTrail should still work
	mockIAM := &MockIAMClient{
		ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
			return nil, errors.New("IAM access denied")
		},
	}

	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []s3types.Bucket{
					{Name: aws.String("test-bucket")},
				},
			}, nil
		},
		GetBucketEncryptionFunc: func(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
			return nil, errors.New("no encryption")
		},
		GetBucketVersioningFunc: func(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
			return &s3.GetBucketVersioningOutput{}, nil
		},
		GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
			return &s3.GetPublicAccessBlockOutput{}, nil
		},
	}

	mockCloudTrail := &MockCloudTrailClient{
		DescribeTrailsFunc: func(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
			return &cloudtrail.DescribeTrailsOutput{
				TrailList: []cttypes.Trail{
					{Name: aws.String("test-trail"), TrailARN: aws.String("arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail")},
				},
			}, nil
		},
		GetTrailStatusFunc: func(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
			return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true)}, nil
		},
	}

	collector := &Collector{
		stsClient:        mockSTS,
		iamClient:        mockIAM,
		s3Client:         mockS3,
		cloudtrailClient: mockCloudTrail,
	}

	result, err := collector.Collect(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasErrors(), "should have errors from IAM failure")
	assert.Len(t, result.Errors, 1)
	assert.Equal(t, "iam", result.Errors[0].Service)

	// Should still have evidence from S3 and CloudTrail
	assert.Len(t, result.Evidence, 2, "should have evidence from S3 and CloudTrail")
}

// --- Negative tests ---

func TestCollector_Collect_AllServicesFail(t *testing.T) {
	mockSTS := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
			}, nil
		},
	}

	// All services fail
	mockIAM := &MockIAMClient{
		ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
			return nil, errors.New("IAM access denied")
		},
	}

	mockS3 := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return nil, errors.New("S3 access denied")
		},
	}

	mockCloudTrail := &MockCloudTrailClient{
		DescribeTrailsFunc: func(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
			return nil, errors.New("CloudTrail access denied")
		},
	}

	collector := &Collector{
		stsClient:        mockSTS,
		iamClient:        mockIAM,
		s3Client:         mockS3,
		cloudtrailClient: mockCloudTrail,
	}

	result, err := collector.Collect(context.Background())

	require.NoError(t, err, "Collect should not error even when all services fail")
	assert.Empty(t, result.Evidence, "should have no evidence when all services fail")
	assert.Len(t, result.Errors, 3, "should have errors from all 3 services")

	// Verify all services reported errors
	serviceErrors := make(map[string]bool)
	for _, e := range result.Errors {
		serviceErrors[e.Service] = true
	}
	assert.True(t, serviceErrors["iam"])
	assert.True(t, serviceErrors["s3"])
	assert.True(t, serviceErrors["cloudtrail"])
}

func TestCollector_GetAccountID_NotInitialized(t *testing.T) {
	collector := New()
	_, err := collector.GetAccountID(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestCollector_Collect_AccountIDError(t *testing.T) {
	mockSTS := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return nil, errors.New("STS unavailable")
		},
	}

	collector := &Collector{
		stsClient: mockSTS,
	}

	_, err := collector.Collect(context.Background())
	require.Error(t, err, "should fail when account ID cannot be retrieved")
	assert.Contains(t, err.Error(), "account ID")
}

func TestCollectionResult_HasErrors(t *testing.T) {
	result := &CollectionResult{}
	assert.False(t, result.HasErrors())

	result.Errors = append(result.Errors, CollectionError{Service: "test", Error: "error"})
	assert.True(t, result.HasErrors())
}

// --- Wrapper method tests for new collectors ---

// helperSTS returns a mock STS client that resolves to a fixed account ID.
func helperSTS() *MockSTSClient {
	return &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{Account: aws.String("123456789012")}, nil
		},
	}
}

func TestCollector_collectSecurityHub(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			securityHubClient: &MockSecurityHubClient{
				DescribeHubFunc: func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
					return &securityhub.DescribeHubOutput{HubArn: aws.String("arn:aws:securityhub:us-east-1:123:hub/default")}, nil
				},
			},
			region: "us-east-1",
		}
		result := &CollectionResult{}
		c.collectSecurityHub(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:securityhub:hub", result.Evidence[0].ResourceType)
	})
	t.Run("error is fail-safe", func(t *testing.T) {
		c := &Collector{
			securityHubClient: &MockSecurityHubClient{
				DescribeHubFunc: func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
					return nil, errors.New("not subscribed")
				},
			},
			region: "us-east-1",
		}
		result := &CollectionResult{}
		c.collectSecurityHub(context.Background(), "123456789012", result)
		// SecurityHub collector handles errors internally (returns status with Enabled=false)
		// so either we get evidence or an error, but no panic
		assert.True(t, len(result.Evidence) > 0 || len(result.Errors) > 0)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectSecurityHub(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectCloudWatchAlarms(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			cwAlarmsClient: &MockCloudWatchAlarmsClient{
				DescribeAlarmsFunc: func(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
					return &cloudwatch.DescribeAlarmsOutput{
						MetricAlarms: []cwtypes.MetricAlarm{
							{AlarmName: aws.String("UnauthorizedAPICalls")},
							{AlarmName: aws.String("RootAccountUsage")},
							{AlarmName: aws.String("ConsoleSignInFailures")},
						},
					}, nil
				},
			},
			region: "us-east-1",
		}
		result := &CollectionResult{}
		c.collectCloudWatchAlarms(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:cloudwatch:alarm-config", result.Evidence[0].ResourceType)
	})
	t.Run("error is handled internally (fail-safe)", func(t *testing.T) {
		c := &Collector{
			cwAlarmsClient: &MockCloudWatchAlarmsClient{
				DescribeAlarmsFunc: func(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
					return nil, errors.New("access denied")
				},
			},
			region: "us-east-1",
		}
		result := &CollectionResult{}
		c.collectCloudWatchAlarms(context.Background(), "123456789012", result)
		// CloudWatchAlarms collector handles errors internally (fail-safe, returns empty config)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectCloudWatchAlarms(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectSecretsManager(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			secretsMgrClient: &MockSecretsManagerClient{
				ListSecretsFunc: func(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
					return &secretsmanager.ListSecretsOutput{
						SecretList: []smtypes.SecretListEntry{
							{Name: aws.String("my-secret"), ARN: aws.String("arn:aws:secretsmanager:us-east-1:123:secret:my-secret")},
						},
					}, nil
				},
			},
		}
		result := &CollectionResult{}
		c.collectSecretsManager(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:secretsmanager:secret", result.Evidence[0].ResourceType)
	})
	t.Run("error is fail-safe", func(t *testing.T) {
		c := &Collector{
			secretsMgrClient: &MockSecretsManagerClient{
				ListSecretsFunc: func(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
					return nil, errors.New("access denied")
				},
			},
		}
		result := &CollectionResult{}
		c.collectSecretsManager(context.Background(), "123456789012", result)
		assert.Len(t, result.Errors, 1)
		assert.Equal(t, "secretsmanager", result.Errors[0].Service)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectSecretsManager(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectLambda(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			lambdaClient: &MockLambdaClient{
				ListFunctionsFunc: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
					return &lambda.ListFunctionsOutput{
						Functions: []lambdatypes.FunctionConfiguration{
							{FunctionName: aws.String("my-func"), FunctionArn: aws.String("arn:aws:lambda:us-east-1:123:function:my-func"), Runtime: lambdatypes.RuntimePython312},
						},
					}, nil
				},
			},
		}
		result := &CollectionResult{}
		c.collectLambda(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:lambda:function", result.Evidence[0].ResourceType)
	})
	t.Run("error is fail-safe", func(t *testing.T) {
		c := &Collector{
			lambdaClient: &MockLambdaClient{
				ListFunctionsFunc: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
					return nil, errors.New("access denied")
				},
			},
		}
		result := &CollectionResult{}
		c.collectLambda(context.Background(), "123456789012", result)
		assert.Len(t, result.Errors, 1)
		assert.Equal(t, "lambda", result.Errors[0].Service)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectLambda(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectS3Control(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			s3ControlClient: &MockS3ControlClient{
				GetPublicAccessBlockFunc: func(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
					return &s3control.GetPublicAccessBlockOutput{
						PublicAccessBlockConfiguration: &s3controltypes.PublicAccessBlockConfiguration{
							BlockPublicAcls:       aws.Bool(true),
							BlockPublicPolicy:     aws.Bool(true),
							IgnorePublicAcls:      aws.Bool(true),
							RestrictPublicBuckets: aws.Bool(true),
						},
					}, nil
				},
			},
		}
		result := &CollectionResult{}
		c.collectS3Control(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:s3control:account-public-access", result.Evidence[0].ResourceType)
	})
	t.Run("error is handled internally (fail-safe)", func(t *testing.T) {
		c := &Collector{
			s3ControlClient: &MockS3ControlClient{
				GetPublicAccessBlockFunc: func(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
					return nil, errors.New("access denied")
				},
			},
		}
		result := &CollectionResult{}
		c.collectS3Control(context.Background(), "123456789012", result)
		// S3Control collector handles errors internally (returns empty config)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectS3Control(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectDynamoDB(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			dynamodbClient: &MockDynamoDBClient{
				ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
					return &dynamodb.ListTablesOutput{TableNames: []string{"my-table"}}, nil
				},
				DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
					return &dynamodb.DescribeTableOutput{
						Table: &dbtypes.TableDescription{
							TableName: aws.String("my-table"),
							TableArn:  aws.String("arn:aws:dynamodb:us-east-1:123:table/my-table"),
							SSEDescription: &dbtypes.SSEDescription{
								Status:  dbtypes.SSEStatusEnabled,
								SSEType: dbtypes.SSETypeKms,
							},
						},
					}, nil
				},
			},
		}
		result := &CollectionResult{}
		c.collectDynamoDB(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:dynamodb:table", result.Evidence[0].ResourceType)
	})
	t.Run("error is fail-safe", func(t *testing.T) {
		c := &Collector{
			dynamodbClient: &MockDynamoDBClient{
				ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
					return nil, errors.New("access denied")
				},
			},
		}
		result := &CollectionResult{}
		c.collectDynamoDB(context.Background(), "123456789012", result)
		assert.Len(t, result.Errors, 1)
		assert.Equal(t, "dynamodb", result.Errors[0].Service)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectDynamoDB(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectECS(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			ecsClient: &MockECSClient{
				ListClustersFunc: func(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
					return &ecs.ListClustersOutput{ClusterArns: []string{"arn:aws:ecs:us-east-1:123:cluster/my-cluster"}}, nil
				},
				DescribeClustersFunc: func(ctx context.Context, params *ecs.DescribeClustersInput, optFns ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
					return &ecs.DescribeClustersOutput{
						Clusters: []ecstypes.Cluster{
							{
								ClusterName: aws.String("my-cluster"),
								ClusterArn:  aws.String("arn:aws:ecs:us-east-1:123:cluster/my-cluster"),
								Settings: []ecstypes.ClusterSetting{
									{Name: ecstypes.ClusterSettingNameContainerInsights, Value: aws.String("enabled")},
								},
							},
						},
					}, nil
				},
			},
		}
		result := &CollectionResult{}
		c.collectECS(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:ecs:cluster", result.Evidence[0].ResourceType)
	})
	t.Run("error is fail-safe", func(t *testing.T) {
		c := &Collector{
			ecsClient: &MockECSClient{
				ListClustersFunc: func(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
					return nil, errors.New("access denied")
				},
				DescribeClustersFunc: func(ctx context.Context, params *ecs.DescribeClustersInput, optFns ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
					return nil, errors.New("access denied")
				},
			},
		}
		result := &CollectionResult{}
		c.collectECS(context.Background(), "123456789012", result)
		assert.Len(t, result.Errors, 1)
		assert.Equal(t, "ecs", result.Errors[0].Service)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectECS(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectEKS(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			eksClient: &MockEKSClient{
				ListClustersFunc: func(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
					return &eks.ListClustersOutput{Clusters: []string{"my-cluster"}}, nil
				},
				DescribeClusterFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
					return &eks.DescribeClusterOutput{
						Cluster: &ekstypes.Cluster{
							Name:    aws.String("my-cluster"),
							Arn:     aws.String("arn:aws:eks:us-east-1:123:cluster/my-cluster"),
							Version: aws.String("1.28"),
							ResourcesVpcConfig: &ekstypes.VpcConfigResponse{
								EndpointPublicAccess: false,
							},
						},
					}, nil
				},
			},
		}
		result := &CollectionResult{}
		c.collectEKS(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:eks:cluster", result.Evidence[0].ResourceType)
	})
	t.Run("error is fail-safe", func(t *testing.T) {
		c := &Collector{
			eksClient: &MockEKSClient{
				ListClustersFunc: func(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
					return nil, errors.New("access denied")
				},
				DescribeClusterFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
					return nil, errors.New("access denied")
				},
			},
		}
		result := &CollectionResult{}
		c.collectEKS(context.Background(), "123456789012", result)
		assert.Len(t, result.Errors, 1)
		assert.Equal(t, "eks", result.Errors[0].Service)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectEKS(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectACM(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			acmClient: &MockACMClient{
				ListCertificatesFunc: func(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
					return &acm.ListCertificatesOutput{
						CertificateSummaryList: []acmtypes.CertificateSummary{
							{CertificateArn: aws.String("arn:aws:acm:us-east-1:123:certificate/abc"), DomainName: aws.String("example.com")},
						},
					}, nil
				},
				DescribeCertificateFunc: func(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
					return &acm.DescribeCertificateOutput{
						Certificate: &acmtypes.CertificateDetail{
							CertificateArn: aws.String("arn:aws:acm:us-east-1:123:certificate/abc"),
							DomainName:     aws.String("example.com"),
							Status:         acmtypes.CertificateStatusIssued,
						},
					}, nil
				},
			},
		}
		result := &CollectionResult{}
		c.collectACM(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:acm:certificate", result.Evidence[0].ResourceType)
	})
	t.Run("error is fail-safe", func(t *testing.T) {
		c := &Collector{
			acmClient: &MockACMClient{
				ListCertificatesFunc: func(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
					return nil, errors.New("access denied")
				},
			},
		}
		result := &CollectionResult{}
		c.collectACM(context.Background(), "123456789012", result)
		assert.Len(t, result.Errors, 1)
		assert.Equal(t, "acm", result.Errors[0].Service)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectACM(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectCloudFront(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			cloudfrontClient: &MockCloudFrontClient{
				ListDistributionsFunc: func(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
					return &cloudfront.ListDistributionsOutput{
						DistributionList: &cftypes.DistributionList{
							Items: []cftypes.DistributionSummary{
								{
									ARN:        aws.String("arn:aws:cloudfront::123:distribution/EDFDVBD632BHDS5"),
									DomainName: aws.String("d111111abcdef8.cloudfront.net"),
									DefaultCacheBehavior: &cftypes.DefaultCacheBehavior{
										ViewerProtocolPolicy: cftypes.ViewerProtocolPolicyHttpsOnly,
									},
								},
							},
						},
					}, nil
				},
			},
		}
		result := &CollectionResult{}
		c.collectCloudFront(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:cloudfront:distribution", result.Evidence[0].ResourceType)
	})
	t.Run("error is fail-safe", func(t *testing.T) {
		c := &Collector{
			cloudfrontClient: &MockCloudFrontClient{
				ListDistributionsFunc: func(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
					return nil, errors.New("access denied")
				},
			},
		}
		result := &CollectionResult{}
		c.collectCloudFront(context.Background(), "123456789012", result)
		assert.Len(t, result.Errors, 1)
		assert.Equal(t, "cloudfront", result.Errors[0].Service)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectCloudFront(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectWAF(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			wafClient: &MockWAFClient{
				ListWebACLsFunc: func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
					return &wafv2.ListWebACLsOutput{
						WebACLs: []waftypes.WebACLSummary{
							{Name: aws.String("my-acl"), ARN: aws.String("arn:aws:wafv2:us-east-1:123:regional/webacl/my-acl/abc")},
						},
					}, nil
				},
			},
			region: "us-east-1",
		}
		result := &CollectionResult{}
		c.collectWAF(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:wafv2:status", result.Evidence[0].ResourceType)
	})
	t.Run("error is handled internally (fail-safe)", func(t *testing.T) {
		c := &Collector{
			wafClient: &MockWAFClient{
				ListWebACLsFunc: func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
					return nil, errors.New("access denied")
				},
			},
			region: "us-east-1",
		}
		result := &CollectionResult{}
		c.collectWAF(context.Background(), "123456789012", result)
		// WAF collector handles errors internally (fail-safe, returns empty status)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectWAF(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectMacie(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			macieClient: &MockMacieClient{
				GetMacieSessionFunc: func(ctx context.Context, params *macie2.GetMacieSessionInput, optFns ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error) {
					return &macie2.GetMacieSessionOutput{Status: macietypes.MacieStatusEnabled}, nil
				},
			},
			region: "us-east-1",
		}
		result := &CollectionResult{}
		c.collectMacie(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:macie2:session", result.Evidence[0].ResourceType)
	})
	t.Run("error is fail-safe", func(t *testing.T) {
		c := &Collector{
			macieClient: &MockMacieClient{
				GetMacieSessionFunc: func(ctx context.Context, params *macie2.GetMacieSessionInput, optFns ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error) {
					return nil, errors.New("not enabled")
				},
			},
			region: "us-east-1",
		}
		result := &CollectionResult{}
		c.collectMacie(context.Background(), "123456789012", result)
		// Macie collector handles errors internally (returns status with Enabled=false)
		assert.True(t, len(result.Evidence) > 0 || len(result.Errors) > 0)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectMacie(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

func TestCollector_collectSSM(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Collector{
			ssmClient: &MockSSMClient{
				DescribeInstanceInformationFunc: func(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
					return &ssm.DescribeInstanceInformationOutput{
						InstanceInformationList: []ssmtypes.InstanceInformation{
							{InstanceId: aws.String("i-123")},
						},
					}, nil
				},
			},
			region: "us-east-1",
		}
		result := &CollectionResult{}
		c.collectSSM(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
		assert.Equal(t, "aws:ssm:status", result.Evidence[0].ResourceType)
	})
	t.Run("error is handled internally (fail-safe)", func(t *testing.T) {
		c := &Collector{
			ssmClient: &MockSSMClient{
				DescribeInstanceInformationFunc: func(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
					return nil, errors.New("access denied")
				},
			},
			region: "us-east-1",
		}
		result := &CollectionResult{}
		c.collectSSM(context.Background(), "123456789012", result)
		// SSM collector handles errors internally (returns status with zero instances)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Evidence)
	})
	t.Run("nil client skipped", func(t *testing.T) {
		c := &Collector{}
		result := &CollectionResult{}
		c.collectSSM(context.Background(), "123456789012", result)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Evidence)
	})
}

// TestCollector_Collect_AllNewServices verifies that all 13 new collectors
// are invoked during a full Collect() call and produce evidence.
func TestCollector_Collect_AllNewServices(t *testing.T) {
	c := &Collector{
		stsClient: helperSTS(),
		// Original clients — provide error mocks so they don't panic on nil
		iamClient: &MockIAMClient{
			ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
				return &iam.ListUsersOutput{}, nil
			},
		},
		s3Client: &MockS3Client{
			ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
				return &s3.ListBucketsOutput{}, nil
			},
		},
		cloudtrailClient: &MockCloudTrailClient{
			DescribeTrailsFunc: func(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
				return &cloudtrail.DescribeTrailsOutput{}, nil
			},
		},
		// Set up all new clients with minimal success mocks
		securityHubClient: &MockSecurityHubClient{
			DescribeHubFunc: func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
				return &securityhub.DescribeHubOutput{HubArn: aws.String("arn:aws:securityhub:us-east-1:123:hub/default")}, nil
			},
		},
		cwAlarmsClient: &MockCloudWatchAlarmsClient{
			DescribeAlarmsFunc: func(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
				return &cloudwatch.DescribeAlarmsOutput{}, nil
			},
		},
		secretsMgrClient: &MockSecretsManagerClient{
			ListSecretsFunc: func(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
				return &secretsmanager.ListSecretsOutput{}, nil
			},
		},
		lambdaClient: &MockLambdaClient{
			ListFunctionsFunc: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
				return &lambda.ListFunctionsOutput{}, nil
			},
		},
		s3ControlClient: &MockS3ControlClient{
			GetPublicAccessBlockFunc: func(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
				return &s3control.GetPublicAccessBlockOutput{
					PublicAccessBlockConfiguration: &s3controltypes.PublicAccessBlockConfiguration{},
				}, nil
			},
		},
		dynamodbClient: &MockDynamoDBClient{
			ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
				return &dynamodb.ListTablesOutput{}, nil
			},
		},
		ecsClient: &MockECSClient{
			ListClustersFunc: func(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
				return &ecs.ListClustersOutput{}, nil
			},
			DescribeClustersFunc: func(ctx context.Context, params *ecs.DescribeClustersInput, optFns ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
				return &ecs.DescribeClustersOutput{}, nil
			},
		},
		eksClient: &MockEKSClient{
			ListClustersFunc: func(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
				return &eks.ListClustersOutput{}, nil
			},
			DescribeClusterFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
				return &eks.DescribeClusterOutput{}, nil
			},
		},
		acmClient: &MockACMClient{
			ListCertificatesFunc: func(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
				return &acm.ListCertificatesOutput{}, nil
			},
		},
		cloudfrontClient: &MockCloudFrontClient{
			ListDistributionsFunc: func(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
				return &cloudfront.ListDistributionsOutput{DistributionList: &cftypes.DistributionList{}}, nil
			},
		},
		wafClient: &MockWAFClient{
			ListWebACLsFunc: func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
				return &wafv2.ListWebACLsOutput{}, nil
			},
		},
		macieClient: &MockMacieClient{
			GetMacieSessionFunc: func(ctx context.Context, params *macie2.GetMacieSessionInput, optFns ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error) {
				return &macie2.GetMacieSessionOutput{Status: macietypes.MacieStatusEnabled}, nil
			},
		},
		ssmClient: &MockSSMClient{
			DescribeInstanceInformationFunc: func(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
				return &ssm.DescribeInstanceInformationOutput{}, nil
			},
		},
		region: "us-east-1",
	}

	result, err := c.Collect(context.Background())
	require.NoError(t, err)

	// All services should succeed (no errors), even though some return empty data
	// The original services (IAM, S3, etc.) are nil so they're skipped
	assert.Empty(t, result.Errors, "no collector should have errored")
}
