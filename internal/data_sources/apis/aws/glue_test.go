package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockGlueClient struct {
	GetJobsFunc func(ctx context.Context, params *glue.GetJobsInput, optFns ...func(*glue.Options)) (*glue.GetJobsOutput, error)
}

func (m *MockGlueClient) GetJobs(ctx context.Context, params *glue.GetJobsInput, optFns ...func(*glue.Options)) (*glue.GetJobsOutput, error) {
	return m.GetJobsFunc(ctx, params, optFns...)
}

func TestGlueCollector_CollectJobs(t *testing.T) {
	mock := &MockGlueClient{
		GetJobsFunc: func(ctx context.Context, params *glue.GetJobsInput, optFns ...func(*glue.Options)) (*glue.GetJobsOutput, error) {
			return &glue.GetJobsOutput{
				Jobs: []gluetypes.Job{
					{
						Name:                  awssdk.String("encrypted-job"),
						GlueVersion:           awssdk.String("4.0"),
						SecurityConfiguration: awssdk.String("my-security-config"),
					},
					{
						Name:        awssdk.String("unencrypted-job"),
						GlueVersion: awssdk.String("2.0"),
					},
				},
			}, nil
		},
	}

	collector := NewGlueCollector(mock)
	jobs, err := collector.CollectJobs(context.Background(), "123456789012")
	require.NoError(t, err)
	require.Len(t, jobs, 2)

	assert.Equal(t, "encrypted-job", jobs[0].JobName)
	assert.True(t, jobs[0].Encrypted)
	assert.Equal(t, "4.0", jobs[0].GlueVersion)
	assert.Equal(t, "arn:aws:glue::123456789012:job/encrypted-job", jobs[0].ARN)

	assert.Equal(t, "unencrypted-job", jobs[1].JobName)
	assert.False(t, jobs[1].Encrypted)
	assert.Equal(t, "2.0", jobs[1].GlueVersion)
	assert.Equal(t, "arn:aws:glue::123456789012:job/unencrypted-job", jobs[1].ARN)
}

func TestGlueCollector_CollectJobs_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockGlueClient{
		GetJobsFunc: func(ctx context.Context, params *glue.GetJobsInput, optFns ...func(*glue.Options)) (*glue.GetJobsOutput, error) {
			callCount++
			if callCount == 1 {
				return &glue.GetJobsOutput{
					Jobs:      []gluetypes.Job{{Name: awssdk.String("job-1"), GlueVersion: awssdk.String("4.0")}},
					NextToken: awssdk.String("page2"),
				}, nil
			}
			return &glue.GetJobsOutput{
				Jobs: []gluetypes.Job{{Name: awssdk.String("job-2"), GlueVersion: awssdk.String("3.0")}},
			}, nil
		},
	}

	collector := NewGlueCollector(mock)
	jobs, err := collector.CollectJobs(context.Background(), "123456789012")
	require.NoError(t, err)
	assert.Len(t, jobs, 2)
	assert.Equal(t, 2, callCount)
}

func TestGlueCollector_CollectJobs_Error(t *testing.T) {
	mock := &MockGlueClient{
		GetJobsFunc: func(ctx context.Context, params *glue.GetJobsInput, optFns ...func(*glue.Options)) (*glue.GetJobsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewGlueCollector(mock)
	_, err := collector.CollectJobs(context.Background(), "123456789012")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get Glue jobs")
}

func TestGlueCollector_CollectEvidence(t *testing.T) {
	mock := &MockGlueClient{
		GetJobsFunc: func(ctx context.Context, params *glue.GetJobsInput, optFns ...func(*glue.Options)) (*glue.GetJobsOutput, error) {
			return &glue.GetJobsOutput{
				Jobs: []gluetypes.Job{
					{Name: awssdk.String("my-job"), GlueVersion: awssdk.String("4.0")},
				},
			}, nil
		},
	}

	collector := NewGlueCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")
	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:glue:job", ev[0].ResourceType)
	assert.Equal(t, "123456789012", ev[0].Metadata.AccountID)
}
