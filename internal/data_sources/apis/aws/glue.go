package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// GlueClient defines the interface for Glue operations.
type GlueClient interface {
	GetJobs(ctx context.Context, params *glue.GetJobsInput, optFns ...func(*glue.Options)) (*glue.GetJobsOutput, error)
}

// GlueJob represents a Glue ETL job.
type GlueJob struct {
	JobName     string `json:"job_name"`
	ARN         string `json:"arn,omitempty"`
	Encrypted   bool   `json:"encrypted"`
	GlueVersion string `json:"glue_version"`
}

// ToEvidence converts a GlueJob to Evidence.
func (j *GlueJob) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(j) //nolint:errcheck
	resourceID := j.ARN
	if resourceID == "" {
		resourceID = fmt.Sprintf("arn:aws:glue::%s:job/%s", accountID, j.JobName)
	}
	ev := evidence.New("aws", "aws:glue:job", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// GlueCollector collects AWS Glue job data.
type GlueCollector struct {
	client GlueClient
}

// NewGlueCollector creates a new Glue collector.
func NewGlueCollector(client GlueClient) *GlueCollector {
	return &GlueCollector{client: client}
}

// CollectJobs retrieves all Glue jobs.
func (c *GlueCollector) CollectJobs(ctx context.Context, accountID string) ([]GlueJob, error) {
	var jobs []GlueJob
	var nextToken *string

	for {
		output, err := c.client.GetJobs(ctx, &glue.GetJobsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get Glue jobs: %w", err)
		}

		for _, job := range output.Jobs {
			gjob := GlueJob{
				JobName:     awssdk.ToString(job.Name),
				GlueVersion: awssdk.ToString(job.GlueVersion),
				// A non-empty SecurityConfiguration means the job uses encryption
				Encrypted: job.SecurityConfiguration != nil && awssdk.ToString(job.SecurityConfiguration) != "",
			}
			// Glue Job does not have a dedicated ARN field; construct it
			gjob.ARN = fmt.Sprintf("arn:aws:glue::%s:job/%s", accountID, gjob.JobName)

			jobs = append(jobs, gjob)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return jobs, nil
}

// CollectEvidence collects Glue jobs as evidence.
func (c *GlueCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	jobs, err := c.CollectJobs(ctx, accountID)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(jobs))
	for i := range jobs {
		evidenceList = append(evidenceList, jobs[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
