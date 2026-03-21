package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// CodeBuildClient defines the interface for CodeBuild operations.
type CodeBuildClient interface {
	ListProjects(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error)
	BatchGetProjects(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error)
}

// CodeBuildProject represents a CodeBuild project.
type CodeBuildProject struct {
	Name                   string `json:"name"`
	ARN                    string `json:"arn"`
	CleartextCredentials   bool   `json:"cleartext_credentials"`
	SourceCredentialsInURL bool   `json:"source_credentials_in_url"`
	S3LogsEncrypted        bool   `json:"s3_logs_encrypted"`
	LoggingConfigured      bool   `json:"logging_configured"`
	PrivilegedMode         bool   `json:"privileged_mode"`
}

// ToEvidence converts a CodeBuildProject to Evidence.
func (p *CodeBuildProject) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(p) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:codebuild:project", p.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// CodeBuildCollector collects CodeBuild project data.
type CodeBuildCollector struct {
	client CodeBuildClient
}

// NewCodeBuildCollector creates a new CodeBuild collector.
func NewCodeBuildCollector(client CodeBuildClient) *CodeBuildCollector {
	return &CodeBuildCollector{client: client}
}

// CollectProjects retrieves all CodeBuild projects.
//nolint:gocyclo // AWS API response mapping requires sequential field extraction
func (c *CodeBuildCollector) CollectProjects(ctx context.Context) ([]CodeBuildProject, error) {
	var projects []CodeBuildProject
	var nextToken *string

	for {
		listOutput, err := c.client.ListProjects(ctx, &codebuild.ListProjectsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list CodeBuild projects: %w", err)
		}

		if len(listOutput.Projects) == 0 {
			break
		}

		batchOutput, err := c.client.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: listOutput.Projects,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get CodeBuild project details: %w", err)
		}

		for i := range batchOutput.Projects {
			proj := &batchOutput.Projects[i]
			project := CodeBuildProject{
				Name: awssdk.ToString(proj.Name),
				ARN:  awssdk.ToString(proj.Arn),
			}

			// Check for cleartext credentials in environment variables
			if proj.Environment != nil {
				project.PrivilegedMode = awssdk.ToBool(proj.Environment.PrivilegedMode)
				for _, envVar := range proj.Environment.EnvironmentVariables {
					if envVar.Type == "PLAINTEXT" {
						name := strings.ToUpper(awssdk.ToString(envVar.Name))
						if strings.Contains(name, "PASSWORD") || strings.Contains(name, "SECRET") ||
							strings.Contains(name, "TOKEN") || strings.Contains(name, "KEY") {
							project.CleartextCredentials = true
						}
					}
				}
			}

			// Check source for credentials in URL
			if proj.Source != nil {
				loc := awssdk.ToString(proj.Source.Location)
				if strings.Contains(loc, "@") || strings.Contains(loc, "://") && strings.Contains(loc, ":") {
					// Basic heuristic: URL with embedded credentials
					if strings.Contains(loc, "://") {
						parts := strings.SplitN(loc, "://", 2)
						if len(parts) == 2 && strings.Contains(strings.SplitN(parts[1], "/", 2)[0], "@") {
							project.SourceCredentialsInURL = true
						}
					}
				}
			}

			// Check logging configuration
			if proj.LogsConfig != nil {
				cwConfigured := proj.LogsConfig.CloudWatchLogs != nil && string(proj.LogsConfig.CloudWatchLogs.Status) == statusEnabled
				s3Configured := proj.LogsConfig.S3Logs != nil && string(proj.LogsConfig.S3Logs.Status) == statusEnabled
				project.LoggingConfigured = cwConfigured || s3Configured

				if proj.LogsConfig.S3Logs != nil && string(proj.LogsConfig.S3Logs.Status) == statusEnabled {
					project.S3LogsEncrypted = !awssdk.ToBool(proj.LogsConfig.S3Logs.EncryptionDisabled)
				}
			}

			projects = append(projects, project)
		}

		if listOutput.NextToken == nil {
			break
		}
		nextToken = listOutput.NextToken
	}

	return projects, nil
}

// CollectEvidence collects CodeBuild projects as evidence.
func (c *CodeBuildCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	projects, err := c.CollectProjects(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(projects))
	for i := range projects {
		evidenceList = append(evidenceList, projects[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
