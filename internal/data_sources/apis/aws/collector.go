// Package aws provides evidence collection from AWS services.
package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// STSClient defines the interface for STS operations we use.
type STSClient interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// CollectorStatus represents the current state of the AWS collector.
type CollectorStatus struct {
	Connected bool   `json:"connected"`
	AccountID string `json:"account_id,omitempty"`
	Region    string `json:"region,omitempty"`
	Error     string `json:"error,omitempty"`
}

// CollectionResult represents the result of collecting evidence from AWS.
type CollectionResult struct {
	Evidence []evidence.Evidence `json:"evidence"`
	Errors   []CollectionError   `json:"errors,omitempty"`
}

// CollectionError represents an error during collection from a specific service.
type CollectionError struct {
	Service string `json:"service"`
	Error   string `json:"error"`
}

// HasErrors returns true if there were any collection errors.
func (r *CollectionResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// Collector gathers evidence from AWS services.
type Collector struct {
	stsClient          STSClient
	iamClient          IAMClient
	accountClient      AccountClient
	s3Client           S3Client
	cloudtrailClient   CloudTrailClient
	ec2Client          EC2Client
	rdsClient          RDSClient
	kmsClient          KMSClient
	guarddutyClient    GuardDutyClient
	cloudwatchClient   CloudWatchLogsClient
	ecrClient          ECRClient
	configClient       ConfigServiceClient
	securityHubClient  SecurityHubClient
	cwAlarmsClient     CloudWatchAlarmsClient
	secretsMgrClient   SecretsManagerClient
	lambdaClient       LambdaClient
	s3ControlClient    S3ControlClient
	dynamodbClient     DynamoDBClient
	ecsClient          ECSClient
	eksClient          EKSClient
	acmClient          ACMClient
	cloudfrontClient   CloudFrontClient
	wafClient          WAFClient
	macieClient        MacieClient
	ssmClient          SSMClient
	elbv2Client        ELBv2Client
	inspectorClient    InspectorClient
	backupClient       BackupClient
	snsClient          SNSClient
	sqsClient          SQSClient
	eventbridgeClient  EventBridgeClient
	orgsClient         OrganizationsClient
	efsClient          EFSClient
	redshiftClient     RedshiftClient
	opensearchClient   OpenSearchClient
	apigatewayClient       APIGatewayClient
	accessAnalyzerClient   AccessAnalyzerClient
	identityCenterClient   IdentityCenterClient
	elasticacheClient      ElastiCacheClient
	codebuildClient        CodeBuildClient
	dmsClient              DMSClient
	emrClient              EMRClient
	sagemakerClient        SageMakerClient
	accountServiceClient   AccountServiceClient
	neptuneClient          NeptuneClient
	documentdbClient       DocumentDBClient
	mskClient              MSKClient
	kinesisClient          KinesisClient
	networkFirewallClient  NetworkFirewallClient
	autoscalingClient      AutoScalingClient
	glueClient             GlueClient
	beanstalkClient        ElasticBeanstalkClient
	stepFunctionsClient    StepFunctionsClient
	mqClient               MQClient
	route53Client          Route53Client
	fsxClient              FSxClient
	appsyncClient          AppSyncClient
	athenaClient           AthenaClient
	bedrockClient          BedrockClient
	datasyncClient         DataSyncClient
	transferClient         TransferClient
	apigatewayV2Client     APIGatewayV2Client
	cognitoClient          CognitoClient
	redshiftServerlessClient RedshiftServerlessClient
	daxClient              DAXClient
	region                 string
	accountID          string // Cached after first retrieval
	cfg                aws.Config
}

// New creates a new AWS Collector with auto-detected credentials.
func New() *Collector {
	return &Collector{}
}

// WithRegion sets the AWS region for the collector.
func (c *Collector) WithRegion(region string) *Collector {
	c.region = region
	return c
}

// Init initializes all AWS service clients with auto-detected credentials.
func (c *Collector) Init(ctx context.Context) error {
	opts := []func(*awsconfig.LoadOptions) error{}

	if c.region != "" {
		opts = append(opts, awsconfig.WithRegion(c.region))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	c.cfg = cfg

	// Store the resolved region
	if c.region == "" {
		c.region = cfg.Region
	}

	// Initialize all service clients
	c.stsClient = sts.NewFromConfig(cfg)
	c.iamClient = iam.NewFromConfig(cfg)
	c.accountClient = iam.NewFromConfig(cfg)
	c.s3Client = s3.NewFromConfig(cfg)
	c.cloudtrailClient = cloudtrail.NewFromConfig(cfg)
	c.ec2Client = ec2.NewFromConfig(cfg)
	c.rdsClient = rds.NewFromConfig(cfg)
	c.kmsClient = kms.NewFromConfig(cfg)
	c.guarddutyClient = guardduty.NewFromConfig(cfg)
	c.cloudwatchClient = cloudwatchlogs.NewFromConfig(cfg)
	c.ecrClient = ecr.NewFromConfig(cfg)
	c.configClient = configservice.NewFromConfig(cfg)
	c.securityHubClient = securityhub.NewFromConfig(cfg)
	c.cwAlarmsClient = cloudwatch.NewFromConfig(cfg)
	c.secretsMgrClient = secretsmanager.NewFromConfig(cfg)
	c.lambdaClient = lambda.NewFromConfig(cfg)
	c.s3ControlClient = s3control.NewFromConfig(cfg)
	c.dynamodbClient = dynamodb.NewFromConfig(cfg)
	c.ecsClient = ecs.NewFromConfig(cfg)
	c.eksClient = eks.NewFromConfig(cfg)
	c.acmClient = acm.NewFromConfig(cfg)
	c.cloudfrontClient = cloudfront.NewFromConfig(cfg)
	c.wafClient = wafv2.NewFromConfig(cfg)
	c.macieClient = macie2.NewFromConfig(cfg)
	c.ssmClient = ssm.NewFromConfig(cfg)
	c.elbv2Client = elasticloadbalancingv2.NewFromConfig(cfg)
	c.inspectorClient = inspector2.NewFromConfig(cfg)
	c.backupClient = backup.NewFromConfig(cfg)
	c.snsClient = sns.NewFromConfig(cfg)
	c.sqsClient = sqs.NewFromConfig(cfg)
	c.eventbridgeClient = eventbridge.NewFromConfig(cfg)
	c.orgsClient = organizations.NewFromConfig(cfg)
	c.efsClient = efs.NewFromConfig(cfg)
	c.redshiftClient = redshift.NewFromConfig(cfg)
	c.opensearchClient = opensearch.NewFromConfig(cfg)
	c.apigatewayClient = apigateway.NewFromConfig(cfg)
	c.accessAnalyzerClient = accessanalyzer.NewFromConfig(cfg)
	c.identityCenterClient = ssoadmin.NewFromConfig(cfg)
	c.elasticacheClient = elasticache.NewFromConfig(cfg)
	c.codebuildClient = codebuild.NewFromConfig(cfg)
	c.accountServiceClient = account.NewFromConfig(cfg)
	c.dmsClient = databasemigrationservice.NewFromConfig(cfg)
	c.sagemakerClient = sagemaker.NewFromConfig(cfg)
	c.emrClient = emr.NewFromConfig(cfg)
	c.neptuneClient = neptune.NewFromConfig(cfg)
	c.documentdbClient = docdb.NewFromConfig(cfg)
	c.mskClient = kafka.NewFromConfig(cfg)
	c.kinesisClient = kinesis.NewFromConfig(cfg)
	c.networkFirewallClient = networkfirewall.NewFromConfig(cfg)
	c.autoscalingClient = autoscaling.NewFromConfig(cfg)
	c.glueClient = glue.NewFromConfig(cfg)
	c.beanstalkClient = elasticbeanstalk.NewFromConfig(cfg)
	c.stepFunctionsClient = sfn.NewFromConfig(cfg)
	c.mqClient = mq.NewFromConfig(cfg)
	c.route53Client = route53.NewFromConfig(cfg)
	c.fsxClient = fsx.NewFromConfig(cfg)
	c.appsyncClient = appsync.NewFromConfig(cfg)
	c.athenaClient = athena.NewFromConfig(cfg)
	c.bedrockClient = bedrock.NewFromConfig(cfg)
	c.datasyncClient = datasync.NewFromConfig(cfg)
	c.transferClient = transfer.NewFromConfig(cfg)
	c.apigatewayV2Client = apigatewayv2.NewFromConfig(cfg)
	c.cognitoClient = cognitoidentityprovider.NewFromConfig(cfg)
	c.redshiftServerlessClient = redshiftserverless.NewFromConfig(cfg)
	c.daxClient = dax.NewFromConfig(cfg)

	return nil
}

// GetAccountID retrieves the AWS account ID using STS GetCallerIdentity.
func (c *Collector) GetAccountID(ctx context.Context) (string, error) {
	// Return cached value if available
	if c.accountID != "" {
		return c.accountID, nil
	}

	if c.stsClient == nil {
		return "", errors.New("collector not initialized: call Init() first")
	}

	result, err := c.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}

	if result.Account == nil {
		return "", errors.New("account ID not returned from STS")
	}

	c.accountID = *result.Account
	return c.accountID, nil
}

// Status returns the current connection status of the collector.
// Note: This method intentionally returns nil error even when connection fails,
// because connection failure is a valid status (not an execution error).
func (c *Collector) Status(ctx context.Context) CollectorStatus {
	status := CollectorStatus{
		Region: c.region,
	}

	accountID, err := c.GetAccountID(ctx)
	if err != nil {
		status.Connected = false
		status.Error = err.Error()
		return status
	}

	status.Connected = true
	status.AccountID = accountID
	return status
}

// Region returns the configured region.
func (c *Collector) Region() string {
	return c.region
}

// Collect gathers evidence from AWS services using fail-safe pattern.
// If one service fails, the others continue and partial results are returned.
// When services are specified, only those services are collected. When no
// services are specified, all services are collected (backward compatible).
func (c *Collector) Collect(ctx context.Context, services ...string) (*CollectionResult, error) {
	accountID, err := c.GetAccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get account ID: %w", err)
	}

	serviceFilter := make(map[string]bool, len(services))
	for _, s := range services {
		serviceFilter[s] = true
	}
	shouldCollect := func(svc string) bool {
		return len(serviceFilter) == 0 || serviceFilter[svc]
	}

	result := &CollectionResult{
		Evidence: []evidence.Evidence{},
		Errors:   []CollectionError{},
	}

	if shouldCollect("iam") {
		c.collectIAM(ctx, accountID, result)
		c.collectAccount(ctx, accountID, result)
	}

	if shouldCollect("s3") {
		c.collectS3(ctx, accountID, result)
	}

	if shouldCollect("cloudtrail") {
		c.collectCloudTrail(ctx, accountID, result)
	}

	if shouldCollect("ec2") {
		c.collectEC2(ctx, accountID, result)
	}

	if shouldCollect("rds") {
		c.collectRDS(ctx, accountID, result)
	}

	if shouldCollect("kms") {
		c.collectKMS(ctx, accountID, result)
	}

	if shouldCollect("guardduty") {
		c.collectGuardDuty(ctx, accountID, result)
	}

	if shouldCollect("logs") {
		c.collectCloudWatch(ctx, accountID, result)
	}

	if shouldCollect("ecr") {
		c.collectECR(ctx, accountID, result)
	}

	if shouldCollect("config") {
		c.collectConfig(ctx, accountID, result)
	}

	if shouldCollect("securityhub") {
		c.collectSecurityHub(ctx, accountID, result)
	}

	if shouldCollect("cloudwatch") {
		c.collectCloudWatchAlarms(ctx, accountID, result)
	}

	if shouldCollect("secretsmanager") {
		c.collectSecretsManager(ctx, accountID, result)
	}

	if shouldCollect("lambda") {
		c.collectLambda(ctx, accountID, result)
	}

	if shouldCollect("s3control") {
		c.collectS3Control(ctx, accountID, result)
	}

	if shouldCollect("dynamodb") {
		c.collectDynamoDB(ctx, accountID, result)
	}

	if shouldCollect("ecs") {
		c.collectECS(ctx, accountID, result)
	}

	if shouldCollect("eks") {
		c.collectEKS(ctx, accountID, result)
	}

	if shouldCollect("acm") {
		c.collectACM(ctx, accountID, result)
	}

	if shouldCollect("cloudfront") {
		c.collectCloudFront(ctx, accountID, result)
	}

	if shouldCollect("wafv2") {
		c.collectWAF(ctx, accountID, result)
	}

	if shouldCollect("macie2") {
		c.collectMacie(ctx, accountID, result)
	}

	if shouldCollect("ssm") {
		c.collectSSM(ctx, accountID, result)
	}

	if shouldCollect("elbv2") {
		c.collectELBv2(ctx, accountID, result)
	}

	if shouldCollect("inspector") {
		c.collectInspector(ctx, accountID, result)
	}

	if shouldCollect("backup") {
		c.collectBackup(ctx, accountID, result)
	}

	if shouldCollect("eventbridge") {
		c.collectEventBridge(ctx, accountID, result)
	}

	if shouldCollect("sns") {
		c.collectSNS(ctx, accountID, result)
	}

	if shouldCollect("sqs") {
		c.collectSQS(ctx, accountID, result)
	}

	if shouldCollect("organizations") {
		c.collectOrganizations(ctx, accountID, result)
	}

	if shouldCollect("efs") {
		c.collectEFS(ctx, accountID, result)
	}

	if shouldCollect("redshift") {
		c.collectRedshift(ctx, accountID, result)
	}

	if shouldCollect("opensearch") {
		c.collectOpenSearch(ctx, accountID, result)
	}

	if shouldCollect("apigateway") {
		c.collectAPIGateway(ctx, accountID, result)
	}

	if shouldCollect("accessanalyzer") {
		c.collectAccessAnalyzer(ctx, accountID, result)
	}

	if shouldCollect("identitycenter") {
		c.collectIdentityCenter(ctx, accountID, result)
	}

	if shouldCollect("elasticache") {
		c.collectElastiCache(ctx, accountID, result)
	}

	if shouldCollect("account") {
		c.collectAccountService(ctx, accountID, result)
	}

	if shouldCollect("codebuild") {
		c.collectCodeBuild(ctx, accountID, result)
	}

	if shouldCollect("dms") {
		c.collectDMS(ctx, accountID, result)
	}

	if shouldCollect("sagemaker") {
		c.collectSageMaker(ctx, accountID, result)
	}

	if shouldCollect("emr") {
		c.collectEMR(ctx, accountID, result)
	}

	if shouldCollect("neptune") {
		c.collectNeptune(ctx, accountID, result)
	}

	if shouldCollect("documentdb") {
		c.collectDocumentDB(ctx, accountID, result)
	}

	if shouldCollect("msk") {
		c.collectMSK(ctx, accountID, result)
	}

	if shouldCollect("kinesis") {
		c.collectKinesis(ctx, accountID, result)
	}

	if shouldCollect("networkfirewall") {
		c.collectNetworkFirewall(ctx, accountID, result)
	}

	if shouldCollect("autoscaling") {
		c.collectAutoScaling(ctx, accountID, result)
	}

	if shouldCollect("glue") {
		c.collectGlue(ctx, accountID, result)
	}

	if shouldCollect("elasticbeanstalk") {
		c.collectBeanstalk(ctx, accountID, result)
	}

	if shouldCollect("stepfunctions") {
		c.collectStepFunctions(ctx, accountID, result)
	}

	if shouldCollect("mq") {
		c.collectMQ(ctx, accountID, result)
	}

	if shouldCollect("route53") {
		c.collectRoute53(ctx, accountID, result)
	}

	if shouldCollect("fsx") {
		c.collectFSx(ctx, accountID, result)
	}

	if shouldCollect("appsync") {
		c.collectAppSync(ctx, accountID, result)
	}

	if shouldCollect("athena") {
		c.collectAthena(ctx, accountID, result)
	}

	if shouldCollect("bedrock") {
		c.collectBedrock(ctx, accountID, result)
	}

	if shouldCollect("datasync") {
		c.collectDataSync(ctx, accountID, result)
	}

	if shouldCollect("transfer") {
		c.collectTransfer(ctx, accountID, result)
	}

	if shouldCollect("apigatewayv2") {
		c.collectAPIGatewayV2(ctx, accountID, result)
	}

	if shouldCollect("cognito") {
		c.collectCognito(ctx, accountID, result)
	}

	if shouldCollect("redshiftserverless") {
		c.collectRedshiftServerless(ctx, accountID, result)
	}

	if shouldCollect("dax") {
		c.collectDAX(ctx, accountID, result)
	}

	return result, nil
}

// collectEFS collects EFS evidence with fail-safe pattern.
func (c *Collector) collectEFS(ctx context.Context, accountID string, result *CollectionResult) {
	if c.efsClient == nil {
		return
	}
	collector := NewEFSCollector(c.efsClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "efs", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectRedshift collects Redshift evidence with fail-safe pattern.
func (c *Collector) collectRedshift(ctx context.Context, accountID string, result *CollectionResult) {
	if c.redshiftClient == nil {
		return
	}
	collector := NewRedshiftCollector(c.redshiftClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "redshift", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectOpenSearch collects OpenSearch evidence with fail-safe pattern.
func (c *Collector) collectOpenSearch(ctx context.Context, accountID string, result *CollectionResult) {
	if c.opensearchClient == nil {
		return
	}
	collector := NewOpenSearchCollector(c.opensearchClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "opensearch", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectAPIGateway collects API Gateway evidence with fail-safe pattern.
func (c *Collector) collectAPIGateway(ctx context.Context, accountID string, result *CollectionResult) {
	if c.apigatewayClient == nil {
		return
	}
	collector := NewAPIGatewayCollector(c.apigatewayClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "apigateway", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectIAM collects IAM user evidence with fail-safe pattern.
func (c *Collector) collectIAM(ctx context.Context, accountID string, result *CollectionResult) {
	iamCollector := NewIAMCollector(c.iamClient)
	ev, err := iamCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "iam",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectS3 collects S3 bucket evidence with fail-safe pattern.
func (c *Collector) collectS3(ctx context.Context, accountID string, result *CollectionResult) {
	s3Collector := NewS3Collector(c.s3Client)
	ev, err := s3Collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "s3",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectCloudTrail collects CloudTrail evidence with fail-safe pattern.
func (c *Collector) collectCloudTrail(ctx context.Context, accountID string, result *CollectionResult) {
	ctCollector := NewCloudTrailCollector(c.cloudtrailClient)
	ev, err := ctCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "cloudtrail",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectAccount collects account-level IAM evidence with fail-safe pattern.
func (c *Collector) collectAccount(ctx context.Context, accountID string, result *CollectionResult) {
	if c.accountClient == nil {
		return
	}
	accountCollector := NewAccountCollector(c.accountClient)
	ev, err := accountCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "iam-account",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectEC2 collects EC2 evidence with fail-safe pattern.
func (c *Collector) collectEC2(ctx context.Context, accountID string, result *CollectionResult) {
	if c.ec2Client == nil {
		return
	}
	ec2Collector := NewEC2Collector(c.ec2Client, c.region)
	ev, err := ec2Collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "ec2",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectRDS collects RDS evidence with fail-safe pattern.
func (c *Collector) collectRDS(ctx context.Context, accountID string, result *CollectionResult) {
	if c.rdsClient == nil {
		return
	}
	rdsCollector := NewRDSCollector(c.rdsClient)
	ev, err := rdsCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "rds",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectKMS collects KMS evidence with fail-safe pattern.
func (c *Collector) collectKMS(ctx context.Context, accountID string, result *CollectionResult) {
	if c.kmsClient == nil {
		return
	}
	kmsCollector := NewKMSCollector(c.kmsClient)
	ev, err := kmsCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "kms",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectGuardDuty collects GuardDuty evidence with fail-safe pattern.
func (c *Collector) collectGuardDuty(ctx context.Context, accountID string, result *CollectionResult) {
	if c.guarddutyClient == nil {
		return
	}
	gdCollector := NewGuardDutyCollector(c.guarddutyClient, c.region)
	ev, err := gdCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "guardduty",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectCloudWatch collects CloudWatch evidence with fail-safe pattern.
func (c *Collector) collectCloudWatch(ctx context.Context, accountID string, result *CollectionResult) {
	if c.cloudwatchClient == nil {
		return
	}
	cwCollector := NewCloudWatchCollector(c.cloudwatchClient)
	ev, err := cwCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "cloudwatch-logs",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectECR collects ECR evidence with fail-safe pattern.
func (c *Collector) collectECR(ctx context.Context, accountID string, result *CollectionResult) {
	if c.ecrClient == nil {
		return
	}
	ecrCollector := NewECRCollector(c.ecrClient)
	ev, err := ecrCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "ecr",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectConfig collects AWS Config evidence with fail-safe pattern.
func (c *Collector) collectConfig(ctx context.Context, accountID string, result *CollectionResult) {
	if c.configClient == nil {
		return
	}
	configCollector := NewConfigCollector(c.configClient, c.region)
	ev, err := configCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Service: "config",
			Error:   err.Error(),
		})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectSecurityHub collects Security Hub evidence with fail-safe pattern.
func (c *Collector) collectSecurityHub(ctx context.Context, accountID string, result *CollectionResult) {
	if c.securityHubClient == nil {
		return
	}
	collector := NewSecurityHubCollector(c.securityHubClient, c.region)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "securityhub", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectCloudWatchAlarms collects CloudWatch alarm evidence with fail-safe pattern.
func (c *Collector) collectCloudWatchAlarms(ctx context.Context, accountID string, result *CollectionResult) {
	if c.cwAlarmsClient == nil {
		return
	}
	collector := NewCloudWatchAlarmsCollector(c.cwAlarmsClient, c.region)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "cloudwatch-alarms", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectSecretsManager collects Secrets Manager evidence with fail-safe pattern.
func (c *Collector) collectSecretsManager(ctx context.Context, accountID string, result *CollectionResult) {
	if c.secretsMgrClient == nil {
		return
	}
	collector := NewSecretsManagerCollector(c.secretsMgrClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "secretsmanager", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectLambda collects Lambda evidence with fail-safe pattern.
func (c *Collector) collectLambda(ctx context.Context, accountID string, result *CollectionResult) {
	if c.lambdaClient == nil {
		return
	}
	collector := NewLambdaCollector(c.lambdaClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "lambda", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectS3Control collects S3 account-level public access block evidence with fail-safe pattern.
func (c *Collector) collectS3Control(ctx context.Context, accountID string, result *CollectionResult) {
	if c.s3ControlClient == nil {
		return
	}
	collector := NewS3ControlCollector(c.s3ControlClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "s3control", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectDynamoDB collects DynamoDB evidence with fail-safe pattern.
func (c *Collector) collectDynamoDB(ctx context.Context, accountID string, result *CollectionResult) {
	if c.dynamodbClient == nil {
		return
	}
	collector := NewDynamoDBCollector(c.dynamodbClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "dynamodb", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectECS collects ECS evidence with fail-safe pattern.
func (c *Collector) collectECS(ctx context.Context, accountID string, result *CollectionResult) {
	if c.ecsClient == nil {
		return
	}
	collector := NewECSCollector(c.ecsClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "ecs", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectEKS collects EKS evidence with fail-safe pattern.
func (c *Collector) collectEKS(ctx context.Context, accountID string, result *CollectionResult) {
	if c.eksClient == nil {
		return
	}
	collector := NewEKSCollector(c.eksClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "eks", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectACM collects ACM certificate evidence with fail-safe pattern.
func (c *Collector) collectACM(ctx context.Context, accountID string, result *CollectionResult) {
	if c.acmClient == nil {
		return
	}
	collector := NewACMCollector(c.acmClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "acm", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectCloudFront collects CloudFront evidence with fail-safe pattern.
func (c *Collector) collectCloudFront(ctx context.Context, accountID string, result *CollectionResult) {
	if c.cloudfrontClient == nil {
		return
	}
	collector := NewCloudFrontCollector(c.cloudfrontClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "cloudfront", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectWAF collects WAF evidence with fail-safe pattern.
func (c *Collector) collectWAF(ctx context.Context, accountID string, result *CollectionResult) {
	if c.wafClient == nil {
		return
	}
	collector := NewWAFCollector(c.wafClient, c.region)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "waf", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectMacie collects Macie evidence with fail-safe pattern.
func (c *Collector) collectMacie(ctx context.Context, accountID string, result *CollectionResult) {
	if c.macieClient == nil {
		return
	}
	collector := NewMacieCollector(c.macieClient, c.region)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "macie", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectSSM collects SSM evidence with fail-safe pattern.
func (c *Collector) collectSSM(ctx context.Context, accountID string, result *CollectionResult) {
	if c.ssmClient == nil {
		return
	}
	collector := NewSSMCollector(c.ssmClient, c.region)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "ssm", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectELBv2 collects ELBv2 evidence with fail-safe pattern.
func (c *Collector) collectELBv2(ctx context.Context, accountID string, result *CollectionResult) {
	if c.elbv2Client == nil {
		return
	}
	elbCollector := NewELBv2Collector(c.elbv2Client)
	ev, err := elbCollector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "elbv2", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectInspector collects Inspector evidence with fail-safe pattern.
func (c *Collector) collectInspector(ctx context.Context, accountID string, result *CollectionResult) {
	if c.inspectorClient == nil {
		return
	}
	collector := NewInspectorCollector(c.inspectorClient, c.region)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "inspector", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectBackup collects Backup evidence with fail-safe pattern.
func (c *Collector) collectBackup(ctx context.Context, accountID string, result *CollectionResult) {
	if c.backupClient == nil {
		return
	}
	collector := NewBackupCollector(c.backupClient, c.region)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "backup", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectEventBridge collects EventBridge evidence with fail-safe pattern.
func (c *Collector) collectEventBridge(ctx context.Context, accountID string, result *CollectionResult) {
	if c.eventbridgeClient == nil {
		return
	}
	collector := NewEventBridgeCollector(c.eventbridgeClient, c.region)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "eventbridge", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectSNS collects SNS topic evidence with fail-safe pattern.
func (c *Collector) collectSNS(ctx context.Context, accountID string, result *CollectionResult) {
	if c.snsClient == nil {
		return
	}
	collector := NewSNSCollector(c.snsClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "sns", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectSQS collects SQS queue evidence with fail-safe pattern.
func (c *Collector) collectSQS(ctx context.Context, accountID string, result *CollectionResult) {
	if c.sqsClient == nil {
		return
	}
	collector := NewSQSCollector(c.sqsClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "sqs", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectOrganizations collects Organizations evidence with fail-safe pattern.
func (c *Collector) collectOrganizations(ctx context.Context, accountID string, result *CollectionResult) {
	if c.orgsClient == nil {
		return
	}
	collector := NewOrganizationsCollector(c.orgsClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "organizations", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectAccessAnalyzer collects Access Analyzer evidence with fail-safe pattern.
func (c *Collector) collectAccessAnalyzer(ctx context.Context, accountID string, result *CollectionResult) {
	if c.accessAnalyzerClient == nil {
		return
	}
	collector := NewAccessAnalyzerCollector(c.accessAnalyzerClient, c.region)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "accessanalyzer", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectIdentityCenter collects Identity Center evidence with fail-safe pattern.
func (c *Collector) collectIdentityCenter(ctx context.Context, accountID string, result *CollectionResult) {
	if c.identityCenterClient == nil {
		return
	}
	collector := NewIdentityCenterCollector(c.identityCenterClient, c.region)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "identitycenter", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectAccountService collects Account service evidence with fail-safe pattern.
func (c *Collector) collectAccountService(ctx context.Context, accountID string, result *CollectionResult) {
	if c.accountServiceClient == nil {
		return
	}
	collector := NewAccountServiceCollector(c.accountServiceClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "account", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectElastiCache collects ElastiCache evidence with fail-safe pattern.
func (c *Collector) collectElastiCache(ctx context.Context, accountID string, result *CollectionResult) {
	if c.elasticacheClient == nil {
		return
	}
	collector := NewElastiCacheCollector(c.elasticacheClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "elasticache", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectDMS collects DMS evidence with fail-safe pattern.
func (c *Collector) collectDMS(ctx context.Context, accountID string, result *CollectionResult) {
	if c.dmsClient == nil {
		return
	}
	collector := NewDMSCollector(c.dmsClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "dms", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectSageMaker collects SageMaker evidence with fail-safe pattern.
func (c *Collector) collectSageMaker(ctx context.Context, accountID string, result *CollectionResult) {
	if c.sagemakerClient == nil {
		return
	}
	collector := NewSageMakerCollector(c.sagemakerClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "sagemaker", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectCodeBuild collects CodeBuild evidence with fail-safe pattern.
func (c *Collector) collectCodeBuild(ctx context.Context, accountID string, result *CollectionResult) {
	if c.codebuildClient == nil {
		return
	}
	collector := NewCodeBuildCollector(c.codebuildClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "codebuild", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectEMR collects EMR evidence with fail-safe pattern.
func (c *Collector) collectEMR(ctx context.Context, accountID string, result *CollectionResult) {
	if c.emrClient == nil {
		return
	}
	collector := NewEMRCollector(c.emrClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "emr", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectNeptune collects Neptune evidence with fail-safe pattern.
func (c *Collector) collectNeptune(ctx context.Context, accountID string, result *CollectionResult) {
	if c.neptuneClient == nil {
		return
	}
	collector := NewNeptuneCollector(c.neptuneClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "neptune", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectDocumentDB collects DocumentDB evidence with fail-safe pattern.
func (c *Collector) collectDocumentDB(ctx context.Context, accountID string, result *CollectionResult) {
	if c.documentdbClient == nil {
		return
	}
	collector := NewDocumentDBCollector(c.documentdbClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "documentdb", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectMSK collects MSK evidence with fail-safe pattern.
func (c *Collector) collectMSK(ctx context.Context, accountID string, result *CollectionResult) {
	if c.mskClient == nil {
		return
	}
	collector := NewMSKCollector(c.mskClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "msk", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectKinesis collects Kinesis evidence with fail-safe pattern.
func (c *Collector) collectKinesis(ctx context.Context, accountID string, result *CollectionResult) {
	if c.kinesisClient == nil {
		return
	}
	collector := NewKinesisCollector(c.kinesisClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "kinesis", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectNetworkFirewall collects Network Firewall evidence with fail-safe pattern.
func (c *Collector) collectNetworkFirewall(ctx context.Context, accountID string, result *CollectionResult) {
	if c.networkFirewallClient == nil {
		return
	}
	collector := NewNetworkFirewallCollector(c.networkFirewallClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "networkfirewall", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectAutoScaling collects Auto Scaling evidence with fail-safe pattern.
func (c *Collector) collectAutoScaling(ctx context.Context, accountID string, result *CollectionResult) {
	if c.autoscalingClient == nil {
		return
	}
	collector := NewAutoScalingCollector(c.autoscalingClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "autoscaling", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectGlue collects Glue evidence with fail-safe pattern.
func (c *Collector) collectGlue(ctx context.Context, accountID string, result *CollectionResult) {
	if c.glueClient == nil {
		return
	}
	collector := NewGlueCollector(c.glueClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "glue", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectBeanstalk collects Elastic Beanstalk evidence with fail-safe pattern.
func (c *Collector) collectBeanstalk(ctx context.Context, accountID string, result *CollectionResult) {
	if c.beanstalkClient == nil {
		return
	}
	collector := NewBeanstalkCollector(c.beanstalkClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "elasticbeanstalk", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectStepFunctions collects Step Functions evidence with fail-safe pattern.
func (c *Collector) collectStepFunctions(ctx context.Context, accountID string, result *CollectionResult) {
	if c.stepFunctionsClient == nil {
		return
	}
	collector := NewStepFunctionsCollector(c.stepFunctionsClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "stepfunctions", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectMQ collects MQ evidence with fail-safe pattern.
func (c *Collector) collectMQ(ctx context.Context, accountID string, result *CollectionResult) {
	if c.mqClient == nil {
		return
	}
	collector := NewMQCollector(c.mqClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "mq", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectRoute53 collects Route 53 evidence with fail-safe pattern.
func (c *Collector) collectRoute53(ctx context.Context, accountID string, result *CollectionResult) {
	if c.route53Client == nil {
		return
	}
	collector := NewRoute53Collector(c.route53Client)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "route53", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectFSx collects FSx evidence with fail-safe pattern.
func (c *Collector) collectFSx(ctx context.Context, accountID string, result *CollectionResult) {
	if c.fsxClient == nil {
		return
	}
	collector := NewFSxCollector(c.fsxClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "fsx", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectAppSync collects AppSync evidence with fail-safe pattern.
func (c *Collector) collectAppSync(ctx context.Context, accountID string, result *CollectionResult) {
	if c.appsyncClient == nil {
		return
	}
	collector := NewAppSyncCollector(c.appsyncClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "appsync", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectAthena collects Athena evidence with fail-safe pattern.
func (c *Collector) collectAthena(ctx context.Context, accountID string, result *CollectionResult) {
	if c.athenaClient == nil {
		return
	}
	collector := NewAthenaCollector(c.athenaClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "athena", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectBedrock collects Bedrock evidence with fail-safe pattern.
func (c *Collector) collectBedrock(ctx context.Context, accountID string, result *CollectionResult) {
	if c.bedrockClient == nil {
		return
	}
	collector := NewBedrockCollector(c.bedrockClient, c.region)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "bedrock", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectDataSync collects DataSync evidence with fail-safe pattern.
func (c *Collector) collectDataSync(ctx context.Context, accountID string, result *CollectionResult) {
	if c.datasyncClient == nil {
		return
	}
	collector := NewDataSyncCollector(c.datasyncClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "datasync", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectTransfer collects Transfer Family evidence with fail-safe pattern.
func (c *Collector) collectTransfer(ctx context.Context, accountID string, result *CollectionResult) {
	if c.transferClient == nil {
		return
	}
	collector := NewTransferCollector(c.transferClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "transfer", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectAPIGatewayV2 collects API Gateway V2 evidence with fail-safe pattern.
func (c *Collector) collectAPIGatewayV2(ctx context.Context, accountID string, result *CollectionResult) {
	if c.apigatewayV2Client == nil {
		return
	}
	collector := NewAPIGatewayV2Collector(c.apigatewayV2Client)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "apigatewayv2", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectCognito collects Cognito evidence with fail-safe pattern.
func (c *Collector) collectCognito(ctx context.Context, accountID string, result *CollectionResult) {
	if c.cognitoClient == nil {
		return
	}
	collector := NewCognitoCollector(c.cognitoClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "cognito", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectRedshiftServerless collects Redshift Serverless evidence with fail-safe pattern.
func (c *Collector) collectRedshiftServerless(ctx context.Context, accountID string, result *CollectionResult) {
	if c.redshiftServerlessClient == nil {
		return
	}
	collector := NewRedshiftServerlessCollector(c.redshiftServerlessClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "redshift-serverless", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}

// collectDAX collects DAX evidence with fail-safe pattern.
func (c *Collector) collectDAX(ctx context.Context, accountID string, result *CollectionResult) {
	if c.daxClient == nil {
		return
	}
	collector := NewDAXCollector(c.daxClient)
	ev, err := collector.CollectEvidence(ctx, accountID)
	if err != nil {
		result.Errors = append(result.Errors, CollectionError{Service: "dax", Error: err.Error()})
		return
	}
	result.Evidence = append(result.Evidence, ev...)
}
