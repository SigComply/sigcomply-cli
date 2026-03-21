module github.com/sigcomply/sigcomply-cli

go 1.25.0

require (
	github.com/aws/aws-sdk-go-v2 v1.41.4
	github.com/aws/aws-sdk-go-v2/config v1.32.12
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.45.11
	github.com/aws/aws-sdk-go-v2/service/account v1.30.4
	github.com/aws/aws-sdk-go-v2/service/acm v1.37.22
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.39.0
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.33.8
	github.com/aws/aws-sdk-go-v2/service/appsync v1.53.4
	github.com/aws/aws-sdk-go-v2/service/athena v1.57.3
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.64.3
	github.com/aws/aws-sdk-go-v2/service/backup v1.54.10
	github.com/aws/aws-sdk-go-v2/service/bedrock v1.56.1
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.60.3
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.55.8
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.55.2
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.64.1
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.68.12
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.59.2
	github.com/aws/aws-sdk-go-v2/service/configservice v1.62.0
	github.com/aws/aws-sdk-go-v2/service/databasemigrationservice v1.61.9
	github.com/aws/aws-sdk-go-v2/service/datasync v1.58.1
	github.com/aws/aws-sdk-go-v2/service/dax v1.29.15
	github.com/aws/aws-sdk-go-v2/service/docdb v1.48.12
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.57.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.296.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.56.1
	github.com/aws/aws-sdk-go-v2/service/ecs v1.74.0
	github.com/aws/aws-sdk-go-v2/service/efs v1.41.13
	github.com/aws/aws-sdk-go-v2/service/eks v1.81.1
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.51.12
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.34.1
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.54.9
	github.com/aws/aws-sdk-go-v2/service/emr v1.58.0
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.45.22
	github.com/aws/aws-sdk-go-v2/service/fsx v1.65.6
	github.com/aws/aws-sdk-go-v2/service/glue v1.139.0
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.74.1
	github.com/aws/aws-sdk-go-v2/service/iam v1.53.6
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.47.3
	github.com/aws/aws-sdk-go-v2/service/kafka v1.49.1
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.43.3
	github.com/aws/aws-sdk-go-v2/service/kms v1.50.3
	github.com/aws/aws-sdk-go-v2/service/lambda v1.88.3
	github.com/aws/aws-sdk-go-v2/service/macie2 v1.50.12
	github.com/aws/aws-sdk-go-v2/service/mq v1.34.18
	github.com/aws/aws-sdk-go-v2/service/neptune v1.44.2
	github.com/aws/aws-sdk-go-v2/service/networkfirewall v1.59.6
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.61.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.50.5
	github.com/aws/aws-sdk-go-v2/service/rds v1.116.3
	github.com/aws/aws-sdk-go-v2/service/redshift v1.62.4
	github.com/aws/aws-sdk-go-v2/service/redshiftserverless v1.34.3
	github.com/aws/aws-sdk-go-v2/service/route53 v1.62.4
	github.com/aws/aws-sdk-go-v2/service/s3 v1.97.1
	github.com/aws/aws-sdk-go-v2/service/s3control v1.68.3
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.236.1
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.4
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.68.2
	github.com/aws/aws-sdk-go-v2/service/sfn v1.40.9
	github.com/aws/aws-sdk-go-v2/service/sns v1.39.14
	github.com/aws/aws-sdk-go-v2/service/sqs v1.42.24
	github.com/aws/aws-sdk-go-v2/service/ssm v1.68.3
	github.com/aws/aws-sdk-go-v2/service/ssoadmin v1.37.4
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.9
	github.com/aws/aws-sdk-go-v2/service/transfer v1.69.4
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.71.2
	github.com/google/go-github/v57 v57.0.0
	github.com/google/uuid v1.6.0
	github.com/open-policy-agent/opa v1.12.3
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	golang.org/x/oauth2 v0.35.0
	google.golang.org/api v0.269.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cloud.google.com/go/auth v0.18.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/agnivade/levenshtein v1.2.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.7 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.12 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.20 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.20 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.20 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.11.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.17 // indirect
	github.com/aws/smithy-go v1.24.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.12 // indirect
	github.com/googleapis/gax-go/v2 v2.17.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.0.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.1 // indirect
	github.com/lestrrat-go/jwx/v3 v3.0.12 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/sirupsen/logrus v1.9.4-0.20230606125235-dd1b4c2e81af // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/tchap/go-patricia/v2 v2.3.3 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	github.com/vektah/gqlparser/v2 v2.5.31 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.63.0 // indirect
	go.opentelemetry.io/otel v1.42.0 // indirect
	go.opentelemetry.io/otel/metric v1.42.0 // indirect
	go.opentelemetry.io/otel/sdk v1.42.0 // indirect
	go.opentelemetry.io/otel/trace v1.42.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/net v0.50.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260217215200-42d3e9bedb6d // indirect
	google.golang.org/grpc v1.79.1 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)
