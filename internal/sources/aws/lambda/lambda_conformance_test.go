package lambda

import (
	"encoding/json"
	"testing"
	"time"

	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// lambda_conformance_test.go: aws.serverless_function L1+L2 (WU-2.4).
func TestLambdaConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := awslambda.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/functions"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:         newPlugin(),
		Request:        core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"serverless_function.reserved_concurrency_set"},
	})
	if len(recs) != 1 {
		t.Fatalf("serverless_function records = %d, want 1", len(recs))
	}
	var p functionPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Runtime == "" || !p.TracingEnabled {
		t.Errorf("function = %+v; want a runtime and tracing enabled", p)
	}
}
