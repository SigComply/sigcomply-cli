package securitygroups

import (
	"encoding/json"
	"testing"
	"time"

	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awstest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// securitygroups_conformance_test.go: aws.firewall_rule L1+L2 (WU-2.6).
// Recorded against the default security group (egress open to 0.0.0.0/0).
func TestSecurityGroupsConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		c := awsec2.NewFromConfig(awstest.ReplayConfig(t, "testdata/cassettes/rules"))
		return New(Options{API: c, Region: awstest.Region, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"firewall_rule.source_cidr", "firewall_rule.dest_cidr"},
	})
	if len(recs) < 1 {
		t.Fatalf("firewall_rule records = %d, want >= 1", len(recs))
	}
	var sawEgressOpen bool
	for _, r := range recs {
		var p rulePayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.Direction == "egress" && p.IsUnrestrictedIPv4 {
			sawEgressOpen = true
		}
	}
	if !sawEgressOpen {
		t.Error("expected the default SG's open egress rule (is_unrestricted_ipv4)")
	}
}
