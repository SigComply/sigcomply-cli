package aks

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// aks_conformance_test.go: azure.kubernetes_cluster L1+L2 (WU-2.12). Hand-authored:
// a private cluster with KMS secrets encryption, stable auto-upgrade, and
// kube-audit diagnostic logging.
func TestAzureAKSConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealAKS(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/clusters"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
	})
	if len(recs) != 1 {
		t.Fatalf("kubernetes_cluster records = %d, want 1", len(recs))
	}
	var p clusterPayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.SecretsEncryptionEnabled || !p.IsPrivateEndpoint || !p.LoggingEnabled {
		t.Errorf("cluster = %+v; want secrets-encryption, private, logging", p)
	}
}
