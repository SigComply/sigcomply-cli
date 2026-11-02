package compute

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// compute_conformance_test.go: azure.compute_instance L1+L2 (WU-2.12).
// One running Linux VM (sigcomply-e2e-vm) whose single NIC has a private IP
// only. The statusOnly list is a live recording; the plain list and the NIC GET
// are hand-authored (see the cassette header). vm_size and os_type come only
// from the plain list, so asserting them proves the adapter reads the full
// model and not the profile-less statusOnly answer.
func TestAzureComputeConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealCompute(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/vms"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"compute_instance.monitoring_enabled", "compute_instance.metadata_service_hardened"},
	})
	if len(recs) != 1 {
		t.Fatalf("compute_instance records = %d, want 1", len(recs))
	}
	var p instancePayload
	if err := json.Unmarshal(recs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsRunning || p.HasPublicIP || !p.RootVolumeEncrypted {
		t.Errorf("vm = %+v; want running, no public IP, encrypted root", p)
	}
	if p.VMSize != "Standard_D2als_v7" || p.OSType != osLinux {
		t.Errorf("vm_size/os_type = %q/%q, want Standard_D2als_v7/Linux (read from the plain list)", p.VMSize, p.OSType)
	}
}
