package sql

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azuretest"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// sql_conformance_test.go: azure.managed_database_instance L1+L2 (WU-2.12).
// Hand-authored: one Azure SQL database (TDE on, zone-redundant, private) + one
// PostgreSQL flexible server (CMEK, zone-redundant, private). MySQL family empty.
func TestAzureSQLConformance(t *testing.T) {
	fixedNow := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	newPlugin := func() core.SourcePlugin {
		adapter, err := newRealSQL(azuretest.SubscriptionID, azuretest.FakeCredential(),
			azuretest.ReplayOptions(t, "testdata/cassettes/databases"))
		if err != nil {
			t.Fatal(err)
		}
		return New(Options{API: adapter, SubscriptionID: azuretest.SubscriptionID, Now: func() time.Time { return fixedNow }})
	}
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(), Request: core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"managed_database_instance.ssl_required", "managed_database_instance.kms_key_id"},
	})
	if len(recs) != 2 {
		t.Fatalf("managed_database_instance records = %d, want 2 (sql db + pg)", len(recs))
	}
	var encrypted, private int
	for _, r := range recs {
		var p instancePayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.StorageEncrypted {
			encrypted++
		}
		if !p.PubliclyAccessible {
			private++
		}
	}
	if encrypted != 2 || private != 2 {
		t.Errorf("encrypted=%d private=%d, want 2/2", encrypted, private)
	}
}
