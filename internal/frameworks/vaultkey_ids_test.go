package frameworks_test

import (
	"testing"

	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	fwregistry "github.com/sigcomply/sigcomply-cli/internal/frameworks"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/vaultkey"
)

// TestBuiltinIDsAreVaultSafe: every framework ID, policy ID and evidence
// type ID becomes a segment of a vault key (run folder, result, state
// shard, envelope file). The vault-key builders refuse an unsafe
// segment at write time; this catches a shipped ID that would make
// them refuse, before a customer's run does.
func TestBuiltinIDsAreVaultSafe(t *testing.T) {
	for _, fwID := range fwregistry.IDs() {
		if !vaultkey.ValidID(fwID) {
			t.Errorf("framework ID %q is not vault-safe", fwID)
		}
		f, _ := fwregistry.Lookup(fwID)
		set := registry.NewSet()
		if err := evidencetypes.Register(set); err != nil {
			t.Fatal(err)
		}
		if err := f.Register(set); err != nil {
			t.Fatalf("%s: register: %v", fwID, err)
		}
		if set.Policies.Len() == 0 {
			t.Errorf("%s: no policies registered", fwID)
		}
		for _, p := range set.Policies.All() {
			if !vaultkey.ValidID(p.ID) {
				t.Errorf("%s: policy ID %q is not vault-safe", fwID, p.ID)
			}
		}
		for _, et := range set.EvidenceTypes.All() {
			if _, err := vaultkey.Join(et.ID); err != nil {
				t.Errorf("evidence type ID %q is not a vault-safe segment: %v", et.ID, err)
			}
		}
	}
}
