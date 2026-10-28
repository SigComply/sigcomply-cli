package evidencetypes

import (
	"encoding/json"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// A source that cannot read a log destination's retention (an Azure
// workspace whose retentionInDays is unreported) must be able to omit
// both retention fields instead of inventing a value. retention_set
// false means never-expire, which the minimum-retention policies pass,
// so it is not an honest stand-in for "unknown".
func TestLogGroup_RetentionFieldsOptional(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	et, ok := set.EvidenceTypes.Lookup("log_group")
	if !ok {
		t.Fatal("log_group not registered")
	}
	for name, payload := range map[string]string{
		"retention_unknown": `{"id":"ws","name":"ws","provider":"azure"}`,
		"never_expire":      `{"id":"lg","name":"lg","retention_set":false,"retention_days":0}`,
		"finite":            `{"id":"lg","name":"lg","retention_set":true,"retention_days":30}`,
	} {
		if err := Validate(et.Schema, json.RawMessage(payload)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := Validate(et.Schema, json.RawMessage(`{"name":"lg"}`)); err == nil {
		t.Error("payload without id validated; want id still required")
	}
}
