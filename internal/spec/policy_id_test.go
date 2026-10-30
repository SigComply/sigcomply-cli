package spec

import (
	"strings"
	"testing"
)

// A project-local policy.yaml's id becomes a folder in every run
// (<run>/policies/<id>/...) and the state shard's file name. On the S3,
// GCS and Azure backends a "/" or ".." in it wrote outside the run
// folder. It must match the same grammar as source keys.
func TestLoadPolicy_RejectsPathUnsafeID(t *testing.T) {
	base := string(readTestdata(t, "policy/valid_mfa_enforced.yaml"))
	for _, id := range []string{"../../escape", "a/b", `a\b`, ".hidden", "a b", "x:y", "acme.policy[x]", "a[b"} {
		data := strings.Replace(base, "id: soc2.cc6.1.mfa_enforced", "id: \""+strings.ReplaceAll(id, `\`, `\\`)+"\"", 1)
		if data == base {
			t.Fatal("fixture id line not found")
		}
		_, err := LoadPolicy([]byte(data))
		if err == nil || !strings.Contains(err.Error(), "id") {
			t.Errorf("LoadPolicy(id %q) err = %v; want an invalid-id error", id, err)
		}
	}
}
