//go:build live

package gitlab

import (
	"context"
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// gitlab_live_test.go: L4a GitLab live drift test (WU-4.3). GitLab's published
// OpenAPI is too thin for an L3 spec-diff (it covers none of the endpoints we
// call), so this live run IS GitLab's drift signal: it exercises the real SDK
// against a live group and schema-validates every record, catching upstream
// shape changes and mapper regressions on the scheduled run. Gated on creds.
//
//	GITLAB_TEST_TOKEN     a read_api PAT (classic; fine-grained 403s on /user)
//	GITLAB_TEST_GROUP     group ID or full path
//	GITLAB_TEST_BASE_URL  optional; blank = gitlab.com
func TestGitLabLive(t *testing.T) {
	env := sourcetest.RequireEnv(t, "GITLAB_TEST_TOKEN", "GITLAB_TEST_GROUP")
	ctx := context.Background()
	p, err := NewFromToken(ctx, env["GITLAB_TEST_GROUP"], env["GITLAB_TEST_TOKEN"], os.Getenv("GITLAB_TEST_BASE_URL"))
	if err != nil {
		t.Fatal(sourcetest.PublicError(err))
	}
	recs, err := p.Collect(ctx, core.SlotRequest{AcceptedTypes: p.Emits()})
	if err != nil {
		t.Fatalf("collect: %s", sourcetest.PublicError(err))
	}

	types := sourcetest.BuiltinEvidenceTypes(t)
	counts := map[string]int{}
	drift := map[string]int{}
	for i := range recs {
		r := &recs[i]
		counts[r.Type]++
		et, ok := types.Lookup(r.Type)
		if !ok {
			t.Errorf("record %s: no registered evidence type", r.Type)
			continue
		}
		if err := evidencetypes.Validate(et.Schema, r.Payload); err != nil {
			// Record IDs and the validator's text can quote payload values
			// (names, e-mails); the public log gets counts per type only.
			drift[r.Type]++
		}
	}
	if len(drift) > 0 {
		t.Errorf("schema drift: records per type that fail their schema: %v", drift)
	}
	t.Logf("collected: %v", counts)

	if counts[EvidenceTypeRepository] < 1 {
		t.Errorf("git_repository = %d, want >= 1", counts[EvidenceTypeRepository])
	}
	if counts[EvidenceTypeDirectoryUser] < 1 {
		t.Errorf("directory_user = %d, want >= 1", counts[EvidenceTypeDirectoryUser])
	}
}
