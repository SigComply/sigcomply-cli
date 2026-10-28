package evaluator

import (
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// An out-of-window upload says when the file was uploaded and which
// window it missed; "outside the configured temporal window" gave the
// user neither, and they never configured a window.
func TestEvaluateManual_WindowReasonNamesWindowAndUploadTime(t *testing.T) {
	uploaded := time.Date(2026, 3, 1, 9, 30, 0, 0, time.UTC)
	payload := mustJSON(map[string]any{
		"file_present": true, "in_temporal_window": false, "file_valid": true,
		"file_hash": "sha256:ab", "expected_uri": "file://./evidence/manual/nda/2026-Q2/",
		"uploaded_at": uploaded,
	})
	period := &planner.Period{
		ID:    "2026-Q2",
		Start: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
	}
	out := evaluateManualIn(map[string][]core.EvidenceRecord{spec.ManualSlotName: {{ID: "nda", Payload: payload}}}, period)
	if out.Status != core.StatusFail || len(out.Violations) != 1 {
		t.Fatalf("want one failing violation; got %+v", out)
	}
	reason := out.Violations[0].Reason
	for _, want := range []string{"2026-03-01T09:30:00Z", "2026-04-01", "2026-06-30", "grace"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q should contain %q", reason, want)
		}
	}
}
