package orchestrator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// The bare "pass=N" line is the number a reader over-trusts. These tests
// pin the breakdown that deflates it.
func TestRenderAssurance(t *testing.T) {
	for _, tc := range []struct {
		name    string
		results []core.PolicyResult
		want    []string
		absent  []string
	}{
		{
			name: "mixed passes are broken down and caveated",
			results: []core.PolicyResult{
				{Status: core.StatusPass, EvidenceMode: core.EvidenceModeAutomated},
				{Status: core.StatusPass, EvidenceMode: core.EvidenceModeManual},
				{Status: core.StatusPass, EvidenceMode: core.EvidenceModeManual},
				{Status: core.StatusFail, EvidenceMode: core.EvidenceModeAutomated},
			},
			want: []string{
				"of 3 passing: 1 verified by inspection, 2 by document presence",
				"not that its contents were checked",
				"--view coverage",
			},
		},
		{
			name: "an all-automated run gets the count and no caveat",
			results: []core.PolicyResult{
				{Status: core.StatusPass, EvidenceMode: core.EvidenceModeAutomated},
			},
			want:   []string{"of 1 passing: 1 verified by inspection, 0 by document presence"},
			absent: []string{"its contents were checked"},
		},
		{
			name: "a carried-forward pass still counts — it stands for the control",
			results: []core.PolicyResult{
				{Status: core.StatusCarriedForward, EvidenceMode: core.EvidenceModeManual},
			},
			want: []string{"of 1 passing: 0 verified by inspection, 1 by document presence"},
		},
		{
			name:    "nothing passed, nothing to say",
			results: []core.PolicyResult{{Status: core.StatusFail, EvidenceMode: core.EvidenceModeManual}},
			absent:  []string{"passing"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			renderAssurance(&buf, tc.results)
			for _, w := range tc.want {
				if !strings.Contains(buf.String(), w) {
					t.Errorf("output missing %q:\n%s", w, buf.String())
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(buf.String(), a) {
					t.Errorf("output should not contain %q:\n%s", a, buf.String())
				}
			}
		})
	}
}
