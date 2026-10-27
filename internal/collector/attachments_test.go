package collector

import (
	"bytes"
	"context"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

func collectOne(t *testing.T, rec *core.EvidenceRecord) (*Output, *memVault) {
	t.Helper()
	src := &stubSource{id: testSourceManualPDF, emits: []string{testTypeSignedDoc}, records: []core.EvidenceRecord{*rec}}
	reg := registry.NewSet()
	mustRegister(t, reg.Sources.Register(src))
	pp := makePolicy("p1", "u", testTypeSignedDoc, testSourceManualPDF)
	vault := newMemVault()
	out, err := Collect(context.Background(), &Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}}, Sources: reg.Sources, Vault: vault, RunRoot: "r",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return out, vault
}

// A record's attachments land in the run folder next to its envelope,
// so they are in the manifest's file_hashes like every other run file.
func TestCollect_WritesRecordAttachments(t *testing.T) {
	pdf := []byte("%PDF-merged")
	out, vault := collectOne(t, &core.EvidenceRecord{
		Type: testTypeSignedDoc, ID: "e1/2026", SourceID: testSourceManualPDF,
		Attachments: []core.Attachment{{Name: "e1.pdf", Data: pdf}},
	})
	if err := out.CollectErrorsByPolicy["p1"]; err != nil {
		t.Fatalf("collect error: %v", err)
	}
	got, ok := vault.bins["r/policies/p1/attachments/e1.pdf"]
	if !ok {
		t.Fatalf("attachment not written; binaries = %v", vault.bins)
	}
	if !bytes.Equal(got, pdf) {
		t.Errorf("attachment bytes = %q; want %q", got, pdf)
	}
}

// An attachment name is a single path segment; anything that could
// escape the policy's folder is a plugin bug and errors the policy.
func TestCollect_RejectsUnsafeAttachmentName(t *testing.T) {
	for _, name := range []string{"", "..", "../x.pdf", "a/b.pdf", `a\b.pdf`} {
		out, vault := collectOne(t, &core.EvidenceRecord{
			Type: testTypeSignedDoc, ID: "e1/2026", SourceID: testSourceManualPDF,
			Attachments: []core.Attachment{{Name: name, Data: []byte("x")}},
		})
		if out.CollectErrorsByPolicy["p1"] == nil {
			t.Errorf("name %q: want a collect error", name)
		}
		if len(vault.bins) != 0 {
			t.Errorf("name %q: wrote %v", name, vault.bins)
		}
	}
}
