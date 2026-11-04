package manualcatalog_test

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

func TestFormURL_BuildsTheSPARoute(t *testing.T) {
	got := manualcatalog.FormURL(fwSOC2, "security_awareness_training")
	want := "https://sigcomply.github.io/sigcomply-evidence-spa/evidence/soc2/security_awareness_training"
	if got != want {
		t.Errorf("FormURL = %q; want %q", got, want)
	}
}

// A segment is escaped so an odd ID cannot add path segments, a query
// or a fragment to the link.
func TestFormURL_EscapesEachSegment(t *testing.T) {
	got := manualcatalog.FormURL("so/c2", "a b?c#d/e")
	want := manualcatalog.DefaultFormBaseURL + "evidence/so%2Fc2/a%20b%3Fc%23d%2Fe"
	if got != want {
		t.Errorf("FormURL = %q; want %q", got, want)
	}
}

func TestFormLinks_KeepsOnlyEntriesWithAForm(t *testing.T) {
	cat := manualcatalog.Catalog{Framework: fwSOC2, Entries: []manualcatalog.Entry{
		{ID: "decl", Type: manualcatalog.TypeDeclaration},
		{ID: "check", Type: manualcatalog.TypeChecklist},
		{ID: "doc", Type: manualcatalog.TypeDocumentUpload},
		{ID: "untyped"},
	}}
	links := manualcatalog.FormLinks(fwSOC2, cat)
	if len(links) != 2 {
		t.Fatalf("FormLinks = %v; want exactly decl and check", links)
	}
	for _, id := range []string{"decl", "check"} {
		if links[id] != manualcatalog.FormURL(fwSOC2, id) {
			t.Errorf("links[%q] = %q; want %q", id, links[id], manualcatalog.FormURL(fwSOC2, id))
		}
	}
}

// Every form entry in each shipped catalog gets the SPA route, and no
// document_upload entry gets one (the SPA has no page for it, so the
// link would 404).
func TestFormLinks_ShippedCatalogs(t *testing.T) {
	for _, fw := range frameworks() {
		t.Run(fw.id, func(t *testing.T) {
			cat := fw.export()
			links := manualcatalog.FormLinks(fw.id, cat)
			forms := 0
			for _, e := range cat.Entries {
				got, ok := links[e.ID]
				switch e.Type {
				case manualcatalog.TypeDeclaration, manualcatalog.TypeChecklist:
					forms++
					want := manualcatalog.DefaultFormBaseURL + "evidence/" + fw.id + "/" + e.ID
					if got != want {
						t.Errorf("%s: link = %q; want %q", e.ID, got, want)
					}
				default:
					if ok {
						t.Errorf("%s (%s) has a form link %q; the SPA has no form for it", e.ID, e.Type, got)
					}
				}
			}
			if forms == 0 {
				t.Errorf("%s ships no declaration or checklist entry; this test checks nothing", fw.id)
			}
			if len(links) != forms {
				t.Errorf("FormLinks returned %d links; want %d", len(links), forms)
			}
		})
	}
}

// A fan-out entry has one folder per vendor, while a form link names
// only the catalog entry. Every fan-out entry is a document_upload
// today, so none gets a link; if one becomes a form, the link and the
// SPA route need a vendor segment first.
func TestFanOutEntriesAreDocumentUploads(t *testing.T) {
	runtime := map[string]func() map[string]manual.CatalogEntry{
		fwSOC2:     soc2.ManualCatalog,
		fwISO27001: iso27001.ManualCatalog,
	}
	for _, fw := range frameworks() {
		types := map[string]manualcatalog.EvidenceType{}
		for _, e := range fw.export().Entries {
			types[e.ID] = e.Type
		}
		for id, entry := range runtime[fw.id]() {
			if entry.FanOut == "" {
				continue
			}
			if types[id] != manualcatalog.TypeDocumentUpload {
				t.Errorf("%s: fan-out entry %q has type %q; want document_upload", fw.id, id, types[id])
			}
		}
	}
}
