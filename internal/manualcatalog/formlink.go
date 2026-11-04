package manualcatalog

import "net/url"

// DefaultFormBaseURL is the hosted Evidence SPA. Its route
// /evidence/<framework>/<evidence_id> (src/App.tsx in the SPA repo)
// opens the form for one catalog entry. The link is a convenience
// printed to the operator's own terminal: the SPA has no backend and
// the CLI never sends it anything.
const DefaultFormBaseURL = "https://sigcomply.github.io/sigcomply-evidence-spa/"

// FormURL returns the SPA link to one entry's form. Each segment is
// path-escaped so an ID cannot add segments, a query or a fragment.
func FormURL(framework, id string) string {
	return DefaultFormBaseURL + "evidence/" + url.PathEscape(framework) + "/" + url.PathEscape(id)
}

// FormLinks maps each catalog ID that has a form to its link. Only
// declaration and checklist entries have one: the SPA renders no page
// for a document_upload entry, so a link there would 404.
func FormLinks(framework string, cat Catalog) map[string]string {
	links := make(map[string]string)
	for i := range cat.Entries {
		switch cat.Entries[i].Type {
		case TypeDeclaration, TypeChecklist:
			links[cat.Entries[i].ID] = FormURL(framework, cat.Entries[i].ID)
		}
	}
	return links
}
