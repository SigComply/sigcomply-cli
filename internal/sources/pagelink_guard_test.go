package sources

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// paginationLinkRE matches code that reads a server-provided next-page
// URL: a Link header, or a nextLink/next_link field.
var paginationLinkRE = regexp.MustCompile(`(?i)(Get|Values)\("Link"\)|nextLink|next_link|"next"`)

// TestPaginationLinksGoThroughFollowableLink: every source file that
// reads a server-provided pagination URL also calls FollowableLink, so a
// new paginator cannot follow a link off its API host with the
// credential attached. Page-token and page-number paginators (GCP,
// GitLab) never read a URL and are not matched.
func TestPaginationLinksGoThroughFollowableLink(t *testing.T) {
	checked := 0
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || path == "pagelink.go" {
			return nil
		}
		src, err := os.ReadFile(path) //nolint:gosec // walking this package's own tree
		if err != nil {
			return err
		}
		if !paginationLinkRE.Match(src) {
			return nil
		}
		checked++
		if !strings.Contains(string(src), "FollowableLink(") {
			t.Errorf("%s reads a pagination link but never calls sources.FollowableLink", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 3 {
		t.Errorf("matched %d paginating files; want at least github, okta and azure.entra", checked)
	}
}
