package sources

import (
	"fmt"
	"net/url"
	"strings"
)

// FollowableLink checks a pagination link a server returned (a Link
// header's rel="next", Graph's @odata.nextLink) before it is requested
// with the source's credential. The link, resolved against base, must
// use base's scheme and host, carry no user info and lie under base's
// path; otherwise a misbehaving proxy, a hostile mock or a tampered
// response could send the credential to another host. It returns the
// absolute URL to request, or "" when next is empty (the last page).
// source labels the error.
func FollowableLink(source, base, next string) (string, error) {
	if next == "" {
		return "", nil
	}
	b, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("%s: parse API base %q: %w", source, base, err)
	}
	refused := fmt.Errorf("%s: pagination link %q leaves the API base %q; refusing to follow it", source, next, base)
	ref, err := url.Parse(next)
	if err != nil {
		return "", refused
	}
	u := b.ResolveReference(ref)
	basePath := strings.TrimSuffix(b.Path, "/")
	if u.Scheme != b.Scheme || !strings.EqualFold(u.Host, b.Host) || u.User != nil ||
		(basePath != "" && u.Path != basePath && !strings.HasPrefix(u.Path, basePath+"/")) {
		return "", refused
	}
	return u.String(), nil
}
