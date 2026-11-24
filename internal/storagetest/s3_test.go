package storagetest

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// recordingTB captures Errorf so a test can assert the fake reported a bad
// request instead of failing on it.
type recordingTB struct {
	testing.TB
	mu   sync.Mutex
	errs []string
}

func (r *recordingTB) Errorf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

// The S3 fake must refuse what it cannot store faithfully: a body whose
// signed digest does not match, and a streaming (aws-chunked) body.
func TestS3_PutObjectRefusesWhatItCannotStore(t *testing.T) {
	for _, tc := range []struct {
		name, sha, encoding string
		code                int
	}{
		{"digest mismatch", strings.Repeat("0", 64), "", http.StatusBadRequest},
		{"streaming payload", "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "aws-chunked", http.StatusNotImplemented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingTB{TB: t}
			s := NewS3(rec, "b", 10)
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, s.srv.URL+"/b/k", strings.NewReader("body"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Amz-Content-Sha256", tc.sha)
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}
			resp, err := s.srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close() //nolint:errcheck // test
			if resp.StatusCode != tc.code {
				t.Errorf("status = %d; want %d", resp.StatusCode, tc.code)
			}
			if len(rec.errs) != 1 {
				t.Errorf("fake reported %d errors (%q); want 1", len(rec.errs), rec.errs)
			}
			if _, ok := s.Get("k"); ok {
				t.Error("the refused object was stored")
			}
		})
	}
}
