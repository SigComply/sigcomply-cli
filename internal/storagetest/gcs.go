package storagetest

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

// GCS is a fake Google Cloud Storage endpoint holding one bucket.
type GCS struct {
	*store
	bucket string
	srv    *httptest.Server
}

// NewGCS starts a fake GCS server for bucket that lists pageSize objects
// per page. It stops when the test ends.
func NewGCS(t testing.TB, bucket string, pageSize int) *GCS {
	t.Helper()
	g := &GCS{store: newStore(t, pageSize), bucket: bucket}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

// Client returns a real *storage.Client wired to the fake: no
// credentials, no network beyond the loopback server.
func (g *GCS) Client(t testing.TB) *storage.Client {
	t.Helper()
	c, err := storage.NewClient(context.Background(),
		option.WithEndpoint(g.srv.URL+"/storage/v1/"),
		option.WithoutAuthentication(),
		option.WithHTTPClient(g.srv.Client()),
	)
	if err != nil {
		t.Fatalf("storagetest: gcs client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() }) //nolint:errcheck // test cleanup
	return c
}

// gcsObject is the JSON API object resource, reduced to what the SDK reads.
type gcsObject struct {
	Kind     string            `json:"kind"`
	Bucket   string            `json:"bucket"`
	Name     string            `json:"name"`
	Size     string            `json:"size"`
	Updated  string            `json:"updated"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func (g *GCS) resource(name string, o *Object) gcsObject {
	return gcsObject{
		Kind: "storage#object", Bucket: g.bucket, Name: name,
		Size: strconv.Itoa(len(o.Data)), Updated: o.Updated.Format(time.RFC3339Nano), Metadata: o.Metadata,
	}
}

func (g *GCS) serve(w http.ResponseWriter, r *http.Request) {
	listPath := "/storage/v1/b/" + g.bucket + "/o"
	uploadPath := "/upload/storage/v1/b/" + g.bucket + "/o"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == listPath:
		g.list(w, r)
	case r.Method == http.MethodPost && r.URL.Path == uploadPath && r.URL.Query().Get("uploadType") == "multipart":
		g.upload(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/"+g.bucket+"/"):
		// XML API read, the SDK's default for NewReader.
		g.read(w, strings.TrimPrefix(r.URL.EscapedPath(), "/"+g.bucket+"/"))
	default:
		g.t.Errorf("storagetest: unexpected GCS request %s %s", r.Method, r.URL)
		http.Error(w, "unexpected request", http.StatusNotImplemented)
	}
}

func (g *GCS) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	names, objects, next := g.page(q.Get("prefix"), q.Get("pageToken"))
	items := make([]gcsObject, len(names))
	for i := range names {
		items[i] = g.resource(names[i], &objects[i])
	}
	writeJSON(g.t, w, map[string]any{"kind": "storage#objects", "items": items, "nextPageToken": next})
}

// upload accepts the multipart upload the SDK sends for a body smaller
// than its chunk size: a JSON metadata part, then the media part.
func (g *GCS) upload(w http.ResponseWriter, r *http.Request) {
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		g.t.Errorf("storagetest: upload content type: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	var meta struct {
		Name     string            `json:"name"`
		Metadata map[string]string `json:"metadata"`
	}
	part, err := mr.NextPart()
	if err == nil {
		err = json.NewDecoder(part).Decode(&meta)
	}
	var data []byte
	if err == nil {
		if part, err = mr.NextPart(); err == nil {
			data, err = io.ReadAll(part)
		}
	}
	if err != nil {
		g.t.Errorf("storagetest: decode upload: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	o := g.put(meta.Name, data, meta.Metadata)
	writeJSON(g.t, w, g.resource(meta.Name, &o))
}

func (g *GCS) read(w http.ResponseWriter, escaped string) {
	name, err := url.PathUnescape(escaped)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	o, ok := g.Get(name)
	if !ok {
		http.Error(w, "<Error><Code>NoSuchKey</Code></Error>", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(o.Data)))
	w.Header().Set("Last-Modified", o.Updated.Format(http.TimeFormat))
	w.Header().Set("X-Goog-Generation", "1")
	w.Header().Set("X-Goog-Metageneration", "1")
	_, _ = w.Write(o.Data) //nolint:errcheck // client gone
}

func writeJSON(t testing.TB, w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("storagetest: encode response: %v", err)
	}
}
