package storagetest

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

// AzureBlob is a fake Azure Blob Storage account holding one container.
type AzureBlob struct {
	*store
	container string
	srv       *httptest.Server
}

// NewAzureBlob starts a fake Blob Storage server for container that lists
// pageSize blobs per page. It stops when the test ends.
func NewAzureBlob(t testing.TB, container string, pageSize int) *AzureBlob {
	t.Helper()
	a := &AzureBlob{store: newStore(t, pageSize), container: container}
	a.srv = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.srv.Close)
	return a
}

// Client returns a real *azblob.Client wired to the fake, with no
// credential and no retries, so a failure surfaces at once.
func (a *AzureBlob) Client(t testing.TB) *azblob.Client {
	t.Helper()
	c, err := azblob.NewClientWithNoCredential(a.srv.URL+"/", &azblob.ClientOptions{ClientOptions: azcore.ClientOptions{
		Transport: a.srv.Client(),
		Retry:     policy.RetryOptions{MaxRetries: -1},
	}})
	if err != nil {
		t.Fatalf("storagetest: azblob client: %v", err)
	}
	return c
}

func (a *AzureBlob) serve(w http.ResponseWriter, r *http.Request) {
	containerPath := "/" + a.container
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == containerPath && q.Get("restype") == "container" && q.Get("comp") == "list":
		a.list(w, q)
	case strings.HasPrefix(r.URL.Path, containerPath+"/"):
		name, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), containerPath+"/"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			a.upload(w, r, name)
		case http.MethodGet:
			a.download(w, name)
		default:
			a.unexpected(w, r)
		}
	default:
		a.unexpected(w, r)
	}
}

func (a *AzureBlob) unexpected(w http.ResponseWriter, r *http.Request) {
	a.t.Errorf("storagetest: unexpected Azure Blob request %s %s", r.Method, r.URL)
	http.Error(w, "unexpected request", http.StatusNotImplemented)
}

// upload accepts a single-shot Put Blob, which UploadBuffer sends for any
// body under the SDK's single-upload limit. Metadata arrives as
// x-ms-meta-* headers.
func (a *AzureBlob) upload(w http.ResponseWriter, r *http.Request, name string) {
	if r.Header.Get("x-ms-blob-type") != "BlockBlob" {
		a.unexpected(w, r)
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	meta := map[string]string{}
	for k, v := range r.Header {
		if m, ok := strings.CutPrefix(strings.ToLower(k), "x-ms-meta-"); ok && len(v) > 0 {
			meta[m] = v[0]
		}
	}
	o := a.put(name, data, meta)
	w.Header().Set("ETag", `"0x1"`)
	w.Header().Set("Last-Modified", o.Updated.Format(http.TimeFormat))
	w.WriteHeader(http.StatusCreated)
}

func (a *AzureBlob) download(w http.ResponseWriter, name string) {
	o, ok := a.Get(name)
	if !ok {
		w.Header().Set("x-ms-error-code", "BlobNotFound")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?><Error><Code>BlobNotFound</Code><Message>The specified blob does not exist.</Message></Error>`) //nolint:errcheck // client gone
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(o.Data)))
	w.Header().Set("Last-Modified", o.Updated.Format(http.TimeFormat))
	w.Header().Set("ETag", `"0x1"`)
	w.Header().Set("x-ms-blob-type", "BlockBlob")
	_, _ = w.Write(o.Data) //nolint:errcheck // client gone
}

// azList is the List Blobs (flat) response body.
type azList struct {
	XMLName       xml.Name `xml:"EnumerationResults"`
	ContainerName string   `xml:"ContainerName,attr"`
	Prefix        string   `xml:"Prefix"`
	Marker        string   `xml:"Marker"`
	Blobs         []azBlob `xml:"Blobs>Blob"`
	NextMarker    string   `xml:"NextMarker"`
}

type azBlob struct {
	Name          string `xml:"Name"`
	LastModified  string `xml:"Properties>Last-Modified"`
	ContentLength int    `xml:"Properties>Content-Length"`
	BlobType      string `xml:"Properties>BlobType"`
}

func (a *AzureBlob) list(w http.ResponseWriter, q url.Values) {
	names, objects, next := a.page(q.Get("prefix"), q.Get("marker"))
	body := azList{ContainerName: a.container, Prefix: q.Get("prefix"), Marker: q.Get("marker"), NextMarker: next}
	for i := range names {
		body.Blobs = append(body.Blobs, azBlob{
			Name: names[i], LastModified: objects[i].Updated.Format(http.TimeFormat),
			ContentLength: len(objects[i].Data), BlobType: "BlockBlob",
		})
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, xml.Header) //nolint:errcheck // client gone
	if err := xml.NewEncoder(w).Encode(body); err != nil {
		a.t.Errorf("storagetest: encode list: %v", err)
	}
}
