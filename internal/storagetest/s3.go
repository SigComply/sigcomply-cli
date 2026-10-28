package storagetest

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3 is a fake Amazon S3 endpoint holding one bucket, addressed path-style.
// It serves GetObject and ListObjectsV2, the calls the manual-evidence
// reader makes.
type S3 struct {
	*store
	bucket string
	srv    *httptest.Server
}

// NewS3 starts a fake S3 server for bucket that lists pageSize objects per
// page. It stops when the test ends.
func NewS3(t testing.TB, bucket string, pageSize int) *S3 {
	t.Helper()
	s := &S3{store: newStore(t, pageSize), bucket: bucket}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

// Client returns a real *s3.Client wired to the fake with static dummy
// credentials, so no ambient AWS configuration is read.
func (s *S3) Client() *s3.Client {
	return s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(s.srv.URL),
		UsePathStyle: true,
		Credentials:  aws.CredentialsProviderFunc(staticAWSCredentials),
		HTTPClient:   s.srv.Client(),
	})
}

func staticAWSCredentials(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "test-access-key", SecretAccessKey: "test-secret", Source: "storagetest"}, nil
}

func (s *S3) serve(w http.ResponseWriter, r *http.Request) {
	bucketPath := "/" + s.bucket
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && (r.URL.Path == bucketPath || r.URL.Path == bucketPath+"/") && q.Get("list-type") == "2":
		s.list(w, q)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, bucketPath+"/"):
		name, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), bucketPath+"/"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.get(w, name)
	default:
		s.t.Errorf("storagetest: unexpected S3 request %s %s", r.Method, r.URL)
		http.Error(w, "unexpected request", http.StatusNotImplemented)
	}
}

func (s *S3) get(w http.ResponseWriter, name string) {
	o, ok := s.Get(name)
	if !ok {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`) //nolint:errcheck // client gone
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(o.Data)))
	w.Header().Set("Last-Modified", o.Updated.Format(http.TimeFormat))
	_, _ = w.Write(o.Data) //nolint:errcheck // client gone
}

// s3List is the ListObjectsV2 response body.
type s3List struct {
	XMLName               xml.Name   `xml:"ListBucketResult"`
	Name                  string     `xml:"Name"`
	Prefix                string     `xml:"Prefix"`
	KeyCount              int        `xml:"KeyCount"`
	IsTruncated           bool       `xml:"IsTruncated"`
	ContinuationToken     string     `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string     `xml:"NextContinuationToken,omitempty"`
	Contents              []s3Object `xml:"Contents"`
}

type s3Object struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	Size         int    `xml:"Size"`
}

func (s *S3) list(w http.ResponseWriter, q url.Values) {
	token := q.Get("continuation-token")
	names, objects, next := s.page(q.Get("prefix"), token)
	body := s3List{
		Name: s.bucket, Prefix: q.Get("prefix"), KeyCount: len(names),
		IsTruncated: next != "", ContinuationToken: token, NextContinuationToken: next,
	}
	for i := range names {
		body.Contents = append(body.Contents, s3Object{
			Key: names[i], LastModified: objects[i].Updated.Format(time.RFC3339), Size: len(objects[i].Data),
		})
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, xml.Header) //nolint:errcheck // client gone
	if err := xml.NewEncoder(w).Encode(body); err != nil {
		s.t.Errorf("storagetest: encode list: %v", err)
	}
}
