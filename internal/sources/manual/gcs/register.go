package gcs

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

func init() {
	manual.RegisterReader("gcs", build)
}

func build(raw map[string]any) (reader manual.Reader, scheme, bucketOut, prefixOut string, err error) {
	bucket := sources.StringOpt(raw, "bucket")
	if bucket == "" {
		return nil, "", "", "", fmt.Errorf("manual.pdf gcs: %q required", "bucket")
	}
	prefix := sources.StringOpt(raw, "prefix")
	if prefix == "" {
		prefix = "manual/"
	}
	r, buildErr := New(context.Background(), Options{
		Bucket: bucket,
		Prefix: prefix,
	})
	if buildErr != nil {
		return nil, "", "", "", buildErr
	}
	return r, "gs", bucket, prefix, nil
}
