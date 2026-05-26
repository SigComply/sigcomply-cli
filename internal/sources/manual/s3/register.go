package s3

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

func init() {
	manual.RegisterReader("s3", build)
}

func build(raw map[string]any) (reader manual.Reader, scheme, bucketOut, prefixOut string, err error) {
	bucket := sources.StringOpt(raw, "bucket")
	if bucket == "" {
		return nil, "", "", "", fmt.Errorf("manual.pdf s3: %q required", "bucket")
	}
	region := sources.StringOpt(raw, "region")
	if region == "" {
		return nil, "", "", "", fmt.Errorf("manual.pdf s3: %q required", "region")
	}
	prefix := sources.StringOpt(raw, "prefix")
	if prefix == "" {
		prefix = "manual/"
	}
	endpoint := sources.StringOpt(raw, "endpoint")
	var forcePathStyle bool
	if v, ok := raw["force_path_style"].(bool); ok {
		forcePathStyle = v
	}
	r, buildErr := New(context.Background(), Options{
		Bucket:         bucket,
		Region:         region,
		Prefix:         prefix,
		Endpoint:       endpoint,
		ForcePathStyle: forcePathStyle,
	})
	if buildErr != nil {
		return nil, "", "", "", buildErr
	}
	return r, "s3", bucket, prefix, nil
}
