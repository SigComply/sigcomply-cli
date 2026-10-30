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
	endpoint, err := sources.ResolveEndpoint(raw, "manual.pdf s3", "endpoint")
	if err != nil {
		return nil, "", "", "", err
	}
	forcePathStyle, err := boolOrString(raw, "force_path_style")
	if err != nil {
		return nil, "", "", "", err
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

// boolOrString reads a YAML bool, or the strings "true"/"false" that a
// quoted value decodes to. The key is registered as typed, so the
// unknown-key warning never fires for it: anything else must be a
// config error, not a silent false.
func boolOrString(raw map[string]any, key string) (bool, error) {
	switch v := raw[key].(type) {
	case nil:
		return false, nil
	case bool:
		return v, nil
	case string:
		switch v {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, fmt.Errorf("manual.pdf s3: %q must be true or false, got %v", key, raw[key])
}
