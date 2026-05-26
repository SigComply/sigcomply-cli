package azureblob

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

func init() {
	manual.RegisterReader("azure_blob", build)
}

func build(raw map[string]any) (reader manual.Reader, scheme, bucketOut, prefixOut string, err error) {
	account := sources.StringOpt(raw, "account")
	container := sources.StringOpt(raw, "container")
	if account == "" || container == "" {
		return nil, "", "", "", fmt.Errorf("manual.pdf azureblob: \"account\" and \"container\" both required")
	}
	prefix := sources.StringOpt(raw, "prefix")
	if prefix == "" {
		prefix = "manual/"
	}
	r, buildErr := New(context.Background(), Options{
		Account:   account,
		Container: container,
		Prefix:    prefix,
	})
	if buildErr != nil {
		return nil, "", "", "", buildErr
	}
	return r, "azure", container, prefix, nil
}
