package manual

import "fmt"

// FolderPrefix returns the object-key prefix that holds one catalog
// entry's evidence for one period:
//
//	{prefix}{evidence_catalog_id}/{period_id}/
//
// This is the single source of truth for the manual-evidence folder
// scheme. The Evidence SPA mirrors it in src/lib/storage-path.ts, and
// `sigcomply evidence due` reuses it so that the folder it reports as
// empty is byte-identical to the one Collect will read.
//
// prefix is used verbatim — a config value without a trailing slash
// yields a run-on key, which is the documented behavior.
func FolderPrefix(prefix, evidenceID, periodID string) string {
	return fmt.Sprintf("%s%s/%s/", prefix, evidenceID, periodID)
}

// FolderURI renders FolderPrefix as the display URI shown to operators
// in missing-evidence messages. The bucket is not part of the object
// key — it lives on the backend client — so it only appears here.
func FolderURI(scheme, bucket, prefix, evidenceID, periodID string) string {
	return uriForScheme(scheme, bucket, FolderPrefix(prefix, evidenceID, periodID))
}

// uriForScheme is the one place the backend scheme becomes a URI.
func uriForScheme(scheme, bucket, rel string) string {
	switch scheme {
	case "s3":
		return fmt.Sprintf("s3://%s/%s", bucket, rel)
	case "gs":
		return fmt.Sprintf("gs://%s/%s", bucket, rel)
	case "azure":
		return fmt.Sprintf("azure://%s/%s", bucket, rel)
	default:
		if bucket == "" {
			return rel
		}
		return fmt.Sprintf("file://%s/%s", bucket, rel)
	}
}

// NewReaderFromConfig builds a manual-evidence Reader from a raw
// `sources: manual.pdf:` config block, without constructing the source
// plugin, the collector, or a vault. It is the entry point for
// read-only consumers such as `sigcomply evidence due`.
//
// Backends register themselves via side-effect imports; a caller
// outside this package must blank-import internal/sources/manual/builtin
// for s3/gcs/azure_blob (local is registered by this package).
func NewReaderFromConfig(raw map[string]any) (reader Reader, scheme, bucket, prefix string, err error) {
	return buildReader(raw)
}
