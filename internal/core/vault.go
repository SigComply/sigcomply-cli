package core

import "context"

// Vault is the customer-side persistence layer. Append-only per run;
// the CLI writes, auditors and dashboards read. Implementations are
// backend-specific (local, s3, gcs, azure_blob) but all conform to
// this interface.
//
// The CLI never reads from the vault during the same run — vault is
// one-way for write-side flows.
type Vault interface {
	Init(ctx context.Context) error
	PutEnvelope(ctx context.Context, path string, e Envelope) error
	PutJSON(ctx context.Context, path string, body any) error
	PutBinary(ctx context.Context, path string, body []byte, meta map[string]string) error
	GetBinary(ctx context.Context, path string) ([]byte, error)
	List(ctx context.Context, prefix string) ([]string, error)
}
