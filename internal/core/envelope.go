package core

import "time"

// Envelope is the signed wrapper around a batch of EvidenceRecords.
// Every envelope is independently verifiable: the public key and
// signature live inside the envelope, so an auditor with one envelope
// file and nothing else can verify it offline.
type Envelope struct {
	FormatVersion string
	ProducedAt    time.Time
	Records       []EvidenceRecord
	Signature     EnvelopeSignature
}

// EnvelopeSignature is the Ed25519 signature over canonical JSON of
// {format_version, produced_at, records}. The keypair is ephemeral —
// generated per envelope at write time and discarded the instant the
// signature is computed.
type EnvelopeSignature struct {
	Algorithm string
	PublicKey []byte
	Value     []byte
}
