package core

import "time"

// Envelope is the signed wrapper around a batch of EvidenceRecords.
// Every envelope is independently verifiable: the public key and
// signature live inside the envelope, so an auditor with one envelope
// file and nothing else can verify it offline.
type Envelope struct {
	FormatVersion string `json:"format_version"`
	// ProducedAt is the RUN's reference time, captured once at run start
	// and threaded through collector.Input.Now — not the moment this file
	// was written. It therefore precedes every record's CollectedAt in
	// the same envelope, which looks backwards until you know why: one
	// `now` per run is what makes a re-run byte-identical (Principle #7).
	// The honest as-of for a single observation is that record's own
	// CollectedAt, and those spread across the run's whole duration.
	ProducedAt time.Time         `json:"produced_at"`
	Records    []EvidenceRecord  `json:"records"`
	Signature  EnvelopeSignature `json:"signature"`
}

// EnvelopeSignature is the Ed25519 signature over canonical JSON of
// {format_version, produced_at, records}. The keypair is ephemeral —
// generated per envelope at write time and discarded the instant the
// signature is computed.
type EnvelopeSignature struct {
	Algorithm string `json:"algorithm"`
	PublicKey []byte `json:"public_key"`
	Value     []byte `json:"value"`
}
