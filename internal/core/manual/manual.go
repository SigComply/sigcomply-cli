package manual

// EvidencePDFFilename is the strict, fixed filename of the user-supplied PDF
// for every manual evidence entry. The CLI looks for this exact name (no
// globbing, no case variants) under {framework}/{evidence_id}/{period}/.
//
// This is the cross-repo contract with the Evidence SPA, which downloads
// `evidence.pdf` for the user to upload. It also matches the path the CLI
// mirrors into per-policy result folders under
// manual_attachments/{evidence_id}/evidence.pdf.
const EvidencePDFFilename = "evidence.pdf"
