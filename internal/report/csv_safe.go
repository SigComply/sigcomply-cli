package report

import (
	"encoding/csv"
	"io"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/log"
)

// csvRows is what every CSV rendering writes to: one record at a time.
type csvRows interface {
	Write(record []string) error
}

// safeCSVWriter neutralizes spreadsheet formulas (OWASP "CSV
// injection"). A cell that starts with =, +, -, @, tab or carriage
// return is evaluated as a formula when an auditor opens the export in
// Excel, LibreOffice or Google Sheets, and report cells carry text from
// resource names, API responses and the project's config. Such a cell
// is prefixed with a single quote, which spreadsheets show as text and
// which keeps the original characters readable. Each cell then goes
// through log.Sanitize, so an export printed into a CI log carries no
// newline, escape sequence or workflow command.
type safeCSVWriter struct {
	w *csv.Writer
}

// newSafeCSVWriter is the only csv.NewWriter in the CLI
// (TestCSVWritersAreNeutralized).
func newSafeCSVWriter(w io.Writer) *safeCSVWriter {
	return &safeCSVWriter{w: csv.NewWriter(w)}
}

func (s *safeCSVWriter) Write(record []string) error {
	out := make([]string, len(record))
	for i, cell := range record {
		out[i] = log.Sanitize(neutralizeCSVCell(cell))
	}
	return s.w.Write(out)
}

// Flush writes buffered records and returns any write error.
func (s *safeCSVWriter) Flush() error {
	s.w.Flush()
	return s.w.Error()
}

func neutralizeCSVCell(cell string) string {
	if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
		return "'" + cell
	}
	return cell
}
