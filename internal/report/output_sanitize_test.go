package report

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// hostileText is what a tampered vault file, a resource name or an API
// error body can put into a report cell.
const hostileText = "x\n::add-mask::secret\r##[error]forged\x1b[2Khidden\u202eevil"

// fillStrings sets every reachable string field to s, giving every
// pointer a value and every slice one element, so a renderer that
// prints any field sees hostile text in it.
func fillStrings(v reflect.Value, s string, depth int) {
	if depth > 8 {
		return
	}
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(s)
		}
	case reflect.Pointer:
		if v.IsNil() && v.CanSet() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		if !v.IsNil() {
			fillStrings(v.Elem(), s, depth+1)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fillStrings(v.Field(i), s, depth+1)
			}
		}
	case reflect.Slice:
		if v.CanSet() {
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
			fillStrings(v.Index(0), s, depth+1)
		}
	}
}

func assertSafeReport(t *testing.T, name, out string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(strings.Trim(line, `"',`))
		if strings.HasPrefix(trimmed, "::") || strings.HasPrefix(trimmed, "##[") {
			t.Errorf("%s: a line starts a workflow command: %q", name, line)
		}
	}
	for _, bad := range []string{"\x1b", "\u202e", "\r", "add-mask::"} {
		if strings.Contains(out, bad) {
			t.Errorf("%s: output carries %q: %q", name, bad, out)
		}
	}
	if !strings.Contains(out, "forged") {
		t.Errorf("%s: the text itself should still be shown: %q", name, out)
	}
}

// TestReportFormats_SanitizeEveryField: every text and CSV view prints
// each string field of its snapshot without newlines, escapes, bidi
// overrides or workflow commands, whichever field carries them. The
// snapshot is filled by reflection, so a field added later is covered.
func TestReportFormats_SanitizeEveryField(t *testing.T) {
	for _, view := range []View{ViewLatest, ViewExceptions, ViewIntegrity, ViewScope, ViewCoverage, ViewSoA} {
		snap := &Snapshot{}
		fillStrings(reflect.ValueOf(snap), hostileText, 0)
		snap.View = view
		before := snap.Latest.Policies[0].Reason

		var text bytes.Buffer
		if err := FormatText(&text, snap); err != nil {
			t.Fatalf("%s: FormatText: %v", view, err)
		}
		assertSafeReport(t, string(view)+"/text", text.String())

		var csvOut bytes.Buffer
		if err := FormatCSV(&csvOut, snap); err != nil {
			t.Fatalf("%s: FormatCSV: %v", view, err)
		}
		assertSafeReport(t, string(view)+"/csv", csvOut.String())

		if snap.Latest.Policies[0].Reason != before {
			t.Errorf("%s: formatting changed the caller's snapshot", view)
		}
	}
}
