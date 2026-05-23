package core

import "testing"

func TestSeverityValues(t *testing.T) {
	want := map[Severity]string{
		SeverityInfo:     "info",
		SeverityLow:      "low",
		SeverityMedium:   "medium",
		SeverityHigh:     "high",
		SeverityCritical: "critical",
	}
	for got, expect := range want {
		if string(got) != expect {
			t.Errorf("Severity %q = %q; want %q", expect, string(got), expect)
		}
	}
}

func TestPolicyStatusValues(t *testing.T) {
	want := map[PolicyStatus]string{
		StatusPass:   "pass",
		StatusFail:   "fail",
		StatusSkip:   "skip",
		StatusError:  "error",
		StatusNA:     "na",
		StatusWaived: "waived",
	}
	for got, expect := range want {
		if string(got) != expect {
			t.Errorf("PolicyStatus %q = %q; want %q", expect, string(got), expect)
		}
	}
}

func TestSlotCardinalityValues(t *testing.T) {
	want := map[SlotCardinality]string{
		SlotExactlyOne: "exactly-one",
		SlotAtMostOne:  "at-most-one",
		SlotOneOrMore:  "one-or-more",
		SlotOptional:   "optional",
	}
	for got, expect := range want {
		if string(got) != expect {
			t.Errorf("SlotCardinality %q = %q; want %q", expect, string(got), expect)
		}
	}
}
