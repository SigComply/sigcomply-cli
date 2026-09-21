package cloudidentity

import (
	"errors"
	"math"
	"testing"
)

// setting_test.go pins the tolerant decoder.
//
// The point of these cases is NOT that Google sends one shape or the
// other — nobody outside Google knows which, which is the whole problem.
// The point is that the collector is correct under EITHER, and that
// anything outside the accepted set stops the run instead of leaving a
// zero behind. That is a real property of this code, not a bet on an
// unverified fact.

// TestFlexDuration_AcceptsEitherWireShape is the central case: the same
// 90 days, expressed every way the two candidate encodings allow.
func TestFlexDuration_AcceptsEitherWireShape(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantSecs float64
		wantDays int64
	}{
		{"protobuf_duration_string", `{"expirationDuration":"7776000s"}`, 7776000, 90},
		{"bare_integer_seconds", `{"expirationDuration":7776000}`, 7776000, 90},
		{"string_without_the_unit_suffix", `{"expirationDuration":"7776000"}`, 7776000, 90},
		// Half a second past 90 days IS more than 90 days, and days()
		// rounds up, so 91 is the answer rather than a rounding that
		// quietly reports a longer policy as a shorter one.
		{"fractional_duration_string", `{"expirationDuration":"7776000.500s"}`, 7776000.5, 91},
		{"json_float_seconds", `{"expirationDuration":7776000.0}`, 7776000, 90},
		// Zero is Google's "passwords never expire", and it must survive as
		// an exact zero: the schema reads 0 as an OBSERVED no-expiry.
		{"explicit_zero_string", `{"expirationDuration":"0s"}`, 0, 0},
		{"explicit_zero_integer", `{"expirationDuration":0}`, 0, 0},
		// Anything under a day rounds UP, never down — see days().
		{"sub_day_rounds_up_not_to_no_expiry", `{"expirationDuration":"3600s"}`, 3600, 1},
		{"one_second_over_a_day_rounds_up", `{"expirationDuration":86401}`, 86401, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps, err := decodePasswordSetting([]byte(tc.raw))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if ps.ExpirationDuration == nil {
				t.Fatal("expirationDuration decoded to nil; want a value")
			}
			if math.Abs(ps.ExpirationDuration.Seconds-tc.wantSecs) > 1e-6 {
				t.Errorf("seconds = %v, want %v", ps.ExpirationDuration.Seconds, tc.wantSecs)
			}
			if got := ps.ExpirationDuration.days(); got != tc.wantDays {
				t.Errorf("days = %d, want %d", got, tc.wantDays)
			}
		})
	}
}

// TestFlexDuration_UndecodableIsAnErrorNeverAZero is the regression guard
// for the failure mode this whole design exists to prevent: a silent
// decode failure would leave max_age_days at 0, and 0 PASSES the expiry
// policy (it is the schema's observed-no-expiry). So the bug would ship
// as a green tick, not as a broken run.
func TestFlexDuration_UndecodableIsAnErrorNeverAZero(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"unit_we_do_not_recognize", `{"expirationDuration":"90d"}`},
		{"words", `{"expirationDuration":"ninety days"}`},
		{"empty_string", `{"expirationDuration":""}`},
		{"bare_unit", `{"expirationDuration":"s"}`},
		{"object", `{"expirationDuration":{"seconds":7776000}}`},
		{"boolean", `{"expirationDuration":true}`},
		{"negative_expiry_is_nonsense", `{"expirationDuration":"-60s"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps, err := decodePasswordSetting([]byte(tc.raw))
			if err == nil {
				t.Fatalf("decode succeeded with %+v; want an error rather than a zero", ps.ExpirationDuration)
			}
			if !errors.Is(err, errDecode) {
				t.Errorf("error %v is not errDecode — callers key off it", err)
			}
		})
	}
}

// TestFlexInt_AcceptsEitherWireShape: the proto3 JSON mapping encodes
// int64 as a string and int32 as a number, and Google publishes neither
// the field's proto type nor a sample body — so both are accepted here
// for the same reason the duration is.
func TestFlexInt_AcceptsEitherWireShape(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int64
	}{
		{"number", `{"minimumLength":12}`, 12},
		{"string", `{"minimumLength":"12"}`, 12},
		{"whole_float", `{"minimumLength":12.0}`, 12},
		{"zero", `{"minimumLength":0}`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps, err := decodePasswordSetting([]byte(tc.raw))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if ps.MinimumLength == nil {
				t.Fatal("minimumLength decoded to nil")
			}
			if int64(*ps.MinimumLength) != tc.want {
				t.Errorf("minimumLength = %d, want %d", int64(*ps.MinimumLength), tc.want)
			}
		})
	}
}

// A fractional length is not an integer and must not be truncated into
// one: truncating is how a number nobody reported gets signed.
func TestFlexInt_RejectsWhatIsNotAnInteger(t *testing.T) {
	for _, raw := range []string{
		`{"minimumLength":12.5}`,
		`{"minimumLength":"twelve"}`,
		`{"minimumLength":true}`,
		`{"minimumLength":[12]}`,
	} {
		if _, err := decodePasswordSetting([]byte(raw)); err == nil {
			t.Errorf("%s: decode succeeded; want an error", raw)
		}
	}
}

// Absent and null converge on "the tenant never set it" — which is
// exactly what Google's contract means by both, and what makes the
// `defaulted` marker rather than absence the right answer downstream.
func TestDecode_AbsentAndNullAreBothUnset(t *testing.T) {
	for _, raw := range []string{`{}`, `{"minimumLength":null,"expirationDuration":null,"allowReuse":null,"allowedStrength":null}`} {
		ps, err := decodePasswordSetting([]byte(raw))
		if err != nil {
			t.Fatalf("%s: decode: %v", raw, err)
		}
		if ps.MinimumLength != nil || ps.ExpirationDuration != nil || ps.AllowReuse != nil || ps.AllowedStrength != nil {
			t.Errorf("%s: decoded to %+v; want every field unset", raw, ps)
		}
	}
}

// An unknown field must not break a run: Google adding a seventh
// attribute to the setting is a routine event, and refusing to decode
// would turn it into an outage for every Google-backed customer.
func TestDecode_UnknownFieldsAreIgnored(t *testing.T) {
	ps, err := decodePasswordSetting([]byte(`{"minimumLength":12,"somethingGoogleAddedLater":{"a":1}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ps.MinimumLength == nil || int64(*ps.MinimumLength) != 12 {
		t.Errorf("minimumLength = %v, want 12", ps.MinimumLength)
	}
}

func TestDecode_EmptyValueIsAnError(t *testing.T) {
	if _, err := decodePasswordSetting(nil); !errors.Is(err, errDecode) {
		t.Errorf("err = %v, want errDecode", err)
	}
}
