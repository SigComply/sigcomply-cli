package cloudidentity

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// setting.go decodes the value of a `settings/security.password` Setting.
//
// # Why this file exists at all
//
// The Cloud Identity Policy API models a Setting's value as an untyped
// `google.protobuf.Struct` — the generated Go client hands it over as a
// raw `googleapi.RawMessage` and offers no struct for it. So the shape is
// ours to assert. Google documents the FIELD NAMES of
// `settings/security.password` (minimumLength, maximumLength,
// allowedStrength, allowReuse, expirationDuration,
// enforceRequirementsAtLogin) but publishes NO sample response body
// anywhere, which leaves the JSON encoding of two of them genuinely
// unverifiable without a real tenant.
//
// The response to an unverifiable wire detail is not to pick the likelier
// option and hope. It is to accept every shape the detail could plausibly
// take, and to fail loudly on anything outside that set — so the
// collector is correct under either possibility rather than correct under
// one of them. That is what flexInt and flexDuration are for.
//
// # The dangerous failure this design exists to prevent
//
// A silently-failed decode would leave a Go zero value behind, and for
// max_age_days the zero is not a neutral "unknown": `0` is the schema's
// encoding of an OBSERVED no-expiry, which
// soc2.cc6.1.password_expiry_90d deliberately PASSES (NIST 800-63B treats
// no expiry as correct where rotation is event-driven). A decode bug
// would therefore not show up as a broken run — it would show up as a
// green tick. Every decoder below returns an error instead of a zero, and
// Collect propagates it, so the failure mode is a loud run rather than a
// quiet pass. TestFlexDuration_* and TestCollect_DecodeFailureIsAnError
// pin exactly that.
//
// # Pointers everywhere
//
// Every field is a pointer because the API returns ONLY explicitly-set
// values: nil here means "this tenant never set it", which is a fact
// about the tenant and not a hole in the read. What the plugin does with
// that distinction — report the documented default and mark the field in
// `defaulted` — is in reduce.go.

// errDecode is the sentinel for "a field of the password setting did not
// decode". It is deliberately one error for the whole file: every caller
// treats a decode failure identically (hard error, never a zero), and a
// per-field taxonomy would invite a caller to handle one kind leniently.
var errDecode = errors.New("gcp.cloud_identity: undecodable settings/security.password value")

// passwordSetting is the decoded `settings/security.password` value.
//
// MaximumLength and EnforceRequirementsAtLogin are decoded but not
// emitted: password_policy.v2 has no field for either, and no shipped
// clause asks about them. They are kept here rather than dropped because
// decoding them is how a shape change in them is noticed (a string where
// an integer was expected errors the run) and because a "maximum length"
// clause, if one is ever written, needs the value to already be read
// rather than a second API call bolted on.
type passwordSetting struct {
	MinimumLength              *flexInt      `json:"minimumLength"`
	MaximumLength              *flexInt      `json:"maximumLength"`
	AllowedStrength            *string       `json:"allowedStrength"`
	AllowReuse                 *bool         `json:"allowReuse"`
	ExpirationDuration         *flexDuration `json:"expirationDuration"`
	EnforceRequirementsAtLogin *bool         `json:"enforceRequirementsAtLogin"`
}

// decodePasswordSetting decodes one Setting value. Unknown fields are
// ignored on purpose — Google adding a seventh attribute must not break
// a customer's run — but a KNOWN field arriving in an undecodable shape
// is fatal, because that is the case where continuing means emitting a
// number nobody read.
func decodePasswordSetting(raw []byte) (passwordSetting, error) {
	var ps passwordSetting
	if len(raw) == 0 {
		return ps, fmt.Errorf("%w: empty value", errDecode)
	}
	if err := json.Unmarshal(raw, &ps); err != nil {
		return passwordSetting{}, err
	}
	return ps, nil
}

// flexInt is an integer that decodes from either a JSON number or a JSON
// string.
//
// Both are live possibilities and neither can be confirmed without a
// tenant: the proto3 JSON mapping encodes int64 as a STRING and int32 as
// a number, and Google does not publish the field's proto type or a
// sample body. Accepting both costs four lines and removes the guess.
type flexInt int64

// UnmarshalJSON accepts 8, "8", and 8.0 (an integral JSON float, which
// some JSON producers emit for whole numbers), and rejects everything
// else. A JSON null leaves the value untouched; because every use site
// holds a *flexInt, encoding/json sets the pointer to nil for null
// without calling this method at all, so null and absent converge on
// "not set" — which is what Google's contract means by both.
func (v *flexInt) UnmarshalJSON(b []byte) error {
	text := strings.TrimSpace(string(b))
	if text == nullLiteral {
		return nil
	}
	if strings.HasPrefix(text, `"`) {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("%w: integer field: %s", errDecode, text)
		}
		text = strings.TrimSpace(s)
	}
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		*v = flexInt(n)
		return nil
	}
	// A whole-numbered float ("8.0") is the same integer; a fractional one
	// is not an integer at all and is rejected rather than truncated,
	// because truncating is how a wrong number gets signed into evidence.
	if f, err := strconv.ParseFloat(text, 64); err == nil && f == math.Trunc(f) && !math.IsInf(f, 0) {
		*v = flexInt(int64(f))
		return nil
	}
	return fmt.Errorf("%w: integer field: %s", errDecode, text)
}

// nullLiteral is the JSON null token, compared as raw bytes.
const nullLiteral = "null"

// secondsPerDay converts an expiry duration into the schema's days.
const secondsPerDay = 86400

// flexDuration is `expirationDuration`, decoded from either shape it
// could arrive in.
//
// THIS IS THE ONE THE WHOLE FILE IS ABOUT. Google documents the field and
// publishes no example of it. Two encodings are plausible and only one
// can be right: a protobuf Duration STRING ("7776000s" — what the proto3
// JSON mapping prescribes, and what the only third-party fixtures we
// could find show) or a bare INTEGER of seconds. Rather than betting on
// the string, this decoder takes either, and takes the fractional form
// the Duration grammar also permits ("7776000.500s").
//
// Anything else is an error, never a zero. See the file comment for why
// a zero here would pass the expiry policy rather than fail the run.
type flexDuration struct {
	// Seconds is float64 rather than int64 because the protobuf Duration
	// grammar allows up to nine fractional digits. Every real expiry is a
	// whole number of days, so the fraction only ever matters as something
	// not to silently discard.
	Seconds float64
}

// UnmarshalJSON accepts "7776000s", "7776000", 7776000 and 7776000.5.
func (d *flexDuration) UnmarshalJSON(b []byte) error {
	text := strings.TrimSpace(string(b))
	if text == nullLiteral {
		return nil
	}
	if strings.HasPrefix(text, `"`) {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("%w: expirationDuration: %s", errDecode, text)
		}
		// The trailing "s" is the Duration grammar's unit marker and is
		// the only unit it defines — there is no "7776000m" to mishandle.
		text = strings.TrimSuffix(strings.TrimSpace(s), "s")
	}
	secs, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(secs) || math.IsInf(secs, 0) {
		return fmt.Errorf("%w: expirationDuration: %s", errDecode, strings.TrimSpace(string(b)))
	}
	if secs < 0 {
		return fmt.Errorf("%w: expirationDuration is negative: %s", errDecode, strings.TrimSpace(string(b)))
	}
	d.Seconds = secs
	return nil
}

// days converts the duration to whole days, ROUNDING UP.
//
// The direction is load-bearing, not a style choice. Truncation would map
// any sub-day expiry to 0, and 0 in password_policy.v2 does not mean
// "very short" — it means "no expiry", which the expiry clause passes.
// So truncating turns the strictest possible rotation policy into the
// weakest-looking one, and into a pass. Rounding up can only ever report
// an expiry slightly LONGER than the truth, which errs toward failing the
// 90-day clause: the recoverable direction.
//
// An exact zero stays zero, because there it really is Google's
// "passwords never expire".
func (d flexDuration) days() int64 {
	if d.Seconds <= 0 {
		return 0
	}
	return int64(math.Ceil(d.Seconds / secondsPerDay))
}
