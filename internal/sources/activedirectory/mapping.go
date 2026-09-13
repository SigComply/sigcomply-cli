package activedirectory

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// AD attribute names read from each user entry. Lookups are
// case-insensitive (GetEqualFold*) because servers may echo attribute
// names in a different case than requested.
const (
	attrObjectGUID           = "objectGUID"
	attrSAMAccountName       = "sAMAccountName"
	attrUserPrincipalName    = "userPrincipalName"
	attrMail                 = "mail"
	attrProxyAddresses       = "proxyAddresses"
	attrDisplayName          = "displayName"
	attrGivenName            = "givenName"
	attrSn                   = "sn"
	attrUserAccountControl   = "userAccountControl"
	attrAccountExpires       = "accountExpires"
	attrEmployeeID           = "employeeID"
	attrEmployeeNumber       = "employeeNumber"
	attrEmployeeType         = "employeeType"
	attrServicePrincipalName = "servicePrincipalName"
	attrDistinguishedName    = "distinguishedName"
)

// userAttributes is the exact attribute list requested — nothing else is
// ever read from the directory (data minimisation).
var userAttributes = []string{
	attrObjectGUID, attrSAMAccountName, attrUserPrincipalName, attrMail,
	attrProxyAddresses, attrDisplayName, attrGivenName, attrSn,
	attrUserAccountControl, attrAccountExpires, attrEmployeeID,
	attrEmployeeNumber, attrEmployeeType, attrServicePrincipalName,
	attrDistinguishedName,
}

// Normalized roster_entry status values and the AD source_status values
// they derive from.
const (
	statusActive   = "active"
	statusInactive = "inactive"

	sourceStatusEnabled  = "enabled"
	sourceStatusDisabled = "disabled"
	sourceStatusExpired  = "expired"
)

// uacAccountDisable is the ACCOUNTDISABLE bit of userAccountControl.
const uacAccountDisable = 0x2

// FILETIME constants: accountExpires counts 100ns intervals since
// 1601-01-01 UTC. 0 and math.MaxInt64 both mean "never expires".
const (
	fileTimeNever         int64 = 0x7FFFFFFFFFFFFFFF
	fileTimeUnixEpochDiff int64 = 116444736000000000 // 1601→1970 in 100ns
	fileTimeTicksPerSec   int64 = 10000000
)

// rosterPayload is the roster_entry v1 shape. Optional strings are
// omitted when empty (the schema's minLength 1 forbids ""). The schema
// sets additionalProperties:false, so nothing else may be added.
type rosterPayload struct {
	ID               string `json:"id"`
	Status           string `json:"status"`
	Email            string `json:"email,omitempty"`
	DisplayName      string `json:"display_name,omitempty"`
	EmployeeID       string `json:"employee_id,omitempty"`
	EmployeeType     string `json:"employee_type,omitempty"`
	IsServiceAccount bool   `json:"is_service_account"`
	SourceStatus     string `json:"source_status"`
}

// mapEntry converts one LDAP user entry into a roster_entry payload.
// Entries missing an objectGUID or carrying a malformed
// userAccountControl/accountExpires are errors, not guesses: a roster
// entry with an invented status could vouch for an account it shouldn't.
func mapEntry(e *ldap.Entry, now time.Time, serviceOUs []*ldap.DN) (rosterPayload, error) {
	id, err := guidString(e.GetEqualFoldRawAttributeValue(attrObjectGUID))
	if err != nil {
		return rosterPayload{}, fmt.Errorf("entry %q: %w", e.DN, err)
	}
	status, sourceStatus, err := entryStatus(e, now)
	if err != nil {
		return rosterPayload{}, fmt.Errorf("entry %q: %w", e.DN, err)
	}
	return rosterPayload{
		ID:               id,
		Status:           status,
		Email:            entryEmail(e),
		DisplayName:      entryDisplayName(e),
		EmployeeID:       firstNonEmpty(attr(e, attrEmployeeID), attr(e, attrEmployeeNumber)),
		EmployeeType:     attr(e, attrEmployeeType),
		IsServiceAccount: isServiceAccount(e, serviceOUs),
		SourceStatus:     sourceStatus,
	}, nil
}

// guidString renders a 16-byte objectGUID in Microsoft's registry format:
// the first three groups are little-endian (Data1 uint32, Data2/Data3
// uint16), the last two are byte order as stored. Output is lowercase,
// matching PowerShell's Get-ADUser ObjectGUID.
func guidString(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("objectGUID missing or not 16 bytes (got %d)", len(b))
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8:10], b[10:16]), nil
}

// entryStatus derives (status, source_status). A disabled account reports
// "disabled" even when also expired — disablement is the stronger,
// deliberate administrative signal.
func entryStatus(e *ldap.Entry, now time.Time) (status, sourceStatus string, err error) {
	disabled, err := uacDisabled(attr(e, attrUserAccountControl))
	if err != nil {
		return "", "", err
	}
	if disabled {
		return statusInactive, sourceStatusDisabled, nil
	}
	expired, err := accountExpired(attr(e, attrAccountExpires), now)
	if err != nil {
		return "", "", err
	}
	if expired {
		return statusInactive, sourceStatusExpired, nil
	}
	return statusActive, sourceStatusEnabled, nil
}

// uacDisabled reports whether the ACCOUNTDISABLE bit is set. AD always
// populates userAccountControl on user objects, so an absent value means
// the bind account cannot read it — an error, never "enabled".
func uacDisabled(raw string) (bool, error) {
	if raw == "" {
		return false, fmt.Errorf("userAccountControl missing (does the bind account have read access?)")
	}
	// Signed parse: some servers render the 32-bit flags as a negative int.
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false, fmt.Errorf("userAccountControl %q: %w", raw, err)
	}
	return v&uacAccountDisable != 0, nil
}

// accountExpired reports whether accountExpires (a FILETIME) is at or
// before now. Absent, 0 and 0x7FFFFFFFFFFFFFFF mean the account never
// expires.
func accountExpired(raw string, now time.Time) (bool, error) {
	if raw == "" {
		return false, nil
	}
	ft, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false, fmt.Errorf("accountExpires %q: %w", raw, err)
	}
	if ft == 0 || ft == fileTimeNever {
		return false, nil
	}
	if ft < 0 {
		return false, fmt.Errorf("accountExpires %q: negative FILETIME", raw)
	}
	return !fileTimeToTime(ft).After(now), nil
}

// fileTimeToTime converts a FILETIME (100ns ticks since 1601-01-01 UTC) to
// a time.Time. Splitting into seconds + remainder before subtracting the
// epoch offset keeps the arithmetic inside int64 for every input.
func fileTimeToTime(ft int64) time.Time {
	sec := ft/fileTimeTicksPerSec - fileTimeUnixEpochDiff/fileTimeTicksPerSec
	nsec := (ft % fileTimeTicksPerSec) * 100
	return time.Unix(sec, nsec).UTC()
}

// entryEmail picks mail → the primary proxyAddress (upper-case "SMTP:"
// prefix; lower-case "smtp:" marks secondaries) → userPrincipalName.
func entryEmail(e *ldap.Entry) string {
	if m := attr(e, attrMail); m != "" {
		return m
	}
	for _, pa := range e.GetEqualFoldAttributeValues(attrProxyAddresses) {
		if addr, ok := strings.CutPrefix(pa, "SMTP:"); ok && strings.TrimSpace(addr) != "" {
			return strings.TrimSpace(addr)
		}
	}
	return attr(e, attrUserPrincipalName)
}

// entryDisplayName picks displayName → "givenName sn" → sAMAccountName.
func entryDisplayName(e *ldap.Entry) string {
	full := strings.TrimSpace(attr(e, attrGivenName) + " " + attr(e, attrSn))
	return firstNonEmpty(attr(e, attrDisplayName), full, attr(e, attrSAMAccountName))
}

// isServiceAccount flags entries carrying a servicePrincipalName (Kerberos
// service identity) or living at/under a configured service-account OU
// (case-insensitive DN comparison).
func isServiceAccount(e *ldap.Entry, serviceOUs []*ldap.DN) bool {
	for _, spn := range e.GetEqualFoldAttributeValues(attrServicePrincipalName) {
		if strings.TrimSpace(spn) != "" {
			return true
		}
	}
	return underAnyOU(entryDN(e), serviceOUs)
}

func entryDN(e *ldap.Entry) string {
	return firstNonEmpty(e.DN, attr(e, attrDistinguishedName))
}

func underAnyOU(dn string, ous []*ldap.DN) bool {
	if dn == "" || len(ous) == 0 {
		return false
	}
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return false
	}
	for _, ou := range ous {
		if ou.EqualFold(parsed) || ou.AncestorOfFold(parsed) {
			return true
		}
	}
	return false
}

// attr returns the first value of an attribute, trimmed ("" when absent).
func attr(e *ldap.Entry, name string) string {
	return strings.TrimSpace(e.GetEqualFoldAttributeValue(name))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
