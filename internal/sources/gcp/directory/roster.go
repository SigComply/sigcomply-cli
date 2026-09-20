package directory

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	admin "google.golang.org/api/admin/directory/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// RosterEvidenceTypeID is the workforce-roster evidence type this plugin
// emits when a project designates Google Workspace as its roster.
const RosterEvidenceTypeID = "roster_entry"

// Normalized roster_entry status values (schema enum). Workspace has no
// "provisioned but cannot sign in" state, so pending is never emitted.
const (
	rosterActive   = "active"
	rosterInactive = "inactive"
)

// externalIDTypeOrganization is the Admin SDK externalIds type that
// carries the organization-assigned employee ID.
const externalIDTypeOrganization = "organization"

// rosterPayload is the roster_entry shape. The schema forbids additional
// properties and empty optional strings, so every optional is omitempty.
type rosterPayload struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Email        string `json:"email,omitempty"`
	DisplayName  string `json:"display_name,omitempty"`
	EmployeeID   string `json:"employee_id,omitempty"`
	SourceStatus string `json:"source_status,omitempty"`
}

// userStatus maps a Workspace user to (normalized, raw) status. Suspended
// and archived users cannot sign in, so both are inactive; suspended wins
// when both are set because it is the stronger administrative action.
func userStatus(u *admin.User) (status, sourceStatus string) {
	switch {
	case u.Suspended:
		return rosterInactive, "suspended"
	case u.Archived:
		return rosterInactive, "archived"
	default:
		return rosterActive, "active"
	}
}

// userDisplayName returns the user's full name, or "" when Name is unset.
func userDisplayName(u *admin.User) string {
	if u.Name == nil {
		return ""
	}
	return u.Name.FullName
}

// rosterRecord builds one roster_entry record from a Workspace user.
func rosterRecord(u *admin.User, now time.Time, scope *core.RecordScope) (core.EvidenceRecord, error) {
	status, sourceStatus := userStatus(u)
	payload := rosterPayload{
		ID:           u.Id,
		Status:       status,
		Email:        u.PrimaryEmail,
		DisplayName:  userDisplayName(u),
		EmployeeID:   organizationEmployeeID(u.ExternalIds),
		SourceStatus: sourceStatus,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("gcp.directory: marshal roster payload: %w", err)
	}
	return core.EvidenceRecord{
		Type:        RosterEvidenceTypeID,
		ID:          u.Id,
		IdentityKey: strings.ToLower(u.PrimaryEmail),
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
		Scope:       scope,
	}, nil
}

// organizationEmployeeID returns the value of the first externalIds entry
// of type "organization" with a non-empty value, or "". The generated
// client types User.ExternalIds as interface{}: decoded from JSON it is a
// []any of map[string]any, but callers building users in Go may set typed
// slices, so those are accepted too. Any other shape yields "".
func organizationEmployeeID(ext any) string {
	for _, id := range externalIDs(ext) {
		if id.Type == externalIDTypeOrganization && id.Value != "" {
			return id.Value
		}
	}
	return ""
}

// externalIDs normalizes the interface{}-typed User.ExternalIds into typed
// entries, skipping items that are not objects. Non-string type/value
// members decode as "".
func externalIDs(ext any) []admin.UserExternalId {
	switch ids := ext.(type) {
	case []any:
		out := make([]admin.UserExternalId, 0, len(ids))
		for _, item := range ids {
			if m, ok := item.(map[string]any); ok {
				out = append(out, admin.UserExternalId{Type: stringField(m, "type"), Value: stringField(m, "value")})
			}
		}
		return out
	case []*admin.UserExternalId:
		out := make([]admin.UserExternalId, 0, len(ids))
		for _, id := range ids {
			if id != nil {
				out = append(out, *id)
			}
		}
		return out
	case []admin.UserExternalId:
		return ids
	}
	return nil
}

// stringField returns m[key] when it is a string, else "".
func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
