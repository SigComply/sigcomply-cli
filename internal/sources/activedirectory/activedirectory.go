// Package activedirectory implements the active_directory source plugin:
// it reads user objects from an on-premises Active Directory domain over
// LDAPS (or LDAP + StartTLS) and emits one roster_entry per user, so a
// project can designate AD as its workforce roster.
//
// It emits only roster_entry — never directory_user: AD carries no MFA
// signal, so it cannot satisfy the directory_user contract honestly.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md), the
// plugin caches nothing across Collect calls: every Collect dials, binds,
// pages through the users and closes the connection.
//
// Test seams: Directory lets unit tests inject canned *ldap.Entry values;
// the real adapter's unexported dial function lets the L2 stand-in test
// drive the genuine bind / RootDSE / paged-search code over a scripted
// in-memory BER responder (there is no HTTP, so no cassette).
package activedirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// SourceID is the registered ID for the plugin.
const SourceID = "active_directory"

// EvidenceTypeRosterEntry is the only evidence type this plugin emits.
const EvidenceTypeRosterEntry = "roster_entry"

// Directory lists the raw user entries the plugin maps. The concrete
// *ldapDirectory satisfies it; unit tests inject a fake.
type Directory interface {
	ListUsers(ctx context.Context) ([]*ldap.Entry, error)
}

// Plugin is the in-process active_directory source.
type Plugin struct {
	dir        Directory
	serviceOUs []*ldap.DN
	now        func() time.Time
}

// Options is the constructor input.
type Options struct {
	Directory Directory
	// ServiceAccountOUs flags entries at or under these DNs as service
	// accounts (in addition to any entry carrying a servicePrincipalName).
	ServiceAccountOUs []*ldap.DN
	// Now is the clock used for CollectedAt and accountExpires comparison.
	Now func() time.Time
}

// New constructs a Plugin around an explicit Directory implementation.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{dir: opts.Directory, serviceOUs: opts.ServiceAccountOUs, now: now}
}

// NewFromConfig constructs a Plugin backed by a real LDAP connection. It
// does not dial; the connection is opened inside Collect.
func NewFromConfig(cfg *Config) *Plugin {
	return New(Options{
		Directory:         newLDAPDirectory(cfg),
		ServiceAccountOUs: cfg.ServiceAccountOUs,
	})
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeRosterEntry} }

// Init is a no-op; configuration arrives via the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// Collect lists every user matching the configured filter and returns one
// roster_entry record per user, sorted by ID (the objectGUID string).
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeRosterEntry) {
		return nil, fmt.Errorf("active_directory: AcceptedTypes %v does not include emitted type %q",
			req.AcceptedTypes, EvidenceTypeRosterEntry)
	}
	entries, err := p.dir.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("active_directory: list users: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(entries))
	for _, e := range entries {
		rec, err := p.record(e, now)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func (p *Plugin) record(e *ldap.Entry, now time.Time) (core.EvidenceRecord, error) {
	payload, err := mapEntry(e, now, p.serviceOUs)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("active_directory: %w", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("active_directory: marshal roster_entry: %w", err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeRosterEntry,
		ID:          payload.ID,
		IdentityKey: strings.ToLower(payload.Email),
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
	}, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
