package sources

import (
	"context"
	"regexp"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// IDPattern is the grammar for a source key in `sources:`.
//
// A key is a base plugin ID, optionally followed by a bracketed instance
// name: `aws.iam`, `aws.iam[backup]`. The instance name makes a second,
// independently-configured copy of the same plugin — a second AWS
// account, a second GitHub org.
//
// The grammar is restrictive on purpose. A source key is not just a map
// key: it becomes part of an evidence envelope's object key in the vault
// (see collector.envelopePath). Letting `/` or `..` through would let a
// config write outside its own run folder, and only the local backend
// guards against that. Forbidding the characters outright is the cheaper
// and more obvious defense.
//
// Uppercase is permitted because project-local plugins register whatever
// ID they like (see docs/architecture/07-extensibility.md) and we do not
// want the config loader to be stricter than the registry. ':' is
// excluded because the binding syntax already uses it to separate a
// source from a catalog entry (`manual.pdf:entry_id`).
var IDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._-]{1,64}\])?$`)

// ValidID reports whether id is a well-formed source key.
func ValidID(id string) bool { return IDPattern.MatchString(id) }

// SplitInstanceID splits a source key into its base plugin ID and its
// instance name. `aws.iam[backup]` → ("aws.iam", "backup"); a plain
// `aws.iam` → ("aws.iam", ""). Assumes a key that already satisfies
// IDPattern; anything else is returned unchanged as the base.
func SplitInstanceID(key string) (base, instance string) {
	open := strings.IndexByte(key, '[')
	if open <= 0 || !strings.HasSuffix(key, "]") {
		return key, ""
	}
	return key[:open], key[open+1 : len(key)-1]
}

// instancePlugin re-identifies a plugin as one named instance of itself.
//
// Plugins hardcode their ID (`func (*Plugin) ID() string { return
// SourceID }`) and stamp that same constant onto every record they
// return. That is correct for the single-instance case and wrong for
// every other one: two instances would collide in the source registry,
// and their evidence would be indistinguishable once collected — same
// ID in the envelope filename, same source_id inside the signed records.
//
// Wrapping is what makes an instance a first-class thing without editing
// ~60 plugins. The wrapper answers with the instance key and re-stamps
// records on the way out, so provenance names the account the evidence
// actually came from.
//
// Only bracketed keys are wrapped. A plain `aws.iam` is registered
// unwrapped, so its records and envelope filenames are byte-for-byte
// what they were before instancing existed.
type instancePlugin struct {
	inner core.SourcePlugin
	id    string
}

func (p *instancePlugin) ID() string      { return p.id }
func (p *instancePlugin) Emits() []string { return p.inner.Emits() }

func (p *instancePlugin) Init(ctx context.Context, cfg map[string]any) error {
	return p.inner.Init(ctx, cfg)
}

// Collect delegates, then rewrites each record's SourceID to the
// instance key. This runs before schema validation and before signing
// (see collector.collectBinding), so the stamped value is the one that
// is validated, signed, and read back by an auditor.
func (p *instancePlugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	records, err := p.inner.Collect(ctx, req)
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i].SourceID = p.id
	}
	return records, nil
}

// asInstance returns plugin re-identified as key, or plugin unchanged
// when key names no instance.
func asInstance(plugin core.SourcePlugin, key string) core.SourcePlugin {
	if _, instance := SplitInstanceID(key); instance == "" {
		return plugin
	}
	return &instancePlugin{inner: plugin, id: key}
}
