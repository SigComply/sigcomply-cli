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
// ID in the envelope filename, same source_id inside the signed records,
// and colliding record IDs wherever a plugin's id is only unique within
// one account (see Collect).
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

// Collect delegates, then rewrites each record's SourceID *and* ID to
// carry the instance key. This runs before schema validation and before
// signing (see collector.collectBinding), so the stamped values are the
// ones that are validated, signed, and read back by an auditor.
//
// Namespacing the ID is what closes the cross-account collision. A
// plugin's record ID only has to be unique within the account it was
// read from, and several are not unique across accounts at all:
// aws.password_policy emits the constant "account" (a stable id was
// chosen to avoid an sts:GetCallerIdentity purely to learn the account
// number), aws.security_services emits "aws-macie" and friends,
// azure.defender emits "azure-defender-for-cloud", and resource *names*
// like a GCP "default" network repeat in every project by construction.
// The collector unions both bindings into one slot and the evaluator
// dedups violations by record ID, so two accounts failing the same check
// collapsed into a single violation with resources_failed=1, naming
// neither account — and one resource_id exception waived both.
//
// IdentityKey is deliberately NOT namespaced. It is the cross-source
// join key (an email that okta and aws.iam both report for one person),
// and prefixing it would break exactly the dedup it exists to perform.
// recordIdentity prefers the clause's identity key and falls back to the
// record ID, so a record with no cross-source identity now falls back to
// a per-instance one rather than a colliding one — the right direction.
//
// Only bracketed keys reach here, so every unbracketed source's records
// are byte-identical to what they were before instancing existed.
func (p *instancePlugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	records, err := p.inner.Collect(ctx, req)
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i].SourceID = p.id
		records[i].ID = p.id + "/" + records[i].ID
	}
	return records, nil
}

// caveatedInstancePlugin is instancePlugin for an inner plugin that also
// implements core.CaveatedSource.
//
// Two types rather than one method on instancePlugin, because the optional
// interface has to stay optional: a Caveats() method on instancePlugin would
// make EVERY bracketed source satisfy core.CaveatedSource, so a plugin that
// declares no caveats would start claiming an empty set — which reads the
// same as "asked and told there are none". The wrapper must be exactly as
// caveated as what it wraps.
type caveatedInstancePlugin struct {
	instancePlugin
	caveats core.CaveatedSource
}

func (p *caveatedInstancePlugin) Caveats() []core.SourceCaveat { return p.caveats.Caveats() }

// asInstance returns plugin re-identified as key, or plugin unchanged
// when key names no instance.
//
// Any optional interface the inner plugin implements must be forwarded here.
// A missed forward fails silently — the consumer's type assertion simply
// returns false — so a bracketed key would lose behavior its plain-key twin
// has, which is the multi-account case most likely to need it.
func asInstance(plugin core.SourcePlugin, key string) core.SourcePlugin {
	if _, instance := SplitInstanceID(key); instance == "" {
		return plugin
	}
	wrapped := instancePlugin{inner: plugin, id: key}
	if c, ok := plugin.(core.CaveatedSource); ok {
		return &caveatedInstancePlugin{instancePlugin: wrapped, caveats: c}
	}
	return &wrapped
}
