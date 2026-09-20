package spec

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RisksKey is the subkey under `experimental:` that carries the risk
// register. It lives under the escape hatch for the same reason
// VendorsKey and ScopeKey do: the loader runs with KnownFields(true), so
// a brand-new top-level key would hard-fail every older pinned CLI that
// predates it. See docs/architecture/08-project-config.md §Config
// evolution policy.
const RisksKey = "risks"

// Risk treatment options, in ISO/IEC 27005's vocabulary — the four ways
// an organization can respond to an evaluated risk.
//
// The names are the standard's, not colloquial synonyms: "retain" is
// what most people call accepting a risk, and "modify" is what most
// people call mitigating it. Using the standard's words keeps the
// register legible to the auditor reading it beside the clause.
const (
	// TreatmentModify applies controls to reduce the risk — the option
	// that selects Annex A controls, and the reason a risk carries a
	// controls list at all.
	TreatmentModify = "modify"
	// TreatmentRetain accepts the risk at its evaluated level without
	// further treatment. It is the one option that produces no control,
	// so it is the one that must name who accepted it.
	TreatmentRetain = "retain"
	// TreatmentAvoid stops the activity that gives rise to the risk.
	TreatmentAvoid = "avoid"
	// TreatmentShare transfers part of the risk to another party —
	// insurance, or an outsourcing arrangement. ISO/IEC 27005 3.2.9
	// notes that transferring is a *form of* sharing, not a synonym,
	// which is why the broader word is the canonical one.
	TreatmentShare = "share"
)

// treatmentAliases accepts the vocabulary most registers are already
// written in. ISO/IEC 27001 itself enumerates no treatment options at
// all — 6.1.3 a) only says "select appropriate options" — and the
// canonical four come from ISO 31000 6.5.2 via ISO/IEC 27005. Every
// competing list in the field (AART, avoid/reduce/transfer/accept,
// decrease/avoid/share/retain) means the same four things, and no
// auditor can cite a clause mandating one vocabulary. So the canonical
// name is what gets stored, and the synonym an operator already uses is
// accepted rather than rejected on a technicality.
var treatmentAliases = map[string]string{
	"accept":   TreatmentRetain,
	"mitigate": TreatmentModify,
	"reduce":   TreatmentModify,
	"decrease": TreatmentModify,
	"transfer": TreatmentShare,
}

// Risk levels. Deliberately the same four words as the vendor tiers, so
// an operator learns one vocabulary rather than two.
//
// Two levels are carried, not three, and that is deliberate: ISO/IEC
// 27001 6.1.2 d) 3) asks the organization to "determine the levels of
// risk" — singular per risk — and 6.1.3 f) separately requires
// acceptance of the *residual* risk. The before/after pair that most
// register templates carry as "inherent" and "residual" is convention;
// the word "inherent" appears nowhere in the standard, and neither do
// asset, threat or vulnerability, all of which the 2005 edition
// mandated and the 2022 edition deliberately dropped. Forcing a
// methodology the standard declined to impose is not this tool's job.
//
// A level is descriptive. It NEVER decides whether a risk owes a
// treatment, an owner, or an acceptance record — every risk owes all
// three at every level. This is the same guardrail the vendor tiers
// carry, and for the same reason: an operator-chosen value that removes
// an obligation would make under-declaring the register the cheapest way
// to look compliant.
const (
	RiskLevelCritical = "critical"
	RiskLevelHigh     = "high"
	RiskLevelModerate = "moderate"
	RiskLevelLow      = "low"
)

// riskIDPattern bounds a risk ID to a short, lowercase, greppable slug.
// Unlike a vendor ID it is never appended to a policy ID — no risk mints
// a policy — so the cap is about legibility in a report column rather
// than about a database column width.
var riskIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,39}$`)

// RiskRegister is the operator's declaration of the information security
// risks this project has assessed, and the Annex A controls chosen to
// treat them.
//
// It exists to close the one gap the Statement of Applicability cannot
// close on its own. `report --view soa` already discharges ISO/IEC
// 27001:2022 6.1.3 d) — which controls are necessary, why each is
// included, whether it is implemented, and why any were excluded. What
// it has never been able to say is *which risk made a control
// necessary*, because nothing in the vault or the framework carries that
// edge. Risk→control traceability is a classic certification finding,
// and the answer only exists in the operator's head until they write it
// down somewhere the tool can read.
//
// This is a register, not a replacement for a document. The four
// ISO clause entries that ask for the risk assessment process, the risk
// treatment process and the retained documented information
// (C.6.1.2, C.6.1.3, C.8.2, C.8.3) are untouched and still owe their
// uploads. The argument in docs/architecture/13-isms-clauses-and-soa.md
// — that rendering a management artifact as structured fields
// reproduces the overclaim those entries exist to retire — is why this
// is additive: a risk register is genuinely tabular where minutes are
// not, and it supplements the document rather than standing in for it.
//
// Nothing in here crosses the aggregation boundary. Risk descriptions
// are a map of where an organization believes it is weakest and owner
// addresses are personal identifiers; both stay vault-side. The SoA is a
// vault-read-only report, and no risk field has any path to the
// SubmissionPayload (Invariant #1).
type RiskRegister struct {
	// DeclaredBy and DeclaredAt are an optional audit trail: who last
	// reviewed the register and when.
	DeclaredBy string
	DeclaredAt string

	// Risks is the declared register, sorted by ID.
	Risks []Risk

	// UnknownKeys names subkeys under experimental.risks the loader did
	// not recognize, so a typo is reported rather than silently ignored.
	UnknownKeys []string
}

// Risk is one row of the register.
//
// Every field is declared, never parsed or inferred — the same idiom as
// the vendor register's assurance_period_end. The CLI checks the shape
// and the arithmetic of the dates; it never reads a document to confirm
// any of it, and it never second-guesses the operator's evaluation.
type Risk struct {
	// ID is a short stable slug, e.g. "r-001" or "laptop_theft".
	ID string `yaml:"id"`
	// Description is what the risk actually is, in the operator's words.
	Description string `yaml:"description"`
	// Owner is the person accountable for the risk — ISO 27001 6.1.2 c)
	// requires every risk to have one.
	Owner string `yaml:"owner"`
	// Level is the evaluated risk level before treatment.
	Level string `yaml:"level"`
	// Treatment is the chosen option: modify, retain, avoid or share.
	Treatment string `yaml:"treatment"`
	// Controls names the Annex A control IDs chosen to treat this risk.
	// This is the edge the Statement of Applicability joins on, and the
	// whole reason the register exists.
	Controls []string `yaml:"controls"`
	// ResidualLevel is the level that remains after treatment.
	ResidualLevel string `yaml:"residual_level"`
	// AcceptedBy and AcceptanceRationale record who signed off on
	// retaining a risk and why. Required when Treatment is "retain",
	// which is the only option that produces no control.
	AcceptedBy          string `yaml:"accepted_by"`
	AcceptanceRationale string `yaml:"acceptance_rationale"`
	// AssessedAt is the date this risk was last assessed (YYYY-MM-DD).
	// Compared arithmetically against the audit period — the only thing
	// that catches a register nobody has revisited in three years.
	AssessedAt string `yaml:"assessed_at"`
}

// risksRaw / riskRaw are the YAML shapes. Kept separate from the loaded
// types for the same reason the vendor register does: the tags belong to
// the parsing layer.
type risksRaw struct {
	DeclaredBy string    `yaml:"declared_by"`
	DeclaredAt string    `yaml:"declared_at"`
	Register   []riskRaw `yaml:"register"`
}

type riskRaw Risk

var knownRisksKeys = map[string]struct{}{
	keyDeclaredBy: {}, keyDeclaredAt: {}, "register": {},
}

// Declared reports whether a register was declared at all. A nil
// register is the undeclared case, which is not an error: the risk
// register is optional, and a project without one behaves exactly as it
// did before this existed.
func (r *RiskRegister) Declared() bool { return r != nil && len(r.Risks) > 0 }

// ControlRisks indexes the register by control ID, returning the sorted
// risk IDs that name each control. This is the join the Statement of
// Applicability consumes. A nil register yields a nil map, so the SoA
// renders exactly as before when no register is declared.
func (r *RiskRegister) ControlRisks() map[string][]string {
	if !r.Declared() {
		return nil
	}
	out := map[string][]string{}
	for i := range r.Risks {
		for _, c := range r.Risks[i].Controls {
			out[c] = append(out[c], r.Risks[i].ID)
		}
	}
	for c := range out {
		sort.Strings(out[c])
	}
	return out
}

// DeclaredControls returns every control ID named by any risk, sorted.
// Used to report a risk that names a control the framework does not
// have — a typo that would otherwise just fail to join, silently.
func (r *RiskRegister) DeclaredControls() []string {
	idx := r.ControlRisks()
	out := make([]string, 0, len(idx))
	for c := range idx {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// LoadRiskRegister projects the experimental.risks block out of a loaded
// project config. Returns (nil, nil) when no register is declared.
func LoadRiskRegister(cfg *ProjectConfig) (*RiskRegister, error) {
	if cfg == nil || len(cfg.Experimental) == 0 {
		return nil, nil
	}
	raw, ok := cfg.Experimental[RisksKey]
	if !ok || raw == nil {
		return nil, nil
	}

	// experimental: decodes into map[string]any, so the original
	// yaml.Node is gone by the time we get here. Round-tripping through
	// the marshaller is what gives us a typed decode; the cost is that
	// error messages carry no line numbers, which is acceptable for a
	// block this small.
	asMap, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("project config: experimental.risks must be a mapping of register settings")
	}

	// Check the one non-scalar field's shape up front: yaml's own type
	// error names the Go type rather than the YAML key, which is not a
	// message a hand-editing operator can act on.
	if v, present := asMap["register"]; present {
		if _, isList := v.([]any); !isList {
			return nil, fmt.Errorf("project config: experimental.risks.register must be a list of risks, e.g. [{id: r-001, description: ..., owner: ..., level: high, treatment: modify, controls: [A.8.7], residual_level: low, assessed_at: \"2026-01-15\"}]")
		}
	}

	buf, err := yaml.Marshal(asMap)
	if err != nil {
		return nil, fmt.Errorf("project config: experimental.risks: %w", err)
	}
	var rawRisks risksRaw
	if err := yaml.Unmarshal(buf, &rawRisks); err != nil {
		return nil, fmt.Errorf("project config: experimental.risks: %w", err)
	}

	out := &RiskRegister{DeclaredBy: rawRisks.DeclaredBy, DeclaredAt: rawRisks.DeclaredAt}
	for k := range asMap {
		if _, known := knownRisksKeys[k]; !known {
			out.UnknownKeys = append(out.UnknownKeys, k)
		}
	}
	sort.Strings(out.UnknownKeys)

	if err := validateOptionalDate(rawRisks.DeclaredAt); err != nil {
		return nil, fmt.Errorf("project config: experimental.risks.%s: %w", keyDeclaredAt, err)
	}

	risks, err := validateRiskRegister(rawRisks.Register)
	if err != nil {
		return nil, err
	}
	out.Risks = risks
	return out, nil
}

// validateRiskRegister checks the declared register is non-empty and
// every risk is well-formed and uniquely identified, and returns them
// sorted by ID.
func validateRiskRegister(raw []riskRaw) ([]Risk, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("project config: experimental.risks: register must list at least one risk (remove the risks block entirely to leave the register undeclared)")
	}
	out := make([]Risk, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for i := range raw {
		r := &raw[i]
		if err := validateRisk(i, r, seen); err != nil {
			return nil, err
		}
		seen[r.ID] = struct{}{}
		out = append(out, Risk(*r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// validateRisk checks one register row.
func validateRisk(i int, r *riskRaw, seen map[string]struct{}) error {
	where := fmt.Sprintf("project config: experimental.risks.register[%d]", i)
	if r.ID == "" {
		return fmt.Errorf("%s: missing required field \"id\"", where)
	}
	if !riskIDPattern.MatchString(r.ID) {
		return fmt.Errorf("%s: id %q must be 1-40 characters of lowercase letters, digits, underscore, dot or hyphen, starting with a letter or digit", where, r.ID)
	}
	if _, dup := seen[r.ID]; dup {
		return fmt.Errorf("project config: experimental.risks.register: duplicate risk id %q", r.ID)
	}
	where = fmt.Sprintf("%s (%s)", where, r.ID)

	if strings.TrimSpace(r.Description) == "" {
		return fmt.Errorf("%s: missing required field \"description\" (what the risk actually is)", where)
	}
	// ISO 27001 6.1.2 c) 2): every risk has an identified owner. A
	// register of unowned risks is the finding, not the evidence.
	if strings.TrimSpace(r.Owner) == "" {
		return fmt.Errorf("%s: missing required field \"owner\" (ISO 27001 6.1.2 requires every risk to have an identified owner)", where)
	}
	if err := validateRiskLevel(where, "level", r.Level); err != nil {
		return err
	}
	if err := validateRiskLevel(where, "residual_level", r.ResidualLevel); err != nil {
		return err
	}
	if err := validateRiskTreatment(where, r); err != nil {
		return err
	}
	if r.AssessedAt == "" {
		return fmt.Errorf("%s: missing required field \"assessed_at\" (the date this risk was last assessed; without it nothing can tell a current register from an abandoned one)", where)
	}
	if err := validateOptionalDate(r.AssessedAt); err != nil {
		return fmt.Errorf("%s: assessed_at: %w", where, err)
	}
	return nil
}

func validateRiskLevel(where, field, level string) error {
	switch level {
	case RiskLevelCritical, RiskLevelHigh, RiskLevelModerate, RiskLevelLow:
		return nil
	}
	return fmt.Errorf("%s: %s: invalid value %q (want %s|%s|%s|%s)",
		where, field, level, RiskLevelCritical, RiskLevelHigh, RiskLevelModerate, RiskLevelLow)
}

// validateRiskTreatment checks the treatment option and the obligations
// that follow from it. Split out of validateRisk to keep each function
// readable rather than to share anything.
func validateRiskTreatment(where string, r *riskRaw) error {
	if canonical, alias := treatmentAliases[r.Treatment]; alias {
		r.Treatment = canonical
	}
	switch r.Treatment {
	case TreatmentModify, TreatmentRetain, TreatmentAvoid, TreatmentShare:
	default:
		return fmt.Errorf("%s: treatment: invalid value %q (want %s|%s|%s|%s — accept/mitigate/reduce/decrease/transfer are accepted as synonyms)",
			where, r.Treatment, TreatmentModify, TreatmentRetain, TreatmentAvoid, TreatmentShare)
	}
	// "Modify" means "apply controls". A modify with no controls names
	// no treatment at all, and would join to nothing in the SoA — the
	// silent version of an unfilled register.
	if r.Treatment == TreatmentModify && len(r.Controls) == 0 {
		return fmt.Errorf("%s: treatment %q requires at least one entry in \"controls\" (modifying a risk means applying controls; name the Annex A controls that treat it)", where, TreatmentModify)
	}
	// Retain is the one option that produces no control, so it is the
	// one that must be signed for — the direct analog of a low-tier
	// vendor owing tier_rationale + approved_by rather than an artifact.
	if r.Treatment == TreatmentRetain {
		if strings.TrimSpace(r.AcceptedBy) == "" {
			return fmt.Errorf("%s: treatment %q requires \"accepted_by\" (ISO 27001 6.1.3 f) requires documented approval of residual risk — name who accepted it)", where, TreatmentRetain)
		}
		if strings.TrimSpace(r.AcceptanceRationale) == "" {
			return fmt.Errorf("%s: treatment %q requires \"acceptance_rationale\" (a retained risk files no control, so the justification is the evidence)", where, TreatmentRetain)
		}
	}
	for j, c := range r.Controls {
		if strings.TrimSpace(c) == "" {
			return fmt.Errorf("%s: controls[%d] is empty (name an Annex A control, e.g. \"A.8.7\")", where, j)
		}
	}
	return nil
}
