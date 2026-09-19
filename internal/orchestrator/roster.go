package orchestrator

import (
	"fmt"
	"io"

	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// emitRosterWarnings logs the non-fatal findings about experimental.roster:
// unrecognized subkeys (tolerated — that tolerance is the point of the
// experimental: hatch — but a typo should still be loud) and a roster
// designated for a framework that never consults one. Everything fatal
// about the block has already failed the plan.
func emitRosterWarnings(logger *log.Logger, cfg *spec.ProjectConfig, set *registry.Set) {
	for _, w := range planner.RosterWarnings(cfg, set) {
		logger.Warnf("roster: %s", w)
	}
}

// emitRosterUsageWarnings names the experimental.roster account names no
// collected account carried. The source-ID half of a typo already fails
// the plan (planner.checkRosterSourceKeys); the account-name half cannot
// be checked before the records exist, so it is checked here, once, at
// the end of evaluation.
//
// Run-scoped on purpose: the planner hands every roster policy the same
// maps, and a key used by one of them is used. See evaluator.RosterUsage.
//
// stdout, not the logger: log.Redact rewrites anything email-shaped to
// <redacted:email>, and roster keys are frequently emails (a gcp.iam
// principal, an Okta login) — a redacted warning names nothing the
// operator can go and fix. This is the operator's own terminal; only
// the cloud payload is counts-only.
func emitRosterUsageWarnings(stdout io.Writer, usage *evaluator.RosterUsage) {
	if stdout == nil || usage == nil {
		return
	}
	for _, k := range usage.UnusedAliases() {
		_, _ = fmt.Fprintf(stdout, "unused-alias: experimental.roster.aliases[%q][%q] matched no collected account — no record from %s carries that id, username or principal_id\n", k.SourceID, k.Name, k.SourceID) //nolint:errcheck // status output
	}
	for _, k := range usage.UnusedNonHuman() {
		_, _ = fmt.Fprintf(stdout, "unused-non-human: experimental.roster.non_human[%q][%q] matched no collected account — no record from %s carries that id, username or principal_id\n", k.SourceID, k.Name, k.SourceID) //nolint:errcheck // status output
	}
}
