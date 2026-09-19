package builtin_test

import (
	"context"
	"sort"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/entra"
	gcpiam "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/iam"

	// Side-effect imports: register every in-tree framework and source
	// factory so the coverage check sees the full shipped catalog.
	_ "github.com/sigcomply/sigcomply-cli/internal/frameworks/builtin"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/builtin"
)

// testDummyID is the placeholder account/org/group identifier the dummy
// factory config uses for every provider.
const testDummyID = "coverage-test"

// emittableTypes builds the universe of evidence types any in-tree source
// can emit. Factories are built with a best-effort env carrying the
// common config keys (region/project_id); a factory that still cannot be
// instantiated without live config is recorded so the coverage assertion
// can explain a gap rather than silently undercount.
func emittableTypes(t *testing.T) (emittable map[string]bool, failed map[string]error) {
	t.Helper()
	// Static dummy AWS credentials. AWS factories resolve credentials at
	// construction (awscfg.Load) so that a source configured in `sources:`
	// with no credentials fails the run rather than reporting an empty
	// account — which means they no longer build on a bare runner. The env
	// provider is first in the SDK's chain and resolves in-process, so this
	// keeps the factories constructible here with no network call; IMDS is
	// disabled so a miss can never reach for the metadata endpoint.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	// Rich dummy config so every network-free factory constructs
	// (github/okta need org+token but make no calls at construction).
	// Plugins whose construction needs live credentials (gcp.* call google
	// ADC; azure.* mint a token) fail here and are handled below.
	env := sources.Env{Config: map[string]any{
		"region":     "us-east-1",
		"project_id": testDummyID,
		"org":        testDummyID,
		"group":      testDummyID,
		"token":      "dummy",
		"org_url":    "https://example.okta.com",
		"api_token":  "dummy",
	}}
	emittable = map[string]bool{}
	failed = map[string]error{}
	for _, id := range sources.IDs() {
		// azure.entra is the one Azure factory that needs no subscription_id,
		// so it is the only one that reaches the credential step — where it
		// would probe the real identity chain (env, IMDS, then the az / azd /
		// pwsh CLIs as subprocesses). Its siblings fail instantly on config.
		// Building it here would make a hermetic unit test depend on external
		// tooling and the network; its Emits() is read statically below.
		if id == entra.SourceID {
			continue
		}
		p, err := sources.Build(context.Background(), id, env)
		if err != nil {
			failed[id] = err
			continue
		}
		for _, et := range p.Emits() {
			emittable[et] = true
		}
	}
	// gcp.iam is the only emitter of a GCP-only type (iam_binding) that
	// cannot be built here (crm.NewService requires ADC). Its Emits() is a
	// static constant, so read it from a bare instance. Other gcp.* plugins
	// emit cross-vendor types (object_storage_bucket, compute_instance,
	// managed_database_instance) already covered by their AWS counterparts.
	for _, et := range gcpiam.New(gcpiam.Options{}).Emits() {
		emittable[et] = true
	}
	// azure.entra is in the same position since its factory started minting
	// a token to prove the credential works: it cannot be built here, but
	// its Emits() is a static constant. Without this, a policy accepting an
	// Entra-only type would be reported as having no emitter when it has
	// one. Its ARM-plane siblings need a subscription_id and have always
	// failed this loop; every type they emit is cross-vendor.
	for _, et := range entra.New(entra.Options{}).Emits() {
		emittable[et] = true
	}
	return emittable, failed
}

// TestEmitterCoverage_EveryAcceptedTypeHasAnEmitter is the regression
// guard against phantom coverage: a policy must never accept an evidence
// type that no in-tree source plugin can emit (such a policy would
// silently skip at run time, showing coverage that evaluates to nothing).
func TestEmitterCoverage_EveryAcceptedTypeHasAnEmitter(t *testing.T) {
	emittable, failed := emittableTypes(t)

	for _, fwID := range frameworks.IDs() {
		fw, ok := frameworks.Lookup(fwID)
		if !ok {
			t.Fatalf("framework %q not found", fwID)
		}
		set := registry.NewSet()
		if err := evidencetypes.Register(set); err != nil {
			t.Fatalf("register evidence types: %v", err)
		}
		if err := fw.Register(set); err != nil {
			t.Fatalf("register framework %q: %v", fwID, err)
		}
		for _, pol := range set.Policies.All() {
			for _, slotName := range sortedSlotNames(pol.Slots) {
				accepts := pol.Slots[slotName].Accepts
				if len(accepts) == 0 {
					continue // manual implicit slot, etc.
				}
				if !anyEmittable(accepts, emittable) {
					t.Errorf("framework %s: policy %q slot %q accepts %v but no in-tree source emits any of them (failed-to-build sources: %v)",
						fwID, pol.ID, slotName, accepts, failedIDs(failed))
				}
			}
		}
	}
}

func anyEmittable(accepts []string, emittable map[string]bool) bool {
	for _, a := range accepts {
		if emittable[a] {
			return true
		}
	}
	return false
}

func sortedSlotNames(slots map[string]core.Slot) []string {
	names := make([]string, 0, len(slots))
	for n := range slots {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func failedIDs(failed map[string]error) []string {
	ids := make([]string, 0, len(failed))
	for id := range failed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
