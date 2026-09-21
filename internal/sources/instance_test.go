package sources

import (
	"context"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

const (
	testSourceAWSIAM          = "aws.iam"
	testSourceAWSIAMInstance  = "aws.iam[backup]"
	testSourceGitHub          = "github"
	testInstanceSuffix        = "[backup]"
	testEvidenceDirectoryUser = "directory_user"
)

func TestSplitInstanceID(t *testing.T) {
	cases := []struct{ key, base, instance string }{
		{testSourceAWSIAM, testSourceAWSIAM, ""},
		{testSourceAWSIAMInstance, testSourceAWSIAM, "backup"},
		{testSourceGitHub, testSourceGitHub, ""},
		{"gcp.storage[eu-project]", "gcp.storage", "eu-project"},
		{"aws.iam_access_key[prod]", "aws.iam_access_key", "prod"},
		// Malformed keys are returned whole; the grammar rejects them
		// before they reach here.
		{"aws.iam[", "aws.iam[", ""},
		{testInstanceSuffix, testInstanceSuffix, ""},
	}
	for _, c := range cases {
		base, instance := SplitInstanceID(c.key)
		if base != c.base || instance != c.instance {
			t.Errorf("SplitInstanceID(%q) = (%q, %q); want (%q, %q)", c.key, base, instance, c.base, c.instance)
		}
	}
}

func TestValidID(t *testing.T) {
	valid := []string{
		testSourceAWSIAM, testSourceAWSIAMInstance, "manual.pdf", testSourceGitHub, "okta",
		"aws.iam_access_key", "acme.internal_iam", "gcp.scc[org-2]",
		"aws.s3[a.b-c_d]",
	}
	for _, id := range valid {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false; want true", id)
		}
	}

	// Each of these would end up inside a vault object key.
	invalid := []string{
		"", "aws.iam[]", "aws.iam[a/b]", "aws.iam[../../etc]",
		"aws/iam", "../aws.iam", "aws.iam[a][b]", "aws.iam[a",
		"aws.iam]", testInstanceSuffix, ".aws.iam", "aws:iam",
		"aws.iam[with space]",
	}
	for _, id := range invalid {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true; want false", id)
		}
	}
}

type stubPlugin struct {
	id   string
	recs []core.EvidenceRecord
	err  error
}

func (s *stubPlugin) ID() string                                 { return s.id }
func (s *stubPlugin) Emits() []string                            { return []string{testEvidenceDirectoryUser} }
func (s *stubPlugin) Init(context.Context, map[string]any) error { return nil }
func (s *stubPlugin) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	return s.recs, s.err
}

// A plain key must produce the plugin unchanged — same identity, same
// record bytes — so adopting instancing cannot alter an existing run.
func TestAsInstance_PlainKeyIsUntouched(t *testing.T) {
	inner := &stubPlugin{id: testSourceAWSIAM, recs: []core.EvidenceRecord{{ID: "u1", SourceID: testSourceAWSIAM}}}
	got := asInstance(inner, testSourceAWSIAM)
	if got != core.SourcePlugin(inner) {
		t.Fatal("a non-instance key must return the original plugin, unwrapped")
	}
}

func TestAsInstance_StampsProvenance(t *testing.T) {
	inner := &stubPlugin{
		id:   testSourceAWSIAM,
		recs: []core.EvidenceRecord{{ID: "u1", SourceID: testSourceAWSIAM}, {ID: "u2", SourceID: testSourceAWSIAM}},
	}
	got := asInstance(inner, testSourceAWSIAMInstance)

	if got.ID() != testSourceAWSIAMInstance {
		t.Errorf("ID() = %q; want aws.iam[backup]", got.ID())
	}
	if len(got.Emits()) != 1 || got.Emits()[0] != testEvidenceDirectoryUser {
		t.Errorf("Emits() = %v; want delegation to the inner plugin", got.Emits())
	}

	recs, err := got.Collect(context.Background(), core.SlotRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// Without this the evidence of two accounts is indistinguishable:
	// same source_id in the signed records, same envelope filename.
	for i := range recs {
		if recs[i].SourceID != testSourceAWSIAMInstance {
			t.Errorf("record %d SourceID = %q; want aws.iam[backup]", i, recs[i].SourceID)
		}
	}
}

func TestAsInstance_PropagatesCollectError(t *testing.T) {
	inner := &stubPlugin{id: testSourceAWSIAM, err: context.Canceled}
	if _, err := asInstance(inner, testSourceAWSIAMInstance).Collect(context.Background(), core.SlotRequest{}); err == nil {
		t.Fatal("Collect error must propagate through the wrapper")
	}
}

func TestBuild_InstanceResolvesBaseFactory(t *testing.T) {
	reset()
	t.Cleanup(reset)
	RegisterFactory("test.src", func(_ context.Context, env Env) (core.SourcePlugin, error) {
		return &stubPlugin{id: "test.src", recs: []core.EvidenceRecord{{ID: "r1", SourceID: "test.src"}}}, nil
	})

	got, err := Build(context.Background(), "test.src[two]", Env{})
	if err != nil {
		t.Fatalf("Build instance: %v", err)
	}
	if got.ID() != "test.src[two]" {
		t.Errorf("ID() = %q; want test.src[two]", got.ID())
	}

	// An unknown base behind an instance suffix must say so clearly.
	if _, err := Build(context.Background(), "no.such[two]", Env{}); err == nil {
		t.Error("want an error for an instance of an unregistered base")
	}
}

func TestRegisterFactory_RejectsInstanceID(t *testing.T) {
	reset()
	t.Cleanup(reset)
	defer func() {
		if recover() == nil {
			t.Error("registering a bracketed factory ID must panic: instances are runtime, not registration-time")
		}
	}()
	RegisterFactory("test.src[two]", func(_ context.Context, _ Env) (core.SourcePlugin, error) {
		return nil, nil
	})
}

// caveatedStub implements the optional core.CaveatedSource beside the
// mandatory SourcePlugin methods.
type caveatedStub struct {
	stubPlugin
}

func (c *caveatedStub) Caveats() []core.SourceCaveat {
	return []core.SourceCaveat{{EvidenceType: testEvidenceDirectoryUser, Field: "mfa_enabled", Detail: "no API"}}
}

// The wrapper must forward every optional interface the inner plugin
// implements. A missed forward is silent: the type assertion in the planner
// just fails, and aws.iam[backup] quietly loses the caveat that aws.iam
// declares — the instanced estate, which is exactly the multi-account case
// most likely to union two identity sources into one slot.
func TestAsInstance_ForwardsCaveats(t *testing.T) {
	inner := &caveatedStub{stubPlugin{id: testSourceAWSIAM}}
	got := asInstance(inner, testSourceAWSIAMInstance)

	c, ok := got.(core.CaveatedSource)
	if !ok {
		t.Fatal("instance wrapper dropped core.CaveatedSource; bracketed keys would silently lose their caveats")
	}
	if cav := c.Caveats(); len(cav) != 1 || cav[0].Field != "mfa_enabled" {
		t.Errorf("Caveats() = %v; want the inner plugin's caveats", cav)
	}
}

// A plugin that declares no caveats must not start claiming any just because
// it was wrapped.
func TestAsInstance_NoCaveatsWhenInnerDeclaresNone(t *testing.T) {
	got := asInstance(&stubPlugin{id: testSourceAWSIAM}, testSourceAWSIAMInstance)
	if c, ok := got.(core.CaveatedSource); ok {
		t.Errorf("wrapper reports CaveatedSource for a plugin that is not one: %v", c.Caveats())
	}
}

// The collision this namespacing exists to close: two instances of one
// plugin emitting a record whose id is a per-account constant. Before,
// both arrived with the same ID, the collector unioned them into one
// slot, and the evaluator deduped violations by ID — so two failing
// accounts produced one violation and resources_failed counted 1.
func TestAsInstance_NamespacesRecordIDsSoTwoInstancesCannotCollide(t *testing.T) {
	const sentinel = "account" // aws.password_policy's real record id
	collect := func(key string) []core.EvidenceRecord {
		t.Helper()
		inner := &stubPlugin{id: testSourceAWSIAM, recs: []core.EvidenceRecord{{ID: sentinel, SourceID: testSourceAWSIAM}}}
		recs, err := asInstance(inner, key).Collect(context.Background(), core.SlotRequest{})
		if err != nil {
			t.Fatal(err)
		}
		return recs
	}

	a := collect("aws.iam[prod]")
	b := collect("aws.iam[staging]")
	if a[0].ID == b[0].ID {
		t.Fatalf("two instances share record ID %q; they would dedup into one violation", a[0].ID)
	}
	if a[0].ID != "aws.iam[prod]/"+sentinel {
		t.Errorf("ID = %q; want the instance key prefixed", a[0].ID)
	}
}

// IdentityKey is the cross-source join (an email shared by okta and
// aws.iam). Namespacing it would break exactly the dedup it exists to
// perform, so it must survive untouched.
func TestAsInstance_LeavesIdentityKeyAlone(t *testing.T) {
	inner := &stubPlugin{id: testSourceAWSIAM, recs: []core.EvidenceRecord{
		{ID: "u1", IdentityKey: "alice@acme.com", SourceID: testSourceAWSIAM},
	}}
	recs, err := asInstance(inner, testSourceAWSIAMInstance).Collect(context.Background(), core.SlotRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if recs[0].IdentityKey != "alice@acme.com" {
		t.Errorf("IdentityKey = %q; want it unprefixed so cross-source dedup still joins", recs[0].IdentityKey)
	}
}
