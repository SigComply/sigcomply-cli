package core

import (
	"context"
	"testing"
)

// Compile-time assertions that the trivial fakes below satisfy each
// interface. If anyone breaks an interface signature, these lines stop
// compiling and the test file fails to build — which is exactly the
// signal we want.
var (
	_ Framework    = (*fakeFramework)(nil)
	_ SourcePlugin = (*fakeSource)(nil)
	_ Rule         = (*fakeRule)(nil)
	_ Vault        = (*fakeVault)(nil)
	_ CloudClient  = (*fakeCloud)(nil)
)

type fakeFramework struct{}

func (*fakeFramework) ID() string            { return "fake" }
func (*fakeFramework) Version() string       { return "1" }
func (*fakeFramework) Controls() []Control   { return nil }
func (*fakeFramework) Policies() []PolicyRef { return nil }

type fakeSource struct{}

func (*fakeSource) ID() string                                 { return "fake.src" }
func (*fakeSource) Emits() []string                            { return nil }
func (*fakeSource) Init(context.Context, map[string]any) error { return nil }
func (*fakeSource) Collect(context.Context, string) ([]EvidenceRecord, error) {
	return nil, nil
}

type fakeRule struct{}

func (*fakeRule) ID() string { return "rules.fake.v1" }
func (*fakeRule) Evaluate(context.Context, RuleInput) (RuleResult, error) {
	return RuleResult{Status: StatusPass}, nil
}

type fakeVault struct{}

func (*fakeVault) Init(context.Context) error                                         { return nil }
func (*fakeVault) PutEnvelope(context.Context, string, *Envelope) error               { return nil }
func (*fakeVault) PutJSON(context.Context, string, any) error                         { return nil }
func (*fakeVault) PutBinary(context.Context, string, []byte, map[string]string) error { return nil }
func (*fakeVault) GetBinary(context.Context, string) ([]byte, error)                  { return nil, nil }
func (*fakeVault) List(context.Context, string) ([]string, error)                     { return nil, nil }

type fakeCloud struct{}

func (*fakeCloud) Submit(context.Context, SubmissionPayload) error { return nil }

// TestInterfaceContractsCompile is a no-op at runtime; its job is to
// keep the fakes above referenced so the compile-time assertions
// don't get dead-code-eliminated by accident.
func TestInterfaceContractsCompile(t *testing.T) {
	_ = (*fakeFramework)(nil)
	_ = (*fakeSource)(nil)
	_ = (*fakeRule)(nil)
	_ = (*fakeVault)(nil)
	_ = (*fakeCloud)(nil)
}
