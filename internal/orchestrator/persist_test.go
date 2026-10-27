package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/submitter"
)

// failingJSONVault fails PutJSON for any path ending in failSuffix.
type failingJSONVault struct {
	*inMemVault
	failSuffix string
}

func (v *failingJSONVault) PutJSON(ctx context.Context, k string, body any) error {
	if strings.HasSuffix(k, v.failSuffix) {
		return errors.New("disk full")
	}
	return v.inMemVault.PutJSON(ctx, k, body)
}

// A run whose summary or manifest never reached the vault has no
// verifiable record, so it must not exit 0 as if it did.
func TestRun_VaultWriteFailureIsExecutionError(t *testing.T) {
	for _, file := range []string{"summary.json", "manifest.json"} {
		t.Run(file, func(t *testing.T) {
			regs := registry.NewSet()
			if err := regs.Frameworks.Register(&emptyFramework{}); err != nil {
				t.Fatal(err)
			}
			res, err := Run(context.Background(), &Options{
				Config:        minimalConfig(),
				Registries:    regs,
				Vault:         &failingJSONVault{inMemVault: newInMem(), failSuffix: "/" + file},
				Stdout:        &bytes.Buffer{},
				Logger:        log.New(&bytes.Buffer{}, false),
				DisableCloud:  true,
				SubmitterOpts: submitter.Options{Disable: true},
			})
			if err == nil {
				t.Fatalf("Run: want an error when %s cannot be written", file)
			}
			if !strings.Contains(err.Error(), file) {
				t.Errorf("error %q does not name %s", err, file)
			}
			if res.ExitCode != ExitExecution {
				t.Errorf("ExitCode = %d; want %d", res.ExitCode, ExitExecution)
			}
		})
	}
}

func TestPersistResults_ResultWriteFailureIsAnError(t *testing.T) {
	rec := newRecordingVault(&failingJSONVault{inMemVault: newInMem(), failSuffix: "/result.json"})
	err := persistResults(context.Background(), rec, "r", []core.PolicyResult{{PolicyID: "p1"}}, "run", &planner.RunPlan{}, time.Now(), nil)
	if err == nil || !strings.Contains(err.Error(), "p1") {
		t.Fatalf("persistResults err = %v; want an error naming p1", err)
	}
	// A file that never landed must not be vouched for by the manifest.
	if _, ok := rec.FileHashes("r")["policies/p1/result.json"]; ok {
		t.Error("manifest would list a result.json that was never written")
	}
}
