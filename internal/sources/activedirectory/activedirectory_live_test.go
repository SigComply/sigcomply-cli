//go:build live

package activedirectory

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// activedirectory_live_test.go: live run of the real plugin, built through
// the registered factory, against a reachable domain controller (a real AD
// DC or a Samba AD DC container). Every record is schema-validated. Gated on
// env; skips cleanly without it.
//
//	SIGCOMPLY_AD_TEST_URL        ldaps://dc01.corp.example.com (or ldap://… + SIGCOMPLY_AD_TEST_START_TLS=1)
//	SIGCOMPLY_AD_TEST_BIND_DN    DN of a read-only bind account
//	SIGCOMPLY_AD_TEST_PASSWORD   its password
//
// Optional: SIGCOMPLY_AD_TEST_CA_CERT (PEM path), SIGCOMPLY_AD_TEST_TLS_SERVER_NAME,
// SIGCOMPLY_AD_TEST_BASE_DN, SIGCOMPLY_AD_TEST_SERVICE_OU, SIGCOMPLY_AD_TEST_START_TLS=1,
// SIGCOMPLY_AD_TEST_PAGE_SIZE (e.g. 2, to force several paged-search round trips).
//
// SIGCOMPLY_AD_TEST_SEEDED=1 additionally asserts the seeded users created
// by the Samba recipe: sc-active (active), sc-disabled (inactive/disabled),
// sc-expired (inactive/expired), sc-svc-spn (service account via SPN).
func TestActiveDirectoryLive(t *testing.T) {
	raw := liveConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, err := sources.Build(ctx, SourceID, sources.Env{Config: raw})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := p.Collect(ctx, core.SlotRequest{AcceptedTypes: p.Emits()})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	types := sourcetest.BuiltinEvidenceTypes(t)
	et, ok := types.Lookup(EvidenceTypeRosterEntry)
	if !ok {
		t.Fatal("roster_entry not registered")
	}
	byName := map[string]rosterPayload{}
	counts := map[string]int{}
	for i := range recs {
		if err := evidencetypes.Validate(et.Schema, recs[i].Payload); err != nil {
			t.Errorf("record %s: schema drift: %v", recs[i].ID, err)
		}
		var pl rosterPayload
		if err := json.Unmarshal(recs[i].Payload, &pl); err != nil {
			t.Fatal(err)
		}
		counts[pl.SourceStatus]++
		if pl.IsServiceAccount {
			counts["service_account"]++
		}
		byName[pl.DisplayName] = pl
	}
	t.Logf("roster_entry records=%d by source_status/service=%v", len(recs), counts)
	if len(recs) < 1 {
		t.Fatalf("roster_entry = 0, want >= 1")
	}
	if os.Getenv("SIGCOMPLY_AD_TEST_SEEDED") == "1" {
		assertSeeded(t, byName)
	}
}

func assertSeeded(t *testing.T, byName map[string]rosterPayload) {
	t.Helper()
	want := map[string]struct {
		status, sourceStatus string
		service              bool
	}{
		"sc-active":   {"active", "enabled", false},
		"sc-disabled": {"inactive", "disabled", false},
		"sc-expired":  {"inactive", "expired", false},
		"sc-svc-spn":  {"active", "enabled", true},
	}
	for name, w := range want {
		got, ok := byName[name]
		if !ok {
			t.Errorf("seeded user %q not found (display_name falls back to sAMAccountName)", name)
			continue
		}
		t.Logf("%s → %+v", name, got)
		if got.Status != w.status || got.SourceStatus != w.sourceStatus || got.IsServiceAccount != w.service {
			t.Errorf("%s: got status=%s source_status=%s service=%v, want %s/%s/%v",
				name, got.Status, got.SourceStatus, got.IsServiceAccount, w.status, w.sourceStatus, w.service)
		}
	}
}

// liveConfig maps the SIGCOMPLY_AD_TEST_* environment onto a raw
// sources.active_directory config map (skipping when the required env is absent).
func liveConfig(t *testing.T) map[string]any {
	t.Helper()
	env := sourcetest.RequireEnv(t, "SIGCOMPLY_AD_TEST_URL", "SIGCOMPLY_AD_TEST_BIND_DN", "SIGCOMPLY_AD_TEST_PASSWORD")
	raw := map[string]any{
		"url":           env["SIGCOMPLY_AD_TEST_URL"],
		"bind_dn":       env["SIGCOMPLY_AD_TEST_BIND_DN"],
		"bind_password": env["SIGCOMPLY_AD_TEST_PASSWORD"],
	}
	optional := map[string]string{
		"SIGCOMPLY_AD_TEST_CA_CERT":         "ca_cert",
		"SIGCOMPLY_AD_TEST_TLS_SERVER_NAME": "tls_server_name",
		"SIGCOMPLY_AD_TEST_BASE_DN":         "base_dn",
	}
	for envKey, cfgKey := range optional {
		if v := os.Getenv(envKey); v != "" {
			raw[cfgKey] = v
		}
	}
	if os.Getenv("SIGCOMPLY_AD_TEST_START_TLS") == "1" {
		raw["start_tls"] = true
	}
	if ps := os.Getenv("SIGCOMPLY_AD_TEST_PAGE_SIZE"); ps != "" {
		n, err := strconv.Atoi(ps)
		if err != nil {
			t.Fatalf("SIGCOMPLY_AD_TEST_PAGE_SIZE: %v", err)
		}
		raw["page_size"] = n
	}
	if ou := os.Getenv("SIGCOMPLY_AD_TEST_SERVICE_OU"); ou != "" {
		raw["service_account_ous"] = []any{ou}
	}
	return raw
}
