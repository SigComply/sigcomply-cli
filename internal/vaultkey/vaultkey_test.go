package vaultkey_test

import (
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/vaultkey"
)

func TestValidID(t *testing.T) {
	good := []string{"aws.iam", "aws.iam[backup]", "soc2.cc6.1.mfa", "Acme_Custom-1", "x"}
	bad := []string{"", ".", "..", "../x", "a/b", `a\b`, ".hidden", "-x", "a b", "a:b", "a[]", "a[b/c]", "a\n", "a[" + strings.Repeat("x", 65) + "]"}
	for _, id := range good {
		if !vaultkey.ValidID(id) {
			t.Errorf("ValidID(%q) = false; want true", id)
		}
	}
	for _, id := range bad {
		if vaultkey.ValidID(id) {
			t.Errorf("ValidID(%q) = true; want false", id)
		}
	}
}

func TestJoin(t *testing.T) {
	got, err := vaultkey.Join("soc2", "2026-Q1", "run_20260101T000000Z_abcd1234", "policies", "soc2.cc6.1.mfa", "envelopes", "directory_user.v2__aws.iam[backup].json")
	if err != nil || got != "soc2/2026-Q1/run_20260101T000000Z_abcd1234/policies/soc2.cc6.1.mfa/envelopes/directory_user.v2__aws.iam[backup].json" {
		t.Fatalf("Join = %q, %v", got, err)
	}
	for _, seg := range []string{"", ".", "..", "a/b", `a\b`, "a\x00b", "a\nb", "a b", "a%2fb", strings.Repeat("x", 256)} {
		if _, err := vaultkey.Join("soc2", seg, "x.json"); err == nil {
			t.Errorf("Join accepted segment %q", seg)
		}
	}
	if _, err := vaultkey.Join(); err == nil {
		t.Error("Join() with no segments succeeded")
	}
}

func TestJoinUnder(t *testing.T) {
	got, err := vaultkey.JoinUnder("soc2/2026-Q1/run_x", "policies", "p1", "result.json")
	if err != nil || got != "soc2/2026-Q1/run_x/policies/p1/result.json" {
		t.Fatalf("JoinUnder = %q, %v", got, err)
	}
	for _, root := range []string{"", "/abs", "a//b", "a/../b", "a/"} {
		if _, err := vaultkey.JoinUnder(root, "x.json"); err == nil {
			t.Errorf("JoinUnder accepted root %q", root)
		}
	}
}
