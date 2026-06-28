package sourcetest

import "testing"

func TestLookupEnv(t *testing.T) {
	t.Setenv("SOURCETEST_LIVE_PRESENT", "value-1")
	t.Setenv("SOURCETEST_LIVE_EMPTY", "")

	vals, missing := lookupEnv([]string{"SOURCETEST_LIVE_PRESENT", "SOURCETEST_LIVE_EMPTY", "SOURCETEST_LIVE_ABSENT"})

	if vals["SOURCETEST_LIVE_PRESENT"] != "value-1" {
		t.Errorf("present var = %q, want value-1", vals["SOURCETEST_LIVE_PRESENT"])
	}
	if _, ok := vals["SOURCETEST_LIVE_EMPTY"]; ok {
		t.Error("empty var should be treated as missing, not returned")
	}
	if len(missing) != 2 || missing[0] != "SOURCETEST_LIVE_EMPTY" || missing[1] != "SOURCETEST_LIVE_ABSENT" {
		t.Errorf("missing = %v, want [SOURCETEST_LIVE_EMPTY SOURCETEST_LIVE_ABSENT] in order", missing)
	}
}

func TestRequireEnv_Present(t *testing.T) {
	t.Setenv("SOURCETEST_LIVE_A", "a")
	t.Setenv("SOURCETEST_LIVE_B", "b")
	env := RequireEnv(t, "SOURCETEST_LIVE_A", "SOURCETEST_LIVE_B")
	if env["SOURCETEST_LIVE_A"] != "a" || env["SOURCETEST_LIVE_B"] != "b" {
		t.Errorf("RequireEnv returned %v, want a/b", env)
	}
}

func TestRequireEnv_SkipsWhenAbsent(t *testing.T) {
	// Runs RequireEnv in a subtest with a guaranteed-absent var; the subtest
	// must skip (not fail). t.Run returns true for both pass and skip, so assert
	// the subtest did not fail.
	ok := t.Run("absent", func(st *testing.T) {
		RequireEnv(st, "SOURCETEST_LIVE_DEFINITELY_ABSENT_XYZ")
		st.Fatal("RequireEnv should have skipped before reaching here")
	})
	if !ok {
		t.Error("subtest failed; RequireEnv should have skipped on the absent var")
	}
}
