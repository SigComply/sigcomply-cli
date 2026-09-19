package spec_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// testSourceAWSIAM is the stand-in source key used across the external
// spec_test package fixtures.
const (
	testSourceAWSIAM = "aws.iam"
	testSourceGitHub = "github"
)

func loadRoster(t *testing.T, body string) (*spec.RosterConfig, error) {
	t.Helper()
	cfg, err := spec.LoadProjectConfig([]byte(scopeBase + body))
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	return spec.LoadRosterConfig(&cfg)
}

func TestLoadRosterConfig_AbsentIsUndesignated(t *testing.T) {
	for _, body := range []string{"", "experimental:\n  scope:\n    required_sources: [github]\n", "experimental:\n  roster:\n"} {
		rc, err := loadRoster(t, body)
		if err != nil {
			t.Fatalf("LoadRosterConfig(%q): %v", body, err)
		}
		if rc != nil {
			t.Fatalf("roster = %+v; want nil for %q", rc, body)
		}
	}
	if rc, err := spec.LoadRosterConfig(nil); rc != nil || err != nil {
		t.Fatalf("nil config: got (%v, %v); want (nil, nil)", rc, err)
	}
}

func TestLoadRosterConfig_Full(t *testing.T) {
	rc, err := loadRoster(t, `experimental:
  roster:
    source: okta
    aliases:
      github:
        JDoe: jane@acme.com
        1234: numeric@acme.com
      aws.iam: { jane.doe: " jane@acme.com " }
    non_human:
      github: [Acme-CI-Bot, acme-ci-bot, deploy]
      aws.iam: [terraform-deployer]
`)
	if err != nil {
		t.Fatalf("LoadRosterConfig: %v", err)
	}
	if rc.Source != "okta" {
		t.Errorf("Source = %q; want okta", rc.Source)
	}
	wantAliases := map[string]map[string]string{
		testSourceGitHub: {"jdoe": "jane@acme.com", "1234": "numeric@acme.com"},
		testSourceAWSIAM: {"jane.doe": "jane@acme.com"},
	}
	if !reflect.DeepEqual(rc.Aliases, wantAliases) {
		t.Errorf("Aliases = %v; want %v", rc.Aliases, wantAliases)
	}
	wantNonHuman := map[string][]string{
		testSourceGitHub: {"acme-ci-bot", "deploy"},
		testSourceAWSIAM: {"terraform-deployer"},
	}
	if !reflect.DeepEqual(rc.NonHuman, wantNonHuman) {
		t.Errorf("NonHuman = %v; want %v (lowercased, de-duplicated, sorted)", rc.NonHuman, wantNonHuman)
	}
	if len(rc.UnknownKeys) != 0 {
		t.Errorf("UnknownKeys = %v; want none", rc.UnknownKeys)
	}
}

func TestLoadRosterConfig_UnknownKeysTolerated(t *testing.T) {
	rc, err := loadRoster(t, "experimental:\n  roster:\n    source: okta\n    zeta: 1\n    alias: {}\n")
	if err != nil {
		t.Fatalf("unknown subkeys must not be fatal; got %v", err)
	}
	if want := []string{"alias", "zeta"}; !reflect.DeepEqual(rc.UnknownKeys, want) {
		t.Errorf("UnknownKeys = %v; want %v", rc.UnknownKeys, want)
	}
}

func TestLoadRosterConfig_Rejects(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"not a mapping", "experimental:\n  roster: okta\n", "experimental.roster must be a mapping"},
		{"missing source", "experimental:\n  roster:\n    non_human: {github: [bot]}\n", "experimental.roster.source is required"},
		{"blank source", "experimental:\n  roster:\n    source: \"  \"\n", "experimental.roster.source is required"},
		{"source list", "experimental:\n  roster:\n    source: [okta, github]\n", "must be a single source ID"},
		{"bracketed source", "experimental:\n  roster:\n    source: okta[prod]\n", "bracketed multi-instance"},
		{"aliases not a mapping", "experimental:\n  roster:\n    source: okta\n    aliases: [github]\n", "aliases must map source IDs"},
		{"alias source not a mapping", "experimental:\n  roster:\n    source: okta\n    aliases: {github: [jdoe]}\n", `aliases["github"] must be a mapping`},
		{"empty alias value", "experimental:\n  roster:\n    source: okta\n    aliases: {github: {jdoe: \"\"}}\n", "alias must be a non-empty roster email"},
		{"null alias value", "experimental:\n  roster:\n    source: okta\n    aliases:\n      github:\n        jdoe:\n", "alias must be a non-empty roster email"},
		{"conflicting case alias", "experimental:\n  roster:\n    source: okta\n    aliases: {github: {jdoe: a@x.com, JDOE: b@x.com}}\n", "listed more than once"},
		{"non_human not a mapping", "experimental:\n  roster:\n    source: okta\n    non_human: [bot]\n", "non_human must map source IDs"},
		{"non_human source not a list", "experimental:\n  roster:\n    source: okta\n    non_human: {github: bot}\n", `non_human["github"] must be a list`},
		{"non_human empty name", "experimental:\n  roster:\n    source: okta\n    non_human: {github: [\"\"]}\n", `non_human["github"][0]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadRoster(t, c.body)
			if err == nil {
				t.Fatalf("want error containing %q; got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v; want it to contain %q", err, c.want)
			}
		})
	}
}
