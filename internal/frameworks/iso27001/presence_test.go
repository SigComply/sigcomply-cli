package iso27001

import (
	"slices"
	"testing"
)

// TestPresencePolicies pins which policies fail, rather than skip, when
// their bound source returns no records. See the SOC 2 twin.
func TestPresencePolicies(t *testing.T) {
	want := []string{
		"iso27001.8.15.audit_logging_enabled",
		"iso27001.8.16.security_aggregation_enabled",
		"iso27001.8.16.threat_detection_active",
		"iso27001.8.5.password_minimum_length",
		"iso27001.8.7.threat_detection_enabled",
		"iso27001.8.9.config_recording_enabled",
	}
	var got []string
	for _, p := range Policies() {
		for _, s := range p.Slots {
			if s.FailWhenEmpty {
				got = append(got, p.ID)
				break
			}
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("presence policies = %v\nwant %v", got, want)
	}
}
