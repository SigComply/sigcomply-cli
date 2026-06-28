package gcptest

import "testing"

func TestOptionsConstruct(t *testing.T) {
	// Construction only — these wire a cassette transport + endpoint + no-auth
	// into the GCP SDK option set; the replay/record behavior is covered by the
	// plugin conformance tests and sourcetest's own tests.
	if got := len(RecordOptions(t, t.TempDir()+"/c", "https://example.googleapis.com")); got != 3 {
		t.Errorf("RecordOptions len = %d, want 3", got)
	}
}
