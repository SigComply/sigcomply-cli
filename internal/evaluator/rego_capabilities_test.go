package evaluator

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

var updateRegoBuiltins = flag.Bool("update", false, "regenerate testdata/rego_builtins.golden")

// TestRegoRule_DeniesNetworkAndNondeterministicBuiltins: a project-local
// rule.rego is code from the repository, evaluated over evidence that
// may be sensitive. Before the capability restriction, a module could
// POST the whole input to any URL with http.send and read the CLI's
// environment with opa.runtime. Each module below must fail to compile.
func TestRegoRule_DeniesNetworkAndNondeterministicBuiltins(t *testing.T) {
	hit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case hit <- struct{}{}:
		default:
		}
		if _, err := w.Write([]byte(`{}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	exprs := map[string]string{
		"http.send":          `http.send({"method": "POST", "url": "` + srv.URL + `", "body": input})`,
		"net.lookup_ip_addr": `net.lookup_ip_addr("example.com")`,
		"opa.runtime":        `opa.runtime()`,
		"time.now_ns":        `time.now_ns()`,
		"rand.intn":          `rand.intn("x", 10)`,
		"uuid.rfc4122":       `uuid.rfc4122("x")`,
		"json.match_schema":  `json.match_schema({}, {"$ref": "` + srv.URL + `"})`,
	}
	for name, expr := range exprs {
		t.Run(name, func(t *testing.T) {
			module := "package acme.exfil\nimport rego.v1\nx := " + expr + "\nresult := {\"status\": \"pass\", \"x\": x}\n"
			r, err := NewRegoRule("acme.exfil", module, "data.acme.exfil.result")
			if err == nil {
				res, evalErr := r.Evaluate(context.Background(), core.RuleInput{Now: time.Now()})
				t.Fatalf("(evaluated: %v, %v) "+"NewRegoRule accepted a module calling %s; want a compile error", res.Status, evalErr, name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error %q does not name %s", err, name)
			}
		})
	}
	select {
	case <-hit:
		t.Error("a rule reached the test server")
	default:
	}
}

// TestRegoRule_PureBuiltinsStillWork: the restriction keeps the
// deterministic builtins rules rely on, including the CIDR helpers
// (pure functions, no network) and time parsing against input.now.
func TestRegoRule_PureBuiltinsStillWork(t *testing.T) {
	module := `package acme.ok
import rego.v1
open := net.cidr_contains("0.0.0.0/0", "10.0.0.1")
age := time.parse_rfc3339_ns(input.now) - time.parse_rfc3339_ns("2026-01-01T00:00:00Z")
result := {"status": "pass", "violations": []} if { open; age > 0 }
`
	r, err := NewRegoRule("acme.ok", module, "data.acme.ok.result")
	if err != nil {
		t.Fatalf("NewRegoRule: %v", err)
	}
	res, err := r.Evaluate(context.Background(), core.RuleInput{Now: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil || res.Status != core.StatusPass {
		t.Fatalf("Evaluate = %v, %v; want pass", res.Status, err)
	}
}

// TestRegoRule_StrictBuiltinErrors: a builtin error (here, a malformed
// timestamp) is an evaluation error, not a silently undefined value
// that could let a rule fall through to a pass.
func TestRegoRule_StrictBuiltinErrors(t *testing.T) {
	module := `package acme.strict
import rego.v1
default result := {"status": "pass", "violations": []}
result := {"status": "fail", "violations": []} if { time.parse_rfc3339_ns("not a time") > 0 }
`
	r, err := NewRegoRule("acme.strict", module, "data.acme.strict.result")
	if err != nil {
		t.Fatalf("NewRegoRule: %v", err)
	}
	if res, err := r.Evaluate(context.Background(), core.RuleInput{Now: time.Now()}); err == nil {
		t.Fatalf("Evaluate = %v, nil error; want the builtin error", res.Status)
	}
}

// TestRegoBuiltinsGolden pins the builtins a rule.rego may call. An OPA
// upgrade that adds a builtin changes this list; review whether the new
// builtin can reach the network, the environment or the clock before
// regenerating with `go test ./internal/evaluator -run RegoBuiltinsGolden -update`.
func TestRegoBuiltinsGolden(t *testing.T) {
	builtins := regoCapabilities().Builtins
	names := make([]string, 0, len(builtins))
	for _, b := range builtins {
		names = append(names, b.Name)
	}
	sort.Strings(names)
	got := strings.Join(names, "\n") + "\n"
	path := filepath.Join("testdata", "rego_builtins.golden")
	if *updateRegoBuiltins {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // fixed testdata path
	if err != nil {
		t.Fatalf("read golden (regenerate with -update): %v", err)
	}
	if got != string(want) {
		t.Errorf("allowed Rego builtins changed; review the difference, then regenerate with -update.\ngot:\n%s", got)
	}
	for _, banned := range []string{"http.send", "net.lookup_ip_addr", "opa.runtime", "time.now_ns", "rand.intn", "uuid.rfc4122"} {
		if strings.Contains("\n"+got, "\n"+banned+"\n") {
			t.Errorf("%s is allowed; it must not be", banned)
		}
	}
}
