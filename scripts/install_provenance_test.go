package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The commits a fake `git ls-remote` reports for v1.2.3: the annotated tag
// object and the commit it peels to. Only the peeled one is the source.
const (
	tagObject    = "1111111111111111111111111111111111111111"
	peeledCommit = "2222222222222222222222222222222222222222"
	bundleName   = "sigcomply_1.2.3_provenance.sigstore.json"
	present      = "present"
)

// Fakes for the tools verify_provenance calls. Each logs its arguments
// and answers from FAKE_* variables, so a test controls every outcome
// without the network.
const (
	fakeGHVerifier = `#!/bin/sh
if [ "$1 $2 $3" = "attestation verify --help" ]; then
  printf '%s\n' "$FAKE_GH_HELP"
  exit 0
fi
echo "gh $* token=${GH_TOKEN:-}${GITHUB_TOKEN:-} config=${GH_CONFIG_DIR:-}" >> "$FAKE_LOG"
exit "${FAKE_GH_EXIT:-0}"
`
	fakeCurl = `#!/bin/sh
echo "curl $*" >> "$FAKE_LOG"
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -H) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  *.sigstore.json)
    [ "${FAKE_BUNDLE:-present}" = "present" ] || exit 22
    printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n' > "$out" ;;
  */commits/*)
    [ -n "${FAKE_API_SHA:-}" ] || exit 22
    printf '%s' "$FAKE_API_SHA" ;;
  *) exit 22 ;;
esac
`
	fakeGit = `#!/bin/sh
echo "git $*" >> "$FAKE_LOG"
printf '%b' "${FAKE_LS_REMOTE:-}"
`
)

// fullHelp lists every flag the installer needs; oldHelp lacks
// --source-digest and --deny-self-hosted-runners, as gh did before it
// supported them.
const (
	fullHelp = "  -b, --bundle string\n      --bundle-from-oci\n      --deny-self-hosted-runners\n      --source-digest string\n"
	oldHelp  = "  -b, --bundle string\n      --bundle-from-oci\n"
)

type provenanceRun struct {
	out, log string
	err      error
}

// provenanceCase sets up which fakes exist and how they answer.
type provenanceCase struct {
	gh, git   bool   // whether gh and git are on PATH
	help      string // gh attestation verify --help output
	ghExit    string // gh attestation verify exit code
	bundle    string // "present" or "missing"
	lsRemote  string // git ls-remote output (printf %b)
	apiSHA    string // commit SHA the API returns when git is absent
	require   bool   // SIGCOMPLY_REQUIRE_PROVENANCE=1
	inheritGH bool   // set GH_TOKEN in the environment
	tag       string // release tag; v1.2.3 when empty
}

func (c *provenanceCase) releaseTag() string {
	if c.tag == "" {
		return "v1.2.3"
	}
	return c.tag
}

func annotatedLsRemote() string {
	return tagObject + `\trefs/tags/v1.2.3\n` + peeledCommit + `\trefs/tags/v1.2.3^{}\n`
}

// runVerifyProvenance runs install.sh's verify_provenance for v1.2.3 with
// a PATH holding only the fakes the case asks for and the real tools the
// script needs.
func runVerifyProvenance(t *testing.T, c *provenanceCase) provenanceRun {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil { //nolint:gosec // test stub must be executable
			t.Fatal(err)
		}
	}
	write("curl", fakeCurl)
	if c.gh {
		write("gh", fakeGHVerifier)
	}
	if c.git {
		write("git", fakeGit)
	}
	for _, name := range []string{"awk", "env", "grep", "cat", "mkdir", "head"} {
		target, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("%s not installed", name)
		}
		if err := os.Symlink(target, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(work, 0o750); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(work, "sigcomply_1.2.3_linux_amd64.tar.gz")
	if err := os.WriteFile(archive, []byte("release bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "calls.log")
	tag := c.releaseTag()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), shell, "-c", //nolint:gosec // fixed script; the arguments are positional parameters
		`. ./install.sh && verify_provenance "$1" "$2" "$3" "$4"`, "sh",
		archive, "https://github.com/SigComply/sigcomply-cli/releases/download/"+tag, tag, work)
	env := []string{
		"PATH=" + bin, "SIGCOMPLY_INSTALL_LIB=1", "HOME=" + dir,
		"FAKE_LOG=" + logPath, "FAKE_GH_HELP=" + c.help, "FAKE_GH_EXIT=" + c.ghExit,
		"FAKE_BUNDLE=" + c.bundle, "FAKE_LS_REMOTE=" + c.lsRemote, "FAKE_API_SHA=" + c.apiSHA,
	}
	if c.require {
		env = append(env, "SIGCOMPLY_REQUIRE_PROVENANCE=1")
	}
	if c.inheritGH {
		env = append(env, "GH_TOKEN=caller-token", "GITHUB_TOKEN=caller-token")
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	logBytes, rerr := os.ReadFile(logPath) //nolint:gosec // #nosec G304 -- the test's own temp file
	if rerr != nil && !os.IsNotExist(rerr) {
		t.Fatal(rerr)
	}
	return provenanceRun{out: string(out), log: string(logBytes), err: err}
}

func verifiableCase() provenanceCase {
	return provenanceCase{gh: true, git: true, help: fullHelp, ghExit: "0", bundle: present, lsRemote: annotatedLsRemote()}
}

// With a capable gh, the installer downloads the release's bundle and
// runs gh attestation verify with the pinned identity, the commit the tag
// peels to, and no token from the caller's environment.
func TestInstallScript_VerifyProvenance_Verified(t *testing.T) {
	c := verifiableCase()
	c.inheritGH = true
	r := runVerifyProvenance(t, &c)
	if r.err != nil {
		t.Fatalf("verification failed: %v\n%s", r.err, r.out)
	}
	if !strings.Contains(r.out, "Build provenance verified") {
		t.Errorf("no success message:\n%s", r.out)
	}
	if !strings.Contains(r.log, "curl -fsSL https://github.com/SigComply/sigcomply-cli/releases/download/v1.2.3/"+bundleName) {
		t.Errorf("bundle not downloaded from the release:\n%s", r.log)
	}
	var verify string
	for _, l := range strings.Split(r.log, "\n") {
		if strings.HasPrefix(l, "gh attestation verify ") {
			verify = l
		}
	}
	if verify == "" {
		t.Fatalf("gh attestation verify not called:\n%s", r.log)
	}
	for _, want := range []string{
		"sigcomply_1.2.3_linux_amd64.tar.gz --bundle ",
		"/" + bundleName + " ",
		"--repo SigComply/sigcomply-cli ",
		"--cert-identity-regex " + identityRegex(t) + " ",
		"--source-digest " + peeledCommit + " ",
		"--deny-self-hosted-runners ",
		"token= ",
	} {
		if !strings.Contains(verify, want) {
			t.Errorf("gh call lacks %q:\n%s", want, verify)
		}
	}
	if strings.Contains(verify, "config= ") {
		t.Errorf("gh ran with the caller's config; want a throwaway GH_CONFIG_DIR:\n%s", verify)
	}
}

// A bundle that does not verify (wrong workflow, commit or archive)
// stops the install, whatever SIGCOMPLY_REQUIRE_PROVENANCE says.
func TestInstallScript_VerifyProvenance_MismatchFails(t *testing.T) {
	c := verifiableCase()
	c.ghExit = "1"
	r := runVerifyProvenance(t, &c)
	if r.err == nil {
		t.Fatalf("a failed verification was accepted:\n%s", r.out)
	}
	if !strings.Contains(r.out, "Build provenance verification failed") {
		t.Errorf("error does not explain itself:\n%s", r.out)
	}
}

// Without gh, with a gh too old for the flags, or for a release without a
// bundle, the checksum is all there is: a warning by default, an error
// with SIGCOMPLY_REQUIRE_PROVENANCE=1.
func TestInstallScript_VerifyProvenance_Unavailable(t *testing.T) {
	cases := map[string]func(*provenanceCase){
		"no gh":  func(c *provenanceCase) { c.gh = false },
		"old gh": func(c *provenanceCase) { c.help = oldHelp },
		"release before bundles": func(c *provenanceCase) {
			c.bundle, c.tag, c.lsRemote = "missing", "v0.90.5", peeledCommit+`\trefs/tags/v0.90.5\n`
		},
		"empty gh help": func(c *provenanceCase) { c.help = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := verifiableCase()
			mutate(&c)
			r := runVerifyProvenance(t, &c)
			if r.err != nil {
				t.Fatalf("install stopped without SIGCOMPLY_REQUIRE_PROVENANCE: %v\n%s", r.err, r.out)
			}
			if !strings.Contains(r.out, "Build provenance not verified") {
				t.Errorf("no warning:\n%s", r.out)
			}
			if strings.Contains(r.log, "gh attestation verify ") {
				t.Errorf("gh verify ran although it cannot:\n%s", r.log)
			}

			c.require = true
			r = runVerifyProvenance(t, &c)
			if r.err == nil {
				t.Fatalf("SIGCOMPLY_REQUIRE_PROVENANCE=1 accepted an unverified download:\n%s", r.out)
			}
			if !strings.Contains(r.out, "SIGCOMPLY_REQUIRE_PROVENANCE=1") {
				t.Errorf("error does not name the setting:\n%s", r.out)
			}
		})
	}
}

// A tag whose commit cannot be resolved cannot be verified, and gh is
// never asked to verify against an empty digest.
func TestInstallScript_VerifyProvenance_UnresolvedTagFails(t *testing.T) {
	c := verifiableCase()
	c.lsRemote = ""
	r := runVerifyProvenance(t, &c)
	if r.err == nil {
		t.Fatalf("verification proceeded without a source commit:\n%s", r.out)
	}
	if strings.Contains(r.log, "gh attestation verify ") {
		t.Errorf("gh verify ran without a source commit:\n%s", r.log)
	}
}

// tag_commit peels an annotated tag, takes a lightweight tag as is, and
// asks the GitHub API when git is not installed.
func TestInstallScript_TagCommit(t *testing.T) {
	lightweight := provenanceCase{gh: true, git: true, help: fullHelp, ghExit: "0", bundle: present,
		lsRemote: peeledCommit + `\trefs/tags/v1.2.3\n`}
	noGit := provenanceCase{gh: true, help: fullHelp, ghExit: "0", bundle: present, apiSHA: peeledCommit}
	for name, c := range map[string]provenanceCase{
		"annotated": verifiableCase(), "lightweight": lightweight, "no git": noGit,
	} {
		t.Run(name, func(t *testing.T) {
			r := runVerifyProvenance(t, &c)
			if r.err != nil {
				t.Fatalf("%v\n%s", r.err, r.out)
			}
			if !strings.Contains(r.log, "--source-digest "+peeledCommit+" ") {
				t.Errorf("source digest is not %s:\n%s", peeledCommit, r.log)
			}
		})
	}
}

// identityRegex returns install.sh's PROVENANCE_IDENTITY.
func identityRegex(t *testing.T) string {
	t.Helper()
	got, err := runLib(t, "", `printf '%s' "$PROVENANCE_IDENTITY"`)
	if err != nil || got == "" {
		t.Fatalf("PROVENANCE_IDENTITY: %q, %v", got, err)
	}
	return got
}

// The identity accepts the certificates the two release workflows get
// (auto releases run from main, manual ones from main or a tag) and
// nothing else: another workflow, branch or repository fails.
func TestInstallScript_ProvenanceIdentity(t *testing.T) {
	re := regexp.MustCompile(identityRegex(t))
	const base = "https://github.com/SigComply/sigcomply-cli/.github/workflows/"
	for _, ok := range []string{
		base + "auto-release-pipeline.yml@refs/heads/main",
		base + "release.yml@refs/heads/main",
		base + "release.yml@refs/tags/v1.2.3",
		base + "release.yml@refs/tags/v1.2.3-rc.1",
	} {
		if !re.MatchString(ok) {
			t.Errorf("rejects %s", ok)
		}
	}
	for _, bad := range []string{
		base + "test.yml@refs/heads/main",
		base + "auto-release-pipeline.yml@refs/heads/feature",
		base + "release.yml@refs/tags/latest",
		"https://github.com/attacker/sigcomply-cli/.github/workflows/release.yml@refs/heads/main",
		base + "auto-release-pipeline.yml@refs/heads/main.evil",
	} {
		if re.MatchString(bad) {
			t.Errorf("accepts %s", bad)
		}
	}
}

// From v0.91.0 every release publishes its bundle, so a missing one (or a
// download that fails for any reason) stops the install: a release made
// outside the release workflow cannot skip the check by leaving it out.
func TestInstallScript_VerifyProvenance_MissingBundleFailsFromV0910(t *testing.T) {
	for _, tag := range []string{"v0.91.0", "v0.91.0-rc.1", "v1.2.3", "v0.100.0"} {
		t.Run(tag, func(t *testing.T) {
			c := verifiableCase()
			c.bundle, c.tag = "missing", tag
			r := runVerifyProvenance(t, &c)
			if r.err == nil {
				t.Fatalf("a %s release without its bundle was installed:\n%s", tag, r.out)
			}
			if !strings.Contains(r.out, "provenance.sigstore.json") {
				t.Errorf("error does not name the bundle:\n%s", r.out)
			}
		})
	}
}
