package scripts_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// uname -s values the cases use more than once.
const (
	osLinux  = "Linux"
	osDarwin = "Darwin"
	x86      = "x86_64"
)

// resolveAsset runs install.sh's asset_name function without running
// the installer: SIGCOMPLY_INSTALL_LIB=1 makes the script define its
// functions and return, so nothing is downloaded.
func resolveAsset(t *testing.T, osName, machine, version string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "sh", //nolint:gosec // fixed script; the arguments are test-table values passed as positional parameters, never parsed as shell
		"-c", `. ./install.sh && asset_name "$1" "$2" "$3"`, "sh", osName, machine, version)
	cmd.Env = append(cmd.Environ(), "SIGCOMPLY_INSTALL_LIB=1")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// TestInstallScript_AssetNames pins the archive name the installer asks
// for on every platform to the names .goreleaser.yml publishes:
// `{os}_{arch}` plus `v6`/`v7` for 32-bit ARM, `.zip` on Windows. The
// script used to request `linux_arm.tar.gz` and `windows_amd64.tar.gz`,
// neither of which any release has, so the download failed.
func TestInstallScript_AssetNames(t *testing.T) {
	cases := []struct{ os, machine, want string }{
		{osLinux, x86, "sigcomply_1.2.3_linux_amd64.tar.gz"},
		{osLinux, "aarch64", "sigcomply_1.2.3_linux_arm64.tar.gz"},
		{osLinux, "armv7l", "sigcomply_1.2.3_linux_armv7.tar.gz"},
		{osLinux, "armv8l", "sigcomply_1.2.3_linux_armv7.tar.gz"},
		{osLinux, "armv6l", "sigcomply_1.2.3_linux_armv6.tar.gz"},
		{osDarwin, x86, "sigcomply_1.2.3_darwin_amd64.tar.gz"},
		{osDarwin, "arm64", "sigcomply_1.2.3_darwin_arm64.tar.gz"},
		{"MINGW64_NT-10.0-19045", x86, "sigcomply_1.2.3_windows_amd64.zip"},
		{"MSYS_NT-10.0", x86, "sigcomply_1.2.3_windows_amd64.zip"},
	}
	for _, c := range cases {
		got, err := resolveAsset(t, c.os, c.machine, "1.2.3")
		if err != nil {
			t.Errorf("%s/%s: %v (%s)", c.os, c.machine, err, got)
			continue
		}
		if got != c.want {
			t.Errorf("%s/%s: asset = %q; want %q", c.os, c.machine, got, c.want)
		}
	}
}

// TestInstallScript_UnpublishedPlatformsFail: a platform no release
// builds for must stop with a message, not request an archive that
// 404s.
func TestInstallScript_UnpublishedPlatformsFail(t *testing.T) {
	for _, c := range []struct{ os, machine string }{
		{osLinux, "i686"},
		{osDarwin, "armv7l"},
		{"MINGW64_NT-10.0", "aarch64"},
		{"FreeBSD", "amd64"},
	} {
		got, err := resolveAsset(t, c.os, c.machine, "1.2.3")
		if err == nil {
			t.Errorf("%s/%s: want an error, got asset %q", c.os, c.machine, got)
			continue
		}
		if !strings.Contains(got, "no release") && !strings.Contains(got, "Unsupported") {
			t.Errorf("%s/%s: error does not explain itself: %q", c.os, c.machine, got)
		}
	}
}

// runLib runs snippet with install.sh's functions loaded and nothing
// installed. args become $1.. inside the snippet; path, when set,
// replaces PATH so a test can control which hash tool exists.
func runLib(t *testing.T, path, snippet string, args ...string) (string, error) {
	t.Helper()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), shell, //nolint:gosec // fixed script; test-table arguments are positional parameters
		append([]string{"-c", ". ./install.sh && " + snippet, "sh"}, args...)...)
	env := append(cmd.Environ(), "SIGCOMPLY_INSTALL_LIB=1")
	if path != "" {
		env = append(env, "PATH="+path)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// writeRelease writes an archive and a checksums.txt in GoReleaser's
// format ("<sha256>  <file>") whose entry for the archive is sum.
func writeRelease(t *testing.T, sum string) (archive, checksums string) {
	t.Helper()
	dir := t.TempDir()
	archive = filepath.Join(dir, "sigcomply_1.2.3_linux_amd64.tar.gz")
	if err := os.WriteFile(archive, []byte("release bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sum == "" {
		h := sha256.Sum256([]byte("release bytes"))
		sum = hex.EncodeToString(h[:])
	}
	checksums = filepath.Join(dir, "checksums.txt")
	body := strings.Repeat("0", 64) + "  sigcomply_1.2.3_darwin_arm64.tar.gz\n" +
		sum + "  sigcomply_1.2.3_linux_amd64.tar.gz\n"
	if err := os.WriteFile(checksums, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return archive, checksums
}

// toolPath builds a PATH holding only awk and the named hash tool, or
// skips when the machine lacks it. shasum is a Perl script, so perl
// comes along when present.
func toolPath(t *testing.T, tool string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"awk", tool, "perl"} {
		target, err := exec.LookPath(name)
		if err != nil {
			if name == "perl" {
				continue
			}
			t.Skipf("%s not installed", name)
		}
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The installer verifies the archive against the release's
// checksums.txt with sha256sum (Linux) or shasum (macOS).
func TestInstallScript_VerifyChecksum(t *testing.T) {
	for _, tool := range []string{"sha256sum", "shasum"} {
		t.Run(tool, func(t *testing.T) {
			path := toolPath(t, tool)

			archive, checksums := writeRelease(t, "")
			if out, err := runLib(t, path, `verify_checksum "$1" "$2"`, archive, checksums); err != nil {
				t.Errorf("matching checksum rejected: %v (%s)", err, out)
			}

			archive, checksums = writeRelease(t, strings.Repeat("a", 64))
			out, err := runLib(t, path, `verify_checksum "$1" "$2"`, archive, checksums)
			if err == nil || !strings.Contains(out, "Checksum mismatch") {
				t.Errorf("tampered archive accepted: err=%v out=%q", err, out)
			}
		})
	}
}

func TestInstallScript_VerifyChecksumMissingEntry(t *testing.T) {
	archive, checksums := writeRelease(t, "")
	other := filepath.Join(filepath.Dir(archive), "sigcomply_1.2.3_linux_arm64.tar.gz")
	if err := os.Rename(archive, other); err != nil {
		t.Fatal(err)
	}
	out, err := runLib(t, "", `verify_checksum "$1" "$2"`, other, checksums)
	if err == nil || !strings.Contains(out, "No checksum for sigcomply_1.2.3_linux_arm64.tar.gz") {
		t.Errorf("archive without an entry accepted: err=%v out=%q", err, out)
	}
}

// An explicit version, including a prerelease, names its tag with or
// without the leading v; latest stays latest.
func TestInstallScript_NormalizeVersion(t *testing.T) {
	const final, rc = "v1.2.3", "v1.2.3-rc.1"
	for in, want := range map[string]string{
		"latest":     "latest",
		final:        final,
		"1.2.3":      final,
		rc:           rc,
		"1.2.3-rc.1": rc,
	} {
		got, err := runLib(t, "", `normalize_version "$1"`, in)
		if err != nil || got != want {
			t.Errorf("normalize_version(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// A prerelease's archive carries its full version.
	got, err := resolveAsset(t, osLinux, x86, "1.2.3-rc.1")
	if err != nil || got != "sigcomply_1.2.3-rc.1_linux_amd64.tar.gz" {
		t.Errorf("prerelease asset = %q, %v", got, err)
	}
}
