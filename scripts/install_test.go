package scripts_test

import (
	"context"
	"os/exec"
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
