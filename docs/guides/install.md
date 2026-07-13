# Install the SigComply CLI

How to install the `sigcomply` binary on macOS or Linux, verify it, and understand the released artifacts. This is the same install used inside CI.

> Docs hub: [../README.md](../README.md)

## Prerequisites

- macOS or Linux (x86-64 or arm64). Windows and `arm` builds are published but the install script targets macOS/Linux.
- `curl` on your PATH for the install-script method.
- For the Go method only: a Go toolchain (`go`).

## Install method 1 — install script (recommended)

Downloads the prebuilt binary for your detected OS/arch from the latest GitHub release and places it on your PATH:

```bash
curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
```

This is exactly how the CI templates install the CLI (a `curl` from GitHub Releases), so your local environment matches CI.

### Install-script knobs

These environment variables configure the **installer**, not the CLI itself:

| Variable | Default | Effect |
|---|---|---|
| `SIGCOMPLY_VERSION` | `latest` | Install a specific release tag instead of the latest (e.g. `v1.2.3`). |
| `SIGCOMPLY_INSTALL_DIR` | `/usr/local/bin` | Directory to install the binary into. |
| `SIGCOMPLY_NO_SUDO` | unset | When set, do not use `sudo` to write into the install dir. |

Example — pin a version and install without `sudo` into a user-writable directory:

```bash
curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh \
  | SIGCOMPLY_VERSION=v1.2.3 SIGCOMPLY_INSTALL_DIR="$HOME/.local/bin" SIGCOMPLY_NO_SUDO=1 sh
```

Make sure your chosen `SIGCOMPLY_INSTALL_DIR` is on your `PATH`.

## Install method 2 — Go toolchain

```bash
go install github.com/sigcomply/sigcomply-cli@latest
```

**Caveat:** `go install` names the binary after the module's last path segment, so you get `sigcomply-cli`, not `sigcomply`. Every command in these docs calls `sigcomply`. Rename or symlink it:

```bash
ln -sf "$(go env GOPATH)/bin/sigcomply-cli" "$(go env GOPATH)/bin/sigcomply"
```

Confirm `$(go env GOPATH)/bin` is on your `PATH`.

## Verify the install

```bash
sigcomply version
```

Expected output (exact values vary):

```
sigcomply v1.2.3 (commit abc1234, built 2026-01-15T10:00:00Z)
```

Exit code `0` means the CLI is installed and runnable.

## GitHub Releases artifacts

Binaries are published on the [GitHub Releases page](https://github.com/SigComply/sigcomply-cli/releases). Artifact naming:

| Item | Pattern |
|---|---|
| Archive (macOS/Linux) | `sigcomply_{version}_{os}_{arch}.tar.gz` |
| Archive (Windows) | `sigcomply_{version}_{os}_{arch}.zip` |
| Binary inside archive | `sigcomply` |
| Checksums | `checksums.txt` (SHA-256) |

Supported `os` values: `linux`, `darwin`, `windows`. Supported `arch` values: `amd64`, `arm64`, `arm`.

### Verify a downloaded archive against the checksums

```bash
# From the directory containing the downloaded .tar.gz and checksums.txt:
sha256sum -c checksums.txt --ignore-missing
```

A line ending in `OK` confirms the archive is intact. (On macOS, use `shasum -a 256 -c checksums.txt --ignore-missing`.)

To download a specific artifact by hand (Linux x86-64 shown):

```bash
tag=v1.2.3; ver=${tag#v}
curl -fsSL "https://github.com/SigComply/sigcomply-cli/releases/download/${tag}/sigcomply_${ver}_linux_amd64.tar.gz" -o sigcomply.tar.gz
tar -xzf sigcomply.tar.gz sigcomply
```

> There is **no Homebrew formula**. Use one of the two methods above.

## Next steps

- [Quickstart](../quickstart.md) — zero to a first passing local check.
- [Configure sources](configure-sources.md) — declare evidence sources and credentials.
- [Wire GitHub Actions](ci-github.md) / [Wire GitLab CI](ci-gitlab.md) — run in CI (same curl-from-Releases install).

## See also

- [Configuration reference](../configuration.md)
- [Docs hub](../README.md)
