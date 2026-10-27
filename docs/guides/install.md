# Install the SigComply CLI

Install the `sigcomply` binary on your machine and confirm it runs.

## Prerequisites

- A platform with a release archive: Linux on `amd64`, `arm64`, `armv6` or `armv7`, macOS on
  `amd64` or `arm64`, or Windows on `amd64` in Git Bash, MSYS2 or Cygwin. On any other platform
  the script stops with an error.
- `curl` on your `PATH`, plus `tar`, or `unzip` on Windows.
- `sha256sum` or `shasum` (the install script checks the download with one of them).

## Install with the script

1. Run the install script. It downloads the release archive for your OS and architecture from
   GitHub Releases, checks it against the release's `checksums.txt`, and puts `sigcomply` in
   `/usr/local/bin`:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
   ```

   To pin a version, or to install without `sudo` into a directory you own, set the installer's
   variables:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh \
     | SIGCOMPLY_VERSION=v0.88.4 SIGCOMPLY_INSTALL_DIR="$HOME/.local/bin" SIGCOMPLY_NO_SUDO=1 sh
   ```

   | Variable | Default | Effect |
   |---|---|---|
   | `SIGCOMPLY_VERSION` | `latest` | Release tag to install, for example `v0.88.4`. The leading `v` is optional. A prerelease tag such as `v0.89.0-rc.1` works too; `latest` never picks a prerelease. |
   | `SIGCOMPLY_INSTALL_DIR` | `/usr/local/bin` | Directory the binary goes into. Must be on your `PATH`. |
   | `SIGCOMPLY_NO_SUDO` | `0` | Set to `1` to never call `sudo`. |

2. Check the install:

   ```bash
   sigcomply version
   ```

   A release build prints its version without a leading `v`:

   ```text
   sigcomply 0.88.4 (commit 45c25e38278c8c155b2e875cf4750a42aabecefc, built 2026-10-26T19:12:08Z)
   ```

The script picks the archive from `uname -s` and `uname -m`. On 32-bit ARM, `armv6*` gets the
`armv6` archive and `armv7*` or `armv8l` gets `armv7`. On Windows it downloads the `.zip` and
installs `sigcomply.exe`. It stops with `Checksum mismatch` when the archive's SHA-256 differs
from its entry in `checksums.txt`. It does not check the build attestation; for that, use step 3
of the manual steps below.

## Install a release archive by hand

Each [GitHub release](https://github.com/SigComply/sigcomply-cli/releases) publishes these
archives, plus `checksums.txt` (SHA-256):

| OS | Architectures | Archive |
|---|---|---|
| Linux | `amd64`, `arm64`, `armv6`, `armv7` | `sigcomply_<version>_linux_<arch>.tar.gz` |
| macOS | `amd64`, `arm64` | `sigcomply_<version>_darwin_<arch>.tar.gz` |
| Windows | `amd64` | `sigcomply_<version>_windows_amd64.zip` |

`<version>` is the tag without the `v`.

1. Download the archive and the checksums (Linux x86-64 shown):

   ```bash
   tag=v0.88.4; ver=${tag#v}
   curl -fsSL -O "https://github.com/SigComply/sigcomply-cli/releases/download/${tag}/sigcomply_${ver}_linux_amd64.tar.gz"
   curl -fsSL -O "https://github.com/SigComply/sigcomply-cli/releases/download/${tag}/checksums.txt"
   ```

2. Check the archive against the checksums. Use `shasum -a 256` in place of `sha256sum` on macOS:

   ```bash
   sha256sum -c checksums.txt --ignore-missing
   ```

   The line for your archive must end in `OK`.

3. Optional: check the build provenance with the [GitHub CLI](https://cli.github.com/). Every
   archive carries a GitHub build attestation. Exit code `0` means it verified:

   ```bash
   gh attestation verify "sigcomply_${ver}_linux_amd64.tar.gz" --repo SigComply/sigcomply-cli
   ```

4. Extract the binary and move it onto your `PATH`:

   ```bash
   tar -xzf "sigcomply_${ver}_linux_amd64.tar.gz" sigcomply
   sudo mv sigcomply /usr/local/bin/
   ```

5. Run `sigcomply version`.

## Install with Go

This builds from source and needs Go 1.27 or later.

1. Install the module:

   ```bash
   go install github.com/sigcomply/sigcomply-cli@latest
   ```

2. `go install` names the binary `sigcomply-cli`. Every command in these docs calls `sigcomply`,
   so link it:

   ```bash
   ln -sf "$(go env GOPATH)/bin/sigcomply-cli" "$(go env GOPATH)/bin/sigcomply"
   ```

3. Run `sigcomply version`. A Go build prints `dev` as its version.

There is no Homebrew formula.

## Next steps

- [Quickstart](../quickstart.md): a first local run.
- [Add an evidence source](configure-sources.md).
- [Run in GitHub Actions](ci-github.md) or [Run in GitLab CI](ci-gitlab.md).
