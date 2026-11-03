# Install the SigComply CLI

Install the `sigcomply` binary on your machine and confirm it runs. Use the install script, a
release archive, or Go. There is no Homebrew formula.

## Prerequisites

- A supported platform: Linux on `amd64`, `arm64`, `armv6` or `armv7`, macOS on `amd64` or
  `arm64`, or Windows on `amd64` in Git Bash, MSYS2 or Cygwin.
- `curl`, `tar` (`unzip` on Windows), and `sha256sum` or `shasum`.
- Optional: a recent [GitHub CLI](https://cli.github.com/) (`gh`), to verify the build
  provenance. You don't need to log in.
- In CI, the scaffolded workflows' install step needs `gh` and `git` for the provenance check.
  GitHub-hosted runners have both; add them to a self-hosted runner or container image.

## Install with the script

1. Run the install script:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
   ```

   It downloads the release archive for your OS and architecture, checks it against the
   release's `checksums.txt`, verifies its build provenance when `gh` is installed, and puts
   `sigcomply` in `/usr/local/bin`. On Windows it installs `sigcomply.exe` from the `.zip`. To
   verify provenance, it looks up the release tag's commit with `git` if present, else with the
   GitHub API.

   To pin a version, or to install without `sudo` into a directory you own, set the installer's
   variables:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh \
     | SIGCOMPLY_VERSION=v0.91.0 SIGCOMPLY_INSTALL_DIR="$HOME/.local/bin" SIGCOMPLY_NO_SUDO=1 sh
   ```

   | Variable | Default | Effect |
   |---|---|---|
   | `SIGCOMPLY_VERSION` | `latest` | Release tag to install, for example `v0.91.0`. The leading `v` is optional. A prerelease tag such as `v0.89.0-rc.1` works too; `latest` never picks a prerelease. |
   | `SIGCOMPLY_INSTALL_DIR` | `/usr/local/bin` | Directory the binary goes into. Must be on your `PATH`. |
   | `SIGCOMPLY_NO_SUDO` | `0` | Set to `1` to never call `sudo`. |
   | `SIGCOMPLY_REQUIRE_PROVENANCE` | `0` | Set to `1` to stop the install unless the build provenance is verified. Without `gh`, with a `gh` whose `gh attestation verify --help` lacks `--bundle`, `--source-digest` or `--deny-self-hosted-runners`, or for a release before v0.91.0, the script then exits with an error instead of a warning. |

2. Check the install:

   ```bash
   sigcomply version
   ```

   A release build prints its version without a leading `v`:

   ```text
   sigcomply 0.88.4 (commit 45c25e38278c8c155b2e875cf4750a42aabecefc, built 2026-10-26T19:12:08Z)
   ```

If the script stops with an error, see [Troubleshooting](troubleshooting.md#install).

## Install a release archive by hand

Each [GitHub release](https://github.com/SigComply/sigcomply-cli/releases) publishes these
archives, plus `checksums.txt` (SHA-256) and `sigcomply_<version>_provenance.sigstore.json` (the
build provenance bundle, from v0.91.0):

| OS | Architectures | Archive |
|---|---|---|
| Linux | `amd64`, `arm64`, `armv6`, `armv7` | `sigcomply_<version>_linux_<arch>.tar.gz` |
| macOS | `amd64`, `arm64` | `sigcomply_<version>_darwin_<arch>.tar.gz` |
| Windows | `amd64` | `sigcomply_<version>_windows_amd64.zip` |

`<version>` is the tag without the `v`.

1. Download the archive and the checksums (Linux x86-64 shown):

   ```bash
   tag=v0.91.0; ver=${tag#v}
   curl -fsSL -O "https://github.com/SigComply/sigcomply-cli/releases/download/${tag}/sigcomply_${ver}_linux_amd64.tar.gz"
   curl -fsSL -O "https://github.com/SigComply/sigcomply-cli/releases/download/${tag}/checksums.txt"
   ```

2. Check the archive against the checksums. Use `shasum -a 256` in place of `sha256sum` on macOS:

   ```bash
   sha256sum -c checksums.txt --ignore-missing
   ```

   The line for your archive must end in `OK`.

3. Optional: verify the build provenance with the [GitHub CLI](https://cli.github.com/). This
   step also needs `git`. Every archive carries a GitHub build attestation, signed for the
   release workflow that built it. Download the release's bundle, look up the tag's commit, and
   verify:

   ```bash
   curl -fsSL -O "https://github.com/SigComply/sigcomply-cli/releases/download/${tag}/sigcomply_${ver}_provenance.sigstore.json"
   # Release tags are annotated; ^{} resolves the tag to its commit.
   commit=$(git ls-remote https://github.com/SigComply/sigcomply-cli "refs/tags/${tag}^{}" | cut -f1)
   gh attestation verify "sigcomply_${ver}_linux_amd64.tar.gz" \
     --bundle "sigcomply_${ver}_provenance.sigstore.json" \
     --repo SigComply/sigcomply-cli \
     --cert-identity-regex '^https://github\.com/SigComply/sigcomply-cli/\.github/workflows/(auto-release-pipeline|release)\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$' \
     --source-digest "$commit" \
     --deny-self-hosted-runners
   ```

   Exit code `0` means it verified. The flags pin what the attestation must say:

   | Flag | Checks |
   |---|---|
   | `--bundle` | Verifies against the downloaded bundle. No GitHub login or token is needed; `gh` only fetches Sigstore's public trust root. |
   | `--cert-identity-regex` | The archive was signed by one of SigComply's two release workflows, run from `main` or a release tag. |
   | `--source-digest` | It was built from the commit the tag points at, so an archive from another release fails. Use this, not `--source-ref`: releases are built from `main` before their tag is pushed, so the attestation names the branch and the commit, not the tag. |
   | `--deny-self-hosted-runners` | It was built on a GitHub-hosted runner. |

   Releases before v0.91.0 have no bundle. Drop `--bundle`, and log in with `gh auth login` or
   set `GH_TOKEN`, because `gh` then fetches the attestation from GitHub.

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

## Next steps

- [Quickstart](../quickstart.md): a first local run.
- [Add an evidence source](configure-sources.md).
- [Run in GitHub Actions](ci-github.md) or [Run in GitLab CI](ci-gitlab.md).
