# Install the SigComply CLI

Install the `sigcomply` binary on your machine and confirm it runs.

## Prerequisites

- A platform with a release archive: Linux on `amd64`, `arm64`, `armv6` or `armv7`, macOS on
  `amd64` or `arm64`, or Windows on `amd64` in Git Bash, MSYS2 or Cygwin. On any other platform
  the script stops with an error.
- `curl` on your `PATH`, plus `tar`, or `unzip` on Windows.
- `sha256sum` or `shasum` (the install script checks the download with one of them).
- Optional: the [GitHub CLI](https://cli.github.com/) (`gh`), to verify the build provenance.
  The script needs a `gh` whose `gh attestation verify --help` lists `--bundle`,
  `--source-digest` and `--deny-self-hosted-runners`. It does not need you to be logged in. With
  `SIGCOMPLY_REQUIRE_PROVENANCE=1`, `gh` is required.
- `git`, for the manual provenance check (step 3 of the manual steps). The script uses `git`
  when it is installed and the GitHub API otherwise.

## Install with the script

1. Run the install script. It downloads the release archive for your OS and architecture from
   GitHub Releases, checks it against the release's `checksums.txt`, verifies its build
   provenance when `gh` is installed, and puts `sigcomply` in `/usr/local/bin`:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
   ```

   To pin a version, or to install without `sudo` into a directory you own, set the installer's
   variables:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh \
     | SIGCOMPLY_VERSION=v0.91.0 SIGCOMPLY_INSTALL_DIR="$HOME/.local/bin" SIGCOMPLY_NO_SUDO=1 sh
   ```

   | Variable | Default | Effect |
   |---|---|---|
   | `SIGCOMPLY_VERSION` | `latest` | Release tag to install, for example `v0.88.4`. The leading `v` is optional. A prerelease tag such as `v0.89.0-rc.1` works too; `latest` never picks a prerelease. |
   | `SIGCOMPLY_INSTALL_DIR` | `/usr/local/bin` | Directory the binary goes into. Must be on your `PATH`. |
   | `SIGCOMPLY_NO_SUDO` | `0` | Set to `1` to never call `sudo`. |
   | `SIGCOMPLY_REQUIRE_PROVENANCE` | `0` | Set to `1` to stop the install unless the build provenance is verified: without `gh`, with a `gh` that lacks the flags, or for a release before v0.91.0, the script exits with an error instead of a warning. |

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
from its entry in `checksums.txt`.

With `gh` installed, the script then runs the check in step 3 of
[Install a release archive by hand](#install-a-release-archive-by-hand), without a GitHub token,
against the release's provenance bundle. It stops with `Build provenance verification failed`
when the archive was not built by SigComply's release workflow from the commit the tag points
at, and with `Cannot download` when a release from v0.91.0 on has no bundle. Without `gh`, with
an older `gh`, or for a release before v0.91.0, it prints `Build provenance not verified` and
installs after the checksum check alone, unless `SIGCOMPLY_REQUIRE_PROVENANCE=1` is set.

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

3. Optional: verify the build provenance with the [GitHub CLI](https://cli.github.com/). Every
   archive carries a GitHub build attestation, signed for the release workflow that built it.
   Download the release's bundle, look up the commit the tag points at (release tags are
   annotated, so `^{}` resolves them to the commit), and verify:

   ```bash
   curl -fsSL -O "https://github.com/SigComply/sigcomply-cli/releases/download/${tag}/sigcomply_${ver}_provenance.sigstore.json"
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
   | `--source-digest` | It was built from the commit the tag points at, so an archive from another release fails. |
   | `--deny-self-hosted-runners` | It was built on a GitHub-hosted runner. |

   Use `--source-digest`, not `--source-ref refs/tags/<tag>`: releases are built from `main`
   before their tag is pushed, so the attestation names the branch and the commit, not the tag. For a release before v0.91.0, which has no bundle, drop `--bundle`: `gh` then fetches
   the attestation from GitHub and needs you to be logged in (`gh auth login`) or a `GH_TOKEN`.

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
