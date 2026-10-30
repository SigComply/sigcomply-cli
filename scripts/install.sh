#!/bin/sh
# SigComply CLI Installer
#
# This script downloads and installs the SigComply CLI.
# It auto-detects your operating system and architecture.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
#
# Options (via environment variables):
#   SIGCOMPLY_VERSION - Release tag to install, e.g. v1.2.3 or a prerelease
#                       such as v1.2.3-rc.1 (default: latest, which never
#                       resolves to a prerelease). The leading v is optional.
#   SIGCOMPLY_INSTALL_DIR - Installation directory (default: /usr/local/bin)
#   SIGCOMPLY_NO_SUDO - Set to 1 to skip sudo (for non-root installs)
#   SIGCOMPLY_REQUIRE_PROVENANCE - Set to 1 to stop unless the download's
#                       GitHub build provenance is verified. By default the
#                       installer verifies it when a recent GitHub CLI (gh)
#                       is installed, and warns and continues when gh is
#                       missing or too old, or the release predates bundles
#                       (before v0.91.0).
#
# Every download is checked against the release's checksums.txt. With gh,
# the archive's build provenance is verified too, without a GitHub token,
# against the
# release's sigcomply_<version>_provenance.sigstore.json bundle: the
# archive must have been built by this repository's release workflow, on a
# GitHub-hosted runner, from the commit the release tag points at. A failed
# verification always stops the install.

set -e

# Colors for output (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Configuration
GITHUB_REPO="SigComply/sigcomply-cli"
BINARY_NAME="sigcomply"
VERSION="${SIGCOMPLY_VERSION:-latest}"
INSTALL_DIR="${SIGCOMPLY_INSTALL_DIR:-/usr/local/bin}"
USE_SUDO="${SIGCOMPLY_NO_SUDO:-0}"
REQUIRE_PROVENANCE="${SIGCOMPLY_REQUIRE_PROVENANCE:-0}"

# The certificate identity of a genuine release: one of the two release
# workflows of this repository, run from main or from a release tag.
# Renaming either workflow breaks every verifier that pins this pattern.
PROVENANCE_IDENTITY='^https://github\.com/SigComply/sigcomply-cli/\.github/workflows/(auto-release-pipeline|release)\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$'

# Helper functions
info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

success() {
    printf "${GREEN}[OK]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
    exit 1
}

# Map `uname -s` to the OS in the release archive name.
release_os() {
    case "$1" in
        Linux*)     echo "linux" ;;
        Darwin*)    echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *)          error "Unsupported operating system: $1" ;;
    esac
}

# Map `uname -m` to the architecture in the release archive name. 32-bit
# ARM releases are split by ARM version (armv6, armv7); armv8l is a
# 32-bit userland on a 64-bit core and runs the armv7 build.
release_arch() {
    case "$1" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        armv7*|armv8l)  echo "armv7" ;;
        armv6*)         echo "armv6" ;;
        *)              error "Unsupported architecture: $1" ;;
    esac
}

# Print the release archive name for `uname -s`, `uname -m` and a
# version without the leading v. Mirrors the archives .goreleaser.yml
# publishes: linux amd64/arm64/armv6/armv7, darwin amd64/arm64 and
# windows amd64, as .tar.gz except .zip on Windows.
asset_name() {
    _os=$(release_os "$1") || exit 1
    _arch=$(release_arch "$2") || exit 1
    case "${_os}_${_arch}" in
        linux_amd64|linux_arm64|linux_armv6|linux_armv7|darwin_amd64|darwin_arm64)
            echo "${BINARY_NAME}_${3}_${_os}_${_arch}.tar.gz" ;;
        windows_amd64)
            echo "${BINARY_NAME}_${3}_${_os}_${_arch}.zip" ;;
        *)
            error "There is no release for ${_os}/${_arch}. See https://github.com/${GITHUB_REPO}/releases" ;;
    esac
}

# Check for required commands
check_dependencies() {
    extractor=tar
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*) extractor=unzip ;;
    esac
    for cmd in curl "$extractor" awk; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command not found: $cmd"
        fi
    done
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        error "Required command not found: sha256sum or shasum (to verify the download)"
    fi
}

# Print a release tag for a version: "latest" as is, otherwise with a
# leading v, so SIGCOMPLY_VERSION=1.2.3 and v1.2.3 name the same release.
normalize_version() {
    case "$1" in
        latest|v*) echo "$1" ;;
        *)         echo "v$1" ;;
    esac
}

# Print the SHA-256 of a file with whichever tool the system has:
# sha256sum (Linux, Git Bash) or shasum (macOS).
sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        error "Neither sha256sum nor shasum is available to verify the download"
    fi
}

# verify_checksum <archive> <checksums.txt>: stop unless the archive's
# SHA-256 equals its entry in the release's checksums.txt.
verify_checksum() {
    _name="${1##*/}"
    _want=$(awk -v f="$_name" '$2 == f || $2 == "*" f { print $1; exit }' "$2")
    if [ -z "$_want" ]; then
        error "No checksum for $_name in checksums.txt"
    fi
    _got=$(sha256_file "$1") || exit 1
    if [ "$_got" != "$_want" ]; then
        error "Checksum mismatch for $_name: checksums.txt has $_want, the download hashes to $_got"
    fi
}

# Print the provenance bundle's asset name for a version without the v.
provenance_bundle_name() {
    echo "${BINARY_NAME}_${1}_provenance.sigstore.json"
}

# Succeed when a version without the v (prerelease suffix ignored) is
# v0.91.0 or later: the first release that publishes a provenance bundle.
has_provenance_bundle() {
    _v="${1%%-*}"
    _major="${_v%%.*}"; _rest="${_v#*.}"; _minor="${_rest%%.*}"
    case "$_major$_minor" in
        *[!0-9]*|"") return 1 ;;
    esac
    [ "$_major" -gt 0 ] || [ "$_minor" -ge 91 ]
}

# Succeed when gh is installed and its `attestation verify` has every flag
# the bundle verification needs. An older gh counts as no gh.
gh_can_verify() {
    command -v gh >/dev/null 2>&1 || return 1
    _help=$(gh attestation verify --help 2>&1) || return 1
    for _flag in --bundle --source-digest --deny-self-hosted-runners; do
        case "$_help" in
            *"$_flag"*) ;;
            *) return 1 ;;
        esac
    done
}

# Print the commit a release tag points at. Auto releases are built from
# main, so the attestation names a commit, not the tag: the tag must be
# resolved to compare them. Annotated tags peel with ^{}. Without git, the
# GitHub API answers (rate-limited to 60 requests an hour per IP).
tag_commit() {
    if command -v git >/dev/null 2>&1; then
        _refs=$(git ls-remote "https://github.com/${GITHUB_REPO}" "refs/tags/$1" "refs/tags/$1^{}") || return 1
        _sha=$(printf '%s\n' "$_refs" | awk -v r="refs/tags/$1^{}" '$2 == r {print $1}')
        if [ -z "$_sha" ]; then
            _sha=$(printf '%s\n' "$_refs" | awk -v r="refs/tags/$1" '$2 == r {print $1}')
        fi
    else
        _sha=$(curl -fsSL -H "Accept: application/vnd.github.sha" \
            "https://api.github.com/repos/${GITHUB_REPO}/commits/$1") || return 1
    fi
    case "$_sha" in
        *[!0-9a-f]*|"") return 1 ;;
    esac
    [ "${#_sha}" -eq 40 ] || return 1
    echo "$_sha"
}

# Called when the build provenance cannot be checked at all: a warning,
# or an error with SIGCOMPLY_REQUIRE_PROVENANCE=1.
provenance_unavailable() {
    if [ "$REQUIRE_PROVENANCE" = "1" ]; then
        error "SIGCOMPLY_REQUIRE_PROVENANCE=1, but the build provenance cannot be verified: $1"
    fi
    warn "Build provenance not verified: $1. The checksum was verified; set SIGCOMPLY_REQUIRE_PROVENANCE=1 to require provenance."
}

# verify_provenance <archive> <release-url> <tag> <work-dir>: verify the
# archive's GitHub build provenance with gh, without a token, against the
# release's bundle. Stops the install when the verification fails.
verify_provenance() {
    if ! gh_can_verify; then
        provenance_unavailable "the GitHub CLI (gh) is not installed, or its 'gh attestation verify' lacks --bundle, --source-digest or --deny-self-hosted-runners"
        return 0
    fi
    _bundle="$4/$(provenance_bundle_name "${3#v}")"
    # Quiet: the failure is reported below. From v0.91.0 every release
    # has a bundle, so any failure to fetch it stops the install; leaving
    # the bundle out must not skip the check.
    if ! curl -fsSL "$2/${_bundle##*/}" -o "$_bundle" 2>/dev/null; then
        if has_provenance_bundle "${3#v}"; then
            error "Cannot download ${_bundle##*/} from release $3, so its build provenance cannot be verified"
        fi
        provenance_unavailable "release $3 predates provenance bundles (v0.91.0) and has no ${_bundle##*/}"
        return 0
    fi
    if ! _commit=$(tag_commit "$3"); then
        error "Cannot resolve the commit of $3 to verify its build provenance"
    fi
    # A throwaway gh config and no token: the bundle makes the check
    # check need no GitHub login, and a caller's login or GH_HOST must not
    # change it.
    mkdir -p "$4/gh-config"
    if ! _out=$(env -u GH_TOKEN -u GITHUB_TOKEN -u GH_ENTERPRISE_TOKEN -u GITHUB_ENTERPRISE_TOKEN -u GH_HOST \
        GH_CONFIG_DIR="$4/gh-config" GH_PROMPT_DISABLED=1 \
        gh attestation verify "$1" --bundle "$_bundle" --repo "$GITHUB_REPO" \
        --cert-identity-regex "$PROVENANCE_IDENTITY" --source-digest "$_commit" \
        --deny-self-hosted-runners 2>&1); then
        printf '%s\n' "$_out" >&2
        error "Build provenance verification failed for ${1##*/}: it is not an archive built by ${GITHUB_REPO}'s release workflow from $3 ($_commit)"
    fi
    success "Build provenance verified: built by ${GITHUB_REPO}'s release workflow from $3 ($_commit)"
}

# Get latest version from GitHub API
get_latest_version() {
    curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/'
}

# Download and install
install() {
    info "Detected OS: $(uname -s), Arch: $(uname -m)"

    # Get version
    VERSION=$(normalize_version "$VERSION")
    if [ "$VERSION" = "latest" ]; then
        info "Fetching latest version..."
        VERSION=$(get_latest_version)
        if [ -z "$VERSION" ]; then
            error "Failed to fetch latest version"
        fi
    fi

    info "Installing SigComply CLI $VERSION"

    # Remove 'v' prefix if present for filename
    VERSION_NO_V="${VERSION#v}"

    # Construct download URL
    FILENAME=$(asset_name "$(uname -s)" "$(uname -m)" "$VERSION_NO_V") || exit 1
    RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
    DOWNLOAD_URL="${RELEASE_URL}/${FILENAME}"

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    # Download
    info "Downloading from $DOWNLOAD_URL"
    if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$FILENAME"; then
        error "Failed to download $DOWNLOAD_URL"
    fi

    # Verify against the release's checksums before extracting anything.
    if ! curl -fsSL "${RELEASE_URL}/checksums.txt" -o "$TMP_DIR/checksums.txt"; then
        error "Failed to download ${RELEASE_URL}/checksums.txt"
    fi
    verify_checksum "$TMP_DIR/$FILENAME" "$TMP_DIR/checksums.txt"
    success "Checksum verified"
    verify_provenance "$TMP_DIR/$FILENAME" "$RELEASE_URL" "$VERSION" "$TMP_DIR"

    # Extract
    info "Extracting..."
    case "$FILENAME" in
        *.zip)
            unzip -q "$TMP_DIR/$FILENAME" -d "$TMP_DIR"
            BINARY_NAME="${BINARY_NAME}.exe"
            ;;
        *)
            tar xzf "$TMP_DIR/$FILENAME" -C "$TMP_DIR"
            ;;
    esac

    # Verify binary exists
    if [ ! -f "$TMP_DIR/$BINARY_NAME" ]; then
        error "Binary not found in archive"
    fi

    # Make executable
    chmod +x "$TMP_DIR/$BINARY_NAME"

    # Install
    info "Installing to $INSTALL_DIR"

    # Check if we need sudo
    if [ "$USE_SUDO" != "1" ] && [ ! -w "$INSTALL_DIR" ]; then
        if command -v sudo >/dev/null 2>&1; then
            sudo mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/"
        else
            error "Cannot write to $INSTALL_DIR and sudo is not available. Try setting SIGCOMPLY_INSTALL_DIR to a writable directory."
        fi
    else
        mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/"
    fi

    # Verify installation
    if command -v sigcomply >/dev/null 2>&1; then
        success "SigComply CLI installed successfully!"
        echo ""
        sigcomply version
        echo ""
        info "Run 'sigcomply --help' to get started"
    else
        warn "Installation completed, but 'sigcomply' is not in PATH"
        info "Add $INSTALL_DIR to your PATH or move the binary manually"
    fi
}

# Main
main() {
    echo ""
    echo "  SigComply CLI Installer"
    echo "  ======================="
    echo ""

    check_dependencies
    install

    echo ""
    echo "  Quick Start:"
    echo "  ------------"
    echo "  sigcomply check              # Run compliance checks"
    echo "  sigcomply init               # Scaffold a .sigcomply.yaml"
    echo "  sigcomply --help             # Show all commands and flags"
    echo ""
    echo "  For more information, visit:"
    echo "  https://github.com/${GITHUB_REPO}"
    echo ""
}

# SIGCOMPLY_INSTALL_LIB=1 defines the functions without installing, so
# scripts/install_test.go can test them.
if [ "${SIGCOMPLY_INSTALL_LIB:-0}" != "1" ]; then
    main
fi
