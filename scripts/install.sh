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
#   SIGCOMPLY_VERSION - Specific version to install (default: latest)
#   SIGCOMPLY_INSTALL_DIR - Installation directory (default: /usr/local/bin)
#   SIGCOMPLY_NO_SUDO - Set to 1 to skip sudo (for non-root installs)

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
    for cmd in curl "$extractor"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command not found: $cmd"
        fi
    done
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
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${FILENAME}"

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    # Download
    info "Downloading from $DOWNLOAD_URL"
    if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$FILENAME"; then
        error "Failed to download $DOWNLOAD_URL"
    fi

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
# scripts/install_test.go can check asset_name.
if [ "${SIGCOMPLY_INSTALL_LIB:-0}" != "1" ]; then
    main
fi
