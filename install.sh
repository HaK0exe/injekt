#!/bin/sh
# injekt installer — downloads the right prebuilt binary from GitHub Releases,
# verifies its SHA256 against the published SHA256SUMS, and installs it.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/HaK0exe/injekt/main/install.sh | sh
#
# Env overrides:
#   INJEKT_VERSION      release tag to install (default: latest)
#   INJEKT_INSTALL_DIR  install directory (default: ~/.local/bin)
set -eu

REPO="HaK0exe/injekt"
BIN_NAME="injekt"
INSTALL_DIR="${INJEKT_INSTALL_DIR:-$HOME/.local/bin}"

log() { printf '%s\n' "$*" >&2; }
die() {
    log "error: $*"
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed"
}

detect_target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Linux)
            case "$arch" in
                x86_64 | amd64) echo "x86_64-unknown-linux-gnu" ;;
                *) die "no prebuilt Linux binary for arch '$arch' yet — build from source: cargo install --path ." ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                x86_64) echo "x86_64-apple-darwin" ;;
                arm64) echo "aarch64-apple-darwin" ;;
                *) die "unsupported macOS arch '$arch'" ;;
            esac
            ;;
        *)
            die "unsupported OS '$os' — on Windows, download a release asset manually from https://github.com/$REPO/releases"
            ;;
    esac
}

main() {
    need_cmd curl
    need_cmd tar
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        die "either 'sha256sum' or 'shasum' is required for checksum verification"
    fi

    target=$(detect_target)

    if [ -n "${INJEKT_VERSION:-}" ]; then
        tag="$INJEKT_VERSION"
    else
        log "resolving latest release..."
        tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
            grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
        [ -n "$tag" ] || die "could not resolve the latest release tag"
    fi
    log "installing $BIN_NAME $tag ($target)"

    asset="${BIN_NAME}-${tag}-${target}.tar.gz"
    base_url="https://github.com/$REPO/releases/download/$tag"

    workdir=$(mktemp -d)
    trap 'rm -rf "$workdir"' EXIT

    log "downloading $asset..."
    curl -fsSL "$base_url/$asset" -o "$workdir/$asset" ||
        die "download failed — is '$tag' a real release with a $target asset?"

    log "downloading SHA256SUMS..."
    curl -fsSL "$base_url/SHA256SUMS" -o "$workdir/SHA256SUMS" ||
        die "could not fetch SHA256SUMS for verification"

    log "verifying checksum..."
    expected=$(grep " $asset\$" "$workdir/SHA256SUMS" | cut -d' ' -f1)
    [ -n "$expected" ] || die "no checksum entry for $asset in SHA256SUMS"
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$workdir/$asset" | cut -d' ' -f1)
    else
        actual=$(shasum -a 256 "$workdir/$asset" | cut -d' ' -f1)
    fi
    [ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"

    tar xzf "$workdir/$asset" -C "$workdir"
    binary=$(find "$workdir" -type f -name "$BIN_NAME" -perm -u+x | head -n1)
    [ -n "$binary" ] || die "extracted archive did not contain a '$BIN_NAME' binary"

    mkdir -p "$INSTALL_DIR"
    install -m 755 "$binary" "$INSTALL_DIR/$BIN_NAME"
    log "installed $BIN_NAME to $INSTALL_DIR/$BIN_NAME"

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *) log "note: $INSTALL_DIR is not in your PATH — add it, e.g.: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
    esac

    "$INSTALL_DIR/$BIN_NAME" --no-banner info >/dev/null 2>&1 &&
        log "$BIN_NAME is ready — run: $BIN_NAME --no-banner info" ||
        log "installed, but the smoke test failed — run '$BIN_NAME --no-banner info' manually to check"
}

main "$@"
