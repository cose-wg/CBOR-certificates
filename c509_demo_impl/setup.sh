#!/usr/bin/env bash
# =============================================================================
# setup.sh — install the system prerequisites for the C509 reference tool.
#
# The Rust crate depends on the `openssl` crate (native OpenSSL, used for
# brainpoolP256r1/P384r1/P512r1 and Ed448 Type-2 signing), so a plain
# `cargo build` needs the system OpenSSL development library plus pkg-config
# and a C toolchain to build and link the *-sys crates. The test-vector
# fetcher (fetch_test_vectors.sh) additionally needs curl and python3-lxml.
#
# This installs, per platform:
#   - a C toolchain (cc/make)           [links openssl-sys and friends]
#   - pkg-config                        [locates openssl.pc]
#   - the OpenSSL dev headers/library   [libssl-dev / openssl-devel / openssl]
#   - curl                              [downloads the draft XML]
#   - python3 + lxml                    [runs extract_vectors.py]
#
# It does NOT install Rust — get that from https://rustup.rs if `cargo` is
# missing (the script warns if so).
#
# Usage:   ./setup.sh
# After:   cargo build --release  &&  ./fetch_test_vectors.sh 02
#
# SECURITY NOTICE: installs build/test tooling only. Test credentials only;
# never use generated vectors in production.
# =============================================================================
set -euo pipefail

say()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[setup]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[setup]\033[0m %s\n' "$*" >&2; exit 1; }

# Use sudo only when not already root and sudo exists.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
        warn "not root and no sudo found; package installs may fail."
    fi
fi

install_debian() {
    say "Debian/Ubuntu detected — installing via apt-get."
    $SUDO apt-get update
    $SUDO apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev curl python3 python3-lxml
}

install_fedora() {
    say "Fedora/RHEL detected — installing via dnf."
    $SUDO dnf install -y \
        gcc make pkgconf-pkg-config openssl-devel curl python3 python3-lxml
}

install_arch() {
    say "Arch detected — installing via pacman."
    $SUDO pacman -Sy --needed --noconfirm \
        base-devel pkgconf openssl curl python python-lxml
}

install_macos() {
    say "macOS detected — installing via Homebrew."
    command -v brew >/dev/null 2>&1 || die "Homebrew not found — install from https://brew.sh"
    brew install openssl@3 pkg-config curl python3
    # The openssl crate finds Homebrew OpenSSL via pkg-config once this is set.
    local ossl; ossl="$(brew --prefix openssl@3)"
    export PKG_CONFIG_PATH="${ossl}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
    say "For this shell and future builds, export:"
    say "  export PKG_CONFIG_PATH=\"${ossl}/lib/pkgconfig:\$PKG_CONFIG_PATH\""
    python3 -m pip install --user lxml
}

# ---- dispatch on platform ---------------------------------------------------
OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
    install_macos
elif [ -r /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}${ID_LIKE:-}" in
        *debian*|*ubuntu*) install_debian ;;
        *fedora*|*rhel*|*centos*) install_fedora ;;
        *arch*) install_arch ;;
        *) die "Unrecognised Linux distro '${ID:-?}'. Install manually: a C toolchain, pkg-config, the OpenSSL dev library, curl, and python3 + lxml." ;;
    esac
else
    die "Unsupported OS '$OS'. Install manually: C toolchain, pkg-config, OpenSSL dev lib, curl, python3 + lxml."
fi

# ---- verify -----------------------------------------------------------------
say "Verifying prerequisites..."
ok=1
if pkg-config --exists openssl 2>/dev/null; then
    say "OpenSSL: $(pkg-config --modversion openssl) (pkg-config OK)"
else
    warn "pkg-config cannot find openssl.pc — the openssl crate will not build."; ok=0
fi
command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || { warn "no C compiler (cc/gcc) found."; ok=0; }
command -v curl >/dev/null 2>&1 || { warn "curl not found."; ok=0; }
python3 -c 'import lxml.etree' 2>/dev/null && say "python3 + lxml OK" || { warn "python3 'lxml' not importable."; ok=0; }

if command -v cargo >/dev/null 2>&1; then
    say "cargo found: $(cargo --version)"
else
    warn "cargo not found — install Rust from https://rustup.rs before building."
fi

if [ "$ok" -eq 1 ]; then
    say "All system prerequisites satisfied."
    say "Next:  cargo build --release  &&  ./fetch_test_vectors.sh 02"
else
    die "Some prerequisites are missing (see warnings above)."
fi

# -----------------------------------------------------------------------------
# Fallback for locked-down hosts where you cannot install system OpenSSL:
# build a vendored copy from source instead (needs a C compiler + perl + make).
# Either edit Cargo.toml:
#     openssl = { version = "0.10", features = ["vendored"] }
# or build once with:
#     OPENSSL_STATIC=1 cargo build --release --features <a feature that enables vendored>
# The vendored build is slower and compiles all of OpenSSL, so prefer the
# system package above when you can install it.
# -----------------------------------------------------------------------------
