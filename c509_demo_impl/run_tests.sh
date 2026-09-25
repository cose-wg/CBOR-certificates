#!/usr/bin/env bash
# =============================================================================
# run_tests.sh — C509 demo implementation: full test-vector validation
#
# One invocation to:
#   1. Download  draft-ietf-cose-c509-test-vectors-{VERSION}.xml (if not cached)
#   2. Extract   all test vectors from the XML, named by section number
#   3. Build     the c509 Rust binary (cargo build)
#   4. Run       the validation suite and present a colour-coded summary
#
# Usage:
#   ./run_tests.sh [OPTIONS]
#
# Options:
#   --version VER    Test vectors draft version (default: 02, current draft)
#   --refetch        Force re-download of the XML even if already cached
#   --rebuild        Force cargo build even if the binary is current
#   --verbose        Print tool output for every failing test
#   --help           Show this help
#
# Exit code: 0 if all tests pass or are expected failures, 1 if any unexpected
#            failure is found.
#
# Requirements:
#   - Rust / cargo  (https://rustup.rs)
#   - python3 with lxml  (pip3 install lxml)
#   - curl
#   - openssl  (for DER conversions)
#   - coreutils (od, for hex dumps — normally pre-installed)
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
VERSION="02"
REFETCH=0
REBUILD=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)  VERSION="$2"; shift 2 ;;
        --refetch)  REFETCH=1;    shift   ;;
        --rebuild)  REBUILD=1;    shift   ;;
        --verbose)  VERBOSE=1;    shift   ;;
        --help)
            sed -n '/^# Usage/,/^# =/p' "$0" | grep "^#" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    BOLD="\033[1m"; RST="\033[0m"; GRN="\033[0;32m"; RED="\033[0;31m"; CYN="\033[0;36m"
else
    BOLD=""; RST=""; GRN=""; RED=""; CYN=""
fi

step() { echo -e "${BOLD}>>> $*${RST}"; }
info() { echo -e "    $*"; }

# ---------------------------------------------------------------------------
# Step 1 — Download and extract test vectors
# ---------------------------------------------------------------------------
step "Step 1: Fetch and extract test vectors (draft-ietf-cose-c509-test-vectors-${VERSION})"
echo ""

TV_DIR="${SCRIPT_DIR}/../test_vectors"
XML_FILE="${TV_DIR}/draft-ietf-cose-c509-test-vectors-${VERSION}.xml"

# Force re-download if requested
if [ "${REFETCH}" -eq 1 ] && [ -f "${XML_FILE}" ]; then
    rm -f "${XML_FILE}"
    info "Removed cached XML (--refetch)."
fi

bash "${SCRIPT_DIR}/fetch_test_vectors.sh" "${VERSION}"
echo ""

# ---------------------------------------------------------------------------
# Step 2 — Build
# ---------------------------------------------------------------------------
step "Step 2: Build c509 binary"
echo ""

BUILD_ARGS=""
[ "${REBUILD}" -eq 1 ] && BUILD_ARGS="--offline" || true

if [ "${REBUILD}" -eq 1 ] || [ ! -x "${SCRIPT_DIR}/target/debug/c509" ]; then
    info "Running: cargo build --bin c509"
    (cd "${SCRIPT_DIR}" && cargo build --bin c509)
else
    info "Binary up-to-date: ${SCRIPT_DIR}/target/debug/c509"
    info "(Pass --rebuild to force recompilation.)"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 3 — Run validation suite
# ---------------------------------------------------------------------------
step "Step 3: Run validation suite"
echo ""

VALIDATE_ARGS="--version ${VERSION}"
[ "${VERBOSE}" -eq 1 ] && VALIDATE_ARGS="${VALIDATE_ARGS} --verbose"

# validate_c509.sh builds its own summary; we capture the exit code.
set +e
bash "${SCRIPT_DIR}/validate_c509.sh" ${VALIDATE_ARGS}
RESULT=$?
set -e

# ---------------------------------------------------------------------------
# Final status line
# ---------------------------------------------------------------------------
echo ""
if [ "${RESULT}" -eq 0 ]; then
    echo -e "${GRN}${BOLD}All tests passed or accounted for as expected failures.${RST}"
else
    echo -e "${RED}${BOLD}Unexpected failures detected — see [FAIL] lines above.${RST}"
fi
echo ""
echo -e "${CYN}Test vectors: ${TV_DIR}/${RST}"
echo -e "${CYN}Binary:       ${SCRIPT_DIR}/target/debug/c509${RST}"
echo -e "${CYN}Full details: ${SCRIPT_DIR}/KNOWN_ISSUES.md${RST}"
echo ""
exit "${RESULT}"
