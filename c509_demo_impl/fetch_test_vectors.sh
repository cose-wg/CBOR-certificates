#!/usr/bin/env bash
# =============================================================================
# fetch_test_vectors.sh
#
# Download and extract official C509 test vectors for a given draft version.
#
# Usage:
#   ./fetch_test_vectors.sh [VERSION]
#
# Arguments:
#   VERSION   Draft version number (default: 02, current draft)
#             Examples: 01, 02, 00
#
# What this script does:
#   1. Downloads draft-ietf-cose-c509-test-vectors-{VERSION}.xml from the
#      IETF archive at https://www.ietf.org/archive/id/
#   2. Runs the version-aware Python extractor to produce:
#        - v{VERSION}_*.crt  / v{VERSION}_*.csr   PEM-encoded certificates/CSRs
#        - v{VERSION}_*.cbor.hex                  C509 hex values
#        - v{VERSION}_*.key                       Private keys (test use only)
#   3. All extracted files are written to ../test_vectors/ (relative to this
#      script) so they are available to both this tool and the Rust binary.
#
# Requirements:
#   - curl
#   - python3 with the 'lxml' package (pip3 install lxml)
#
# Output directory: ../test_vectors/  (i.e. CBOR-certificates/test_vectors/)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TV_DIR="${SCRIPT_DIR}/../test_vectors"
EXTRACTOR="${SCRIPT_DIR}/extract_vectors.py"

VERSION="${1:-02}"
DRAFT_NAME="draft-ietf-cose-c509-test-vectors-${VERSION}"
XML_FILENAME="${DRAFT_NAME}.xml"
XML_URL="https://www.ietf.org/archive/id/${XML_FILENAME}"
XML_LOCAL="${TV_DIR}/${XML_FILENAME}"

echo "============================================================"
echo "  C509 Test Vector Fetcher"
echo "  Draft: ${DRAFT_NAME}"
echo "  Target directory: ${TV_DIR}"
echo "============================================================"
echo ""

# Ensure the output directory exists
mkdir -p "${TV_DIR}"

# ----------------------------------------------------------------
# Step 1: Download the XML
# ----------------------------------------------------------------
if [ -f "${XML_LOCAL}" ]; then
    echo "[INFO] XML already present: ${XML_LOCAL}"
    echo "       Use 'rm ${XML_LOCAL}' to force a fresh download."
else
    echo "[FETCH] Downloading ${XML_URL} ..."
    curl --fail --silent --show-error --location \
         --output "${XML_LOCAL}" \
         "${XML_URL}"
    echo "[OK]   Saved to ${XML_LOCAL}"
fi
echo ""

# ----------------------------------------------------------------
# Step 2: Run the version-aware extractor
# ----------------------------------------------------------------
echo "[EXTRACT] Running extractor for version ${VERSION} ..."
python3 "${EXTRACTOR}" --version "${VERSION}" --xml "${XML_LOCAL}" --outdir "${TV_DIR}"
echo ""
echo "[DONE] Test vectors written to ${TV_DIR}/"
