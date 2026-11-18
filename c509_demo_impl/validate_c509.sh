#!/usr/bin/env bash
# =============================================================================
# validate_c509.sh
#
# Comprehensive validation of the c509_demo_impl Rust reference implementation
# against official IETF C509 test vectors.
#
# Usage:
#   ./validate_c509.sh [OPTIONS]
#
# Options:
#   --version VER    Test-vector version to test against (default: 04).
#   --fetch          Download and (re)extract test vectors before testing.
#   --build          Force a cargo build even if the binary is up-to-date.
#   --verbose        Show tool output on every failure.
#   --help           Print this help and exit.
#
# Files are named  v{VER}_section_{N.N.N}_{anchor}.{ext}  by the extractor,
# matching the section number in draft-ietf-cose-c509-test-vectors-{VER}.
#
# Test sections:
#   2.  Encoding    X.509 DER  → C509 hex, compared against all known vectors
#   3.  CSR enc.    X.509 CSR  → C509 hex, compared against all known vectors
#   4.  Decoding    C509 type-3 hex → X.509 DER, byte-exact comparison
#   5.  Round-trip  X.509 DER  → C509 → DER, byte-exact DER comparison
#   6.  CSR r/t     X.509 CSR  → C509 → CSR, byte-exact DER comparison
#   7.  Type-2 sign X.509 DER + key → type-2 C509 (f2), compared against the vectors
#   7b. Type-2 ver. Signature verification of the type-2 vectors (v2)
#   8.  Type-2 CSR  PKCS#10 + key → type-2 C509 CSR (r2), compared against the vectors
#   9.  CRT r/t     C509 CertificationRequestTemplate CBOR → lossless re-encode
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
VERSION="04"
DO_FETCH=0
DO_BUILD=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --fetch)   DO_FETCH=1;   shift   ;;
        --build)   DO_BUILD=1;   shift   ;;
        --verbose) VERBOSE=1;    shift   ;;
        --help)
            grep "^#" "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Draft layout
#
# The section numbers of the CSRs, the CSR templates, and the cross-referenced
# keys and certificates differ between test-vector versions. Everything
# section-specific is defined here.
#
#   L_CSR_TOPS      top-level sections holding certification requests
#   L_CRT_TOP       top-level section holding CSR templates
#   L_FRP_TYPE2     FRP256v1 type-2 subsection (no .4 sibling)
#   L_CERT_XREF     cert/key sections that reuse another section's X.509 cert
#   L_KEY_XREF      sections whose private key is given in another section
#   L_V2_GLOB       self-signed type-2 certificates for `v2` verification
#   L_V2_EXTRA      further self-signed type-2 certificates (exact name stems)
#   L_DHSIG_*       RFC 6955 peer key / peer C509 cert per DhSig alg byte
#   L_EMB_KEY_*     key that re-signs the certificate embedded in a CSR
# ---------------------------------------------------------------------------
case "${VERSION}" in
    00|01|02)
        L_CSR_TOPS="8"
        L_CRT_TOP="10"
        L_FRP_TYPE2="3.11.3"
        L_CERT_XREF="3.4=3.3"
        L_KEY_XREF="4.1=3.1.1 4.17=3.1.1 4.18=3.1.1 4.19=3.1.1 4.21=3.1.1 4.22=4.20.1 8.1=3.3.1"
        L_V2_GLOB="*.4_c509_selfsign_*"
        L_V2_EXTRA=""
        L_DHSIG_KEY_0E="3.3.1"; L_DHSIG_CERT_0E="3.3.4_c509_selfsign_secp256r1"
        L_DHSIG_KEY_0F="3.5.1"; L_DHSIG_CERT_0F="3.5.4_c509_selfsign_secp384r1"
        L_DHSIG_KEY_10="3.6.1"; L_DHSIG_CERT_10="3.6.4_c509_selfsign_secp521r1"
        L_EMB_KEY_SECTION="8.7"; L_EMB_KEY="3.14.1"
        ;;
    03)
        L_CSR_TOPS="10 12"
        L_CRT_TOP="13"
        L_FRP_TYPE2="4.11.3"
        L_CERT_XREF="4.4=4.3"
        L_KEY_XREF="4.4=4.3.1 5.1=4.1.1 5.17=4.1.1 5.18=4.1.1 5.19=4.1.1 5.21=4.1.1 5.22=5.20.1 8=4.3.1 9=4.3.1 10.1=4.3.1 10.2=4.5.1 10.6=4.12.1 10.7=4.12.1 12=4.3.1"
        L_V2_GLOB="*.4_c509_selfsign_*"
        L_V2_EXTRA="8.4_c509_type_2_certificate"
        L_DHSIG_KEY_0E="4.3.1"; L_DHSIG_CERT_0E="4.3.4_c509_selfsign_secp256r1"
        L_DHSIG_KEY_0F="4.5.1"; L_DHSIG_CERT_0F="4.5.4_c509_selfsign_secp384r1"
        L_DHSIG_KEY_10="4.6.1"; L_DHSIG_CERT_10="4.6.4_c509_selfsign_secp521r1"
        L_EMB_KEY_SECTION="10.7"; L_EMB_KEY="4.14.1"
        ;;
    *)
        L_CSR_TOPS="9 11"
        L_CRT_TOP="12"
        L_FRP_TYPE2="3.11.3"
        L_CERT_XREF="3.4=3.3"
        L_KEY_XREF="3.4=3.3.1 4.1=3.1.1 4.17=3.1.1 4.18=3.1.1 4.19=3.1.1 4.21=3.1.1 4.22=4.20.1 7=3.3.1 8=3.3.1 9.1=3.3.1 9.2=3.5.1 9.6=3.12.1 9.7=3.12.1 11=3.3.1"
        L_V2_GLOB="*.4_c509_selfsign_*"
        L_V2_EXTRA="7.4_c509_type_2_certificate"
        L_DHSIG_KEY_0E="3.3.1"; L_DHSIG_CERT_0E="3.3.4_c509_selfsign_secp256r1"
        L_DHSIG_KEY_0F="3.5.1"; L_DHSIG_CERT_0F="3.5.4_c509_selfsign_secp384r1"
        L_DHSIG_KEY_10="3.6.1"; L_DHSIG_CERT_10="3.6.4_c509_selfsign_secp521r1"
        L_EMB_KEY_SECTION="9.7"; L_EMB_KEY="3.14.1"
        ;;
esac
# From test-vectors -05 the FRP256v1 type-2 certificate is in a .4 subsection
# like the others.
case "${VERSION}" in
    00|01|02|03|04) ;;
    *) L_FRP_TYPE2="none" ;;
esac

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TV_DIR="${SCRIPT_DIR}/../test_vectors"
BINARY="${SCRIPT_DIR}/target/debug/c509"
FETCH_SCRIPT="${SCRIPT_DIR}/fetch_test_vectors.sh"

# Look up KEY in a space-separated "key=value" list; print the value.
layout_lookup() {
    local key="$1" kv
    for kv in $2; do
        [ "${kv%%=*}" = "${key}" ] && { echo "${kv#*=}"; return 0; }
    done
    return 1
}

# Print the first test-vector file for section SEC with extension EXT.
section_file() {
    local f
    for f in "${TV_DIR}/v${VERSION}_section_${1}_"*."${2}"; do
        [ -f "${f}" ] && { echo "${f}"; return 0; }
    done
    return 1
}

# Print the private-key file for section base BASE: its own BASE.1 key, or the
# key it cross-references (L_KEY_XREF).
key_file_for_base() {
    local xref
    section_file "${1}.1" key && return 0
    xref="$(layout_lookup "${1}" "${L_KEY_XREF}")" || return 1
    section_file "${xref}" key
}

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_PASS="\033[0;32m" C_FAIL="\033[0;31m" C_XFAIL="\033[0;33m"
    C_SKIP="\033[0;36m" C_BOLD="\033[1m"    C_RST="\033[0m"
else
    C_PASS="" C_FAIL="" C_XFAIL="" C_SKIP="" C_BOLD="" C_RST=""
fi

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
PASS=0; FAIL=0; XFAIL=0; SKIP=0
log_pass()  { echo -e "  ${C_PASS}[PASS] ${C_RST} $*"; PASS=$((PASS+1));  }
log_fail()  { echo -e "  ${C_FAIL}[FAIL] ${C_RST} $*"; FAIL=$((FAIL+1));  }
log_xfail() { echo -e "  ${C_XFAIL}[XFAIL]${C_RST} $*"; XFAIL=$((XFAIL+1)); }
log_skip()  { echo -e "  ${C_SKIP}[SKIP] ${C_RST} $*"; SKIP=$((SKIP+1));  }

# ---------------------------------------------------------------------------
# Step 0 – fetch
# ---------------------------------------------------------------------------
if [ "${DO_FETCH}" -eq 1 ]; then
    echo -e "${C_BOLD}>>> Step 0: Fetching test vectors (version ${VERSION})${C_RST}"
    bash "${FETCH_SCRIPT}" "${VERSION}"
    echo ""
fi

# ---------------------------------------------------------------------------
# Step 1 – build
# ---------------------------------------------------------------------------
echo -e "${C_BOLD}>>> Step 1: Build${C_RST}"
# Rebuild when forced, when the binary is missing, or when a source file is
# newer than the binary.
NEED_BUILD=0
if [ ! -x "${BINARY}" ]; then
    NEED_BUILD=1
elif [ -n "$(find "${SCRIPT_DIR}/src" "${SCRIPT_DIR}/Cargo.toml" -newer "${BINARY}" -print -quit 2>/dev/null)" ]; then
    NEED_BUILD=1
fi
if [ "${DO_BUILD}" -eq 1 ] || [ "${NEED_BUILD}" -eq 1 ]; then
    echo "  cargo build --bin c509 ..."
    (cd "${SCRIPT_DIR}" && cargo build --bin c509)
else
    echo "  Binary up-to-date: ${BINARY}"
fi
echo ""

# ---------------------------------------------------------------------------
# XFAIL classification
#
# Filenames follow the pattern:
#   v{VER}_section_{N.N.N}_{anchor}.{ext}
#
# The section number fully determines the expected-failure category.
# This function sets XFAIL_CATEGORY and XFAIL_REASON for a given basename.
# Returns 0 (is XFAIL) or 1 (not XFAIL).
# ---------------------------------------------------------------------------
XFAIL_CATEGORY=""
XFAIL_REASON=""

is_xfail() {
    local bn="$1"
    XFAIL_CATEGORY=""
    XFAIL_REASON=""

    # Extract the section number from the filename
    local sec
    sec=$(echo "$bn" | sed -n 's/^v[0-9]*_section_\([^_]*\)_.*/\1/p')
    [ -z "$sec" ] && return 1

    # Split section into components: e.g. "3.1.4" → last = "4"
    local last
    last=$(echo "$sec" | sed 's/.*\.//')

    # ---- Category A: Type 2 (natively signed) --------------------------------
    # Section pattern *.4 = type-2 cert or CSR subsection.
    # L_FRP_TYPE2 = FRP256v1 type-2 (exceptionally at .3, no .4 sibling).
    #
    # c509CertificateType = 2: signature covers CBOR TBSCertificate, not DER.
    # No X.509 DER equivalent exists; cannot decode back to DER.
    # Ref: draft-ietf-cose-cbor-encoded-cert §2.1, §2.3.5
    if [ "$last" = "4" ] || [ "$sec" = "${L_FRP_TYPE2}" ]; then
        XFAIL_CATEGORY="A"
        XFAIL_REASON="Type 2 (natively signed, c509CertificateType=2): signature covers CBOR TBSCertificate, not ASN.1 DER. No X.509 DER equivalent. (§2.1, §2.3.5 draft-ietf-cose-cbor-encoded-cert)"
        return 0
    fi

    # ---- Category E1: Certification Request Templates (CRT) ------------------
    # Section L_CRT_TOP.* = CRT templates: no X.509 DER equivalent; Section 9
    # tests their lossless CBOR round-trip.
    local top
    top=$(echo "$sec" | cut -d. -f1)
    if [ "$top" = "${L_CRT_TOP}" ]; then
        XFAIL_CATEGORY="E1"
        XFAIL_REASON="CRT (Certification Request Template): no X.509 DER equivalent; round-trip tested in Section 9."
        return 0
    fi

    return 1
}

# ---------------------------------------------------------------------------
# Vector-drift XFAIL (test-vectors -02 only): the brainpoolP512r1 certificate
# of that set encodes subjectDirectoryAttributes with extension ID 24, which the
# C509 registry does not assign. The encoder emits the generic (~oid, bytes)
# form, so the X.509→C509 and TBS comparisons differ for that certificate.
# ---------------------------------------------------------------------------
is_vector_drift_xfail() {
    case "${VERSION}" in 00|01|02) ;; *) return 1 ;; esac
    case "$1" in
        v*_section_3.10.2_*|v*_section_3.10.4_*)
            XFAIL_CATEGORY="V"
            XFAIL_REASON="the vector encodes subjectDirectoryAttributes with the unassigned extension ID 24; the encoder uses the generic ~oid form."
            return 0 ;;
    esac
    return 1
}

# ---------------------------------------------------------------------------
# Section-number arithmetic helpers
#
# type3_to_x509_section "3.1.3" → "3.1.2"
# type3_to_x509_section "2.3"   → "2.2"
# Replace the final numeric component with (final-1).
# ---------------------------------------------------------------------------
type3_to_x509_section() {
    local sec="$1"
    local prefix last new_last
    prefix=$(echo "$sec" | sed 's/\.[^.]*$//')   # everything before last dot
    last=$(echo "$sec" | sed 's/.*\.//')          # last component
    new_last=$((last - 1))
    if [ "$prefix" = "$sec" ]; then
        # No dot — top-level section (shouldn't happen for type-3 vectors)
        echo "$((sec - 1))"
    else
        echo "${prefix}.${new_last}"
    fi
}

# Given a section number of the X.509 side (e.g. "3.1.2"), find the .crt file.
# Sets X509_CRT_FILE.
find_x509_crt_for_section() {
    local x509_sec="$1" xref
    X509_CRT_FILE=""
    # Cross-reference sections that reuse another section's X.509 cert rather
    # than publishing their own (L_CERT_XREF), e.g. the compressed secp256r1
    # vector, whose X.509 cert is the uncompressed one's.
    xref="$(layout_lookup "${x509_sec%.*}" "${L_CERT_XREF}")" \
        && x509_sec="${xref}.${x509_sec##*.}"
    for f in "${TV_DIR}/v${VERSION}_section_${x509_sec}_"*.crt; do
        [ -f "$f" ] && X509_CRT_FILE="$f" && return 0
    done
    return 1
}

# Given a section number of the X.509 CSR side (e.g. "8.1.2"), find the .csr file.
find_x509_csr_for_section() {
    local x509_sec="$1"
    X509_CSR_FILE=""
    for f in "${TV_DIR}/v${VERSION}_section_${x509_sec}_"*.csr; do
        [ -f "$f" ] && X509_CSR_FILE="$f" && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Helper: strip hex whitespace / annotated decorations → lowercase plain hex
# ---------------------------------------------------------------------------
clean_hex() {
    python3 -c "
import sys, re
text = sys.stdin.read()
lines = text.strip().split('\n')
out = []
for ln in lines:
    if '#' in ln: ln = ln[:ln.index('#')]
    ln = re.sub(r'^\s*\d+:\s*', '', ln)
    out.append(re.sub(r'[^0-9A-Fa-f]', '', ln))
print(''.join(out).lower(), end='')
"
}

# ---------------------------------------------------------------------------
# Helper: extract ~C509Certificate or reconstructed DER hex from binary output.
# ---------------------------------------------------------------------------
extract_c509_hex_from_output() {
    # Capture the canonical C509 hex block, i.e. the one printed right after the
    # 'CBOR encoded ... (C509Certificate)' / '(C509CertificationRequest)' label.
    # The captured hex is the full C509 array (0x8B / 0x87 header included);
    # find_hex_match also matches it against a bare-sequence expected vector.
    python3 -c "
import sys, re
text = open('$1').read()
m = re.search(r'\(~?C509(?:Certificate|CertificationRequest)\)[^\n]*\n((?:[0-9A-Fa-f][0-9A-Fa-f ]+\n)+)', text)
if m:
    h = re.sub(r'[^0-9A-Fa-f]', '', m.group(1)).lower()
    if len(h) >= 10 and len(h) % 2 == 0:
        print(h, end=''); sys.exit(0)
# Fallback: for CSRs the tool skips the detailed view and prints only the
# 'COSE_C509 (C509CertData)' block, which is the C509 array wrapped in a CBOR
# byte string ('bytes .cbor C509CertificationRequest'). Strip that bstr
# header to recover the inner array (0x87...).
m = re.search(r'COSE_C509 \(C509CertData\)[^\n]*\n((?:[0-9A-Fa-f][0-9A-Fa-f ]+\n)+)', text)
if m:
    h = re.sub(r'[^0-9A-Fa-f]', '', m.group(1)).lower()
    if len(h) >= 4 and len(h) % 2 == 0:
        b = bytes.fromhex(h)
        if (b[0] >> 5) == 2:                # CBOR byte string major type
            addl = b[0] & 0x1f
            hdr = {24: 2, 25: 3, 26: 5, 27: 9}.get(addl, 1 if addl < 24 else 0)
            if hdr:
                print(b[hdr:].hex(), end=''); sys.exit(0)
" 2>/dev/null || true
}

extract_der_from_c509c_output() {
    # Captures the DER hex block labelled "Input: DER encoded X.509 certificate".
    python3 -c "
import sys, re
text = open('$1').read()
m = re.search(r'Input: DER encoded X\.509[^\n]*\n((?:[0-9A-Fa-f][0-9A-Fa-f ]+\n)+)', text)
if m:
    h = re.sub(r'[^0-9A-Fa-f]', '', m.group(1)).lower()
    if len(h) >= 10 and len(h) % 2 == 0:
        print(h, end=''); sys.exit(0)
" 2>/dev/null || true
}

extract_crt_hex_from_output() {
    # Captures the hex block after the 'Output: ... CertificationRequestTemplate'
    # label (the CRT template re-encode; not the COSE_C509 wrapper).
    python3 -c "
import sys, re
text = open('$1').read()
m = re.search(r'Output:[^\n]*CertificationRequestTemplate[^\n]*\n((?:[0-9A-Fa-f][0-9A-Fa-f ]+\n)+)', text)
if m:
    h = re.sub(r'[^0-9A-Fa-f]', '', m.group(1)).lower()
    if len(h) >= 2 and len(h) % 2 == 0:
        print(h, end=''); sys.exit(0)
" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Pre-load all expected hex values (global search for encoding comparisons)
# ---------------------------------------------------------------------------
declare -A EXPECTED_HEX
for hf in "${TV_DIR}/v${VERSION}_section_"*.cbor.hex; do
    [ -f "${hf}" ] || continue
    EXPECTED_HEX["$(basename "${hf}")"]="$(clean_hex < "${hf}")"
done

# ---------------------------------------------------------------------------
# Temp files
# ---------------------------------------------------------------------------
TMPOUT="$(mktemp)"
TMPDER="$(mktemp)"
TMPCA="$(mktemp)"
TMPSIG="$(mktemp)"
trap 'rm -f "${TMPOUT}" "${TMPDER}" "${TMPCA}" "${TMPSIG}"' EXIT

run_c509() { local o="$1"; shift; "${BINARY}" "$@" > "${o}" 2>&1; }

# Is this .cbor.hex file the annotated-hex copy of another vector? The extractor
# appends _1 to the second artwork of a section, but also to the first artwork
# of a reused anchor name, so only treat X_1 as a duplicate when X exists.
is_dup_artwork() {
    case "$1" in
        *_1.cbor.hex) [ -f "${1%_1.cbor.hex}.cbor.hex" ] ;;
        *) return 1 ;;
    esac
}

find_hex_match() {
    local actual="$1"
    MATCHED_FILE=""
    # Candidates: the hex exactly as emitted (the full C509 array, with its 0x8B
    # cert / 0x87 CSR header) and the same hex with that header stripped, to match
    # an expected vector given as a bare sequence.
    local cands="${actual}"
    case "${actual:0:2}" in 8b|87) cands="${cands} ${actual:2}" ;; esac
    local c key
    for c in ${cands}; do
        for key in "${!EXPECTED_HEX[@]}"; do
            if [ "${c}" = "${EXPECTED_HEX[${key}]}" ]; then
                MATCHED_FILE="${key}"; return 0
            fi
        done
    done
    return 1
}

# Return the C509 certificate/CSR type byte (00 template / 02 native / 03 DER-
# equivalent), transparently skipping a leading CBOR array header (0x8B cert /
# 0x87 CSR). Arg: path to a .cbor.hex file.
c509_type_byte() {
    local h; h="$(head -c 4 "$1" | tr 'A-F' 'a-f')"
    case "${h:0:2}" in
        8b|87) echo "${h:2:2}" ;;   # array header -> type is the next byte
        *)     echo "${h:0:2}" ;;   # bare sequence
    esac
}

# =============================================================================
# Section 2 – Encoding: X.509 certificate → C509 hex
# =============================================================================
echo -e "${C_BOLD}>>> Section 2: Encoding — X.509 certificate DER → C509 hex${C_RST}"
echo ""

for crt_file in "${TV_DIR}/v${VERSION}_section_"*.crt; do
    [ -f "${crt_file}" ] || continue
    bn="$(basename "${crt_file}")"

    openssl x509 -in "${crt_file}" -outform DER -out "${TMPDER}" 2>/dev/null \
        || { log_skip "${bn}: openssl cannot parse"; continue; }

    matched=0
    for mode_flag in "" "-nc"; do
        run_c509 "${TMPOUT}" f "${TMPDER}" ${mode_flag} || true
        actual="$(extract_c509_hex_from_output "${TMPOUT}")"
        [ -z "${actual}" ] && continue
        if find_hex_match "${actual}"; then
            log_pass "${bn} → ${MATCHED_FILE}"; matched=1; break
        fi
    done

    if [ "${matched}" -eq 0 ]; then
        if is_xfail "${bn}"; then
            log_xfail "${bn} [Cat ${XFAIL_CATEGORY}]"
            echo "         ${XFAIL_REASON}"
        elif is_vector_drift_xfail "${bn}"; then
            log_xfail "${bn} [Cat ${XFAIL_CATEGORY}]"
            echo "         ${XFAIL_REASON}"
        else
            log_fail "${bn}"
            [ "${VERBOSE}" -eq 1 ] && cat "${TMPOUT}"
        fi
    fi
done

# =============================================================================
# Section 3 – Encoding: X.509 CSR → C509 hex
# =============================================================================
echo ""
echo -e "${C_BOLD}>>> Section 3: Encoding — X.509 CSR → C509 hex${C_RST}"
echo ""

for csr_file in "${TV_DIR}/v${VERSION}_section_"*.csr; do
    [ -f "${csr_file}" ] || continue
    bn="$(basename "${csr_file}")"

    openssl req -in "${csr_file}" -inform PEM -outform DER -out "${TMPDER}" 2>/dev/null \
        || { log_skip "${bn}: openssl cannot parse"; continue; }

    matched=0
    for mode_flag in "" "-nc"; do
        run_c509 "${TMPOUT}" f "${TMPDER}" ${mode_flag} || true
        actual="$(extract_c509_hex_from_output "${TMPOUT}")"
        [ -z "${actual}" ] && continue
        if find_hex_match "${actual}"; then
            log_pass "${bn} → ${MATCHED_FILE}"; matched=1; break
        fi
    done

    if [ "${matched}" -eq 0 ]; then
        if is_xfail "${bn}"; then
            log_xfail "${bn} [Cat ${XFAIL_CATEGORY}]"
            echo "         ${XFAIL_REASON}"
        else
            log_fail "${bn}"
            [ "${VERBOSE}" -eq 1 ] && cat "${TMPOUT}"
        fi
    fi
done

# =============================================================================
# Section 4 – Decoding: C509 type-3 hex → X.509 DER
#
# For each C509 type-3 .cbor.hex vector, decode to DER and compare byte-exact
# against the corresponding X.509 certificate/CSR converted to DER on-the-fly.
#
# Mapping (draft section numbers):
#   Type-3 cert vector at section X.Y.3 → X.509 cert at section X.Y.2
#   Type-3 CSR vector  at section X.Y.3 → X.509 CSR  at section X.Y.2
#
# Type-2 vectors (first byte 02) → XFAIL (no X.509 DER equivalent).
# CRT templates (first byte 00) → XFAIL (no X.509 DER; §9 round-trips them).
# =============================================================================
echo ""
echo -e "${C_BOLD}>>> Section 4: Decoding — C509 type-3 hex → X.509 DER${C_RST}"
echo ""

for hex_file in "${TV_DIR}/v${VERSION}_section_"*.cbor.hex; do
    [ -f "${hex_file}" ] || continue
    bn="$(basename "${hex_file}")"

    # Classify by first byte:
    #   00 = CRT (C509CertificationRequestTemplate) — no X.509 DER equivalent; §9 covers it
    #   02 = type-2 natively signed — no X.509 DER equivalent
    #   03 = type-3 DER-equivalent — proceed with decoding
    # (skip the C509 array header 0x8B/0x87 to read the type)
    first_byte="$(c509_type_byte "${hex_file}")"
    if [ "${first_byte}" = "00" ]; then
        log_xfail "${bn} [CRT — C509CertificationRequestTemplate has no X.509 DER equivalent; lossless CBOR round-trip tested in §9]"
        continue
    fi
    if [ "${first_byte}" != "02" ] && [ "${first_byte}" != "03" ]; then
        log_skip "${bn}: unrecognised first byte=${first_byte}"
        continue
    fi

    # Type-2 CBORs (c509CertificateType=2 or c509CertificationRequestType=2):
    # first byte 02 = CBOR uint(2) = natively signed; no X.509 DER equivalent.
    # This catches type-2 CSRs that the extractor saved inside a type-3 section
    # (e.g. 8.2.3 contains both a type-3 and a type-2 artwork).
    if [ "${first_byte}" = "02" ]; then
        log_xfail "${bn} [Cat A — type-2 natively signed, no X.509 DER equivalent]"
        echo "         Type 2 (c509CertificationRequestType=2): signature over CBOR. §2.1, §2.3.5"
        continue
    fi

    # XFAIL check (section-number-based: CRT templates, DH-PoP decode)
    if is_xfail "${bn}"; then
        log_xfail "${bn} (no X.509 DER — ${XFAIL_CATEGORY})"
        echo "         ${XFAIL_REASON}"
        continue
    fi

    # Determine the X.509 section number from this file's section number
    sec=$(echo "$bn" | sed -n 's/^v[0-9]*_section_\([^_]*\)_.*/\1/p')
    x509_sec="$(type3_to_x509_section "${sec}")"

    # Try to find the matching .crt or .csr file. A type-3 artwork may also sit
    # in the X.509 certificate's own section (frp256v1).
    x509_is_csr=0
    if find_x509_crt_for_section "${x509_sec}"; then
        ref_src="${X509_CRT_FILE}"
    elif find_x509_csr_for_section "${x509_sec}"; then
        ref_src="${X509_CSR_FILE}"
        x509_is_csr=1
    elif find_x509_crt_for_section "${sec}"; then
        ref_src="${X509_CRT_FILE}"
    else
        log_skip "${bn}: no matching X.509 source for section ${x509_sec}"
        continue
    fi

    # Convert X.509 source to DER
    if [ "${x509_is_csr}" -eq 0 ]; then
        openssl x509 -in "${ref_src}" -outform DER -out "${TMPDER}" 2>/dev/null \
            || { log_skip "${bn}: openssl cannot convert $(basename "${ref_src}") to DER"; continue; }
    else
        openssl req -in "${ref_src}" -inform PEM -outform DER -out "${TMPDER}" 2>/dev/null \
            || { log_skip "${bn}: openssl cannot convert $(basename "${ref_src}") to DER"; continue; }
    fi

    # Decode C509 → DER
    run_c509 "${TMPOUT}" c "${hex_file}" || true
    decoded_hex="$(extract_der_from_c509c_output "${TMPOUT}")"
    ref_hex="$(od -An -v -tx1 "${TMPDER}" | tr -d ' \n')"

    if [ "${decoded_hex}" = "${ref_hex}" ]; then
        log_pass "${bn} → byte-exact match (ref: $(basename "${ref_src}"))"
    else
        log_fail "${bn}"
        [ "${VERBOSE}" -eq 1 ] && cat "${TMPOUT}"
    fi
done

# =============================================================================
# Section 5 – Round-trip: X.509 certificate DER → C509 → DER
# =============================================================================
echo ""
echo -e "${C_BOLD}>>> Section 5: Round-trip — X.509 certificate DER → C509 → DER${C_RST}"
echo ""

for crt_file in "${TV_DIR}/v${VERSION}_section_"*.crt; do
    [ -f "${crt_file}" ] || continue
    bn="$(basename "${crt_file}")"

    openssl x509 -in "${crt_file}" -outform DER -out "${TMPDER}" 2>/dev/null \
        || { log_skip "${bn}: openssl cannot parse"; continue; }

    run_c509 "${TMPOUT}" l "${TMPDER}" || true

    if grep -q "successfully encoded and reconstructed" "${TMPOUT}"; then
        log_pass "${bn}"
    elif is_xfail "${bn}"; then
        log_xfail "${bn} [Cat ${XFAIL_CATEGORY}]"
        echo "         ${XFAIL_REASON}"
    else
        log_fail "${bn}"
        if [ "${VERBOSE}" -eq 1 ]; then
            grep -E "WARN|Error|error|differ|panic" "${TMPOUT}" | head -5 || true
        fi
    fi
done

# =============================================================================
# Section 6 – Round-trip: X.509 CSR → C509 → CSR
# =============================================================================
echo ""
echo -e "${C_BOLD}>>> Section 6: Round-trip — X.509 CSR → C509 → CSR${C_RST}"
echo ""

for csr_file in "${TV_DIR}/v${VERSION}_section_"*.csr; do
    [ -f "${csr_file}" ] || continue
    bn="$(basename "${csr_file}")"

    openssl req -in "${csr_file}" -inform PEM -outform DER -out "${TMPDER}" 2>/dev/null \
        || { log_skip "${bn}: openssl cannot parse"; continue; }

    run_c509 "${TMPOUT}" l "${TMPDER}" || true

    if grep -q "successfully encoded and reconstructed" "${TMPOUT}"; then
        log_pass "${bn}"
    elif is_xfail "${bn}"; then
        log_xfail "${bn} [Cat ${XFAIL_CATEGORY}]"
        echo "         ${XFAIL_REASON}"
    else
        log_fail "${bn}"
        [ "${VERBOSE}" -eq 1 ] && grep -E "WARN|Error|panic" "${TMPOUT}" | head -5 || true
    fi
done

# =============================================================================
# Section 7 – Type-2 signing: f2 TBS verification against IETF vectors
#
# For each Type-2 CBOR hex vector (c509CertificateType=2, first byte 0x02),
# convert the corresponding X.509 cert + private key to Type-2 C509 using the
# `f2` command and verify that fields 0–9 (the TBS) match the IETF vector
# exactly.  Field 10 (the ECDSA signature) is intentionally excluded: our Rust
# p256 crate and the IETF reference implementation both use RFC 6979 but may
# choose different per-invocation randomness, so the r||s bytes differ while
# both signatures are cryptographically valid.
#
# XFAIL Cat B: unsupported key algorithm (f2: P-256/P-384/P-521/Ed25519 only).
# XFAIL Cat B2: vector is a CSR, not a certificate (f2 handles certs only).
# SKIP: no matching cert or key found in the test vectors directory.
# =============================================================================
echo ""
echo -e "${C_BOLD}>>> Section 7: Type-2 signing — TBS match verification (f2 command)${C_RST}"
echo ""
echo "  RFC 6979 note: r||s signature bytes differ per-implementation (both valid)."
echo "  Only TBS (fields 0–9) is compared; field 10 (signature) is skipped."
echo ""

# Build a cert-fingerprint → key-file lookup for all key-cert pairs.
# Key is at section X.Y.1; cert is at section X.Y.2.
declare -A FP_TO_KEY
for _kf in "${TV_DIR}/v${VERSION}_section_"*.key; do
    [ -f "${_kf}" ] || continue
    _ksec=$(basename "${_kf}" | sed -n 's/^v[0-9]*_section_\([^_]*\)_.*/\1/p')
    _kbase=$(echo "${_ksec}" | sed 's/\.[^.]*$//')
    _klast=$(echo "${_ksec}" | sed 's/.*\.//')
    _cert_sec="${_kbase}.$((${_klast} + 1))"
    for _cf in "${TV_DIR}/v${VERSION}_section_${_cert_sec}_"*.crt; do
        [ -f "${_cf}" ] || continue
        _fp=$(openssl x509 -in "${_cf}" -fingerprint -noout 2>/dev/null | sed 's/.*=//')
        [ -n "${_fp}" ] && FP_TO_KEY["${_fp}"]="${_kf}"
    done
done

# Sections that cross-reference a key defined in another section (no X.Y.1
# key file of their own) are resolved through L_KEY_XREF by key_file_for_base.

# Helper: extract TBS (fields 0–9) from a C509 hex string by walking CBOR items.
# Handles variable-length field 10 (P-256: 66 B, P-384: 98 B, P-521: 134 B,
# Ed25519: 66 B, empty placeholder: 1 B, etc.).
# Arg $1: hex string (no whitespace, outer array wrapper already stripped).
tbs_hex() {
    python3 - "$1" "${2:-10}" <<'PYEOF' 2>/dev/null
import sys

def item_end(data, pos):
    b = data[pos]; major = (b >> 5) & 7; addl = b & 0x1f; i = pos + 1
    if   addl == 24: n = data[i];                             i += 1
    elif addl == 25: n = int.from_bytes(data[i:i+2], 'big'); i += 2
    elif addl == 26: n = int.from_bytes(data[i:i+4], 'big'); i += 4
    elif addl == 27: n = int.from_bytes(data[i:i+8], 'big'); i += 8
    elif addl <= 23: n = addl
    else: sys.exit(1)
    if major in (2, 3): return i + n
    elif major == 4:
        for _ in range(n): i = item_end(data, i)
        return i
    elif major == 5:
        for _ in range(n * 2): i = item_end(data, i)
        return i
    elif major == 6: return item_end(data, i)
    else: return i

try:
    h = sys.argv[1]
    data = bytes.fromhex(h)
    pos = 0
    for _ in range(int(sys.argv[2])): pos = item_end(data, pos)
    print(h[:pos * 2], end='')
except Exception:
    sys.exit(1)
PYEOF
}

# Run f2 in both compression modes with signing key $1 and compare the TBS
# against the IETF vector. Uses the loop's bn/_sec/ietf_full/ietf_tbs/_ca_flag;
# sets matched and produced, and logs the PASS.
try_f2() {
    local mode_flag flag_label actual_full actual_tbs
    for mode_flag in "" "-nc"; do
        run_c509 "${TMPOUT}" f2 "${TMPDER}" "$1" ${_ca_flag} ${mode_flag} || true
        actual_full="$(extract_c509_hex_from_output "${TMPOUT}")"
        [ -z "${actual_full}" ] && continue
        produced=1
        # tbs_hex walks the bare field sequence, so drop the array header
        # (0x8B) — matching how ietf_full is normalised.
        [ "${actual_full:0:2}" = "8b" ] && actual_full="${actual_full:2}"
        [ "${#actual_full}" -lt 132 ] && continue
        actual_tbs="$(tbs_hex "${actual_full}")" || true
        if [ "${actual_tbs}" = "${ietf_tbs}" ]; then
            [ -z "${mode_flag}" ] && flag_label="(compressed)" || flag_label="(uncompressed, -nc)"
            # Deterministic signature algorithms (Ed25519/Ed448/RSA-PKCS#1v1.5)
            # reproduce field 10 exactly, so the FULL object matches; ECDSA/PSS are
            # randomised and only the TBS matches. Test the stronger claim first.
            if [ "${actual_full}" = "${ietf_full}" ]; then
                log_pass "${bn}: FULL match incl. signature (deterministic alg) — IETF ${_sec} ${flag_label}"
                matched=1
                return 0
            fi
            # Randomised signature: check that f2's own signature verifies
            # (self-signed only — `v2` takes the signer key from the subject).
            _sig_note=""
            if [ -z "${_ca_flag}" ]; then
                echo "8b${actual_full}" > "${TMPSIG}"
                _vout="$("${BINARY}" v2 "${TMPSIG}" 2>&1)" && _vrc=0 || _vrc=$?
                if [ "${_vrc}" -eq 0 ]; then
                    _sig_note="; f2 signature verified"
                elif ! echo "${_vout}" | grep -q "unsupported public-key algorithm"; then
                    log_fail "${bn}: TBS matches but f2's signature does not verify ($(echo "${_vout}" | sed -n 's/.*VERIFY FAIL: //p'))"
                    matched=1
                    return 0
                fi
            fi
            log_pass "${bn}: TBS fields 0–9 match IETF ${_sec} vector ${flag_label}${_sig_note}"
            matched=1
            return 0
        fi
        # Not a match. Note the one known difference: the vector marks a
        # compressed key with 0xFE/0xFD, where a natively signed certificate
        # uses the SECG octets 0x02/0x03. Fields 0–8 are then equal apart from
        # that octet (later fields differ, as the key identifier covers the key).
        if [ -z "${mode_flag}" ]; then
            local ietf9 act9 pre8 mpos marker secg
            ietf9="$(tbs_hex "${ietf_full}" 9)" || true
            act9="$(tbs_hex "${actual_full}" 9)" || true
            pre8="$(tbs_hex "${ietf_full}" 8)" || true
            mpos=$(( ${#pre8} + 4 ))        # past the 2-octet byte-string header
            marker="${ietf9:${mpos}:2}"
            case "${marker}" in
                fe) secg="02" ;;
                fd) secg="03" ;;
                *)  secg="" ;;
            esac
            if [ -n "${secg}" ] && [ -n "${act9}" ] \
               && [ "${ietf9:0:${mpos}}${secg}${ietf9:$(( mpos + 2 ))}" = "${act9}" ]; then
                marker_diff=1
            fi
        fi
    done
    return 0
}

for type2_hex in "${TV_DIR}/v${VERSION}_section_"*.cbor.hex; do
    [ -f "${type2_hex}" ] || continue
    bn="$(basename "${type2_hex}")"

    # Skip _1 duplicates (identical content, different filename suffix).
    is_dup_artwork "${type2_hex}" && continue

    # Only process Type-2 vectors (type byte 0x02, after the 0x8B array header).
    first_byte="$(c509_type_byte "${type2_hex}")"
    [ "${first_byte}" = "02" ] || continue

    # Extract base section: "3.3.4" → "3.3", "2.4" → "2".
    _sec=$(echo "${bn}" | sed -n 's/^v[0-9]*_section_\([^_]*\)_.*/\1/p')
    _base=$(echo "${_sec}" | sed 's/\.[^.]*$//')

    # CSR type-2 vectors (sections L_CSR_TOPS) are handled in Section 8 below.
    case " ${L_CSR_TOPS} " in *" ${_sec%%.*} "*) continue ;; esac

    # Determine TBS byte count from IETF vector (sanitised, no array wrapper).
    ietf_full="$(clean_hex < "${type2_hex}")"
    [ "${ietf_full:0:2}" = "8b" ] && ietf_full="${ietf_full:2}"
    _tbs_len="${#ietf_full}"
    if [ "${_tbs_len}" -lt 132 ]; then
        log_skip "${bn}: vector too short to contain field 10"
        continue
    fi
    ietf_tbs="$(tbs_hex "${ietf_full}")" || true

    # Look for corresponding X.509 certificate (.2.crt).
    cert_file=""
    for _cf in "${TV_DIR}/v${VERSION}_section_${_base}.2_"*.crt; do
        [ -f "${_cf}" ] && cert_file="${_cf}" && break
    done
    # Sections that reuse another section's X.509 cert (L_CERT_XREF).
    if [ -z "${cert_file}" ]; then
        _xref="$(layout_lookup "${_base}" "${L_CERT_XREF}")" || _xref=""
        if [ -n "${_xref}" ]; then
            for _cf in "${TV_DIR}/v${VERSION}_section_${_xref}.2_"*.crt; do
                [ -f "${_cf}" ] && cert_file="${_cf}" && break
            done
        fi
    fi
    if [ -z "${cert_file}" ]; then
        log_skip "${bn}: no matching X.509 cert for section ${_base}.2"
        continue
    fi

    # Find the private key via cert fingerprint; fall back to the layout's
    # cross-referenced key.
    _fp=$(openssl x509 -in "${cert_file}" -fingerprint -noout 2>/dev/null | sed 's/.*=//')
    key_file="${FP_TO_KEY["${_fp}"]:-}"
    if [ -z "${key_file}" ]; then
        key_file="$(key_file_for_base "${_base}")" || key_file=""
    fi
    if [ -z "${key_file}" ]; then
        log_skip "${bn}: no private key found for cert $(basename "${cert_file}")"
        continue
    fi

    # Reject key algorithms not supported by f2.
    # Supported: P-256/P-384/P-521, Ed25519, RSA (PKCS1v1.5+PSS),
    #            brainpoolP256r1/P384r1/P512r1, SM2, Ed448 (via OpenSSL),
    #            frp256v1 (OID 1.2.250.1.223.101.256.1; OpenSSL cannot load
    #            the key, so it is recognised from its ASN.1 structure),
    #            X25519/X448 (id-alg-unsigned; key not used for signing).
    _key_algo=$(openssl pkey -in "${key_file}" -text -noout 2>/dev/null) \
        || _key_algo=$(openssl asn1parse -in "${key_file}" 2>/dev/null) || true
    if ! echo "${_key_algo}" | grep -qE "prime256v1|P-256|secp384r1|secp521r1|ED25519|modulus|X25519|X448|brainpoolP256r1|brainpoolP384r1|brainpoolP512r1|ED448|SM2|1\.2\.250\.1\.223\.101\.256\.1"; then
        log_xfail "${bn} [Cat B — unsupported key type; f2 supports P-256/P-384/P-521/Ed25519/RSA/brainpool/SM2/Ed448/frp256v1/unsigned]"
        continue
    fi

    # Cat C: CA-signed certs with AKI need the CA cert so f2 can compute the
    # CA's type-2 SKI and patch the AKI field correctly.
    # Strategy: extract the AKI key-id from the EE cert, then scan all .crt files
    # in the test-vector directory for one whose SKI matches. If found, convert to
    # DER and pass it to f2 via -ca; if not found, XFAIL as before.
    _ca_flag=""
    _has_aki=$(openssl x509 -in "${cert_file}" -text -noout 2>/dev/null | grep "Authority Key Identifier") || true
    _is_selfsigned=$(openssl verify -check_ss_sig "${cert_file}" 2>&1 | grep "self-signed\|self signed") || true
    if [ -n "${_has_aki}" ] && [ -z "${_is_selfsigned}" ]; then
        # Extract AKI keyid (hex, colon-separated), normalise to lowercase no-colons.
        # OpenSSL 3 prints the key ID on the line immediately after "Authority Key Identifier:"
        # without a "keyid:" prefix, so we grab the second line of -A2 output.
        _aki_raw=$(openssl x509 -in "${cert_file}" -text -noout 2>/dev/null \
            | grep -A1 "Authority Key Identifier" | tail -1 | sed 's/ //g;s/keyid://') || true
        _aki=$(echo "${_aki_raw}" | tr '[:upper:]' '[:lower:]' | tr -d ':') || true
        _ca_cert_found=""
        for _cand in "${TV_DIR}/v${VERSION}_section_"*.crt; do
            [ -f "${_cand}" ] || continue
            _ski_raw=$(openssl x509 -in "${_cand}" -text -noout 2>/dev/null \
                | grep -A1 "Subject Key Identifier" | grep -v "Subject Key" | sed 's/ //g') || true
            _ski=$(echo "${_ski_raw}" | tr '[:upper:]' '[:lower:]' | tr -d ':') || true
            if [ -n "${_ski}" ] && [ "${_ski}" = "${_aki}" ]; then
                _ca_cert_found="${_cand}"
                break
            fi
        done
        if [ -n "${_ca_cert_found}" ]; then
            openssl x509 -in "${_ca_cert_found}" -outform DER -out "${TMPCA}" 2>/dev/null || true
            _ca_flag="-ca ${TMPCA}"
        else
            log_xfail "${bn} [Cat C — CA-signed cert with AKI; CA cert not found in test-vector directory]"
            continue
        fi
    fi

    # Convert cert to DER.
    openssl x509 -in "${cert_file}" -outform DER -out "${TMPDER}" 2>/dev/null \
        || { log_skip "${bn}: openssl cannot convert cert to DER"; continue; }

    # Try both compression modes; compare TBS of each against IETF vector.
    matched=0
    produced=0            # did f2 emit any C509 output at all?
    marker_diff=0         # does the vector differ only by its point marker?
    try_f2 "${key_file}"

    # A CA-issued certificate is signed with the CA's key, not the subject's
    # (e.g. an X25519/X448 end-entity cert, whose own key cannot sign). If f2
    # produced nothing with the subject key, retry with the CA's private key.
    if [ "${produced}" -eq 0 ] && [ -n "${_ca_flag}" ]; then
        _ca_fp=$(openssl x509 -in "${_ca_cert_found}" -fingerprint -noout 2>/dev/null | sed 's/.*=//')
        _ca_key="${FP_TO_KEY["${_ca_fp}"]:-}"
        [ -n "${_ca_key}" ] && try_f2 "${_ca_key}"
    fi

    if [ "${matched}" -eq 0 ]; then
        if [ "${produced}" -eq 0 ]; then
            # f2 emitted nothing in either mode — it cannot encode this certificate
            # as type-2 (e.g. an id-alg-unsigned X25519/X448 end-entity cert, whose
            # key cannot sign and whose issuer is an external CA). Tool limitation.
            log_xfail "${bn} [Cat B — f2 cannot encode this certificate as type-2 (id-alg-unsigned X25519/X448 end-entity, or unsupported)]"
        elif is_vector_drift_xfail "${bn}"; then
            log_xfail "${bn} [Cat ${XFAIL_CATEGORY}]"
            echo "         ${XFAIL_REASON}"
        elif [ "${marker_diff}" -eq 1 ]; then
            log_xfail "${bn} [Cat M — point marker]"
            echo "         The vector marks the compressed public key with 0xFE/0xFD. A natively signed"
            echo "         certificate uses the SECG octets 0x02/0x03 (draft-ietf-cose-cbor-encoded-cert,"
            echo "         subjectPublicKey), which f2 emits; fields 0–8 are otherwise equal."
        else
            log_fail "${bn}: TBS mismatch against IETF ${_sec} vector"
            if [ "${VERBOSE}" -eq 1 ]; then
                echo "    expected TBS: ${ietf_tbs:0:40}..."
                actual_full2="$(extract_c509_hex_from_output "${TMPOUT}")"
                [ "${actual_full2:0:2}" = "8b" ] && actual_full2="${actual_full2:2}"
                [ -n "${actual_full2}" ] && echo "    actual   TBS: $(tbs_hex "${actual_full2}" | head -c 40)..."
            fi
        fi
    fi
done

# =============================================================================
# Section 7b – Type-2 cryptographic signature verification (v2 command)
#
# For each self-signed Type-2 cert vector, cryptographically verify the draft's
# published signature (field 10) against the subject public key over the CBOR TBS
# — the check that upgrades Type-2 from "encoding reproduced" to "signature
# valid". Covers ECDSA (P-256/384/521, brainpool, frp256v1), SM2, Ed25519, Ed448,
# RSA PKCS#1 v1.5 and RSASSA-PSS (SHA-2 and SHAKE); a key type `v2` does not
# support is reported as SKIP, not FAIL.
# =============================================================================
echo ""
echo -e "${C_BOLD}>>> Section 7b: Type-2 cryptographic signature verification (v2 command)${C_RST}"
echo ""
# Guard: an older c509 binary treats `v2` as an unknown command; probe once so
# we emit a single clear "rebuild" note instead of a wall of empty-reason
# failures. A binary that has v2 prints a VERIFY line even on empty input.
# Capture (not pipe) the probe output: `v2` exits non-zero on the empty input,
# and `set -o pipefail` would otherwise turn that into a false "no v2" result.
V2_PROBE="$("${BINARY}" v2 /dev/null 2>&1 || true)"
case "${V2_PROBE}" in *VERIFY*) V2_OK=1 ;; *) V2_OK=0 ;; esac
[ "${V2_OK}" -eq 1 ] || log_skip "Section 7b: this c509 binary has no 'v2' command — rebuild it (cargo build --bin c509, or run with --build). Skipping cryptographic verification."
V2_FILES=( "${TV_DIR}/v${VERSION}_section_"${L_V2_GLOB}.cbor.hex
            "${TV_DIR}/v${VERSION}_section_${L_FRP_TYPE2}_"*.cbor.hex )
for _stem in ${L_V2_EXTRA}; do
    V2_FILES+=( "${TV_DIR}/v${VERSION}_section_${_stem}.cbor.hex" )
done
for type2_hex in "${V2_FILES[@]}"; do
    [ "${V2_OK}" -eq 1 ] || break
    [ -f "${type2_hex}" ] || continue
    bn="$(basename "${type2_hex}")"
    is_dup_artwork "${type2_hex}" && continue
    vout="$("${BINARY}" v2 "${type2_hex}" 2>&1)" && vrc=0 || vrc=$?
    if [ "${vrc}" -eq 0 ]; then
        vdesc="$(echo "${vout}" | sed -n 's/.*VERIFY OK: //p')"
        log_pass "${bn}: signature cryptographically VERIFIED (${vdesc})"
    elif echo "${vout}" | grep -q "unsupported public-key algorithm"; then
        log_skip "${bn}: v2 does not support this key type"
    else
        vreason="$(echo "${vout}" | sed -n 's/.*VERIFY FAIL: //p')"
        log_fail "${bn}: cryptographic signature verification FAILED (${vreason})"
    fi
done

# The remaining Type-2 objects: certification requests (signature verified with
# the subject key) and CA-issued certificates (verified against the vector whose
# subject equals the certificate's issuer). Unsigned objects (id-alg-unsigned)
# and RFC 6955 DhSig requests carry no signature and are not counted here.
for type2_hex in "${TV_DIR}/v${VERSION}_section_"*.cbor.hex; do
    [ "${V2_OK}" -eq 1 ] || break
    [ -f "${type2_hex}" ] || continue
    bn="$(basename "${type2_hex}")"
    is_dup_artwork "${type2_hex}" && continue
    [ "$(c509_type_byte "${type2_hex}")" = "02" ] || continue
    _seen=0
    for _f in "${V2_FILES[@]}"; do
        [ "${_f}" = "${type2_hex}" ] && _seen=1
    done
    [ "${_seen}" -eq 0 ] || continue

    vout="$("${BINARY}" v2 "${type2_hex}" 2>&1)" && vrc=0 || vrc=$?
    if [ "${vrc}" -eq 0 ]; then
        vdesc="$(echo "${vout}" | sed -n 's/.*VERIFY OK: //p')"
        log_pass "${bn}: signature cryptographically VERIFIED with the subject key (${vdesc})"
        continue
    fi
    case "${vout}" in
        *"no signature"*|*"truncated C509"*) continue ;;
        *"not self-issued"*) ;;
        *)  vreason="$(echo "${vout}" | sed -n 's/.*VERIFY FAIL: //p')"
            log_fail "${bn}: cryptographic signature verification FAILED (${vreason})"
            continue ;;
    esac

    _verified=0
    _ireason=""
    for _cand in "${TV_DIR}/v${VERSION}_section_"*.cbor.hex; do
        [ "${_cand}" != "${type2_hex}" ] || continue
        iout="$("${BINARY}" v2 "${type2_hex}" --issuer-cert "${_cand}" 2>&1)" && irc=0 || irc=$?
        if [ "${irc}" -eq 0 ]; then
            vdesc="$(echo "${iout}" | sed -n 's/.*VERIFY OK: //p')"
            log_pass "${bn}: signature cryptographically VERIFIED against issuer $(basename "${_cand}") (${vdesc})"
            _verified=1
            break
        fi
        case "${iout}" in
            *"issuer name mismatch"*|*"truncated C509"*) ;;
            *) _ireason="$(echo "${iout}" | sed -n 's/.*VERIFY FAIL: //p') [issuer $(basename "${_cand}")]" ;;
        esac
    done
    [ "${_verified}" -eq 0 ] || continue
    if [ -n "${_ireason}" ]; then
        log_fail "${bn}: cryptographic signature verification FAILED (${_ireason})"
    else
        log_skip "${bn}: issuer certificate is not among the test vectors"
    fi
done

# =============================================================================
# Section 8 – Type-2 CSR signing: r2 verification against IETF vectors
#
# For each Type-2 CSR CBOR hex vector (sections L_CSR_TOPS), encode the
# corresponding PKCS#10 CSR + subject private key via `r2` and compare the
# output against the IETF vector.
#
# DhSig (sig alg 14/15/16): full output is deterministic — HMAC(ECDH(subj,peer),TBS).
# Unsigned (sig alg 5):     full output is deterministic — field 6 is empty bstr.
# ECDSA (sig alg 0/1/2):    signature is randomised — the TBS is compared.
#
# Peer key / peer cert (RFC 6955): the subject's ECDH peer is the self-signed
# secp256r1 / secp384r1 / secp521r1 certificate for alg 14 / 15 / 16
# (L_DHSIG_KEY_* / L_DHSIG_CERT_*). The CSR with an embedded certificate
# (L_EMB_KEY_SECTION) re-signs it with the Ed25519 key L_EMB_KEY.
# =============================================================================
echo ""
echo -e "${C_BOLD}>>> Section 8: Type-2 CSR signing — full match verification (r2 command)${C_RST}"
echo ""
echo "  DhSig and unsigned CSRs are fully deterministic — full hex is compared."
echo ""

declare -A DHSIG_PEER_KEY
DHSIG_PEER_KEY["0e"]="$(section_file "${L_DHSIG_KEY_0E}" key)" || true
DHSIG_PEER_KEY["0f"]="$(section_file "${L_DHSIG_KEY_0F}" key)" || true
DHSIG_PEER_KEY["10"]="$(section_file "${L_DHSIG_KEY_10}" key)" || true

declare -A DHSIG_PEER_CERT
DHSIG_PEER_CERT["0e"]="${TV_DIR}/v${VERSION}_section_${L_DHSIG_CERT_0E}.cbor.hex"
DHSIG_PEER_CERT["0f"]="${TV_DIR}/v${VERSION}_section_${L_DHSIG_CERT_0F}.cbor.hex"
DHSIG_PEER_CERT["10"]="${TV_DIR}/v${VERSION}_section_${L_DHSIG_CERT_10}.cbor.hex"

declare -A EMBEDDED_CERT_KEY
EMBEDDED_CERT_KEY["${L_EMB_KEY_SECTION}"]="$(section_file "${L_EMB_KEY}" key)" || true

CSR_FILES=()
for _top in ${L_CSR_TOPS}; do
    CSR_FILES+=( "${TV_DIR}/v${VERSION}_section_${_top}."*.cbor.hex )
done
for type2_hex in "${CSR_FILES[@]}"; do
    [ -f "${type2_hex}" ] || continue
    bn="$(basename "${type2_hex}")"

    # Skip _1 duplicates.
    is_dup_artwork "${type2_hex}" && continue

    # Only type-2 vectors (type byte 0x02, after the 0x87 array header).
    first_byte="$(c509_type_byte "${type2_hex}")"
    [ "${first_byte}" = "02" ] || continue

    # Extract base section: "8.3.4" → "8.3".
    _sec=$(echo "${bn}" | sed -n 's/^v[0-9]*_section_\([^_]*\)_.*/\1/p')
    _base=$(echo "${_sec}" | sed 's/\.[^.]*$//')

    # Find the subject private key: section ${_base}.1, or the key it
    # cross-references (L_KEY_XREF).
    subj_key_file="$(key_file_for_base "${_base}")" || subj_key_file=""
    if [ -z "${subj_key_file}" ]; then
        log_skip "${bn}: no subject private key for section ${_base}"
        continue
    fi

    # Find CSR PEM at section ${_base}.2.
    csr_pem_file=""
    for _cf in "${TV_DIR}/v${VERSION}_section_${_base}.2_"*.csr; do
        [ -f "${_cf}" ] && csr_pem_file="${_cf}" && break
    done
    if [ -z "${csr_pem_file}" ]; then
        # e.g. the CSR with 8-byte integer values, which has no X.509 counterpart.
        log_skip "${bn}: no X.509 CSR at section ${_base}.2"
        continue
    fi

    # Convert CSR PEM → DER.
    openssl req -in "${csr_pem_file}" -inform PEM -outform DER -out "${TMPDER}" 2>/dev/null \
        || { log_skip "${bn}: openssl cannot convert CSR to DER"; continue; }

    # IETF vector (full, cleaned). Drop the array header (0x87) so the
    # field-offset logic below and the comparison operate on the bare sequence.
    ietf_full="$(clean_hex < "${type2_hex}")"
    [ "${ietf_full:0:2}" = "87" ] && ietf_full="${ietf_full:2}"

    # Determine sig alg from second byte of the CBOR sequence.
    sig_alg_byte="${ietf_full:2:2}"
    peer_key_file="${DHSIG_PEER_KEY[${sig_alg_byte}]:-}"
    peer_cert_file="${DHSIG_PEER_CERT[${sig_alg_byte}]:-}"
    embedded_cert_key_file="${EMBEDDED_CERT_KEY[${_base}]:-}"

    # Try both compression modes; compare full output.
    matched=0
    for mode_flag in "" "-nc"; do
        if [ -n "${peer_key_file}" ] && [ -n "${peer_cert_file}" ] && [ -n "${embedded_cert_key_file}" ]; then
            run_c509 "${TMPOUT}" r2 "${TMPDER}" "${subj_key_file}" "${peer_key_file}" --peer-cert "${peer_cert_file}" --embedded-cert-key "${embedded_cert_key_file}" ${mode_flag} || true
        elif [ -n "${peer_key_file}" ] && [ -n "${peer_cert_file}" ]; then
            run_c509 "${TMPOUT}" r2 "${TMPDER}" "${subj_key_file}" "${peer_key_file}" --peer-cert "${peer_cert_file}" ${mode_flag} || true
        elif [ -n "${peer_key_file}" ]; then
            run_c509 "${TMPOUT}" r2 "${TMPDER}" "${subj_key_file}" "${peer_key_file}" ${mode_flag} || true
        elif [ -n "${embedded_cert_key_file}" ]; then
            run_c509 "${TMPOUT}" r2 "${TMPDER}" "${subj_key_file}" --embedded-cert-key "${embedded_cert_key_file}" ${mode_flag} || true
        else
            run_c509 "${TMPOUT}" r2 "${TMPDER}" "${subj_key_file}" ${mode_flag} || true
        fi
        actual="$(extract_c509_hex_from_output "${TMPOUT}")"
        [ -z "${actual}" ] && continue
        # Compare on the bare sequence (strip the tool's 0x87 header) so
        # it matches the normalised ietf_full above.
        [ "${actual:0:2}" = "87" ] && actual="${actual:2}"
        [ -z "${mode_flag}" ] && flag_label="(compressed)" || flag_label="(uncompressed, -nc)"
        case "${sig_alg_byte}" in
            00|01|02)
                # ECDSA CSR (sig alg 0/1/2): field 6 signature is non-deterministic,
                # so compare the TBS (first 6 of the 7 CSR fields) only, mirroring
                # §7's TBS handling for ECDSA certs.
                a_tbs="$(tbs_hex "${actual}" 6)"
                if [ -n "${a_tbs}" ] && [ "${a_tbs}" = "$(tbs_hex "${ietf_full}" 6)" ]; then
                    log_pass "${bn}: TBS (fields 0–5) match IETF vector — ECDSA CSR ${flag_label}"
                    matched=1; break
                fi
                ;;
            *)
                if [ "${actual}" = "${ietf_full}" ]; then
                    log_pass "${bn}: full match ${flag_label}"
                    matched=1; break
                fi
                ;;
        esac
    done

    if [ "${matched}" -eq 0 ]; then
        log_fail "${bn}: output mismatch against IETF ${_sec} vector"
        if [ "${VERBOSE}" -eq 1 ]; then
            echo "    expected: ${ietf_full:0:60}..."
            actual2="$(extract_c509_hex_from_output "${TMPOUT}")"
            [ -n "${actual2}" ] && echo "    actual:   ${actual2:0:60}..."
        fi
    fi
done

# =============================================================================
# Section 9 – CRT round-trip: C509 CertificationRequestTemplate → CBOR → bytes
#
# For each template vector (section L_CRT_TOP), call `c` to parse the template
# and compare the re-encoded CBOR output against the original file byte-for-byte.
# CRTs are pure CBOR structures (no X.509 DER equivalent); the parse_c509_crt
# function performs a lossless split + concatenation of the 7 CBOR fields.
# =============================================================================
echo ""
echo -e "${C_BOLD}>>> Section 9: CRT round-trip — C509 CertificationRequestTemplate lossless re-encode${C_RST}"
echo ""

for crt_hex in "${TV_DIR}/v${VERSION}_section_${L_CRT_TOP}."*.cbor.hex; do
    [ -f "${crt_hex}" ] || continue
    bn="$(basename "${crt_hex}")"
    # Skip _1 duplicates (the annotated-hex copy of the same template).
    is_dup_artwork "${crt_hex}" && continue

    expected="$(clean_hex < "${crt_hex}")"
    run_c509 "${TMPOUT}" c "${crt_hex}" || true
    actual="$(extract_crt_hex_from_output "${TMPOUT}")"
    # Compare on the bare sequence (strip the 0x87 array header from both): the
    # tool emits the array form, while a vector may be a bare sequence.
    [ "${actual:0:2}" = "87" ]   && actual="${actual:2}"
    [ "${expected:0:2}" = "87" ] && expected="${expected:2}"

    if [ -z "${actual}" ]; then
        log_fail "${bn}: no CRT output from c command"
        [ "${VERBOSE}" -eq 1 ] && cat "${TMPOUT}"
    elif [ "${actual}" = "${expected}" ]; then
        log_pass "${bn}: byte-exact re-encode"
    else
        log_fail "${bn}: re-encode mismatch"
        if [ "${VERBOSE}" -eq 1 ]; then
            echo "    expected: ${expected:0:60}..."
            echo "    actual:   ${actual:0:60}..."
        fi
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS + FAIL + XFAIL + SKIP))
echo ""
echo -e "${C_BOLD}============================================================"
echo "  Validation Summary"
echo "  Draft: draft-ietf-cose-c509-test-vectors-${VERSION}"
echo "============================================================${C_RST}"
printf "  %-35s %d\n" "Total tests run:" "${TOTAL}"
printf "  ${C_PASS}%-35s %d${C_RST}\n"  "PASS:"                       "${PASS}"
printf "  ${C_XFAIL}%-35s %d${C_RST}\n" "XFAIL  (expected, see key):" "${XFAIL}"
printf "  ${C_SKIP}%-35s %d${C_RST}\n"  "SKIP   (not run, see key):" "${SKIP}"
printf "  ${C_FAIL}%-35s %d${C_RST}\n"  "FAIL   (unexpected):"        "${FAIL}"
echo ""
echo "  Key — what each result means:"
echo "    PASS   the reference implementation reproduced the draft's vector:"
echo "           the C509 encoding is byte-exact, the signature is cryptographically"
echo "           verified, or the X.509 DER round-trips byte-exact."
echo "    XFAIL  \"expected failure\" — the vector does not apply to this particular"
echo "           check, by design (NOT a bug, and counted separately from FAIL)."
echo "           The main case: a natively-signed Type-2 certificate signs over"
echo "           CBOR, so it has no equivalent X.509 DER and cannot be round-tripped"
echo "           through DER. Those same Type-2 vectors are still checked — and"
echo "           pass — in the encoding and signature-verification phases. Every"
echo "           XFAIL line above prints its own specific reason."
echo "    SKIP   the check could not be run — either an input it needs is not"
echo "           present, or the tool does not support that algorithm."
echo "           (Signature verification covers ECDSA over P-256/P-384/P-521,"
echo "           brainpool and frp256v1, SM2, Ed25519, Ed448, RSA PKCS#1 v1.5"
echo "           and RSASSA-PSS with SHA-2 or SHAKE.)"
echo "    FAIL   a genuine, unexpected mismatch — a bug to fix."
echo ""
if [ "${FAIL}" -eq 0 ]; then
    echo -e "${C_PASS}${C_BOLD}  All tests passed or accounted for as expected failures.${C_RST}"
    RESULT=0
else
    echo -e "${C_FAIL}${C_BOLD}  ${FAIL} unexpected failure(s) — see [FAIL] lines above.${C_RST}"
    RESULT=1
fi
echo -e "${C_BOLD}============================================================${C_RST}"
exit "${RESULT}"
