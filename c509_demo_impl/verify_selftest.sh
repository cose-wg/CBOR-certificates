#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${SCRIPT_DIR}/target/debug/c509"
TV="${SCRIPT_DIR}/../test_vectors"

if [ ! -x "$BIN" ]; then
  echo "Error: binary not found. Please run 'cargo build' first."
  exit 1
fi

pass=0
fail=0

check() { # args: <description> <expected_exit> <cmd...>
  local desc="$1" want="$2"; shift 2
  "$@" >/dev/null 2>&1; local got=$?
  if [ "$got" -eq "$want" ]; then echo "  PASS $desc"; pass=$((pass+1));
  else echo "  FAIL $desc (exit $got, wanted $want)"; fail=$((fail+1)); fi
}

check "P-256 self-signed verifies"        0 "$BIN" v2 "$TV/v02_section_3.3.4_c509_selfsign_secp256r1.cbor.hex"
check "P-256 compressed verifies"         0 "$BIN" v2 "$TV/v02_section_3.4.4_c509_selfsign_compress_secp256r1.cbor.hex"
check "P-384 self-signed verifies"        0 "$BIN" v2 "$TV/v02_section_3.5.4_c509_selfsign_secp384r1.cbor.hex"
check "P-521 self-signed verifies"        0 "$BIN" v2 "$TV/v02_section_3.6.4_c509_selfsign_secp521r1.cbor.hex"
check "Ed25519 self-signed verifies"      0 "$BIN" v2 "$TV/v02_section_3.14.4_c509_selfsign_ed25519.cbor.hex"
check "brainpoolP384r1 -> unsupported"    1 "$BIN" v2 "$TV/v02_section_3.9.4_c509_selfsign_brainpoolp384r1.cbor.hex"

# Tamper check
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

hexdata=$(sed 's/[[:space:]]*$//' "$TV/v02_section_3.3.4_c509_selfsign_secp256r1.cbor.hex")
last_char="${hexdata: -1}"
if [ "$last_char" = "0" ]; then
  tampered_hex="${hexdata%?}1"
else
  tampered_hex="${hexdata%?}0"
fi

echo "$tampered_hex" > "$tmpfile"
check "tampered P-256 signature rejected"  1 "$BIN" v2 "$tmpfile"

echo "verify_selftest: $pass passed, $fail failed"
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
