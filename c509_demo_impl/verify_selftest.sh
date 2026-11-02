#!/usr/bin/env bash
# Self-test of the `v2` command against the draft-03 test vectors: one
# self-signed type-2 certificate per signature-algorithm family must verify,
# a tampered signature must be rejected, and a key that cannot sign (X25519)
# must be reported as unsupported. Run fetch_test_vectors.sh 03 first.
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

v() { echo "$TV/v03_section_$1.cbor.hex"; }

check "RSA PKCS#1 v1.5 SHA-256 verifies"   0 "$BIN" v2 "$(v 4.1.4_c509_selfsign_rsa)"
check "P-256 self-signed verifies"         0 "$BIN" v2 "$(v 4.3.4_c509_selfsign_secp256r1)"
check "P-256 compressed verifies"          0 "$BIN" v2 "$(v 4.4.4_c509_selfsign_compress_secp256r1)"
check "P-384 self-signed verifies"         0 "$BIN" v2 "$(v 4.5.4_c509_selfsign_secp384r1)"
check "P-521 self-signed verifies"         0 "$BIN" v2 "$(v 4.6.4_c509_selfsign_secp521r1)"
check "SM2 self-signed verifies"           0 "$BIN" v2 "$(v 4.7.4_c509_selfsign_sm2p256v1)"
check "brainpoolP256r1 (SHAKE128) verifies" 0 "$BIN" v2 "$(v 4.8.4_c509_selfsign_brainpoolp256r1)"
check "brainpoolP384r1 verifies"           0 "$BIN" v2 "$(v 4.9.4_c509_selfsign_brainpoolp384r1)"
check "brainpoolP512r1 (SHAKE256) verifies" 0 "$BIN" v2 "$(v 4.10.4_c509_selfsign_brainpoolp512r1)"
check "frp256v1 self-signed verifies"      0 "$BIN" v2 "$(v 4.11.3_c509_selfsign_frp256v1)"
check "Ed25519 self-signed verifies"       0 "$BIN" v2 "$(v 4.14.4_c509_selfsign_ed25519)"
check "Ed448 self-signed verifies"         0 "$BIN" v2 "$(v 4.15.4_c509_selfsign_ed448)"
check "RSASSA-PSS SHA-256 verifies"        0 "$BIN" v2 "$(v 5.18.4_c509_selfsign_rsassa_pss_sha256)"
check "RSASSA-PSS SHAKE128 verifies"       0 "$BIN" v2 "$(v 5.21.4_c509_selfsign_rsassa_pss_shake128)"
check "RSASSA-PSS SHAKE256 verifies"       0 "$BIN" v2 "$(v 5.22.4_c509_selfsign_rsassa_pss_shake256)"
check "X25519 subject key -> unsupported"  1 "$BIN" v2 "$(v 4.12.4_c509_ee_x25519)"

# Tamper check: flip the last hex digit of the P-256 signature.
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

hexdata=$(sed 's/[[:space:]]*$//' "$(v 4.3.4_c509_selfsign_secp256r1)")
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
