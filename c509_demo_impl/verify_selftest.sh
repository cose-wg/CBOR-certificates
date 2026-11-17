#!/usr/bin/env bash
# Self-test of the `v2` command against the test vectors: one self-signed
# type-2 certificate per signature-algorithm family, a CA-issued certificate and
# a certification request must verify; a tampered signature, a wrong issuer and
# a CA-issued certificate given without its issuer must be rejected.
# Run fetch_test_vectors.sh first.
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

v() { echo "$TV/v04_section_$1.cbor.hex"; }

check "RSA PKCS#1 v1.5 SHA-256 verifies"   0 "$BIN" v2 "$(v 3.1.4_c509_selfsign_rsa)"
check "P-256 self-signed verifies"         0 "$BIN" v2 "$(v 3.3.4_c509_selfsign_secp256r1)"
check "P-256 compressed verifies"          0 "$BIN" v2 "$(v 3.4.4_c509_selfsign_compress_secp256r1)"
check "P-384 self-signed verifies"         0 "$BIN" v2 "$(v 3.5.4_c509_selfsign_secp384r1)"
check "P-521 self-signed verifies"         0 "$BIN" v2 "$(v 3.6.4_c509_selfsign_secp521r1)"
check "SM2 self-signed verifies"           0 "$BIN" v2 "$(v 3.7.4_c509_selfsign_sm2p256v1)"
check "brainpoolP256r1 (SHAKE128) verifies" 0 "$BIN" v2 "$(v 3.8.4_c509_selfsign_brainpoolp256r1)"
check "brainpoolP384r1 verifies"           0 "$BIN" v2 "$(v 3.9.4_c509_selfsign_brainpoolp384r1)"
check "brainpoolP512r1 (SHAKE256) verifies" 0 "$BIN" v2 "$(v 3.10.4_c509_selfsign_brainpoolp512r1)"
check "frp256v1 self-signed verifies"      0 "$BIN" v2 "$(v 3.11.3_c509_selfsign_frp256v1)"
check "Ed25519 self-signed verifies"       0 "$BIN" v2 "$(v 3.14.4_c509_selfsign_ed25519)"
check "Ed448 self-signed verifies"         0 "$BIN" v2 "$(v 3.15.4_c509_selfsign_ed448)"
check "RSASSA-PSS SHA-256 verifies"        0 "$BIN" v2 "$(v 4.18.4_c509_selfsign_rsassa_pss_sha256)"
check "RSASSA-PSS SHAKE128 verifies"       0 "$BIN" v2 "$(v 4.21.4_c509_selfsign_rsassa_pss_shake128)"
check "RSASSA-PSS SHAKE256 verifies"       0 "$BIN" v2 "$(v 4.22.4_c509_selfsign_rsassa_pss_shake256)"
check "CA-issued X25519 cert verifies"     0 "$BIN" v2 "$(v 3.12.4_c509_ee_x25519)" --issuer-cert "$(v 2.4_c509_ca)"
check "CA-issued X448 cert verifies"       0 "$BIN" v2 "$(v 3.13.4_c509_ee_x448)" --issuer-cert "$(v 2.4_c509_ca)"
check "ECDSA CSR verifies"                 0 "$BIN" v2 "$(v 9.1.4_c509csr_ecdsa_p256)"
check "CA-issued cert without issuer rejected" 1 "$BIN" v2 "$(v 3.12.4_c509_ee_x25519)"
check "wrong issuer rejected"              1 "$BIN" v2 "$(v 3.12.4_c509_ee_x25519)" --issuer-cert "$(v 3.14.4_c509_selfsign_ed25519)"
check "unsigned CSR has nothing to verify" 1 "$BIN" v2 "$(v 9.6.4_c509csr_x25519)"

# Tamper check: flip the last hex digit of the P-256 signature.
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

hexdata=$(sed 's/[[:space:]]*$//' "$(v 3.3.4_c509_selfsign_secp256r1)")
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
