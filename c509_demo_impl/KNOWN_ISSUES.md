# Known Issues and Limitations

Reference implementation of draft-ietf-cose-cbor-encoded-cert, aligned with
**draft-20** (RFC-track).

## Test Vector Status (default: draft-ietf-cose-c509-test-vectors-02)

`validate_c509.sh` is **version-agnostic**: file pairing, the C509 type byte, and
the hex comparisons transparently handle the draft-20 CBOR-array header
(`0x8B` cert / `0x87` CSR), so it runs clean against draft-02 (default) and still
against draft-01 (`--version 01`). It uses `od` (not `xxd`) so it needs no
`vim-common`. Run `./validate_c509.sh` from this directory.

| Result | Count | Meaning |
|--------|-------|---------|
| PASS   | 117   | Tool output matches the official draft-02 vector exactly |
| XFAIL  | 68    | Expected failure — Cat A / Cat B (see below) |
| SKIP   | 4     | No reference data (e.g. a type-2 vector with no private key) |
| FAIL   | 0     | No unexpected failures |

The 68 XFAILs are **inherent**, not tool gaps: **Cat A** (59) type-2 natively-signed
vectors have no X.509 DER to decode back to; the **CRT-template decode** entries (6)
in §4 likewise have no DER equivalent (their lossless CBOR round-trip is tested in
§9 instead); **Cat B** (3) are certs `f2` cannot sign as type-2 (an id-alg-unsigned
X25519/X448 end-entity, or the frp256v1 curve).

The former draft-20 gaps are now **implemented**:
- **`r2` type-2 CSR** — RFC 6955 DhSig (the peer cert's `0x8B` array header is
  skipped in the KDF field walk) and the nested `withcert` embedded certificate
  (unwrapped from `bytes .cbor`, re-signed type-2, re-wrapped) both round-trip.
- **CRT templates (§10)** — the `c` dispatch now detects a template by its first
  array element (`templateType = 0`) rather than the raw first byte, and
  `parse_c509_crt` skips the `0x87` array header, giving a byte-exact re-encode.

Running `--version 01` (legacy draft-19 vectors) against this draft-20 tool leaves
one expected divergence — the §8.7 `withcert` CSR, whose embedded certificate is
`bytes .cbor`-wrapped from draft-20 but embedded directly in draft-19.

### draft-01 section-number reference

Filenames follow the pattern `v{VER}_section_{N.N.N}_{anchor}.{ext}` matching the
section number in the corresponding draft version.

The XFAIL classification in sections §2–§6 is driven by section number patterns:
- Section `*.4` and `3.11.3` → Type 2 natively-signed (Category A)
- Section `10.*` → CRT templates (Category E1; §8 not implemented)
- Type-2 content in any section (first byte `02`) → Category A

Section §7 (Type-2 signing via `f2`) introduces new categories:
- Cat B → unsupported key algorithm (brainpool, SM2, FRP256v1, Ed448, RSA, X25519/X448 EE)
- Cat B2 → CSR type-2 (`f2` encodes certificates only)

All previously XFAIL categories that are now implemented:
- DH-PoP CSRs (§9.1 Table 3 values 14–16): **IMPLEMENTED, PASS**
- X25519 PoP CSRs (§7.2 attr type 2): **IMPLEMENTED, PASS**
- RFC 9090 OID fallback (§2.2, §2.3.3): **IMPLEMENTED, PASS**
- SM2 and FRP256v1 type-3: **PASS** (Weierstrass bignum handles both)

### XFAIL breakdown

#### Category A — Type 2 (natively signed) — 46 XFAILs (decoding test, §4)

`c509CertificateType = 2` means `issuerSignatureValue` covers the *CBOR*
`TBSCertificate`, not the ASN.1 DER one (§2.1, §2.3.5
draft-ietf-cose-cbor-encoded-cert).  No X.509 DER origin exists for these
certificates; they can only live in C509 form.

All 46 XFAILs are in the **decoding test** (Section 4 of validate_c509.sh):
the decoded DER cannot be compared to anything.  The 23 affected algorithm
variants appear as a plain `.cbor.hex` and an annotated `_1.cbor.hex` file:

- CA cert: `c509_ca`
- RSA: `c509_selfsign_rsa`, `_rsa_f5`, `_rsa_with_sha1`, `_rsa_with_sha512`
- RSASSA-PSS: `c509_selfsign_rsassa_pss_sha{256,384,512}`, `_shake{128,256}`
- EC Weierstrass: `c509_selfsign_secp{256,384,521}r1`, `_compress_secp256r1`
- Edwards: `c509_selfsign_ed{25519,448}`
- Brainpool: `c509_selfsign_brainpoolp{256,384,512}r1`
- FRP256v1: `c509_selfsign_frp256v1`
- SM2: `c509_selfsign_sm2p256v1`
- EE with DH keys: `c509_ee_x25519`, `c509_ee_x448`

These Cat A XFAILs cannot be eliminated from §4 (there is no DER to compare
against by design).  **However**, the §7 signing test (`f2` command) tests
the *TBS generation* (fields 0–9) independently of §4.  `f2` supports
secp256r1, secp384r1, secp521r1, and Ed25519, giving PASSes in §7 for
sections 2.4, 3.3.4, 3.4.4, 3.5.4, 3.6.4, and 3.14.4.

#### Category B — Unsupported key in type-2 signing — 11 XFAILs (§7 only)

`f2` supports secp256r1, secp384r1, secp521r1, and Ed25519.  All other key
types present in the test vectors report Cat B in §7.

| Curve/algorithm | Section | Crate | Status |
|-----------------|---------|-------|--------|
| secp256r1 | 3.3.4, 3.4.4 | `p256 0.13` | **PASS** |
| secp384r1 | 3.5.4 | `p384 0.13` | **PASS** |
| secp521r1 | 3.6.4 | `p521 0.13` | **PASS** |
| Ed25519 | 3.14.4, 2.4 | `ed25519-dalek 2` | **PASS** |
| brainpoolP256r1 | 3.8.4 | `bp256 0.14.0-rc` | deferred — see note |
| brainpoolP384r1 | 3.9.4 | `bp384 0.14.0-rc` | deferred — see note |
| brainpoolP512r1 | 3.10.4 | — | not planned (no RustCrypto crate exists) |
| SM2 | 3.7.4 | `sm2 0.14.0-rc` | deferred — see note |
| FRP256v1 | 3.11.3 | — | not planned (no Rust support anywhere) |
| Ed448 | 3.15.4 | `ed448-goldilocks 0.14.0-pre` | deferred — see note |
| RSA / RSA-PSS | 3.1, 3.2, 4.20 | — | not planned (different signature structure) |
| X25519 / X448 EE | 3.12, 3.13 | — | not planned (key-agreement keys; no signing key in test vectors) |

##### RustCrypto availability and the 0.14.0-rc blocker

RustCrypto's elliptic-curves repository (<https://github.com/RustCrypto/elliptic-curves>)
provides crates for brainpoolP256r1/384r1, SM2, and Ed448, but all are
currently in the **0.14.0-rc.9 / 0.14.0-pre.12** pre-release series:

- `bp256 0.14.0-rc.9` — brainpoolP256r1, ECDSA + PKCS#8 (`DecodePrivateKey`)
- `bp384 0.14.0-rc.9` — brainpoolP384r1, ECDSA + PKCS#8
- `sm2 0.14.0-rc.9` — SM2DSA + PKCS#8 (OID 1.2.156.10197.1.301)
- `ed448-goldilocks 0.14.0-pre.12` — Ed448 EdDSA + PKCS#8

**The 0.14.0-rc compatibility problem:**
The currently used crates (`p256`/`p384`/`p521` at 0.13) and the RC crates
share foundational dependencies at incompatible major versions:

```
p256 0.13  ──► elliptic-curve 0.13, ecdsa 0.16 (signature 2.1), pkcs8 0.10
bp256 0.14 ──► elliptic-curve 0.14, ecdsa 0.17 (signature 2.2-rc)
```

Cargo can load both versions simultaneously, but Rust traits from different
crate versions are distinct types.  The `use p256::pkcs8::DecodePrivateKey`
and `use p256::ecdsa::signature::Signer` imports in `sign_tbs()` work because
all 0.13 EC crates re-export the same underlying trait objects.  Adding a
0.14-rc crate alongside them would require a separate import for the 0.17
version of those traits, and the single dispatch function would stop
compiling.  Resolution requires upgrading p256/p384/p521 to 0.14.0-rc
simultaneously — a coherent but risky upgrade against a moving API target.

**SM2 additional complexity:**
SM2DSA signs `SM3(ZA || message)` where ZA is a hash of the curve parameters
and the signer's distinguished ID (default `"1234567812345678"`).  The `sm2`
crate handles this internally, but it is unclear whether the IETF test vector
was generated with the default ID — reproducibility of the exact TBS is
uncertain until tested.

**Recommendation:** wait for the stable 0.14.0 release (rc.9 is late in the
cycle), then upgrade all EC crates atomically.  At that point brainpoolP256r1,
brainpoolP384r1, and Ed448 should be straightforward additions (same
`from_pkcs8_pem` + `.sign(tbs)` pattern as the existing arms in `sign_tbs()`).
SM2 warrants a separate investigation of the ZA prefix after upgrading.

#### Category B2 — CSR type-2 not supported by `f2` — 5 XFAILs (§7 only)

`f2` encodes X.509 certificates only; PKCS#10 CSR type-2 encoding is not
implemented.  Affected: sections 8.1.4, 8.3.4, 8.4.4, 8.5.4, 8.7.4.

#### Category B — SM2 — RESOLVED (type-3 now PASSING)

The SM2 type-3 encoding and round-trip (`v01_x509_selfsign_sm2p256v1.crt`)
now PASS.  The SM2 curve (OID `1.2.156.10197.1.301`, §9.2 Table 4) is a
standard Weierstrass curve so the existing bignum-based `decompress_ecc_key`
and `tonelli_shanks` implementations handle it correctly.  The SM3 hash is
not required for type-3 re-encoding because the signature bytes are copied
verbatim from the input DER, not recomputed.

The two remaining SM2 XFAILs (`v01_c509_selfsign_sm2p256v1.cbor.hex` and
`_1`) are type-2 (natively signed) vectors — Category A applies.

**No external SM2/SM3 crates needed** for the current re-encoding use case.

#### Category C — FRP256v1 — RESOLVED (type-3 now PASSING)

FRP256v1 (OID `1.2.250.1.223.101.256.1`, §9.2 Table 4, the French ANSSI
national curve) type-3 encoding, decoding, and round-trip now PASS without
any new dependencies.  The curve parameters were already present in
`decompress_ecc_key` in `keys.rs`.  The decoding test extraction was also
fixed: `c509 c` labels the reconstructed DER as "Input: DER encoded X.509
certificate" (the tool shows both input and output); the validation script
now captures that block instead of the final CBOR line.

Encoding comparison: the test vector uses the uncompressed key (`04` prefix);
the tool (without `-nc`) produces compressed (`FE` prefix).  Both are
correct — the `-nc` variant matches the expected vector exactly.

The two type-2 FRP256v1 XFAILs remain under Category A (natively signed).

#### Category D — Unconvertible certificate — RESOLVED (now PASSING)

`v01_x509_unconvertible.crt` uses a public-key OID absent from the C509 integer
registry.  The RFC 9090 OID fallback (`[~oid_value_bytes, params_der_bytes]` for
algorithm fields; `~oid_value_bytes` for extension IDs) is now implemented.

Also fixed: AS Identifiers extension with `rdi` field present.  The draft
(§ext-encoding) says "If 'rdi' is not present, the extension value can be
CBOR-encoded."  When `rdi` IS present, the extension now correctly uses the OID
fallback form instead of encoding with integer `33`.

Three locations fixed in `conversion.rs` and `keys.rs`:
1. Sig-alg encoding fallback: `[~oid]` or `[~oid, params]` array (not raw DER)
2. PkAlg encoding fallback: same (`keys.rs` encoding + decoding)
3. AS Identifiers rdi detection: forced OID fallback when rdi [1] is present

#### Category E — Unimplemented CSR/CRT features — 27 XFAILs

**E1 — Certification Request Templates (§8): 6 XFAILs**
`C509CertificationRequestTemplate` is a distinct CBOR structure from
`TBSCertificationRequest` that omits `subjectSignatureValue` and adds a
`templateValues` component.  Not implemented.
Files: `v01_{complex,oneelement,undefined}_csrt.cbor.hex` + `_1` each.

**E2 — Type-3 CSR decoding without reference DER: 8 XFAILs**
`v01_c509_type_3_certification_request_{1…6}.cbor.hex` are type-3 C509 CSRs.
The tool can decode them, but the test vectors do not include reference `.der`
files to verify correctness against.

**E3 — DH-signature (proof-of-possession) CSRs: 9 XFAILs**
Algorithm values 14–16 in §9.1 Table 3 (`DhSigStatic` with HMAC-SHA256/384/512,
RFC 6955 proof-of-possession).  Tool panics: `Unknown sign alg type: 14`.
Files: `v01_x509csr_dhsig_sha{256,384,512}.csr` (§6 round-trip × 3) and
`v01_c509csr_dhsig_sha{256,384,512}.cbor.hex` + `_1` (§4 decoding × 6).

**E4 — X25519 proof-of-possession CSRs: 4 XFAILs**
SubjectPublicKeyInfo attribute type 2 (ECDH key-agreement PoP, §7.2).  Tool
panics: `Unknown CSR attribute type 2`.
Files: `v01_x509csr_x25519{,_withcert}.csr` (§6 round-trip × 2) and
`v01_c509csr_ecdsa_p256.cbor.hex` + `_1` (§4 decoding × 2, type-2 natively
signed, no reference DER).

---

## Open Issues

### 1. CRT (Certification Request Template, §8) — OPEN

`C509CertificationRequestTemplate` is a distinct CBOR structure not yet
implemented.  Test vectors at sections 10.1–10.3.
Status: **planned**, lower priority.

### Previously resolved issues

| Issue | Resolution | Date |
|-------|-----------|------|
| SM2 type-3 | PASS — Weierstrass bignum handles the curve; no new crates needed | 2026-05-29 |
| FRP256v1 type-3 | PASS — curve parameters already in `keys.rs` | 2026-05-29 |
| RFC 9090 OID fallback | IMPLEMENTED — `[~oid, params]` arrays in sig/pk alg encoding/decoding; AS Identifiers rdi fallback | 2026-05-29 |
| DH-PoP decode (§9.1 vals 14–16) | IMPLEMENTED — `parse_cbor_sig_info` handles DhSigStatic DER reconstruction | 2026-05-29 |
| X25519 PoP attr type 2 (§7.2) | IMPLEMENTED — `parse_c509_csr` case 2 reconstructs PrivateKeyPossessionStatement DER | 2026-05-29 |
| `parse_c509_item` dispatch | IMPLEMENTED — auto-detects cert (11 elements) vs CSR (7 elements) | 2026-05-29 |
| Type-2 secp256r1 (`f2` command) | IMPLEMENTED — `type2.rs`: SHA-256 SKI, RFC 6979 ECDSA; §7 PASS for 3.3.4, 3.4.4 | 2026-06-04 |
| Type-2 secp384r1, secp521r1, Ed25519 | IMPLEMENTED — `type2.rs` extended; §7 PASS for 3.5.4, 3.6.4, 3.14.4, 2.4 | 2026-06-04 |

---

## Real-world round-trip results

`test_results/batch_test_2026-05-22_16-16-07.log`:
**4710 / 5000 hosts** pass lossless round-trip.  1 conversion failure
(barcelona.cat cert #3 — BMPString `explicitText` in UserNotice; C509
normalises string types to UTF-8 so this cert is inherently non-roundtrippable
by design).  Rest of failures are network timeouts or unreachable hosts.
