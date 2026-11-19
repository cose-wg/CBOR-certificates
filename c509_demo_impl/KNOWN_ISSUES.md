# Known Issues and Limitations

Reference implementation of draft-ietf-cose-cbor-encoded-cert, aligned with
**draft-21** and validated against **draft-ietf-cose-c509-test-vectors-04**.

## Test-vector status

`./validate_c509.sh` (223 checks):

| Result | Count | Meaning |
|--------|-------|---------|
| PASS   | 150   | The tool reproduces the vector: byte-exact encoding, verified signature, or byte-exact DER round-trip |
| XFAIL  | 71    | The check does not apply to the vector, or the vector differs in a known way (see below) |
| SKIP   | 2     | The check could not run (see below) |
| FAIL   | 0     | |

**XFAIL (71).** 70 are in the decoding check (C509 → X.509 DER), for objects
that have no X.509 DER form:

- 62 type-2 (natively signed) certificates and certification requests. The
  signature covers the CBOR TBS, not ASN.1 DER. These vectors are checked in the
  type-2 signing (`f2` / `r2`) and signature-verification (`v2`) sections.
- 8 certification request templates. Their lossless CBOR round-trip is checked
  in the template section.

One is in the type-2 signing check: the natively signed certificate with a
compressed secp256r1 key. The vector marks the key with `0xFD`; the draft
specifies the SECG octets `0x02` / `0x03` for natively signed certificates, and
`f2` emits `0x03`. Fields 0–8 are otherwise equal, and the key identifier and
signature differ as a consequence. The vector's own signature verifies.

**SKIP (2).** The 8-byte-integer certificate and certification request have no
X.509 counterpart for `f2` / `r2` to start from. Their signatures are verified
by `v2`, and the 8-byte-integer template round-trips.

`--version 03` gives the same result. `--version 02` gives 144 PASS / 68 XFAIL /
0 SKIP / 0 FAIL; two of its XFAILs are the brainpoolP512r1 certificate, which
that set encodes with extension ID 24 (see "Decode-only forms").

## Type-2 signing and verification by key type

Every signing key in the test vectors is supported by both `f2` and `v2`:

| Key | Signature algorithms in the vectors | Library |
|-----|------------------------------------|---------|
| secp256r1 / secp384r1 / secp521r1 | ECDSA-SHA256 / -SHA384 / -SHA512 | `p256` / `p384` / `p521` |
| brainpoolP256r1 / P384r1 / P512r1 | ECDSA-SHAKE128 / -SHA384 / -SHAKE256 | OpenSSL (`openssl` crate) |
| frp256v1 | ECDSA-SHA1 | OpenSSL, group built from the explicit curve parameters (OpenSSL has no named curve for it) |
| SM2 | SM2-with-SM3, default distinguishing ID `1234567812345678` | `sm2.rs` on OpenSSL big-number / EC-point primitives |
| Ed25519 / Ed448 | EdDSA | `ed25519-dalek` / OpenSSL |
| RSA | PKCS#1 v1.5 SHA-1/256/384/512, RSASSA-PSS SHA-256/384/512 | `rsa` |
| RSA | RSASSA-PSS SHAKE128/256 (RFC 8702) | EMSA-PSS in `type2.rs` / `verify.rs`, SHAKE from OpenSSL |

The X25519 and X448 end-entity certificates are signed by the Ed25519 CA key and
verify against the CA certificate. The CA certificate itself is unsigned
(id-alg-unsigned), so it has no signature to verify.

## Limitations

- **Type-2 name attributes.** `f2` reuses the type-3 name encoding. For a
  printableString attribute in a multi-attribute name it emits a negative
  `attributeType`, which the draft allows only in type 3 (in a natively signed
  certificate the value must be non-negative). No test vector has such a name.
- **Generic `~oid` CSR attributes.** The encoder emits the DER-encoded `values`
  of an attribute without a registered integer ID. No test vector covers
  decoding that form back to PKCS#10.
- **Certificate policies.** The v1 RSP role entries (IDs 26, 28, 30, 32, 34, 36,
  38) are not mapped to OIDs; decoding one of them fails.
- **ECDSA signature length in type 3.** Each signature integer is padded to the
  length of the signer's curve. The curve is taken from the subject key for a
  self-signed certificate and a certification request, and from the issuer's
  certificate for a CA-issued certificate: the one given with `f --issuer-cert`,
  or the one with the matching subject name in the same TLS chain (`u`, `ll`,
  `t`) or file set (`tf`). Without the issuer's certificate, the encoder uses
  the smallest curve length that holds both integers; that is shorter than the
  signer's curve length in the rare case where both integers of a signature
  fit a smaller curve (for example a P-521 signature whose integers both fit
  64 bytes). Decoding is not affected.
- **ECDSA hash on the NIST curves.** For secp256r1/384r1/521r1 the hash is fixed
  by the curve (SHA-256/384/512); other combinations are not supported.
- **SM2 distinguishing ID.** The OpenSSL EVP interface applies an empty
  distinguishing ID and the `openssl` crate cannot set one, so SM2 is computed
  in `sm2.rs` with the default ID. Other IDs are not supported.
- **`v2 --issuer-point`** requires the issuer key to use the subject key's
  algorithm and does not accept RSA keys. `--issuer-cert` has neither limit.
- **Integer identifiers without an OID** (for example the 8-byte attribute types
  and extension IDs of the 8-byte-integer certificate) cannot be converted to
  X.509; `c` reports an error.
- **Algorithm identifiers in the generic form.** A registered int is used for a
  public key or signature algorithm only if the AlgorithmIdentifier is exactly
  the one the int stands for. Otherwise the generic `[~oid, parameters]` form
  is used, which is lossless but larger: EC keys with explicit curve
  parameters, RSA keys without the NULL parameter, ECDSA with a NULL
  parameter, and RSASSA-PSS with parameters other than the registered sets.
  The ECDSA signature value is then kept in its DER form.
- **Specific encodings not used.** An extension is encoded with its int
  extensionID only if that encoding decodes back to the input; otherwise the
  generic OID form is used, which is always lossless but larger. Extensions
  that the batch test shows in the generic form although an int is registered
  are certificate policies (e.g. an `explicitText` that is not a UTF8String or
  an empty qualifier list), authority key identifiers, CRL
  distribution points with a directoryName, and name constraints.

## Certificates that cannot be represented as type 3

A type-3 C509 certificate decodes to DER as RFC 5280 profiles it. An X.509
certificate that deviates in a field without a generic form cannot be encoded
losslessly; the tool reports an error or a mismatch. Seen in the batch test:

- an X.509 version 1 certificate;
- validity dates before 2050 encoded as GeneralizedTime, or a UTCTime without
  seconds;
- a negative serial number;
- the `critical` flag of an extension encoded explicitly as FALSE;
- a signature AlgorithmIdentifier in `tbsCertificate` that differs from the
  outer one.

## Decode-only forms

The decoder accepts three forms that the encoder never emits:

- Extension ID 24 for Subject Directory Attributes. The registry does not assign
  it; the encoder uses the generic OID form.
- A one-element `[~oid]` array for an AlgorithmIdentifier without parameters.
  The encoder emits the bare `~oid`.
- `true` between the `~oid` and the value of a critical extension in the generic
  form. The encoder wraps the value in an array.

## Batch test on real certificates

`c509 t` / `c509 tf` on 2026-11-19 (details in
[batch_runs/2026-11-19/RESULTS.md](batch_runs/2026-11-19/RESULTS.md)):

| Set | Distinct certificates | Lossless | Not lossless | C509 / DER |
|-----|----------------------|----------|--------------|------------|
| TLS chains of the Tranco top 10,000 | 7941 | 7936 | 5 | 78.4% |
| TLS chains of 5,000 hosts sampled from CrUX | 4894 | 4894 | 0 | 76.0% |
| CCADB CA certificates issued in the 2020s | 4284 | 4282 | 2 | 76.0% |
| CCADB CA certificates issued in the 2010s | 4754 | 4722 | 32 | 77.5% |
| CSCA master list (passport-signer CA certificates) | 609 | 607 | 2 | 77.5% |
| Matter production PAA roots | 72 | 72 | 0 | 47.3% |

All 41 that are not lossless are of the kinds listed under "Certificates that
cannot be represented as type 3". The ratio depends mainly on the key and
signature sizes: about 57–61% for a CA certificate with an EC key and an ECDSA
signature, about 81% with an RSA-4096 key and an RSA signature. End-entity TLS
certificates carry an SCT list (RFC 6962), on average about 320 bytes that C509
does not reduce; without it they are at 69–73%.
