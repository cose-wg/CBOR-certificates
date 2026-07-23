# C509 Reference Implementation

Rust reference implementation of CBOR-encoded X.509 certificates (C509),
tracking **[draft-ietf-cose-cbor-encoded-cert](https://datatracker.ietf.org/doc/draft-ietf-cose-cbor-encoded-cert/)**
— aligned with **draft-20** (the version now in the RFC-publication pipeline).

Converts, bidirectionally and losslessly, between standard X.509 DER
certificates/CSRs and their compact C509 CBOR representation. Targets
constrained IoT devices where certificate size matters.

A C509 certificate is the CBOR **array** `C509Certificate` (draft §3), carried
with its `0x8B` array(11) header everywhere it is transported or hashed; a
certification request is the `0x87` array(7) `C509CertificationRequest`. Two
representations are supported per draft §3:

- **Type 3** — DER-equivalent: reconstructs byte-for-byte identical X.509 DER,
  so an existing X.509 certificate can be shrunk on the wire and expanded back.
- **Type 2** — natively signed: the signature is over the CBOR encoding itself;
  no X.509 DER equivalent exists.

Licensed under the 3-Clause BSD License (see `../LICENSE.md`).

## Quick Start

```bash
# Clone (if not already inside the CBOR-certificates repo):
git clone https://github.com/cose-wg/CBOR-certificates
cd CBOR-certificates/c509_demo_impl

# Run the full test-vector suite in one command:
./run_tests.sh
```

That single command downloads the official IETF test vectors, extracts them,
builds the binary, runs the validation suite, and prints a colour-coded
summary.  See [Test Vectors](#test-vectors) for details.

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| `cargo` / `rustc` | Build the Rust binary | <https://rustup.rs> |
| `python3` + `lxml` | Extract XML test vectors | `pip3 install lxml` |
| `curl` | Download XML draft | Usually pre-installed |
| `openssl` | DER/PEM conversions in tests | Usually pre-installed |

## CLI Usage

```bash
cargo build --bin c509
./target/debug/c509 <command> <file> [flags]
```

| Command | Description |
|---------|-------------|
| `f <cert.der>` | X.509 DER → C509 type-3 hex (stdout) |
| `f <cert.der> -w` | Same, also write `.cbor.hex` sidecar file |
| `f <cert.der> -wo` | Write sidecar only, suppress stdout unless errors |
| `f <cert.der> -nc` | Encode EC public keys uncompressed (no FE/FD prefix) |
| `f2 <cert.der> <key.pem>` | X.509 DER + PKCS#8 key → C509 type-2 (natively signed) hex |
| `f2 <cert.der> <key.pem> -nc` | Same, store EC public key uncompressed |
| `r2 <csr.der> <subj_key.pem>` | PKCS#10 DER → type-2 C509 CSR (ECDSA / unsigned) |
| `r2 … <peer_key.pem> --peer-cert <hex>` | type-2 CSR with DhSigStatic proof-of-possession (RFC 6955) |
| `r2 … --embedded-cert-key <key.pem>` | Also re-sign any embedded C509 certs in attributes as type-2 |
| `c <c509.cbor.hex>` | C509 hex → X.509 DER/CSR (auto-detects cert vs CSR) |
| `c <c509.cbor.hex> -w` | Same, also write `.crt` / `.pem` files |
| `u <domain>` | Fetch TLS certificate chain, encode each cert to C509 |
| `l <cert.der>` | Round-trip: X.509 → C509 → X.509, compare bytes |
| `ll <domain …>` | Round-trip for one or more live TLS chains (parallel) |
| `t <urllist.txt>` | Bulk round-trip from a URL list, results logged under `test_results/` |

```bash
RUST_LOG=debug ./target/debug/c509 f cert.der   # verbose/diagnostic output
```

> **Note:** Modes `l`, `ll`, and `t` require `could_convert/` and
> `failed_convert/` directories to exist in the parent of `c509_demo_impl/`.
> They are already present in the repository.

## Test Vectors

The official IETF test vectors are defined in
`draft-ietf-cose-c509-test-vectors-{VERSION}`.  The tooling in this directory
downloads, extracts, and validates against them automatically.

### One-command run

```bash
./run_tests.sh [OPTIONS]
```

| Option | Effect |
|--------|--------|
| `--version VER` | Test vector draft version to use (default: `02`, the current draft) |
| `--refetch` | Force re-download of the XML even if already cached |
| `--rebuild` | Force `cargo build` even if the binary is current |
| `--verbose` | Print tool output for every failing test |
| `--help` | Show usage |

What it does internally:

1. **Download** — fetches
   `https://www.ietf.org/archive/id/draft-ietf-cose-c509-test-vectors-{VER}.xml`
   (skips download if the file is already present).

2. **Extract** — runs `extract_vectors.py` to parse the XML and write every
   `<artwork>` block to `../test_vectors/` as a named file.  Files are named
   after their section number in the draft:

   ```
   v01_section_3.3.2_x509_selfsign_secp256r1.crt
   v01_section_3.3.3_c509_type_3_certificate_3.cbor.hex
   ```

   OpenSSL verbose dumps embedded in the XML are automatically skipped.

3. **Build** — runs `cargo build --bin c509` (incremental; usually a no-op).

4. **Validate** — runs `validate_c509.sh` which exercises seven test sections:

   | Section | What is tested |
   |---------|---------------|
   | §2 Encoding | X.509 DER → C509 hex, compared to every known official hex |
   | §3 CSR encoding | X.509 CSR → C509 hex |
   | §4 Decoding | C509 type-3 hex → X.509 DER, byte-exact match against source cert |
   | §5 Round-trip | X.509 DER → C509 → DER, byte-exact comparison |
   | §6 CSR round-trip | X.509 CSR → C509 → CSR, byte-exact comparison |
   | §7 Type-2 signing | `f2` TBS verification: fields 0–9 match IETF type-2 vector exactly (sig skipped — RFC 6979 per-implementation) |

5. **Report** — prints PASS / XFAIL / SKIP / FAIL counts plus a final
   PASS/FAIL banner.

### Individual scripts

If you need to run steps separately:

```bash
# Download + extract only:
./fetch_test_vectors.sh [VERSION]

# Validate only (binary must already be built; defaults to draft-02):
./validate_c509.sh [--version 02] [--verbose]

# Extract only (XML already downloaded). Use the latest draft version:
python3 extract_vectors.py \
    --version 02 \
    --xml ../test_vectors/draft-ietf-cose-c509-test-vectors-02.xml \
    --outdir ../test_vectors/
```

The `-02` set (`v02_section_*`) aligns with draft-ietf-cose-cbor-encoded-cert-20:
every C509 object carries its CBOR-array leading byte (`0x8B` cert / `0x87` CSR),
and the tool emits exactly that form.

### Current results (`validate_c509.sh`, default draft-02)

`validate_c509.sh` is **version-agnostic**: file pairing, the C509 type byte, and
the hex comparisons all transparently handle the draft-20 CBOR-array header
(`0x8B` / `0x87`), so the suite runs clean against draft-02 (default) and still
against draft-01 (`--version 01`).

```
PASS:  117   type-3 certs/CSRs (encode, decode, round-trip) + type-2 f2/r2 (incl. DhSig, withcert) + CRT round-trip
XFAIL:  68   Cat A type-2 (no DER equiv) + CRT-template decode (no DER); Cat B f2 cannot sign
SKIP:    4   no reference data (e.g. type-2 vector without a private key)
FAIL:    0
```

The 68 XFAILs are **inherent**, not tool gaps:

- **Cat A** — type-2 (natively signed): the signature is over the CBOR TBS, so there
  is no X.509 DER to decode back to. The §10 CRT templates are XFAIL'd in the decode
  section for the same reason (their lossless CBOR round-trip is verified in §9).
- **Cat B** — `f2` type-2 signing: unsupported key type, or a cert `f2` cannot encode
  as type-2 (an id-alg-unsigned X25519/X448 end-entity cert, or the frp256v1 curve).

The draft-20 `r2` type-2-CSR path (RFC 6955 DhSig and the nested `bytes .cbor`
`withcert` embedded cert) and CRT-template decode/round-trip are **implemented** and
pass. (Running `--version 01` leaves the §8.7 `withcert` CSR as one expected
draft-19-vs-20 divergence.)

Type-2 signing (`f2`, §7) compares fields 0–9 (the TBS) byte-exactly; field 10 (the
ECDSA/EdDSA signature) is excluded because different RFC 6979 implementations
produce different r‖s values while both are valid. Supported: secp256r1, secp384r1,
secp521r1, Ed25519. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for the full breakdown.

Round-trip mode (`l` / `ll` / `t`) is independent of the draft version and also
passes on live TLS chains (4710/5000 public hosts lossless — the one by-design
exception is a `BMPString` `explicitText` that C509 normalises to UTF-8).

## Implemented features

| Feature | Status |
|---------|--------|
| X.509 DER cert → C509 type-3 (all IANA-registered algorithms) | ✓ |
| C509 type-3 → X.509 DER (all IANA-registered algorithms) | ✓ |
| PKCS#10 CSR → C509 type-3 | ✓ |
| C509 type-3 CSR → PKCS#10 DER | ✓ |
| ECDSA / EdDSA / RSA / RSA-PSS signature encoding | ✓ |
| DH proof-of-possession (DhSigStatic, §9.1 values 14–16) | ✓ |
| PrivateKeyPossessionStatement attribute, incl. draft-20 `bytes .cbor` embedded cert | ✓ |
| EC point compression (FE/FD prefix, §2.3.4) | ✓ |
| RFC 9090 OID fallback for unregistered algorithms (§2.2, §2.3.3) | ✓ |
| SM2 / SM3 (Weierstrass curve, no external crate needed) | ✓ |
| FRP256v1 (ANSSI, curve params in `keys.rs`) | ✓ |
| Brainpool P-256/384/512 | ✓ |
| X25519 / X448 / Ed25519 / Ed448 | ✓ |
| AS Identifiers with rdi field → RFC 9090 fallback | ✓ |
| All registered extensions (§ext-encoding) | ✓ |
| Batch TLS round-trip testing | ✓ |
| C509 type-2 (natively signed) `f2` encode — secp256r1 / P-384 / P-521 / Ed25519 | ✓ |
| C509 type-2 `f2` encode — Ed448 | — planned |
| C509 type-2 `f2` encode — brainpool, SM2, FRP256v1, RSA | — not planned |
| Certification Request Templates | — planned |

## Library API

```rust
use c509::conversion::{
    parse_x509_item,   // encode: auto-detects cert vs. CSR
    parse_c509_item,   // decode: auto-detects cert vs. CSR
    parse_x509_cert,   parse_c509_cert,  // cert only
    parse_x509_csr,    parse_c509_csr,   // CSR only
};

// X.509 DER → C509 CBOR (cert or CSR, auto-detected)
let encoded = parse_x509_item(der_bytes, /*no_compression=*/false);
let cbor_bytes: Vec<u8> = encoded.cbor.concat();

// C509 CBOR → X.509 DER (cert or CSR, auto-detected by element count)
let decoded = parse_c509_item(cbor_bytes);
let der_bytes: Vec<u8> = decoded.der;
```

The `Cert` struct holds both `der: Vec<u8>` and `cbor: Vec<Vec<u8>>`.
In the encode direction `cbor` contains individually-encoded CBOR items;
concatenate them to get the full C509 byte string.
In the decode direction `der` contains the reconstructed X.509 DER.

### TLS fetching

```rust
use c509::tester::get_certs_from_tls;
let certs = get_certs_from_tls("example.com".to_string());
```

## Module overview

| Module | Purpose |
|--------|---------|
| `conversion` | Core X.509 ↔ C509 encode/decode logic (certs and CSRs) |
| `keys` | Public key and signature algorithm handling |
| `extensions` | X.509 extension encoding/decoding |
| `registry` | OID ↔ C509 integer ID tables (§9.1, §9.2, §ext-encoding) |
| `lder` | DER parsing and building primitives |
| `lcbor` | CBOR encoding primitives |
| `type2` | Type-2 (natively signed) certificate encoding (`f2`) |
| `type2_csr` | Type-2 (natively signed) CSR encoding (`r2`) |
| `tester` | TLS client, file I/O, batch testing, round-trip harness |
| `help` | Printing and diagnostic utilities |

The binary entry point is `src/main.rs`; `src/bin/decode_cbor.rs` is a standalone
CBOR pretty-printer for debugging. The public library surface (`Cert`, the
`parse_*` functions, `tester::get_certs_from_tls`) is documented in `src/lib.rs`
(`cargo doc --open`).

## Resources

- [cbor.me](http://cbor.me/) — CBOR encoding ↔ diagnostic notation
- [lapo.it/asn1js](https://lapo.it/asn1js/) — DER/ASN.1 decoder online
- [IETF Datatracker: draft-ietf-cose-cbor-encoded-cert](https://datatracker.ietf.org/doc/draft-ietf-cose-cbor-encoded-cert/)
- [IETF Datatracker: draft-ietf-cose-c509-test-vectors](https://datatracker.ietf.org/doc/draft-ietf-cose-c509-test-vectors/)
- [OID converter](https://misc.daniel-marschall.de/asn.1/oid-converter/online.php)

## Contributing

Bug reports and pull requests:
[COSE WG issue tracker](https://github.com/cose-wg/CBOR-certificates/issues).

## Version history

**v0.6.0** (2026-07) — draft-20 / RFC-track alignment
Aligned the whole tool with **draft-ietf-cose-cbor-encoded-cert-20**: a C509
certificate is now the full CBOR **array** (`0x8B` header) — the unwrapped
`~C509Certificate` sequence is gone — and CSRs/templates carry the `0x87` array
header; the COSE and TLS wrappings use `C509CertData = bytes .cbor
C509Certificate`. Fixed the draft-20 `bytes .cbor` wrapping of the certificate
embedded in a `PrivateKeyPossessionStatement` "withcert" CSR attribute (encode
and decode), byte-exact against test-vectors-02 §8.7. Added the `-02` extraction
path (`extract_vectors.py --version 02`). Round-trip validation passes on the
`-02` vectors and on live TLS chains; decoders auto-detect the CBOR array vs. the
legacy sequence, so `-19`-era inputs still parse.

Earlier milestones:

- Type-2 (natively signed) certificate and CSR encoding (`f2` / `r2`, including
  RFC 6955 DhSig), and the draft test-vector validation harness (`run_tests.sh`).
- DH proof-of-possession and `PrivateKeyPossessionStatement` decode; RFC 9090 OID
  fallback for unregistered algorithms/curves; `parse_c509_item` cert-vs-CSR
  auto-dispatch.
- C509 → X.509 decoding direction, and batch round-trip testing over live TLS
  (lossless on 4710/5000 sampled public hosts — the one by-design exception is a
  `BMPString` `explicitText` that C509 normalises to UTF-8).
- Initial release in 2021, tracking the early drafts.
