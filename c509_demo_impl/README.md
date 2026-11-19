# C509 Reference Implementation

Rust reference implementation of CBOR-encoded X.509 certificates (C509),
tracking **[draft-ietf-cose-cbor-encoded-cert](https://datatracker.ietf.org/doc/draft-ietf-cose-cbor-encoded-cert/)**
— aligned with **draft-21**.

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

The quickest path is the bundled installer, which covers every non-Rust
dependency below on Debian/Ubuntu, Fedora, Arch, and macOS:

```bash
./setup.sh
```

Then install Rust from <https://rustup.rs> if you don't have it, and build.

To install manually instead (Debian/Ubuntu package names shown):

| Tool | Purpose | Install |
|------|---------|---------|
| `cargo` / `rustc` | Build the Rust binary | <https://rustup.rs> |
| C toolchain + `pkg-config` + OpenSSL **dev** library | The crate links native OpenSSL (via the `openssl` crate) for Type-2 signing and verification with brainpoolP256r1/P384r1/P512r1, frp256v1, SM2 and Ed448, and for SHAKE, so `cargo build` needs these to compile and link — this is the usual cause of a *"could not find OpenSSL"* build error | `apt-get install build-essential pkg-config libssl-dev` |
| `python3` + `lxml` | Extract XML test vectors (`fetch_test_vectors.sh`) | `apt-get install python3-lxml` |
| `curl` | Download the draft XML | `apt-get install curl` |

> Note: the `openssl` **binary** being present is not enough — the build needs
> the OpenSSL **development** package (`libssl-dev` / `openssl-devel`) plus
> `pkg-config`. On locked-down hosts, build a vendored OpenSSL from source
> instead: `openssl = { version = "0.10", features = ["vendored"] }` in
> `Cargo.toml` (needs a C compiler, `perl`, and `make`). See `setup.sh`.

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
| `f <cert.der> --issuer-cert <issuer.der>` | Encode a CA-issued certificate with the ECDSA signature length taken from the issuer's key |
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
| `v2 <c509.cbor.hex>` | Verify the signature of a self-signed type-2 certificate or of a type-2 certification request (subject key) |
| `v2 <c509.cbor.hex> --issuer-cert <issuer.cbor.hex>` | Verify a CA-issued type-2 certificate against the issuer's C509 certificate |
| `v2 <c509.cbor.hex> --issuer-point <hex>` | Same, with the issuer's EC public key given directly (same algorithm as the subject key) |
| `t <hostlist>` | Batch test on the TLS certificate chains of the listed hosts (see [Batch test](#batch-test-on-real-certificates)) |
| `tf <file-or-dir>` | Batch test on certificates from files |

```bash
RUST_LOG=debug ./target/debug/c509 f cert.der   # verbose/diagnostic output
```

> **Note:** Modes `l` and `ll` require `could_convert/` and
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
| `--version VER` | Test vector draft version to use (default: `04`) |
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
   v04_section_3.3.2_x509_selfsign_secp256r1.crt
   v04_section_3.3.3_c509_type_3_certificate_3.cbor.hex
   ```

   OpenSSL verbose dumps embedded in the XML are automatically skipped.

3. **Build** — runs `cargo build --bin c509` (incremental; usually a no-op).

4. **Validate** — runs `validate_c509.sh`, which exercises these test sections:

   | Section | What is tested |
   |---------|---------------|
   | §2 Encoding | X.509 DER → C509 hex, compared to every known official hex |
   | §3 CSR encoding | X.509 CSR → C509 hex |
   | §4 Decoding | C509 type-3 hex → X.509 DER, byte-exact match against source cert |
   | §5 Round-trip | X.509 DER → C509 → DER, byte-exact comparison |
   | §6 CSR round-trip | X.509 CSR → C509 → CSR, byte-exact comparison |
   | §7 Type-2 signing | `f2`: fields 0–9 match the IETF type-2 vector (field 10 too for deterministic signature algorithms, otherwise `f2`'s own signature is verified with `v2`); CA-issued certificates are signed with the CA key |
   | §7b Signature verification | `v2`: every signature in the type-2 vectors verifies — self-signed certificates and certification requests with the subject key, CA-issued certificates against the issuing certificate |
   | §8 Type-2 CSR signing | `r2`: ECDSA (TBS), DhSig and unsigned CSRs (full) match the IETF vector |
   | §9 CRT round-trip | certification request templates re-encode byte-exact |

   The section numbers of the CSRs, templates and cross-referenced keys differ
   between test-vector versions; they are set per version in the "Draft layout"
   block of `validate_c509.sh`.

5. **Report** — prints PASS / XFAIL / SKIP / FAIL counts plus a final
   PASS/FAIL banner.

### Individual scripts

If you need to run steps separately:

```bash
# Download + extract only:
./fetch_test_vectors.sh [VERSION]

# Validate only (binary must already be built; defaults to test-vectors -04):
./validate_c509.sh [--version 04] [--verbose]

# Extract only (XML already downloaded):
python3 extract_vectors.py \
    --version 04 \
    --xml ../test_vectors/draft-ietf-cose-c509-test-vectors-04.xml \
    --outdir ../test_vectors/
```

The `-03` and `-02` sets also run (`--version 03` / `--version 02`).

### Current results (`validate_c509.sh`, test-vectors -04)

```
PASS:  150   type-3 certs/CSRs (encode, decode, round-trip), type-2 f2/r2 (incl. DhSig,
             withcert, CA-issued X25519/X448), v2 signature verification, CRT round-trip
XFAIL:  71   no X.509 DER equivalent (62 type-2, 8 CRT); 1 point marker
SKIP:    2   no X.509 counterpart to compare (8-byte integer certificate and CSR)
FAIL:    0
```

The XFAILs: a type-2 (natively signed) object is signed over the CBOR TBS, so
there is no X.509 DER to decode back to. CSR templates likewise have no DER
form; their lossless CBOR round-trip is verified in §9. One type-2 signing
check differs from its vector: the vector for the compressed secp256r1
certificate marks the public key with `0xFD`, while `f2` emits the SECG octet
`0x03` that the draft specifies for natively signed certificates.

The SKIPs: the 8-byte-integer certificate and CSR have no X.509 counterpart for
`f2` / `r2` to start from; their signatures are verified by `v2`.

Type-2 signing (`f2`, §7) compares fields 0–9 (the TBS) byte-exactly, and also
field 10 when the signature algorithm is deterministic (Ed25519, Ed448,
RSA-PKCS#1 v1.5). The other signatures cannot be compared: `f2` signs ECDSA on
secp256r1/384r1/521r1 deterministically (RFC 6979), which the vectors do not,
and its remaining ECDSA, SM2 and RSA-PSS signatures differ per run. For a
self-signed certificate `f2`'s signature is verified with `v2` instead.

In a natively signed certificate or certification request, a compressed
Weierstrass public key carries the SECG octets `0x02` / `0x03`; `0xFE` / `0xFD`
are used in type 3 only.

`f2` and `v2` support:

- ECDSA over secp256r1, secp384r1 and secp521r1 with SHA-256, SHA-384 and SHA-512
  respectively;
- ECDSA over brainpoolP256r1/P384r1/P512r1 and frp256v1 with SHA-1, SHA-2,
  SHAKE128 or SHAKE256, as given by the signature algorithm;
- SM2 with SM3 and the default distinguishing ID `1234567812345678`;
- Ed25519 and Ed448;
- RSA PKCS#1 v1.5 with SHA-1 or SHA-2, and RSASSA-PSS with SHA-2, SHAKE128 or
  SHAKE256.

`v2` verifies a self-signed certificate or a certification request with its
subject key. A CA-issued certificate is verified with `--issuer-cert`, which
checks that the issuer certificate's subject equals the certificate's issuer and
verifies with that certificate's key; `--issuer-point <hex>` takes the issuer's
EC public key directly, which must then use the subject key's algorithm.
Unsigned objects (id-alg-unsigned) and Diffie-Hellman proof-of-possession
requests carry no signature to verify. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md)
for limitations.

Integer identifiers without a registered OID (e.g. the 8-byte attribute types and
extension IDs of the 8-byte-integer certificate) cannot be converted to X.509;
`c` reports this as an error (exit status 1).

## Batch test on real certificates

`t` and `tf` run the type-3 round-trip (X.509 → C509 → X.509) on many
certificates and report, for the distinct certificates seen:

- how many round-trip losslessly, and which do not;
- the C509 size relative to the DER size: in total, as a distribution per
  certificate, for end-entity and CA certificates, and per key and signature
  algorithm; for hosts also per chain as sent;
- the extensions, name attributes and algorithms that were encoded in the
  generic OID form.

```bash
./fetch_batch_lists.py                    # host lists and CA certificates -> ../batch_lists/
./target/debug/c509 tf ../batch_lists/ccadb_2020.csv --label "CCADB 2020s" > /dev/null
./target/debug/c509 t  ../batch_lists/tranco_<ID>_top10000.txt \
    --jobs 8 --batch-size 250 --pause 5 --keep-certs --label "Tranco <ID> top 10000" > /dev/null
./fetch_batch_lists.py --tranco-id <ID> --crux-commit <SHA>    # the same host lists again
```

| Input | Accepted form |
|-------|---------------|
| `t <hostlist>` | One host per line; `rank,domain` and `origin,rank` CSV lines and origins with a scheme are accepted |
| `tf <file-or-dir>` | A DER file, a PEM file, any text containing PEM blocks (such as a CSV report), or a directory of such files |

| Flag | Meaning | Default |
|------|---------|---------|
| `--jobs N` | Concurrent TLS connections | 8 |
| `--batch-size N` | Hosts per batch | 250 |
| `--pause S` | Seconds to wait between batches | 5 |
| `--label TEXT` | Recorded in the summary, e.g. the source list and its date | |
| `--out DIR` | Output directory | `test_results` |
| `--keep-certs` | Save every distinct certificate as `batch_<timestamp>_certs/<sha256>.der` | off |

`t` opens one TLS connection per host (port 443, 10 s timeouts, 30 s for the
whole handshake) and converts the chain the host sends. The chain is not
validated, so expired, self-signed and privately issued certificates are
included. A name without an address is tried once more as `www.<name>`. The
conversion prints diagnostics to stdout; redirect it.

Output: `batch_<timestamp>.log` (summary), `batch_<timestamp>.csv` (one row per
distinct certificate) and, for certificates that do not round-trip,
`batch_<timestamp>_failed/<sha256>.der`. The summary gives the sizes of
end-entity certificates with and without an SCT list (RFC 6962), and for those
with one also the sizes with that extension left out of both encodings.

`fetch_batch_lists.py` downloads the inputs and writes `SOURCES.txt` with the
URL, pinning identifier and SHA-256 of each. With `--tranco-id` and
`--crux-commit` it fetches the same host lists again. `batch_runs/` holds, per
run, the host lists used, their identifiers, the commands and the results
(latest: [batch_runs/2026-11-19/RESULTS.md](batch_runs/2026-11-19/RESULTS.md)).

| Source | Content |
|--------|---------|
| [Tranco](https://tranco-list.eu) | Research ranking of popular domains; every list has a permanent, citable ID. The first N domains are used. |
| [CrUX top lists](https://github.com/zakird/crux-top-lists) | Chrome top-million origins, ranked in buckets. A seeded random sample outside the top 10,000 is used. |
| [CCADB](https://www.ccadb.org/resources) | Root and intermediate CA certificates known to the browser root programmes, per decade of issuance. No network connections are needed to test them. |
| [Matter PAA roots](https://github.com/project-chip/connectedhomeip/tree/master/credentials/production/paa-root-certs) | Production device-attestation root certificates of Matter (`--matter`). |
| [CSCA master list](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html) | Passport-signer CA certificates of many countries, as published by the German BSI (`--csca`). Fetched from the publisher, not redistributed here; its signature is not verified. |
| [Open PageRank top 10 million](https://keywordseverywhere.com/openpagerank/top-domains) | Domains ranked by links in the Common Crawl web graph. `sample_openpagerank.py` draws a stratified host sample from the downloaded list: four rank bands and two strata balanced over public-sector and academic suffixes and over country-code top-level domains. |

## Implemented features

| Feature | Status |
|---------|--------|
| X.509 DER cert → C509 type-3 (all IANA-registered algorithms) | ✓ |
| C509 type-3 → X.509 DER (all IANA-registered algorithms) | ✓ |
| PKCS#10 CSR → C509 type-3 | ✓ |
| C509 type-3 CSR → PKCS#10 DER | ✓ |
| ECDSA / EdDSA / RSA / RSA-PSS signature encoding | ✓ |
| DH proof-of-possession (DhSigStatic, §9.1 values 14–16) | ✓ |
| PrivateKeyPossessionStatement attribute, incl. the `bytes .cbor` embedded certificate | ✓ |
| EC point compression (FE/FD prefix, §2.3.4) | ✓ |
| RFC 9090 OID fallback for unregistered algorithms (§2.2, §2.3.3) | ✓ |
| SM2 / SM3 (Weierstrass curve, no external crate needed) | ✓ |
| FRP256v1 (ANSSI, curve params in `keys.rs`) | ✓ |
| Brainpool P-256/384/512 | ✓ |
| X25519 / X448 / Ed25519 / Ed448 | ✓ |
| AS Identifiers with rdi field → RFC 9090 fallback | ✓ |
| All registered extensions (§ext-encoding) | ✓ |
| Batch test on TLS chains and certificate files, with size statistics | ✓ |
| C509 type-2 (natively signed) `f2` encode — all signature algorithms listed above | ✓ |
| C509 type-2 signature verification (`v2`): self-signed and CA-issued certificates, certification requests — all signature algorithms listed above | ✓ |
| Certification Request Templates (parse and lossless re-encode) | ✓ |

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
| `type2` | Type-2 (natively signed) certificate encoding and signing (`f2`) |
| `type2_csr` | Type-2 (natively signed) CSR encoding (`r2`) |
| `verify` | Type-2 signature verification of certificates and certification requests (`v2`) |
| `sm2` | SM2 signing and verification with SM3 and the default distinguishing ID |
| `tester` | TLS client, file I/O, single round-trip, output formatting |
| `batch` | Batch test on TLS chains and certificate files (`t`, `tf`) |
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

- **0.6.3** (2026-11) — batch test with size statistics (`t`, `tf`). SECG point
  markers in natively signed objects. Wi-SUN FAN Device extended key usage.
- **0.6.2** (2026-11) — test-vectors -04. Type-2 signing and signature
  verification for every key type in the vectors; verification of CA-issued
  certificates and of certification requests.
- **0.6.1** (2026-09) — draft-21. Subject Directory Attributes is encoded in the
  generic OID form; an AlgorithmIdentifier without parameters is a bare `~oid`.
- **0.6.0** (2026-07) — draft-20. Certificates, certification requests and
  templates are CBOR arrays; embedded certificates are `bytes .cbor`-wrapped.
- **Earlier** — type-2 certificate and CSR encoding, the test-vector validation
  suite, C509 → X.509 decoding, RFC 9090 OID fallback, Diffie-Hellman
  proof-of-possession, batch round-trip testing over live TLS. Initial release
  in 2021.
