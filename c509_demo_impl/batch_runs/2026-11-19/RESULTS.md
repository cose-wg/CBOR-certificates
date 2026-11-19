# Batch test of 2026-11-19: results

Each certificate is encoded as a C509 type 3 certificate and decoded again.
"Lossless" means that the decoded DER is identical to the input. Sizes compare
the C509 encoding with the DER encoding; percentages are C509 bytes / DER
bytes over the certificates that are lossless. Inputs, tool version and
commands: [SOURCES.md](SOURCES.md).

## Overview

| Set | Distinct certificates | Lossless | Not lossless | C509 / DER |
|-----|----------------------|----------|--------------|------------|
| TLS chains of the Tranco top 10,000 | 7,941 | 7,936 | 5 | 78.4% |
| TLS chains of 5,000 hosts sampled from CrUX | 4,894 | 4,894 | 0 | 76.0% |
| CCADB CA certificates issued in the 2020s | 4,284 | 4,282 | 2 | 76.0% |
| CCADB CA certificates issued in the 2010s | 4,754 | 4,722 | 32 | 77.5% |
| CSCA master list (passport-signer CA certificates) | 609 | 607 | 2 | 77.5% |
| Matter production PAA roots | 72 | 72 | 0 | 47.3% |

All 41 certificates that are not lossless deviate from the RFC 5280 profile
in a way that a type 3 certificate cannot express:

| Reason | Tranco | CCADB 2020s | CCADB 2010s | CSCA |
|--------|--------|-------------|-------------|------|
| X.509 version 1 | 5 | | | |
| Negative serial number | | | | 2 |
| Validity time encoding (GeneralizedTime before 2050, UTCTime without seconds) | | 2 | 23 | |
| `critical` encoded explicitly as FALSE | | | 6 | |
| Signature algorithm in `tbsCertificate` differs from the outer one | | | 3 | |

## Hosts

| | Tranco top 10,000 | CrUX sample of 5,000 |
|---|---|---|
| Hosts listed | 10,000 | 5,000 |
| Chain received | 7,855 | 4,736 |
| Unreachable (DNS or TCP) | 2,060 | 236 |
| TLS handshake failed | 85 | 28 |
| Certificates received | 23,993 | 15,059 |
| C509 / DER over whole chains as sent | 74.5% | 72.1% |

Of the unreachable Tranco hosts, 1,576 are names without an address record;
the list ranks domains, not web sites.

## Size by role

| Set | Group | Certificates | C509 / DER | 10th percentile | Median | 90th percentile |
|-----|-------|--------------|------------|-----------------|--------|-----------------|
| Tranco | end-entity | 7,589 | 78.5% | 66.1% | 78.4% | 83.5% |
| Tranco | CA | 347 | 75.9% | 58.8% | 76.9% | 82.0% |
| CrUX | end-entity | 4,660 | 76.0% | 66.0% | 74.0% | 82.2% |
| CrUX | CA | 234 | 76.5% | 60.2% | 77.5% | 82.0% |
| CCADB 2020s | CA | 4,282 | 76.0% | 58.9% | 77.9% | 82.3% |
| CCADB 2010s | CA | 4,722 | 77.5% | 70.7% | 77.3% | 82.5% |
| CSCA | CA | 599 | 77.4% | 70.4% | 77.7% | 82.2% |
| Matter | CA | 72 | 47.3% | 45.6% | 47.3% | 49.1% |

The percentiles are over the per-certificate ratios.

## Size by key and signature (end-entity certificates of the host runs)

| Key, signature | Tranco: certificates | Tranco: C509 / DER | CrUX: certificates | CrUX: C509 / DER |
|----------------|---------------------|--------------------|--------------------|------------------|
| P-256, ECDSA SHA-256 | 2,015 | 67.5% | 1,332 | 66.6% |
| P-256, ECDSA SHA-384 | 1,029 | 71.8% | 989 | 68.5% |
| RSA-2048, RSA SHA-256 | 4,029 | 81.8% | 2,029 | 81.0% |
| RSA-4096, RSA SHA-256 | 275 | 84.2% | 177 | 83.1% |

CA certificates in the CCADB: about 57–61% with an EC key and an ECDSA
signature, 75–78% with an RSA-2048 key, 81–83% with an RSA-4096 key. The 72
Matter roots all have a P-256 key and an ECDSA SHA-256 signature.

## The SCT list in end-entity certificates

The SCT list extension (RFC 6962) has no registered C509 extension ID, so it
is carried in the generic form with its DER content unchanged. "Not counted"
takes the extension out of both sizes.

| | Tranco | CrUX |
|---|---|---|
| End-entity certificates with an SCT list | 7,581 of 7,589 | 4,660 of 4,660 |
| Average size of the extension in DER | 327 bytes | 306 bytes |
| Share of the DER certificate | 22.7% | 24.1% |
| C509 / DER, as is | 78.5% | 76.0% |
| C509 / DER, SCT list not counted | 72.7% | 69.0% |
| – median over the certificates | 73.0% | 65.0% |

None of the other sets contains an SCT list.

## Identifiers in the generic form

An extension, name attribute or algorithm without a registered integer is
encoded with its OID. In the host runs this is the SCT list in every
end-entity certificate that has one; all other OIDs occur in less than 1% of
the certificates. In the CSCA set, EC keys with explicit curve parameters
(172 certificates) and RSASSA-PSS signatures with parameters other than the
registered sets use the generic algorithm form.

## Distribution of the ratio

C509 / DER per certificate, in percent:

| Group | Certificates | min | p5 | p10 | p25 | median | p75 | p90 | p95 | p99 | max |
|-------|--------------|-----|----|-----|-----|--------|-----|-----|-----|-----|-----|
| Tranco end-entity | 7,589 | 54.7 | 65.8 | 66.1 | 66.8 | 78.4 | 80.8 | 83.5 | 85.9 | 92.3 | 98.0 |
| CrUX end-entity | 4,660 | 64.8 | 65.7 | 66.0 | 66.6 | 74.0 | 80.1 | 82.2 | 83.6 | 89.8 | 96.9 |
| Tranco CA | 347 | 45.8 | 56.9 | 58.8 | 71.1 | 76.9 | 80.8 | 82.0 | 82.5 | 83.6 | 86.7 |
| CrUX CA | 234 | 45.8 | 56.4 | 60.3 | 72.4 | 77.5 | 80.9 | 82.0 | 82.4 | 83.6 | 85.0 |
| CCADB 2020s | 4,282 | 42.1 | 56.8 | 58.9 | 63.2 | 77.9 | 81.4 | 82.3 | 82.7 | 83.6 | 89.0 |
| CCADB 2010s | 4,722 | 42.8 | 60.9 | 70.7 | 74.9 | 77.3 | 80.7 | 82.5 | 83.6 | 85.1 | 88.4 |
| CSCA | 607 | 56.9 | 68.1 | 70.6 | 74.4 | 77.7 | 80.4 | 82.2 | 83.1 | 84.3 | 86.6 |
| Matter | 72 | 43.6 | 44.7 | 45.6 | 46.0 | 47.2 | 48.9 | 49.1 | 49.2 | 49.4 | 49.5 |

With the SCT list not counted:

| Group | min | p5 | p10 | p25 | median | p75 | p90 | p95 | p99 | max |
|-------|-----|----|-----|-----|--------|-----|-----|-----|-----|-----|
| Tranco end-entity | 50.3 | 52.1 | 52.5 | 53.9 | 73.0 | 75.7 | 79.7 | 83.5 | 91.7 | 98.0 |
| CrUX end-entity | 50.5 | 51.9 | 52.5 | 53.4 | 65.0 | 74.2 | 78.0 | 79.9 | 88.8 | 96.8 |

The end-entity distribution has two groups: certificates with an EC key and an
ECDSA signature at 66–67%, and certificates with an RSA key around 80%.

## Bytes saved

DER bytes minus C509 bytes, per certificate:

| Group | p5 | p25 | median | p75 | p95 |
|-------|----|-----|--------|-----|-----|
| Tranco end-entity | 284 | 296 | 305 | 316 | 357 |
| CrUX end-entity | 284 | 296 | 305 | 307 | 345 |
| CCADB 2020s | 278 | 306 | 322 | 341 | 374 |
| CCADB 2010s | 246 | 289 | 322 | 345 | 386 |
| CSCA | 251 | 297 | 335 | 391 | 464 |
| Matter | 224 | 234 | 242 | 250 | 282 |

The saving is close to constant: about 300 bytes for a certificate of any size.
For the end-entity certificates of the host runs, the ratio follows the DER
size (correlation 0.82) and is unrelated to the number of bytes saved (0.10).
What remains is the content that C509 carries as it is: the key, the
signature, the SCT list and the names. The share of these four in the DER
certificate has a correlation of 0.86 with the ratio.

## Which certificates are reduced most and least

The 12,249 end-entity certificates of the two host runs, ordered by ratio:

| Band | C509 / DER | Median DER size | Median number of names in subjectAltName | Key and signature |
|------|-----------|-----------------|------------------------------------------|-------------------|
| Lowest 5% | 54.7–65.8% | 888 bytes | 1 | P-256 with ECDSA SHA-256: 93% |
| 5–25% | 65.8–66.7% | 905 bytes | 2 | P-256 with ECDSA: 99% |
| Middle 50% | 66.7–80.5% | 1,297 bytes | 2 | RSA-2048: 61%, P-256: 36% |
| 75–95% | 80.5–85.1% | 1,764 bytes | 2 | RSA-2048: 79%, RSA-4096: 16% |
| Highest 5% | 85.1–98.0% | 2,773 bytes | 58 | RSA-2048: 67% |

By key and signature:

| Key, signature | Certificates | Median C509 / DER | p10 | p90 | Median DER size | Median bytes saved |
|----------------|--------------|-------------------|-----|-----|-----------------|--------------------|
| P-256, ECDSA SHA-256 | 3,347 | 66.3% | 65.6% | 67.4% | 906 | 305 |
| P-256, ECDSA SHA-384 | 2,018 | 67.0% | 66.2% | 74.1% | 926 | 306 |
| P-384, ECDSA SHA-384 | 78 | 67.3% | 66.0% | 73.1% | 971 | 319 |
| RSA-2048, RSA SHA-256 | 6,058 | 80.2% | 77.8% | 83.6% | 1,560 | 296 |
| RSA-3072, RSA SHA-256 | 69 | 81.3% | 79.6% | 84.9% | 1,711 | 289 |
| RSA-4096, RSA SHA-256 | 452 | 83.1% | 81.5% | 85.5% | 1,903 | 300 |

By number of names in subjectAltName:

| Names | Certificates | Median C509 / DER | Median DER size | Median bytes saved |
|-------|--------------|-------------------|-----------------|--------------------|
| 0–1 | 2,476 | 73.3% | 1,255 | 306 |
| 2 | 7,194 | 76.8% | 1,281 | 305 |
| 3–5 | 1,090 | 78.7% | 1,345 | 303 |
| 6–20 | 772 | 81.3% | 1,618 | 299 |
| 21–100 | 646 | 87.0% | 2,469 | 310 |
| more than 100 | 71 | 94.3% | 5,376 | 303 |

Reduced most:

- Small certificates with an EC key and an ECDSA signature, one or two names
  and few extensions. The Matter roots (392–529 bytes in DER) are all below
  50%, and the lowest 5% of the CA certificates (42–58%, median 722 bytes) are
  68% P-384 with ECDSA SHA-384.

Reduced least:

- RSA keys and signatures: about 550 bytes for RSA-2048 and 1,070 bytes for
  RSA-4096 that no encoding reduces.
- Many names in subjectAltName. In the highest 5% the extension is 48% of the
  certificate; the certificate with the highest ratio (98.0%) has 268 names in
  9,111 bytes.
- The SCT list in end-entity certificates of TLS servers (see above).
- Among CA certificates, the highest 5% (83–89%) are mostly RSA-4096 with
  large extensions such as policy texts.

The difference between issuers follows from the key type they issue for: the
median is 66.4% for an issuer whose certificates are 94% P-256 and 80.2% for
one whose certificates are 98% RSA-2048.

These tables are produced by `analyse.py` in this directory from the result
tables and the certificates:

```bash
./analyse.py <results-dir> <batch_lists-dir> <tranco-certs-dir> <crux-certs-dir>
```
