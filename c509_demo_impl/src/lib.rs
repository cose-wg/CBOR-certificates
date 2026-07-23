//! Reference implementation of CBOR-encoded X.509 certificates (C509).
//!
//! Implements draft-ietf-cose-cbor-encoded-cert-20. Converts between standard
//! X.509 DER certificates and their compact C509 CBOR representation, targeting
//! constrained IoT devices.
//!
//! # Entry points
//! - [`conversion::parse_x509_cert`] — X.509 DER → C509 CBOR
//! - [`conversion::parse_c509_cert`] — C509 CBOR → X.509 DER
//! - [`conversion::parse_x509_item`] — auto-detects cert vs. CSR, then encodes
//! - [`conversion::parse_x509_csr`] / [`conversion::parse_c509_csr`] — PKCS#10 CSR round-trip
//! - [`tester::get_certs_from_tls`] — fetch and encode a live TLS chain

pub mod help;
pub mod lder;
pub mod lcbor;
pub mod registry;
pub mod keys;
pub mod extensions;
pub mod conversion;
pub mod tester;
pub mod type2;
pub mod type2_csr;

/// Holds one certificate in both DER and C509 CBOR representations.
///
/// When produced by an *encoder* (`parse_x509_cert`, `parse_x509_item`):
/// - `der` contains the original X.509 DER input.
/// - `cbor` contains the C509 fields as a flat sequence of individually-encoded
///   CBOR items (type, serial, sig-alg, issuer, not-before, not-after, subject,
///   pk-alg, pk, extensions, sig-value). Concatenate with `cbor.concat()` to get
///   the serialised C509 certificate.
///
/// When produced by a *decoder* (`parse_c509_cert`, `parse_c509_csr`):
/// - `der` contains the reconstructed X.509 DER output.
/// - `cbor` contains the raw CBOR fields from the input (same layout as above).
#[derive(Clone, Debug)]
pub struct Cert {
    pub der: Vec<u8>,
    pub cbor: Vec<Vec<u8>>,
}


/// Standard SECG prefix for a point with even Y coordinate (compressed).
pub const SECG_EVEN: u8 = 0x02;
/// Standard SECG prefix for a point with odd Y coordinate (compressed).
pub const SECG_ODD: u8 = 0x03;
/// Standard SECG prefix for an uncompressed EC point.
pub const SECG_UNCOMPRESSED: u8 = 0x04;
/// C509 prefix for a compressed EC point with even Y (draft §9.7: `0xFE` ≙ `0x02`).
pub const SECG_EVEN_COMPRESSED: u8 = 0xfe;
/// C509 prefix for a compressed EC point with odd Y (draft §9.7: `0xFD` ≙ `0x03`).
pub const SECG_ODD_COMPRESSED: u8 = 0xfd;

/// C509 certificate type 2: natively signed CBOR (no DER reconstruction needed).
pub const C509_TYPE_NATIVE: u8 = 0x02;
/// C509 certificate type 3: DER-equivalent encoding (reconstructed to identical DER).
pub const C509_TYPE_X509_ENCODED: u8 = 0x03;
/// C509 CSR type 2: natively signed CBOR request.
pub const C509_CSR_TYPE_NATIVE: u8 = 0x02;
/// C509 CSR type 3: DER-equivalent encoding (reconstructed to identical DER).
pub const C509_CSR_TYPE_X509_ENCODED: u8 = 0x03;

/// Enable printing of the raw DER/CBOR input to stdout during conversions.
pub const PRINT_INPUT: bool = true;
/// Enable printing of the converted output to stdout.
pub const PRINT_OUTPUT: bool = true;
/// Enable printing of the CBOR field breakdown.
pub const PRINT_COSE: bool = true;
/// Enable printing of TLS handshake details (verbose; off by default).
pub const PRINT_TLS: bool = false;

/// Enable writing reconstructed X.509 files (`.crt`, `.pem`) when requested.
pub const WRITE_X509: bool = true;
/// Enable writing C509 sidecar files (`.cbor.hex`) when requested.
pub const WRITE_C509: bool = true;
