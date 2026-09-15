//! Minimal DER (Distinguished Encoding Rules) parsing and building primitives.
//!
//! All *parsing* functions take a byte slice and return a sub-slice of the
//! input (zero-copy).  All *building* functions allocate and return a new
//! `Vec<u8>` containing a complete DER TLV (tag-length-value) item.
//!
//! Only the subset of DER encountered in X.509 certificates and PKCS#10 CSRs
//! is handled.  Indefinite-length encodings are rejected.

use crate::help::*;

// ---------------------------------------------------------------------------
// Universal ASN.1 tag constants (X.690 §8)
// ---------------------------------------------------------------------------

pub const ASN1_BOOL:      u8 = 0x01;
pub const ASN1_INT:       u8 = 0x02;
pub const ASN1_BIT_STR:   u8 = 0x03;
pub const ASN1_OCTET_STR: u8 = 0x04;
pub const ASN1_OID:       u8 = 0x06;
pub const ASN1_UTF8_STR:  u8 = 0x0C;
pub const ASN1_PRINT_STR: u8 = 0x13;
pub const ASN1_IA5_STR:   u8 = 0x16;
pub const ASN1_VIS_STR:   u8 = 0x1A;
pub const ASN1_UTC_TIME:  u8 = 0x17;
pub const ASN1_GEN_TIME:  u8 = 0x18;
pub const ASN1_SEQ:       u8 = 0x30;
pub const ASN1_SET:       u8 = 0x31;

// Context-specific constructed tags (implicit/explicit) used in X.509
pub const ASN1_INDEX_ZERO:     u8 = 0xA0; // [0] EXPLICIT
pub const ASN1_INDEX_ONE:      u8 = 0xA1; // [1] EXPLICIT
pub const ASN1_INDEX_TWO:      u8 = 0xA2; // [2] EXPLICIT
pub const ASN1_INDEX_THREE:    u8 = 0xA3; // [3] EXPLICIT
pub const ASN1_INDEX_FOUR:     u8 = 0xA4; // [4] EXPLICIT
pub const ASN1_INDEX_ZERO_EXT: u8 = 0x80; // [0] IMPLICIT primitive
pub const ASN1_INDEX_ONE_EXT:  u8 = 0x81; // [1] IMPLICIT primitive
pub const ASN1_INDEX_TWO_EXT:  u8 = 0x82; // [2] IMPLICIT primitive
pub const ASN1_URL:            u8 = 0x86; // [6] IMPLICIT — uniformResourceIdentifier
pub const ASN1_IP:             u8 = 0x87; // [7] IMPLICIT — iPAddress
pub const ASN1_INDEX_EIGHT_EXT:u8 = 0x88; // [8] IMPLICIT

// Multi-byte length prefix bytes (X.690 §8.1.3)
pub const ASN1_ONE_BYTE_SIZE: u8 = 0x81; // length encoded in next 1 byte
pub const ASN1_TWO_BYTE_SIZE: u8 = 0x82; // length encoded in next 2 bytes

// Boundary timestamps for UTCTime vs GeneralizedTime (RFC 5280 §4.1.2.5)
/// Last second expressible in UTCTime per RFC 5280: 2049-12-31 23:59:59 UTC.
pub const ASN1_UTC_TIME_MAX: i64 = 2524607999;
/// Last second before the year 2000: 1999-12-31 23:59:59 UTC.
/// Dates earlier than this require a two-digit year disambiguation.
pub const ASN1_UTC_TIME_Y2K: i64 = 946684799;

/// The string encoding of the "no expiry" sentinel in GeneralizedTime format.
pub const ASN1_GEN_TIME_MAX: &str = "99991231235959Z";

// Pre-built constant DER fragments
pub const ASN1_NULL:                      &[u8] = &[0x05, 0x00];
pub const ASN1_X509_VERSION_3:            &[u8] = &[0xA0, 0x03, 0x02, 0x01, 0x02];
pub const ASN1_X509_CRITICAL:             &[u8] = &[0x01, 0x01, 0xFF];
pub const ASN1_X509_BASIC_CONSTRAINT_FALSE: &[u8] = &[0x04, 0x02, 0x30, 0x00];
/// DER INTEGER encoding of the RSA public exponent 65537 (F4).
pub const ASN1_65537:                     &[u8] = &[0x02, 0x03, 0x01, 0x00, 0x01];

/// TLS extension type for Signed Certificate Timestamps (RFC 6962 §3.3).
pub const SCT_EXT_AID: &[u8] = &[0x00, 0x00, 0x04, 0x03];

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Verify that `b` begins with `tag`, then return the value bytes (no copy).
///
/// # Panics
/// Panics if the first byte does not match `tag` or if residual bytes remain.
pub fn lder(b: &[u8], tag: u8) -> &[u8] {
    assert!(b[0] == tag, "lder: expected tag 0x{:02X} but got 0x{:02X}", tag, b[0]);
    let (value, rest) = lder_split(b, true);
    assert!(rest.is_empty(), "lder: unexpected trailing bytes after TLV");
    value
}

/// Parse a DER INTEGER and strip the leading `0x00` sign byte, if present.
///
/// DER requires a leading zero when the high bit of a non-negative integer is
/// set to distinguish it from a negative number.  The extra byte is an
/// encoding artefact and is removed here.
pub fn lder_uint(b: &[u8]) -> &[u8] {
    let value = lder(b, ASN1_INT);
    if value.len() > 1 && value[0] == 0 {
        return &value[1..];
    }
    value
}

/// Parse a DER SEQUENCE or SET and return each element as a `&[u8]` TLV slice.
pub fn lder_vec(b: &[u8], tag: u8) -> Vec<&[u8]> {
    let mut vec = Vec::new();
    let mut rest = lder(b, tag);
    while !rest.is_empty() {
        let (tlv, remaining) = lder_split(rest, false);
        vec.push(tlv);
        rest = remaining;
    }
    vec
}

/// Like [`lder_vec`] but also asserts that exactly `length` elements are present.
pub fn lder_vec_len(b: &[u8], tag: u8, length: usize) -> Vec<&[u8]> {
    let vec = lder_vec(b, tag);
    assert!(
        vec.len() == length,
        "lder_vec_len: expected {} elements, got {}",
        length, vec.len()
    );
    vec
}

/// Split one complete DER TLV off the front of `b`.
///
/// Returns `(item, rest)` where `item` is the first TLV (either the value
/// bytes only if `value_only` is `true`, or the full TLV including tag and
/// length) and `rest` is everything after it.
///
/// # Panics
/// Panics on indefinite-length encoding (0x80) or lengths requiring ≥4 extra
/// bytes (rejected to guard against malformed input).
pub fn lder_split(b: &[u8], value_only: bool) -> (&[u8], &[u8]) {
    // Reject lengths that would require 4+ extra bytes (≥2^24 bytes of content).
    // Well-formed X.509 certificates are far smaller than this limit.
    assert!(b[1] < 0x84, "lder_split: length field too large (≥ 2^24)");
    let (start, end) = match b[1] {
        0x80 => panic!("lder_split: indefinite-length encoding is not valid DER"),
        0x81 => (3, 3 + b[2] as usize),
        0x82 => (4, 4 + be_bytes_to_u64(&b[2..4]) as usize),
        0x83 => (5, 5 + be_bytes_to_u64(&b[2..5]) as usize),
        _    => (2, 2 + b[1] as usize),
    };
    // When value_only is true, skip tag+length (start bytes); otherwise include them.
    (&b[if value_only { start } else { 0 }..end], &b[end..])
}

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

/// Wrap `bytes` in a DER BIT STRING, prepending the mandatory unused-bits byte (0x00).
pub fn lder_to_bit_str(bytes: Vec<u8>) -> Vec<u8> {
    let mut result = bytes;
    result.insert(0, 0x00); // zero unused bits — all content bits are significant
    lder_to_generic(result, ASN1_BIT_STR)
}

/// Wrap `bytes` in a DER INTEGER, prepending a leading 0x00 if the high bit is set.
///
/// DER requires the leading byte of an INTEGER value to be 0x00 when the most
/// significant bit would otherwise make a non-negative value look negative.
pub fn lder_to_pos_int(bytes: Vec<u8>) -> Vec<u8> {
    let mut result = bytes;
    if !result.is_empty() && (result[0] & 0x80 != 0) {
        result.insert(0, 0x00);
    }
    lder_to_generic(result, ASN1_INT)
}

/// Prepend a DER tag and definite-length prefix to `bytes`.
///
/// Supports lengths up to 65535 bytes (the range encountered in real-world
/// certificates). Panics if `bytes` exceeds 65535 bytes.
pub fn lder_to_generic(bytes: Vec<u8>, asn1_type: u8) -> Vec<u8> {
    let len = bytes.len();
    assert!(len <= 0xFFFF, "lder_to_generic: length {} exceeds maximum 65535", len);
    let mut result = bytes;
    if len <= 127 {
        result.insert(0, len as u8);
    } else if len <= 255 {
        result.insert(0, len as u8);
        result.insert(0, ASN1_ONE_BYTE_SIZE);
    } else {
        result.insert(0, (len & 0xFF) as u8);
        result.insert(0, (len >> 8) as u8);
        result.insert(0, ASN1_TWO_BYTE_SIZE);
    }
    result.insert(0, asn1_type);
    result
}

/// Concatenate `elements` and wrap them in a DER SEQUENCE.
pub fn lder_to_seq(elements: Vec<Vec<u8>>) -> Vec<u8> {
    lder_to_gen_seq(elements, ASN1_SEQ)
}

/// Concatenate `elements` and wrap them with an arbitrary DER tag.
pub fn lder_to_gen_seq(elements: Vec<Vec<u8>>, asn1_type: u8) -> Vec<u8> {
    let body: Vec<u8> = elements.into_iter().flatten().collect();
    lder_to_generic(body, asn1_type)
}

/// Wrap `first` and `second` together in a DER SEQUENCE.
pub fn lder_to_two_seq(first: Vec<u8>, second: Vec<u8>) -> Vec<u8> {
    lder_to_seq(vec![first, second])
}

/// Wrap a time string in a DER time type (`ASN1_UTC_TIME` or `ASN1_GEN_TIME`).
pub fn lder_to_time(input: String, time_type: u8) -> Vec<u8> {
    lder_to_generic(input.as_bytes().to_vec(), time_type)
}

/// Prepend a 2-byte big-endian length to a Signed Certificate Timestamp list.
///
/// This is the TLS-wire-format length prefix required by RFC 6962 §3.3 when
/// embedding an SCT list inside a DER OCTET STRING extension value.
pub fn sct_add_len(bytes: Vec<u8>) -> Vec<u8> {
    let len = bytes.len() as u16;
    let mut result = bytes;
    let be = len.to_be_bytes();
    result.insert(0, be[1]);
    result.insert(0, be[0]);
    result
}
