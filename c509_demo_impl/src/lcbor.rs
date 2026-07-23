//! Minimal CBOR encoding primitives used throughout this crate.
//!
//! Every function produces the RFC 8949 encoding of one CBOR item as a byte
//! vector.  These are *append-only* builders — the caller concatenates results
//! to construct a CBOR sequence or array.

use serde_cbor::Value;

/// Encode a slice of `serde_cbor::Value` items as a definite-length CBOR array.
pub fn lcbor_array_v(v: &[Value]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = v.iter().map(lcbor_value).collect();
    [lcbor_type_arg(4, v.len() as u64), encoded.concat()].concat()
}

/// Serialize a single `serde_cbor::Value` to its CBOR wire encoding.
pub fn lcbor_value(v: &Value) -> Vec<u8> {
    serde_cbor::to_vec(v).expect("serde_cbor serialization is infallible for well-formed Values")
}

/// Encode a `u64` as a CBOR unsigned integer (major type 0).
pub fn lcbor_uint(u: u64) -> Vec<u8> {
    lcbor_type_arg(0, u)
}

/// Encode an `i64` as a CBOR integer (major type 0 for ≥0, major type 1 for <0).
pub fn lcbor_int(i: i64) -> Vec<u8> {
    if i < 0 {
        lcbor_type_arg(1, -i as u64 - 1)
    } else {
        lcbor_uint(i as u64)
    }
}

/// Encode a byte slice as a CBOR byte string (major type 2).
pub fn lcbor_bytes(b: &[u8]) -> Vec<u8> {
    [&lcbor_type_arg(2, b.len() as u64), b].concat()
}

/// Encode a UTF-8 byte slice as a CBOR text string (major type 3).
///
/// # Panics
/// Panics if `b` is not valid UTF-8.
pub fn lcbor_text(b: &[u8]) -> Vec<u8> {
    let s = std::str::from_utf8(b).expect("lcbor_text: input must be valid UTF-8");
    [&lcbor_type_arg(3, s.len() as u64), s.as_bytes()].concat()
}

/// Encode a slice of pre-encoded CBOR items as a definite-length CBOR array.
///
/// Each element of `v` must already be a complete, encoded CBOR item.
pub fn lcbor_array(v: &[Vec<u8>]) -> Vec<u8> {
    [lcbor_type_arg(4, v.len() as u64), v.concat()].concat()
}

/// Encode a tagged CBOR item: `tag(N, value_bytes)`.
///
/// `value` must be a complete, pre-encoded CBOR item.
pub fn lcbor_tag(tag: u64, value: &[u8]) -> Vec<u8> {
    let mut vec = lcbor_type_arg(6, tag);
    vec.extend_from_slice(value);
    vec
}

/// CBOR simple value `false` (RFC 8949 §3.3).
pub const CBOR_FALSE: u8 = 20;
/// CBOR simple value `true` (RFC 8949 §3.3).
pub const CBOR_TRUE: u8 = 21;
/// CBOR simple value `null` (RFC 8949 §3.3).
pub const CBOR_NULL: u8 = 22;

/// Encode a CBOR simple value (major type 7, additional info = `u`).
///
/// Use the `CBOR_FALSE`, `CBOR_TRUE`, and `CBOR_NULL` constants.
pub fn lcbor_simple(u: u8) -> Vec<u8> {
    lcbor_type_arg(7, u as u64)
}

/// Return the index just past the end of the CBOR item starting at `pos`.
///
/// Handles all major types including nested arrays, maps, and tags.
/// Panics on unsupported additional-info values (indefinite-length, etc.).
pub fn cbor_item_end(data: &[u8], pos: usize) -> usize {
    let b = data[pos];
    let major = b >> 5;
    let additional = b & 0x1f;
    let (length, mut pos) = match additional {
        0..=23 => (additional as usize, pos + 1),
        24 => (data[pos + 1] as usize, pos + 2),
        25 => (u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize, pos + 3),
        26 => (u32::from_be_bytes([data[pos+1], data[pos+2], data[pos+3], data[pos+4]]) as usize, pos + 5),
        _ => panic!("cbor_item_end: unsupported additional info {}", additional),
    };
    match major {
        0 | 1 => pos,          // uint / negint: no payload
        2 | 3 => pos + length, // bstr / tstr: length bytes
        4 => { for _ in 0..length { pos = cbor_item_end(data, pos); } pos }
        5 => { for _ in 0..2*length { pos = cbor_item_end(data, pos); } pos }
        6 => cbor_item_end(data, pos), // tag: one tagged item
        // simple (true/false/null/undefined) or break: `pos` was advanced past
        // any extra bytes in the length/additional-info match above.
        // Floats (additional 25/26/27) are rejected by the _ arm above since
        // their lengths (2/4/8) don't correspond to a payload in the same way,
        // so this branch only handles the simple-value sub-types in practice.
        7 => pos,
        _ => unreachable!(),
    }
}

/// Produce the RFC 8949 initial byte + optional additional bytes for a CBOR
/// item with major type `t` and argument `u`.
///
/// Lengths ≤23 are encoded in the initial byte; larger values use 1, 2, 4, or
/// 8 additional bytes per the CBOR standard.
fn lcbor_type_arg(t: u8, u: u64) -> Vec<u8> {
    let mut vec = vec![t << 5];
    if u < 24 {
        vec[0] |= u as u8;
    } else if u <= 0xFF {
        vec[0] |= 24;
        vec.extend(&(u as u8).to_be_bytes());
    } else if u <= 0xFFFF {
        vec[0] |= 25;
        vec.extend(&(u as u16).to_be_bytes());
    } else if u <= 0xFFFF_FFFF {
        vec[0] |= 26;
        vec.extend(&(u as u32).to_be_bytes());
    } else {
        vec[0] |= 27;
        vec.extend(&u.to_be_bytes());
    }
    vec
}
