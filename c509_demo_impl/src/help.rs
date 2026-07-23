//! Diagnostic printing helpers and small byte-manipulation utilities.

use colored::*;
use oid::prelude::*;
use serde_cbor::Value;
use std::io::Write;

/// Interpret `b` as a big-endian unsigned integer and return its value as `u64`.
///
/// # Panics
/// Panics if `b` is empty or longer than 8 bytes.
pub fn be_bytes_to_u64(b: &[u8]) -> u64 {
    let l = b.len();
    assert!(l > 0 && l < 9, "be_bytes_to_u64: expected 1–8 bytes, got {}", l);
    (0..l).map(|i| (b[i] as u64) << (8 * (l - i - 1))).sum()
}

/// Compress `input` with Brotli at quality 11 / window 22 (maximum compression).
pub fn brotli(input: &[u8]) -> Vec<u8> {
    let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 11, 22);
    writer.write_all(input).expect("brotli: write to in-memory buffer is infallible");
    writer.into_inner()
}

/// Print a labelled hex dump to stdout with 23 bytes per line.
///
/// `is_error` controls whether the heading is rendered in red (error) or
/// yellow (informational).
fn print_internal(s: &str, v: &[u8], is_error: bool) {
    let heading = format!("{} ({} bytes)", s, v.len());
    if is_error {
        print!("{}", heading.red());
    } else {
        print!("{}", heading.yellow());
    }
    for (i, byte) in v.iter().enumerate() {
        print!("{}{:02X}", if i % 23 == 0 { "\n" } else { " " }, byte);
    }
    println!("\n");
}

/// Print a yellow labelled hex dump of `v` to stdout.
pub fn print_vec(s: &str, v: &[u8]) {
    print_internal(s, v, false);
}

/// Print all bytes of `v` as a continuous uppercase hex string with no spacing.
pub fn print_vec_compact(v: &[u8]) {
    for byte in v.iter() {
        print!("{:02X}", byte);
    }
}

/// Print a red warning string to stdout.
pub fn print_str_warning(s: &str) {
    println!("{}", s.red());
}

/// Print a red warning about an OID that has no registered C509 integer mapping.
///
/// Decodes the OID bytes to dotted notation (e.g. `1.2.840.113549.1.1.11`) if
/// possible, otherwise falls back to lowercase hex.
pub fn print_warning(s: &str, v: &[u8], oid: &[u8]) {
    let oid_str: String = match ObjectIdentifier::try_from(oid) {
        Ok(o) => o.into(),
        Err(_) => hex::encode(oid),
    };
    let text = format!("{} ({})", s, oid_str);
    print_internal(&text, v, true);
}

/// Print a green bordered info block (used for section headers in CLI output).
pub fn print_info(rows: &[String]) {
    let bar = "--------------------------------------------------------------------";
    println!("{}", bar.green());
    for row in rows {
        println!("{}", row.green());
    }
    println!("{}", bar.green());
    println!();
}

/// Extract the raw bytes from a `serde_cbor::Value::Bytes` or `Value::Text` item.
///
/// # Panics
/// Panics if `value` is neither `Bytes` nor `Text`.
pub(crate) fn get_as_bytes(value: &Value) -> Vec<u8> {
    match value {
        Value::Bytes(b) => b.to_vec(),
        Value::Text(t)  => t.as_bytes().to_vec(),
        _ => panic!("get_as_bytes: expected Bytes or Text, got {:?}", value),
    }
}

/// Strip a trailing newline byte from `file_contents`, if present.
///
/// Used when reading hex files that may have been written with a trailing `\n`.
pub fn cleanup(mut file_contents: Vec<u8>) -> Vec<u8> {
    if file_contents.last() == Some(&b'\n') {
        file_contents.pop();
    }
    file_contents
}
