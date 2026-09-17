//! `decode_cbor` — tiny debugging helper.
//!
//! Decodes a hex-encoded CBOR byte string on the command line and pretty-prints
//! its `serde_cbor::Value` tree. Handy for eyeballing a C509 certificate's raw
//! CBOR structure. Not part of the conversion library.
//!
//! ```text
//! cargo run --bin decode_cbor -- 8b0342123417f6...
//! ```

use serde_cbor::Value;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: decode_cbor <hex_string>");
        return;
    }
    let hex_str = &args[1];
    let bytes = hex::decode(hex_str).expect("Invalid hex string");
    let value: Value = serde_cbor::from_slice(&bytes).expect("Invalid CBOR");
    println!("{:#?}", value);
}
