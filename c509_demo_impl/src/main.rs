//! Command-line entry point for the C509 reference implementation.
//!
//! Run `cargo run --bin c509 -- --help` or see README.md for usage.

use c509::conversion::*;
use c509::tester::*;
use c509::help::*;
use c509::type2::encode_x509_as_type2;
use c509::type2_csr::encode_csr_as_type2;
use c509::verify::{verify_type2, verify_type2_csr, verify_type2_issued};
use std::env::args;
use env_logger::Env;
use log::info;

/// Decode C509 → X.509 DER/CSR for the `c` command. A C509 object that cannot
/// be converted (e.g. one using integer IDs that have no OID) or is malformed is
/// reported as an error with exit status 1, not as a panic.
fn parse_c509_or_exit(bytes: Vec<u8>) -> c509::Cert {
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(|| parse_c509_item(bytes));
    std::panic::set_hook(prev_hook);
    result.unwrap_or_else(|e| {
        let msg = e.downcast_ref::<String>().map(String::as_str)
            .or_else(|| e.downcast_ref::<&str>().copied())
            .unwrap_or("unknown error");
        eprintln!("c: cannot convert to X.509: {}", msg);
        std::process::exit(1);
    })
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("Logger initialized!");
    std::env::set_var("RUST_BACKTRACE", "1");

    const USAGE: &str = "\
Usage: c509 <command> <file-or-domain> [flags]

Commands:
  f  <cert.der>      Encode X.509 DER → C509 hex (stdout)
  f  <cert.der> -w   Also write .cbor.hex sidecar file
  f  <cert.der> -wo  Write sidecar only; suppress stdout unless errors
  f  <cert.der> -o <out>   Write the C509 certificate to this file and do not print it:
                     binary CBOR if the name ends in .cbor or .bin, hex otherwise
  f  <cert.der> -nc  Encode EC public keys uncompressed (no FE/FD prefix)
  f  <cert.der> --issuer-cert <issuer.der>   Take the ECDSA signature length from the issuer's key (CA-issued certificate)
  c  <c509.cbor.hex> Decode C509 (hex or binary CBOR file) → X.509 DER/CSR (stdout)
  c  <c509.cbor.hex> -w   Also write .crt (.csr for a certification request) and .pem files
  c  <c509.cbor.hex> -o <out>   Write the X.509 encoding to this file (PEM if it ends in .pem, else DER) and do not print it
  u  <domain>        Fetch TLS chain from domain, encode each cert
  l  <cert.der>      Round-trip: X.509 → C509 → X.509, compare bytes
  ll <domain …>      Round-trip for one or more domains (parallel)
  t  <hostlist>      Batch test on the TLS chains of the listed hosts: round-trip and size statistics
  tf <file-or-dir>   Same on certificates from files (DER, PEM, or text containing PEM blocks)
                     t/tf flags: --jobs N --batch-size N --pause SECONDS --label TEXT --out DIR --keep-certs
  f2 <cert.der> <key.pem>                    Encode X.509 DER → Type-2 C509 hex
  f2 <cert.der> <key.pem> -nc               Also store EC public keys uncompressed
  f2 ... -o <out>                           Write to this file (.cbor or .bin: binary CBOR; else hex) and do not print
  r2 <csr.der> <subj_key.pem>               Encode PKCS#10 DER → Type-2 C509 CSR (signed with the subject key, or unsigned)
  r2 <csr.der> <subj_key.pem> <peer_key.pem> --peer-cert <cert.cbor.hex>  DhSigStatic (RFC 6955)
  r2 ... --embedded-cert-key <key.pem>     Re-sign embedded C509 certs in attrs as type-2
  r2 ... -nc                                Also store EC public keys uncompressed
  r2 ... -o <out>                           Write to this file (.cbor or .bin: binary CBOR; else hex) and do not print
  v2 <c509.cbor.hex>                        Cryptographically verify a Type-2 signature (self-signed)
  v2 <c509.cbor.hex> --issuer-cert <issuer.cbor.hex>   Verify a CA-signed Type-2 against the issuer C509 certificate
  v2 <c509.cbor.hex> --issuer-point <hex>   Verify a CA-signed Type-2 with the issuer public key (same algorithm as the subject key; not RSA)
  v2 <c509csr.cbor.hex>                     Verify the signature of a Type-2 certification request (subject key)
";

    let all_args: Vec<String> = args().collect();

    if all_args.len() < 3 {
        eprintln!("{}", USAGE);
        std::process::exit(1);
    }

    let first_arg  = &all_args[1];
    let second_arg = &all_args[2];

    // v2: cryptographically verify a Type-2 C509 signature. Handled early — it
    // reads a hex file and exits, rather than flowing through the Cert pipeline.
    if first_arg == "v2" {
        let cbor = read_c509_file(second_arg)
            .unwrap_or_else(|| panic!("v2: '{}' is neither binary CBOR nor valid hex", second_arg));
        let mut issuer_point: Option<Vec<u8>> = None;
        let mut issuer_cert: Option<Vec<u8>> = None;
        let mut it = all_args.iter().skip(3);
        while let Some(a) = it.next() {
            if a == "--issuer-point" {
                if let Some(h) = it.next() {
                    issuer_point = Some(hex::decode(h.trim())
                        .unwrap_or_else(|e| panic!("v2: bad --issuer-point hex: {}", e)));
                }
            } else if a == "--issuer-cert" {
                if let Some(path) = it.next() {
                    issuer_cert = Some(read_c509_file(path)
                        .unwrap_or_else(|| panic!("v2: '{}' is neither binary CBOR nor valid hex", path)));
                }
            }
        }
        // A certification request is the CBOR array(7); a certificate array(11).
        let result = if cbor.first() == Some(&0x87) {
            verify_type2_csr(&cbor)
        } else if let Some(issuer) = issuer_cert.as_deref() {
            verify_type2_issued(&cbor, issuer)
        } else {
            verify_type2(&cbor, issuer_point.as_deref())
        };
        match result {
            Ok(desc) => { println!("VERIFY OK: {}", desc); std::process::exit(0); }
            Err(reason) => { eprintln!("VERIFY FAIL: {}", reason); std::process::exit(1); }
        }
    }

    let mut suppress_output = false;
    let mut write_output    = false;
    let mut no_compression  = false;
    let target_file = second_arg.clone();

    // -o <path>: write the result to this file and do not print it.
    let mut out_path: Option<String> = None;
    let mut f_issuer_path: Option<String> = None;
    if first_arg == "c" || first_arg == "f" {
        let mut skip_next = false;
        for (i, arg) in all_args.iter().enumerate().skip(3) {
            if skip_next { skip_next = false; continue; }
            match arg.as_str() {
                "-w"  => write_output = true,
                "-wo" => { write_output = true; suppress_output = true; }
                "-nc" => no_compression = true,
                "--issuer-cert" if first_arg == "f" => {
                    f_issuer_path = all_args.get(i + 1).cloned();
                    skip_next = true;
                }
                "-o" => {
                    out_path = Some(all_args.get(i + 1).cloned().unwrap_or_else(|| panic!("-o needs a file name")));
                    suppress_output = true;
                    skip_next = true;
                }
                other => eprintln!("Warning: unknown flag '{}' ignored", other),
            }
        }
    }
    let mut f2_ca_path: Option<String> = None;
    if first_arg == "f2" {
        let mut skip_next = false;
        for (i, arg) in all_args.iter().enumerate().skip(4) {
            if skip_next { skip_next = false; continue; }
            match arg.as_str() {
                "-nc" => no_compression = true,
                "-ca" => {
                    f2_ca_path = all_args.get(i + 1).cloned();
                    skip_next = true;
                }
                "-o" => {
                    out_path = Some(all_args.get(i + 1).cloned().unwrap_or_else(|| panic!("-o needs a file name")));
                    suppress_output = true;
                    skip_next = true;
                }
                other => eprintln!("Warning: unknown flag '{}' ignored", other),
            }
        }
    }
    // r2: peer key is optional at position 4; --peer-cert, --embedded-cert-key, -nc follow.
    if first_arg == "r2" {
        let flag_start = if all_args.len() >= 5 && !all_args[4].starts_with('-') { 5 } else { 4 };
        let mut skip_next = false;
        for (i, arg) in all_args.iter().enumerate().skip(flag_start) {
            if skip_next { skip_next = false; continue; }
            match arg.as_str() {
                "-nc" => no_compression = true,
                "--peer-cert" | "--embedded-cert-key" => skip_next = true, // value consumed later
                "-o" => {
                    out_path = Some(all_args.get(i + 1).cloned().unwrap_or_else(|| panic!("-o needs a file name")));
                    suppress_output = true;
                    skip_next = true;
                }
                other => eprintln!("Warning: unknown flag '{}' ignored", other),
            }
        }
    }

    let certs = match first_arg.as_str() {
        "f" => {
            let der = std::fs::read(second_arg)
                .unwrap_or_else(|e| panic!("f: cannot read '{}': {}", second_arg, e));
            let res = match &f_issuer_path {
                Some(p) => {
                    let issuer = std::fs::read(p)
                        .unwrap_or_else(|e| panic!("f: cannot read issuer cert '{}': {}", p, e));
                    let signer = issuer_key_type(&der, &subject_key_types(&[issuer]));
                    if signer.is_none() {
                        eprintln!("f: '{}' is not the issuer of '{}', or its key type is not registered", p, second_arg);
                        std::process::exit(1);
                    }
                    vec![parse_x509_cert_signed_by(der, no_compression, signer)]
                }
                None => vec![parse_x509_item(der, no_compression)],
            };
            if write_output { write_c509_to_files(&res, &target_file); }
            if let Some(p) = &out_path { write_c509_file(&res[0], p); }
            res
        }
        "f2" => {
            if all_args.len() < 4 {
                eprintln!("f2: requires <cert.der> <key.pem>\n{}", USAGE);
                std::process::exit(1);
            }
            let key_path = &all_args[3];
            let der = std::fs::read(second_arg)
                .unwrap_or_else(|e| panic!("f2: cannot read cert '{}': {}", second_arg, e));
            let pem = std::fs::read_to_string(key_path)
                .unwrap_or_else(|e| panic!("f2: cannot read key '{}': {}", key_path, e));
            let ca_der = f2_ca_path.as_ref().map(|p| {
                std::fs::read(p).unwrap_or_else(|e| panic!("f2: cannot read CA cert '{}': {}", p, e))
            });
            let res = vec![encode_x509_as_type2(der, &pem, no_compression, ca_der)];
            if let Some(p) = &out_path { write_c509_file(&res[0], p); }
            res
        }
        "r2" => {
            if all_args.len() < 4 {
                eprintln!("r2: requires <csr.der> <subj_key.pem> [<peer_key.pem>] [--peer-cert <cert.cbor.hex>] [-nc]\n{}", USAGE);
                std::process::exit(1);
            }
            let key_path = &all_args[3];
            let peer_path: Option<&str> = if all_args.len() >= 5 && !all_args[4].starts_with('-') {
                Some(all_args[4].as_str())
            } else {
                None
            };
            // Scan for --peer-cert <path> flag.
            let peer_cert_path: Option<&str> = {
                let flag_start = if peer_path.is_some() { 5 } else { 4 };
                let mut found: Option<&str> = None;
                let mut take_next = false;
                for arg in all_args.iter().skip(flag_start) {
                    if take_next { found = Some(arg.as_str()); break; }
                    if arg == "--peer-cert" { take_next = true; }
                }
                found
            };
            let der = std::fs::read(second_arg)
                .unwrap_or_else(|e| panic!("r2: cannot read CSR '{}': {}", second_arg, e));
            let subj_pem = std::fs::read_to_string(key_path)
                .unwrap_or_else(|e| panic!("r2: cannot read subject key '{}': {}", key_path, e));
            let peer_pem_owned: Option<String> = peer_path.map(|p|
                std::fs::read_to_string(p)
                    .unwrap_or_else(|e| panic!("r2: cannot read peer key '{}': {}", p, e)));
            let peer_cert_owned: Option<Vec<u8>> = peer_cert_path.map(|p| {
                let raw = std::fs::read_to_string(p)
                    .unwrap_or_else(|e| panic!("r2: cannot read peer cert '{}': {}", p, e));
                hex::decode(raw.split_whitespace().collect::<String>())
                    .unwrap_or_else(|e| panic!("r2: peer cert '{}' is not valid hex: {}", p, e))
            });
            // Scan for --embedded-cert-key <path> flag.
            let embedded_cert_key_path: Option<&str> = {
                let flag_start = if peer_path.is_some() { 5 } else { 4 };
                let mut found: Option<&str> = None;
                let mut take_next = false;
                for arg in all_args.iter().skip(flag_start) {
                    if take_next { found = Some(arg.as_str()); break; }
                    if arg == "--embedded-cert-key" { take_next = true; }
                }
                found
            };
            let embedded_cert_key_pem: Option<String> = embedded_cert_key_path.map(|p|
                std::fs::read_to_string(p)
                    .unwrap_or_else(|e| panic!("r2: cannot read embedded cert key '{}': {}", p, e)));
            let res = vec![encode_csr_as_type2(der, &subj_pem, peer_pem_owned.as_deref(),
                                               peer_cert_owned.as_deref(),
                                               embedded_cert_key_pem.as_deref(),
                                               no_compression)];
            if let Some(p) = &out_path { write_c509_file(&res[0], p); }
            res
        }
        "c" => {
            let raw = std::fs::read(second_arg)
                .unwrap_or_else(|e| panic!("c: cannot read '{}': {}", second_arg, e));
            // Binary CBOR starts with a byte above 0x7F; anything else is hex text.
            let bytes = if raw.iter().any(|b| !b.is_ascii()) {
                raw
            } else {
                let hex_str = String::from_utf8(cleanup(raw))
                    .expect("c: hex file is not valid UTF-8");
                hex::decode(hex_str.trim())
                    .expect("c: hex decoding failed — check that the file contains valid hex")
            };
            // parse_c509_item dispatches to parse_c509_cert (11 elements) or
            // parse_c509_csr (7 elements) based on the CBOR sequence length.
            let res = vec![parse_c509_or_exit(bytes)];
            if write_output { write_x509_to_files(&res, &target_file); }
            if let Some(p) = &out_path { write_x509_file(&res[0], p); }
            res
        }
        "l" => {
            let der = std::fs::read(second_arg)
                .unwrap_or_else(|e| panic!("l: cannot read '{}': {}", second_arg, e));
            let path = std::path::Path::new(second_arg);
            let host = path
                .file_name().expect("l: path has no filename")
                .to_str().expect("l: filename is not valid UTF-8")
                .split('_').next().unwrap_or("unknown")
                .to_string();
            vec![loop_on_x509_cert(der, &host, 0, 0, None).0]
        }
        "ll" => {
            if all_args.len() == 3 && std::path::Path::new(second_arg).exists() {
                read_hosts_from_file(second_arg)
            } else {
                process_hosts_parallel(&all_args[2..])
            }
        }
        "u" => get_certs_from_tls(second_arg.clone()),
        "t" => {
            c509::batch::run_hosts(second_arg, &c509::batch::parse_batch_options(&all_args[3..]));
            Vec::new()
        }
        "tf" => {
            c509::batch::run_files(second_arg, &c509::batch::parse_batch_options(&all_args[3..]));
            Vec::new()
        }
        other => {
            eprintln!("Error: unknown command '{}'\n{}", other, USAGE);
            std::process::exit(1);
        }
    };

    if !certs.is_empty() {
        print_information(&certs, suppress_output);
    }
}
