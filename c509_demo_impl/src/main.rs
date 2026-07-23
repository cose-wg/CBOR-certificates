//! Command-line entry point for the C509 reference implementation.
//!
//! Run `cargo run --bin c509 -- --help` or see README.md for usage.

use c509::conversion::*;
use c509::tester::*;
use c509::help::*;
use c509::type2::encode_x509_as_type2;
use c509::type2_csr::encode_csr_as_type2;
use std::env::args;
use env_logger::Env;
use log::info;

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
  f  <cert.der> -nc  Encode EC public keys uncompressed (no FE/FD prefix)
  c  <c509.cbor.hex> Decode C509 hex → X.509 DER/CSR (stdout)
  c  <c509.cbor.hex> -w   Also write .crt and .pem files
  u  <domain>        Fetch TLS chain from domain, encode each cert
  l  <cert.der>      Round-trip: X.509 → C509 → X.509, compare bytes
  ll <domain …>      Round-trip for one or more domains (parallel)
  t  <urllist.txt>   Bulk round-trip test from a URL list file
  f2 <cert.der> <key.pem>                    Encode X.509 DER → Type-2 C509 hex
  f2 <cert.der> <key.pem> -nc               Also store EC public keys uncompressed
  r2 <csr.der> <subj_key.pem>               Encode PKCS#10 DER → Type-2 C509 CSR (ECDSA/unsigned)
  r2 <csr.der> <subj_key.pem> <peer_key.pem> --peer-cert <cert.cbor.hex>  DhSigStatic (RFC 6955)
  r2 ... --embedded-cert-key <key.pem>     Re-sign embedded C509 certs in attrs as type-2
  r2 ... -nc                                Also store EC public keys uncompressed
";

    let all_args: Vec<String> = args().collect();

    if all_args.len() < 3 {
        eprintln!("{}", USAGE);
        std::process::exit(1);
    }

    let first_arg  = &all_args[1];
    let second_arg = &all_args[2];

    let mut suppress_output = false;
    let mut write_output    = false;
    let mut no_compression  = false;
    let target_file = second_arg.clone();

    if first_arg == "c" || first_arg == "f" {
        for arg in all_args.iter().skip(3) {
            match arg.as_str() {
                "-w"  => write_output = true,
                "-wo" => { write_output = true; suppress_output = true; }
                "-nc" => no_compression = true,
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
                other => eprintln!("Warning: unknown flag '{}' ignored", other),
            }
        }
    }
    // r2: peer key is optional at position 4; --peer-cert, --embedded-cert-key, -nc follow.
    if first_arg == "r2" {
        let flag_start = if all_args.len() >= 5 && !all_args[4].starts_with('-') { 5 } else { 4 };
        let mut skip_next = false;
        for arg in all_args.iter().skip(flag_start) {
            if skip_next { skip_next = false; continue; }
            match arg.as_str() {
                "-nc" => no_compression = true,
                "--peer-cert" | "--embedded-cert-key" => skip_next = true, // value consumed later
                other => eprintln!("Warning: unknown flag '{}' ignored", other),
            }
        }
    }

    let certs = match first_arg.as_str() {
        "f" => {
            let der = std::fs::read(second_arg)
                .unwrap_or_else(|e| panic!("f: cannot read '{}': {}", second_arg, e));
            let res = vec![parse_x509_item(der, no_compression)];
            if write_output { write_c509_to_files(&res, &target_file); }
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
            vec![encode_x509_as_type2(der, &pem, no_compression, ca_der)]
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
            vec![encode_csr_as_type2(der, &subj_pem, peer_pem_owned.as_deref(),
                                     peer_cert_owned.as_deref(),
                                     embedded_cert_key_pem.as_deref(),
                                     no_compression)]
        }
        "c" => {
            let raw = std::fs::read(second_arg)
                .unwrap_or_else(|e| panic!("c: cannot read '{}': {}", second_arg, e));
            let hex_str = String::from_utf8(cleanup(raw))
                .expect("c: hex file is not valid UTF-8");
            let bytes = hex::decode(hex_str.trim())
                .expect("c: hex decoding failed — check that the file contains valid hex");
            // parse_c509_item dispatches to parse_c509_cert (11 elements) or
            // parse_c509_csr (7 elements) based on the CBOR sequence length.
            let res = vec![parse_c509_item(bytes)];
            if write_output { write_x509_to_files(&res, &target_file); }
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
            vec![loop_on_x509_cert(der, &host, 0, 0).0]
        }
        "ll" => {
            if all_args.len() == 3 && std::path::Path::new(second_arg).exists() {
                read_hosts_from_file(second_arg)
            } else {
                process_hosts_parallel(&all_args[2..])
            }
        }
        "u" => get_certs_from_tls(second_arg.clone()),
        "t" => read_hosts_from_file(second_arg),
        other => {
            eprintln!("Error: unknown command '{}'\n{}", other, USAGE);
            std::process::exit(1);
        }
    };

    if !certs.is_empty() {
        print_information(&certs, suppress_output);
    }
}
