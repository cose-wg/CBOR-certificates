//! TLS fetching, batch round-trip testing, and CLI output formatting.
//!
//! The primary public entry points for tests are:
//! - [`loop_on_x509_cert`] — single-cert round-trip (X.509 → C509 → X.509)
//! - [`process_hosts_parallel`] — parallel batch test over a list of domains
//! - [`read_hosts_from_file`] — read hosts from a file, then batch test

use std::convert::TryFrom;
use crate::help::*;
use crate::conversion::*;
use crate::lcbor::*;
use crate::*; // Cert, PRINT_* constants

use std::fs::{File, read_to_string};
use std::io::Write;
use log::{info, warn, trace};
use rayon::prelude::*;
use rustc_serialize::base64::{ToBase64, STANDARD};
use std::panic;

// Relative to the `c509_demo_impl/` directory; created by the repo makefile.
const COULD_CONVERT_DIR: &str = "../could_convert/";
const FAILED_CONVERT_DIR: &str = "../failed_convert/";

/// Result of testing a single TLS host.
#[derive(Debug, Clone)]
pub enum HostTestResult {
    /// TLS connection succeeded and all certs were round-tripped.
    Success { certs: Vec<Cert>, failed_count: usize },
    /// Could not establish a TCP/TLS connection.
    ConnectionError { host: String, error: String },
    /// Connection succeeded but cert processing panicked or failed.
    ProcessingError { host: String, error: String },
}

/// Write the C509 encoding of each cert to a `.cbor.hex` sidecar file.
pub fn write_c509_to_files(certs: &[Cert], input_path: &str) {
    for (i, cert) in certs.iter().enumerate() {
        let base = strip_extension(input_path, &[".crt", ".pem"]);
        let suffix = if certs.len() > 1 { format!("_{}", i) } else { String::new() };
        let hex_path = format!("{}{}.cbor.hex", base, suffix);
        let mut hex_file = File::create(&hex_path).expect("write_c509_to_files: cannot create .cbor.hex");
        // draft-20: the canonical C509Certificate is the full CBOR array (with the
        // `8B` array(11) header); the unwrapped sequence ~C509Certificate is gone.
        for byte in lcbor_array(&cert.cbor) {
            let _ = write!(hex_file, "{:02X}", byte);
        }
        info!("Wrote C509 hex to {}", hex_path);
    }
}

/// Write the X.509 DER and PEM encodings of each cert to sidecar files.
pub fn write_x509_to_files(certs: &[Cert], input_path: &str) {
    for (i, cert) in certs.iter().enumerate() {
        let base = strip_extension(input_path, &[".cbor.hex"]);
        let suffix = if certs.len() > 1 { format!("_{}", i) } else { String::new() };

        let crt_path = format!("{}{}.crt", base, suffix);
        let mut crt_file = File::create(&crt_path).expect("write_x509_to_files: cannot create .crt");
        crt_file.write_all(&cert.der).expect("write_x509_to_files: cannot write DER");
        info!("Wrote X.509 DER to {}", crt_path);

        let pem_path = format!("{}{}.pem", base, suffix);
        let mut pem_file = File::create(&pem_path).expect("write_x509_to_files: cannot create .pem");
        writeln!(pem_file, "-----BEGIN CERTIFICATE-----").expect("write .pem");
        let b64 = cert.der.to_base64(STANDARD);
        for chunk in b64.as_bytes().chunks(64) {
            pem_file.write_all(chunk).expect("write .pem");
            writeln!(pem_file).expect("write .pem");
        }
        writeln!(pem_file, "-----END CERTIFICATE-----").expect("write .pem");
        info!("Wrote X.509 PEM to {}", pem_path);
    }
}

/// Strip any of `suffixes` from the end of `path` and return the result.
fn strip_extension<'a>(path: &'a str, suffixes: &[&str]) -> &'a str {
    for suffix in suffixes {
        if let Some(base) = path.strip_suffix(suffix) {
            return base;
        }
    }
    path
}

/// Fetch the certificate chain from `domain_name:443` via TLS and encode each
/// certificate to C509.
///
/// # Panics
/// Panics if the connection, TLS handshake, or certificate parsing fails.
/// Build a rustls client config that trusts the webpki-roots CA bundle.
fn tls_client_config() -> std::sync::Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject, ta.spki, ta.name_constraints,
        )
    }));
    std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

pub fn get_certs_from_tls(domain_name: String) -> Vec<Cert> {
    let server_name = rustls::ServerName::try_from(domain_name.as_str()).unwrap();
    let mut sess = rustls::ClientConnection::new(tls_client_config(), server_name).unwrap();
    let mut sock = std::net::TcpStream::connect(domain_name.clone() + ":443").unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);
    tls.write_all(b"GET / HTTP/1.1").unwrap();
    tls.flush().unwrap();
    tls.conn
        .peer_certificates()
        .unwrap()
        .iter()
        .map(|c| parse_x509_cert(c.0.clone()))
        .collect()
}

/// Connect to `domain_name:443`, round-trip each certificate (X.509 → C509 →
/// X.509), and return a [`HostTestResult`].
pub fn loop_on_certs_from_tls(domain_name: &String, no: i64) -> HostTestResult {
    let server_name = match rustls::ServerName::try_from(domain_name.as_str()) {
        Ok(name) => name,
        Err(e) => return HostTestResult::ProcessingError {
            host:  domain_name.clone(),
            error: format!("Invalid DNS name: {:?}", e),
        },
    };
    let mut sess = match rustls::ClientConnection::new(tls_client_config(), server_name) {
        Ok(conn) => conn,
        Err(e) => return HostTestResult::ConnectionError {
            host:  domain_name.clone(),
            error: format!("TLS client init error: {:?}", e),
        },
    };
    let conn_addr = format!("{}:443", domain_name);

    match std::net::TcpStream::connect(&conn_addr) {
        Ok(mut stream) => {
            stream.set_write_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
            let mut tls = rustls::Stream::new(&mut sess, &mut stream);

            if tls.write_all(b"GET / HTTP/1.1").is_ok() {
                if let Err(e) = tls.flush() {
                    return HostTestResult::ConnectionError {
                        host:  domain_name.clone(),
                        error: format!("TLS flush error: {:?}", e),
                    };
                }
                // cert_index is passed as sub_no to loop_on_x509_cert so each
                // cert in the chain gets a unique output filename suffix.
                let mut cert_index: u8 = 0;
                let mut failed_count = 0;
                let certs: Vec<Cert> = tls.conn
                    .peer_certificates()
                    .unwrap_or_default()
                    .iter()
                    .map(|c| {
                        cert_index += 1;
                        let (cert, success) =
                            loop_on_x509_cert(c.0.clone(), domain_name.as_str(), no, cert_index);
                        if !success { failed_count += 1; }
                        cert
                    })
                    .collect();
                HostTestResult::Success { certs, failed_count }
            } else {
                let msg = format!("Error writing to {}", domain_name);
                warn!("{}", msg);
                HostTestResult::ConnectionError { host: domain_name.clone(), error: msg }
            }
        }
        Err(_) => {
            let msg = format!("Error opening {}", domain_name);
            warn!("{}", msg);
            HostTestResult::ConnectionError { host: domain_name.clone(), error: msg }
        }
    }
}

/// Round-trip a single X.509 DER cert or CSR: encode to C509, decode back,
/// compare bytes, and log the result.
///
/// Returns `(cert, success)` where `success` is `true` iff the reconstructed
/// DER matches the input byte-for-byte.  The output files are written to
/// `../could_convert/` or `../failed_convert/` depending on the result.
pub fn loop_on_x509_cert(input: Vec<u8>, host: &str, no: i64, sub_no: u8) -> (Cert, bool) {
    let original = input.clone();
    let parsed = parse_x509_item(input, false);

    // Detect cert vs CSR by element count: 11 = certificate, 7 = CSR.
    let is_csr = parsed.cbor.len() == 7;
    let reconstructed = if is_csr {
        parse_c509_csr(lcbor_array(&parsed.cbor))
    } else {
        parse_c509_cert(lcbor_array(&parsed.cbor))
    };

    let ts = chrono::Local::now().format("%Y-%m-%d_%H:%M:%S");
    let base_name = format!("{}_{}_{}", host, sub_no, ts);

    let success = reconstructed.der == original;
    let (write_dir, log_fn): (&str, &dyn Fn(&str)) = if success {
        info!(
            "The input X.509 certificate for host {} with number {} was successfully encoded \
             and reconstructed. {} vs {} bytes",
            host, no, original.len(), reconstructed.der.len()
        );
        (COULD_CONVERT_DIR, &|_| {})
    } else {
        print_str_warning("File re-encoding failure");
        warn!(
            "The input X.509 certificate for host {} with number {} COULD NOT be encoded \
             and reconstructed. {} vs {} bytes",
            host, no, original.len(), reconstructed.der.len()
        );
        (FAILED_CONVERT_DIR, &|p: &str| warn!("Storing file as {}", p))
    };

    let base_path = format!("{}{}", write_dir, base_name);
    log_fn(&base_path);

    let mut in_file  = File::create(format!("{}.input.hex",  base_path)).expect("cannot create input hex");
    let mut out_file = File::create(format!("{}.output.hex", base_path)).expect("cannot create output hex");
    for byte in &original           { let _ = write!(in_file,  "{:02X} ", byte); }
    for byte in &reconstructed.der  { let _ = write!(out_file, "{:02X} ", byte); }

    // Return the original DER with the C509 CBOR fields (the caller may
    // use the CBOR for display purposes).
    (Cert { der: original, cbor: parsed.cbor }, success)
}

/// Summarise batch results and write a timestamped log file to `test_results/`.
pub fn analyze_and_log_batch_results(results: &[HostTestResult]) {
    let total = results.len();
    let mut unreachable = Vec::new();
    let mut successes = 0usize;
    let mut total_certs = 0usize;
    let mut total_failed = 0usize;
    let mut errors = Vec::new();

    for res in results {
        match res {
            HostTestResult::Success { certs, failed_count } => {
                successes += 1;
                total_certs += certs.len();
                total_failed += failed_count;
            }
            HostTestResult::ConnectionError { host, error } => {
                unreachable.push((host.clone(), error.clone()));
            }
            HostTestResult::ProcessingError { host, error } => {
                errors.push((host.clone(), error.clone()));
            }
        }
    }

    let ts = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    let log_path = format!("test_results/batch_test_{}.log", ts);
    let mut log = File::create(&log_path).expect("cannot create batch log");

    let _ = writeln!(log, "Batch Test Summary ({})", ts);
    let _ = writeln!(log, "Total hosts:              {}", total);
    let _ = writeln!(log, "Successfully reached:     {}", successes);
    let _ = writeln!(log, "Unreachable:              {}", unreachable.len());
    let _ = writeln!(log, "Processing errors:        {}", errors.len());
    let _ = writeln!(log, "Certificates found:       {}", total_certs);
    let _ = writeln!(log, "Failed lossless converts: {}", total_failed);

    if !unreachable.is_empty() {
        let _ = writeln!(log, "\n--- Unreachable Hosts ---");
        for (h, e) in &unreachable { let _ = writeln!(log, "{}: {}", h, e); }
    }
    if !errors.is_empty() {
        let _ = writeln!(log, "\n--- Processing Errors ---");
        for (h, e) in &errors { let _ = writeln!(log, "{}: {}", h, e); }
    }

    info!("Batch test complete. Results logged to {}", log_path);
    info!("Summary: {}/{} hosts reached, {} certs, {} conversion failures.",
          successes, total, total_certs, total_failed);
}

/// Run [`loop_on_certs_from_tls`] for every host in `hosts` in parallel using
/// Rayon.  Panics inside individual workers are caught and recorded as
/// [`HostTestResult::ProcessingError`].
///
/// Results are logged to `test_results/` and the function always returns an
/// empty vector (side effects are the primary output).
pub fn process_hosts_parallel(hosts: &[String]) -> Vec<Cert> {
    info!("Starting batch test of {} hosts in parallel…", hosts.len());
    let results: Vec<HostTestResult> = hosts
        .par_iter()
        .enumerate()
        .map(|(i, host)| {
            trace!("Testing {} (index {})", host, i);
            match panic::catch_unwind(|| loop_on_certs_from_tls(host, i as i64)) {
                Ok(res) => res,
                Err(e)  => HostTestResult::ProcessingError {
                    host:  host.clone(),
                    error: format!("panic: {:?}", e),
                },
            }
        })
        .collect();

    analyze_and_log_batch_results(&results);
    Vec::new()
}

/// Read a newline-separated list of hostnames from `filename` and batch-test them.
pub fn read_hosts_from_file(filename: &str) -> Vec<Cert> {
    let hosts: Vec<String> = read_to_string(filename)
        .unwrap_or_else(|e| panic!("read_hosts_from_file: cannot read '{}': {}", filename, e))
        .lines()
        .map(String::from)
        .collect();
    process_hosts_parallel(&hosts)
}

/// Print the full diagnostic output for a set of encoded certs.
///
/// `suppress_output` skips all printing (used with `-wo` write-only mode).
pub fn print_information(certs: &[Cert], suppress_output: bool) {
    if suppress_output { return; }

    let der_total: u64 = certs.iter().map(|c| c.der.len() as u64).sum();
    // draft-20: size counts the full C509Certificate array (incl. the `8B` header).
    let cbor_total: u64 = certs.iter().map(|c| lcbor_array(&c.cbor).len() as u64).sum();
    print_info(&[
        format!("Encoding certificate chain/bag with {} certificates", certs.len()),
        format!("{} bytes / {} bytes ({:.2}%)", cbor_total, der_total,
                100.0 * cbor_total as f64 / der_total as f64),
    ]);

    for (i, cert) in certs.iter().enumerate() {
        // draft-20: emit the full C509Certificate CBOR array (the `8B` header is
        // part of the certificate; the unwrapped ~C509Certificate sequence is gone).
        let cbor_bytes = lcbor_array(&cert.cbor);
        print_info(&[
            format!("Encoding certificate {} of {}", i + 1, certs.len()),
            format!("{} bytes / {} bytes ({:.2}%)", cbor_bytes.len(), cert.der.len(),
                    100.0 * cbor_bytes.len() as f64 / cert.der.len() as f64),
        ]);
        if PRINT_INPUT {
            print_vec("Input: DER encoded X.509 certificate (RFC 5280)", &cert.der);
        }
        if PRINT_OUTPUT {
            if cert.cbor.len() >= 11 {
                // Certificate: 11 CBOR fields
                print_vec("Output: CBOR encoded X.509 certificate (C509Certificate)", &cbor_bytes);
                print_vec("C509 Certificate Type",          &cert.cbor[0]);
                print_vec("Certificate Serial Number",      &cert.cbor[1]);
                print_vec("Issuer Signature Algorithm",     &cert.cbor[2]);
                print_vec("Issuer",                         &cert.cbor[3]);
                print_vec("Validity Not Before",            &cert.cbor[4]);
                print_vec("Validity Not After",             &cert.cbor[5]);
                print_vec("Subject",                        &cert.cbor[6]);
                print_vec("Subject Public Key Algorithm",   &cert.cbor[7]);
                print_vec("Subject Public Key",             &cert.cbor[8]);
                print_vec("Extensions",                     &cert.cbor[9]);
                print_vec("Issuer Signature Value",         &cert.cbor[10]);
            } else if cert.cbor.len() == 7 && cert.cbor.first().map_or(false, |f| f == &[0x00]) {
                // CRT: 7 CBOR fields, first = uint(0) (templateType)
                print_vec("Output: C509 CertificationRequestTemplate", &cbor_bytes);
                print_vec("CRT Template Type",          &cert.cbor[0]);
                print_vec("CRT Request Type",           &cert.cbor[1]);
                print_vec("CRT Subject Sig Alg",        &cert.cbor[2]);
                print_vec("CRT Subject",                &cert.cbor[3]);
                print_vec("CRT Subject PK Alg",         &cert.cbor[4]);
                print_vec("CRT Subject PK",             &cert.cbor[5]);
                print_vec("CRT Extensions Request",     &cert.cbor[6]);
            } else {
                // CSR or other structure with fewer fields
                warn!("Could not print detailed output: cert.cbor.len() = {}", cert.cbor.len());
            }
        }
    }

    if PRINT_COSE {
        print_info(&[format!("CBOR COSE_X509 with {} certificates", certs.len())]);
        if certs.len() > 1 {
            let cose_x509: Vec<Vec<u8>> = certs.iter().map(|c| lcbor_bytes(&c.der)).collect();
            print_vec("COSE_X509", &lcbor_array(&cose_x509));
        } else if !certs.is_empty() {
            print_vec("COSE_X509", &lcbor_bytes(&certs[0].der));
        } else {
            println!("Operation failed, exiting");
            std::process::exit(0);
        }

        // draft-20: COSE_C509 = C509CertData / [2* C509CertData], where
        // C509CertData = bytes .cbor C509Certificate (a CBOR byte string wrapping the
        // full cert array, was `.cborseq` in -19). Media type application/cose-c509+cbor.
        print_info(&[format!("CBOR COSE_C509 with {} certificates", certs.len())]);
        if certs.len() > 1 {
            let mut cose_c509: Vec<Vec<u8>> = Vec::new();
            for cert in certs {
                let cert_data = lcbor_bytes(&lcbor_array(&cert.cbor));
                cose_c509.push(cert_data.clone());
                println!("COSE_C509 C509CertData (single certificate)");
                print_vec_compact(&cert_data);
                println!();
            }
            print_vec("\nCOSE_C509 chain", &lcbor_array(&cose_c509));
        } else {
            let cert_data = lcbor_bytes(&lcbor_array(&certs[0].cbor));
            print_vec("COSE_C509 (C509CertData)", &cert_data);
            print_vec_compact(&cert_data);
            println!();
        }
    }

    if PRINT_TLS {
        // TLS 1.3 Certificate message format (RFC 8446 §4.4.2):
        //   Handshake.msg_type = 0x0b (certificate)
        //   Followed by certificate_request_context (1 byte = 0x00 for server)
        //   Then CertificateList: each entry has 3-byte length + DER + 2-byte extensions length
        let build_tls_cert_msg = |der_list: Vec<&[u8]>| -> Vec<u8> {
            let mut body: Vec<u8> = Vec::new();
            for der in der_list {
                let len = der.len() as u32;
                body.extend(&len.to_be_bytes()[1..4]); // 3-byte cert length
                body.extend(der);
                body.extend(&[0x00, 0x00]);             // 2-byte extensions length
            }
            let body_len = body.len() as u32;
            let mut msg = vec![0x00]; // certificate_request_context length = 0
            msg.extend(&body_len.to_be_bytes()[1..4]);
            msg.extend(body);
            let msg_len = msg.len() as u32;
            let mut handshake = vec![0x0B]; // msg_type = certificate
            handshake.extend(&msg_len.to_be_bytes()[1..4]);
            handshake.extend(msg);
            handshake
        };

        print_info(&[format!("TLS 1.3 Certificate message with {} certificates (X.509)", certs.len())]);
        let tls_x509 = build_tls_cert_msg(certs.iter().map(|c| c.der.as_slice()).collect());
        print_vec("TLS_X509", &tls_x509);

        print_info(&["TLS 1.3 CompressedCertificate message (X.509 + Brotli)".to_string()]);
        let mut tls_x509_brotli = brotli(&tls_x509);
        // CompressedCertificate format (RFC 8879): algorithm (2B) + uncompressed_len (3B) + compressed (length-prefixed)
        let uncomp_len = tls_x509.len() as u32;
        tls_x509_brotli = [&(tls_x509_brotli.len() as u32).to_be_bytes()[1..4], &tls_x509_brotli].concat();
        tls_x509_brotli = [&[0x00, 0x02], &uncomp_len.to_be_bytes()[1..4], &tls_x509_brotli].concat();
        tls_x509_brotli = [&[0x19], &(tls_x509_brotli.len() as u32).to_be_bytes()[1..4], &tls_x509_brotli].concat();
        print_vec("Brotli TLS_X509", &tls_x509_brotli);

        print_info(&[format!("TLS 1.3 Certificate message with {} certificates (C509)", certs.len())]);
        // draft-20: TLS c509_data is the CBOR-encoded C509Certificate (the full array).
        let c509_ders: Vec<Vec<u8>> = certs.iter().map(|c| lcbor_array(&c.cbor)).collect();
        let tls_c509 = build_tls_cert_msg(c509_ders.iter().map(|v| v.as_slice()).collect());
        print_vec("TLS_C509", &tls_c509);

        print_info(&["TLS 1.3 CompressedCertificate message (C509 + Brotli)".to_string()]);
        let uncomp_len = tls_c509.len() as u32;
        let mut tls_c509_brotli = brotli(&tls_c509);
        tls_c509_brotli = [&(tls_c509_brotli.len() as u32).to_be_bytes()[1..4], &tls_c509_brotli].concat();
        tls_c509_brotli = [&[0x00, 0x02], &uncomp_len.to_be_bytes()[1..4], &tls_c509_brotli].concat();
        tls_c509_brotli = [&[0x19], &(tls_c509_brotli.len() as u32).to_be_bytes()[1..4], &tls_c509_brotli].concat();
        print_vec("Brotli TLS_C509", &tls_c509_brotli);
    }
}
