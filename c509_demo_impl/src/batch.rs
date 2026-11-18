//! Batch evaluation on real certificates: lossless round-trip and size statistics.
//!
//! Certificates come from TLS servers (`t <hostlist>`) or from files (`tf <path>`).
//! Every certificate is encoded to C509 type 3 and decoded back; the result must
//! equal the input DER. The summary reports, for the distinct certificates seen,
//! the round-trip outcome, the C509 size relative to the DER size, and which
//! extensions, name attributes and algorithms had to use the generic OID form.
//!
//! Output: `<out>/batch_<timestamp>.log` (summary) and `.csv` (one row per
//! distinct certificate). A certificate that does not round-trip is saved as
//! `<out>/batch_<timestamp>_failed/<fingerprint>.der`.

use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;
use std::net::ToSocketAddrs;

use std::time::Duration;

use log::info;
use rayon::prelude::*;
use rustc_serialize::base64::FromBase64;
use serde_cbor::Value;
use sha2::{Digest, Sha256};

use crate::conversion::{issuer_key_type, parse_c509_cert, parse_x509_cert_signed_by, subject_key_types};
use crate::help::catch_quiet;
use crate::lcbor::lcbor_array;
use crate::registry::{att_map, ext_map};
use crate::tester::tls_client_config;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// How a batch is run and labelled.
pub struct BatchOptions {
    /// Concurrent TLS connections.
    pub jobs: usize,
    /// Hosts per batch; the run pauses between batches.
    pub batch_size: usize,
    /// Pause between batches, in seconds.
    pub pause_secs: u64,
    /// Free text recorded in the summary (e.g. the source list and its date).
    pub label: String,
    /// Output directory.
    pub out_dir: String,
}

impl Default for BatchOptions {
    fn default() -> Self {
        BatchOptions {
            jobs: 8,
            batch_size: 250,
            pause_secs: 5,
            label: String::new(),
            out_dir: "test_results".to_string(),
        }
    }
}

/// Parse `--jobs N --batch-size N --pause S --label TEXT --out DIR`.
pub fn parse_batch_options(args: &[String]) -> BatchOptions {
    let mut opt = BatchOptions::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| -> String {
            it.next().cloned().unwrap_or_else(|| panic!("{} needs a value", name))
        };
        match a.as_str() {
            "--jobs" => opt.jobs = value("--jobs").parse().expect("--jobs: not a number"),
            "--batch-size" => {
                opt.batch_size = value("--batch-size").parse().expect("--batch-size: not a number")
            }
            "--pause" => opt.pause_secs = value("--pause").parse().expect("--pause: not a number"),
            "--label" => opt.label = value("--label"),
            "--out" => opt.out_dir = value("--out"),
            other => eprintln!("Warning: unknown flag '{}' ignored", other),
        }
    }
    opt.jobs = opt.jobs.max(1);
    opt.batch_size = opt.batch_size.max(1);
    opt
}

/// The outcome for one certificate.
struct CertStat {
    fingerprint: String,
    source: String,
    der: Vec<u8>,
    c509_len: usize,
    /// `None`: lossless round-trip. `Some(reason)`: mismatch or conversion error.
    failure: Option<String>,
    is_ca: bool,
    key: String,
    sig: String,
    generic_ext: Vec<String>,
    generic_att: Vec<String>,
    generic_alg: Vec<String>,
}

/// What happened for one host.
enum HostOutcome {
    Chain(Vec<CertStat>),
    Unreachable(String),
    TlsFailure(String),
}

// ── Sources ──────────────────────────────────────────────────────────────────

/// Take the host name from a line of a host list. Accepts a bare name, a
/// `rank,domain` or `origin,rank` CSV line, and an origin with a scheme.
/// Returns `None` for an empty line, a comment or a header.
pub fn host_from_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let field = line.split(',').map(|f| f.trim().trim_matches('"')).find(|f| f.contains('.'))?;
    let host = field
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(|c| c == '/' || c == ':')
        .next()?
        .to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

/// Fetch the certificate chain a TLS server presents on port 443.
fn fetch_chain(host: &str) -> Result<Vec<Vec<u8>>, HostOutcome> {
    let addr = (host, 443)
        .to_socket_addrs()
        .map_err(|e| HostOutcome::Unreachable(format!("DNS: {}", e)))?
        .next()
        .ok_or_else(|| HostOutcome::Unreachable("DNS: no address".into()))?;
    let mut sock = std::net::TcpStream::connect_timeout(&addr, IO_TIMEOUT)
        .map_err(|e| HostOutcome::Unreachable(format!("TCP: {}", e)))?;
    let _ = sock.set_read_timeout(Some(IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(IO_TIMEOUT));

    let name = rustls::ServerName::try_from(host)
        .map_err(|e| HostOutcome::TlsFailure(format!("invalid name: {:?}", e)))?;
    let mut sess = rustls::ClientConnection::new(tls_client_config(), name)
        .map_err(|e| HostOutcome::TlsFailure(format!("{:?}", e)))?;
    while sess.is_handshaking() {
        sess.complete_io(&mut sock).map_err(|e| HostOutcome::TlsFailure(e.to_string()))?;
    }
    Ok(sess.peer_certificates().unwrap_or_default().iter().map(|c| c.0.clone()).collect())
}

/// Every certificate in `data`: the PEM blocks if there are any (also inside
/// other text, such as a CSV report), otherwise the data as one DER certificate.
fn certs_in_file(data: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(data);
    let re = regex::Regex::new(r"(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----")
        .expect("valid regex");
    let pems: Vec<Vec<u8>> = re
        .captures_iter(&text)
        .filter_map(|c| {
            let b64: String = c[1].chars().filter(|ch| !ch.is_whitespace()).collect();
            b64.from_base64().ok()
        })
        .collect();
    if pems.is_empty() && data.first() == Some(&0x30) {
        vec![data.to_vec()]
    } else {
        pems
    }
}

// ── Per-certificate evaluation ───────────────────────────────────────────────

/// Encode `der` to C509 and decode it back; classify the certificate.
fn evaluate(der: Vec<u8>, source: String, signer_key: Option<i64>) -> CertStat {
    let fingerprint = hex::encode(Sha256::digest(&der));
    let mut stat = CertStat {
        fingerprint,
        source,
        der: der.clone(),
        c509_len: 0,
        failure: None,
        is_ca: false,
        key: "?".into(),
        sig: "?".into(),
        generic_ext: vec![],
        generic_att: vec![],
        generic_alg: vec![],
    };

    let encoded = match catch_quiet(|| parse_x509_cert_signed_by(der.clone(), false, signer_key)) {
        Ok(c) if c.cbor.len() == 11 => c,
        Ok(_) => {
            stat.failure = Some("encode: not a certificate".into());
            return stat;
        }
        Err(e) => {
            stat.failure = Some(format!("encode: {}", e));
            return stat;
        }
    };
    let c509 = lcbor_array(&encoded.cbor);
    stat.c509_len = c509.len();
    classify(&encoded.cbor, &mut stat);

    match catch_quiet(|| parse_c509_cert(c509)) {
        Ok(back) if back.der == der => {}
        Ok(_) => stat.failure = Some("decoded DER differs from the input".into()),
        Err(e) => stat.failure = Some(format!("decode: {}", e)),
    }
    stat
}

/// Fill in key, signature, CA flag and the generic-form identifiers from the
/// 11 CBOR fields of a C509 certificate.
fn classify(fields: &[Vec<u8>], stat: &mut CertStat) {
    let value = |i: usize| serde_cbor::from_slice::<Value>(&fields[i]).unwrap_or(Value::Null);

    // Signature algorithm (field 2) and public key (fields 7, 8).
    stat.sig = match value(2) {
        Value::Integer(n) => sig_name(n as i64),
        other => {
            stat.generic_alg.push(alg_oid(&other));
            "other".into()
        }
    };
    stat.key = match value(7) {
        Value::Integer(0) => {
            let modulus = match value(8) {
                Value::Bytes(m) => m.len(),
                Value::Array(a) => match a.first() {
                    Some(Value::Bytes(m)) => m.len(),
                    _ => 0,
                },
                _ => 0,
            };
            format!("RSA-{}", modulus * 8)
        }
        Value::Integer(n) => key_name(n as i64),
        other => {
            stat.generic_alg.push(alg_oid(&other));
            "other".into()
        }
    };

    // Name attributes in the generic form (issuer: field 3, subject: field 6).
    for i in [3usize, 6] {
        if let Value::Array(items) = value(i) {
            for pair in items.chunks(2) {
                if let Some(Value::Bytes(oid)) = pair.first() {
                    stat.generic_att.push(oid_text(oid));
                }
            }
        }
    }

    // Extensions (field 9): an int is the key-usage-only shortcut.
    if let Value::Array(items) = value(9) {
        for pair in items.chunks(2) {
            match pair.first() {
                Some(Value::Integer(id)) if id.abs() == 4 => {
                    // basicConstraints: -2 means cA = false.
                    stat.is_ca = !matches!(pair.get(1), Some(Value::Integer(-2)));
                }
                Some(Value::Bytes(oid)) => stat.generic_ext.push(oid_text(oid)),
                _ => {}
            }
        }
    }
}

fn alg_oid(v: &Value) -> String {
    match v {
        Value::Bytes(oid) => oid_text(oid),
        Value::Array(a) => match a.first() {
            Some(Value::Bytes(oid)) => oid_text(oid),
            _ => "?".into(),
        },
        _ => "?".into(),
    }
}

/// Dotted text of an OID given as its DER value octets.
fn oid_text(oid: &[u8]) -> String {
    let mut arcs: Vec<u64> = Vec::new();
    let mut acc: u64 = 0;
    for (i, b) in oid.iter().enumerate() {
        acc = (acc << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if arcs.is_empty() && i < oid.len() {
                let first = (acc / 40).min(2);
                arcs.push(first);
                arcs.push(acc - first * 40);
            } else {
                arcs.push(acc);
            }
            acc = 0;
        }
    }
    arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".")
}

fn key_name(id: i64) -> String {
    match id {
        1 => "EC P-256".into(),
        2 => "EC P-384".into(),
        3 => "EC P-521".into(),
        6 => "SM2".into(),
        8 => "X25519".into(),
        9 => "X448".into(),
        12 => "Ed25519".into(),
        13 => "Ed448".into(),
        24 => "brainpoolP256r1".into(),
        25 => "brainpoolP384r1".into(),
        26 => "brainpoolP512r1".into(),
        27 => "frp256v1".into(),
        n => format!("key id {}", n),
    }
}

fn sig_name(id: i64) -> String {
    match id {
        -256 => "RSA SHA-1".into(),
        -255 => "ECDSA SHA-1".into(),
        0 => "ECDSA SHA-256".into(),
        1 => "ECDSA SHA-384".into(),
        2 => "ECDSA SHA-512".into(),
        12 => "Ed25519".into(),
        13 => "Ed448".into(),
        23 => "RSA SHA-256".into(),
        24 => "RSA SHA-384".into(),
        25 => "RSA SHA-512".into(),
        26 => "RSA-PSS SHA-256".into(),
        27 => "RSA-PSS SHA-384".into(),
        28 => "RSA-PSS SHA-512".into(),
        n => format!("sig id {}", n),
    }
}

// ── Runs ─────────────────────────────────────────────────────────────────────

/// Test the certificate chains of the hosts listed in `list_path`.
pub fn run_hosts(list_path: &str, opt: &BatchOptions) {
    let hosts: Vec<String> = std::fs::read_to_string(list_path)
        .unwrap_or_else(|e| panic!("t: cannot read '{}': {}", list_path, e))
        .lines()
        .filter_map(host_from_line)
        .collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opt.jobs)
        .build()
        .expect("thread pool");
    info!(
        "{} hosts, {} at a time, batches of {} with {} s pause",
        hosts.len(), opt.jobs, opt.batch_size, opt.pause_secs
    );

    let mut outcomes: Vec<(String, HostOutcome)> = Vec::with_capacity(hosts.len());
    let batches: Vec<&[String]> = hosts.chunks(opt.batch_size).collect();
    {
        for (n, batch) in batches.iter().enumerate() {
            let mut done: Vec<(String, HostOutcome)> = pool.install(|| {
                batch
                    .par_iter()
                    .map(|host| {
                        let outcome = match fetch_chain(host) {
                            Ok(chain) => HostOutcome::Chain({
                                let keys = subject_key_types(&chain);
                                chain
                                    .into_iter()
                                    .enumerate()
                                    .map(|(i, der)| {
                                        let signer = issuer_key_type(&der, &keys);
                                        evaluate(der, format!("{}#{}", host, i), signer)
                                    })
                                    .collect::<Vec<CertStat>>()
                            }),
                            Err(o) => o,
                        };
                        (host.clone(), outcome)
                    })
                    .collect()
            });
            outcomes.append(&mut done);
            info!("batch {}/{} done ({} hosts so far)", n + 1, batches.len(), outcomes.len());
            if n + 1 < batches.len() && opt.pause_secs > 0 {
                std::thread::sleep(Duration::from_secs(opt.pause_secs));
            }
        }
    }
    summarise(&format!("hosts from {}", list_path), outcomes, opt);
}

/// Test the certificates in a file or in every file of a directory.
pub fn run_files(path: &str, opt: &BatchOptions) {
    let mut files: Vec<std::path::PathBuf> = if std::path::Path::new(path).is_dir() {
        std::fs::read_dir(path)
            .unwrap_or_else(|e| panic!("tf: cannot read '{}': {}", path, e))
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect()
    } else {
        vec![std::path::PathBuf::from(path)]
    };
    files.sort();

    let mut ders: Vec<(String, Vec<u8>)> = Vec::new();
    for f in &files {
        let data = std::fs::read(f).unwrap_or_else(|e| panic!("tf: cannot read {:?}: {}", f, e));
        let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        for (i, der) in certs_in_file(&data).into_iter().enumerate() {
            ders.push((format!("{}#{}", name, i), der));
        }
    }
    // The issuer of a certificate is looked up among all certificates read.
    let all: Vec<Vec<u8>> = ders.iter().map(|(_, der)| der.clone()).collect();
    let keys = subject_key_types(&all);
    info!("{} certificates in {} file(s)", ders.len(), files.len());

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opt.jobs)
        .build()
        .expect("thread pool");
    let stats: Vec<CertStat> =
        pool.install(|| {
            ders.into_par_iter()
                .map(|(src, der)| {
                    let signer = issuer_key_type(&der, &keys);
                    evaluate(der, src, signer)
                })
                .collect()
        });
    // Each certificate is its own "chain"; chain statistics are not reported.
    let outcomes = stats
        .into_iter()
        .map(|s| (String::new(), HostOutcome::Chain(vec![s])))
        .collect();
    summarise(&format!("files from {}", path), outcomes, opt);
}

// ── Summary ──────────────────────────────────────────────────────────────────

#[derive(Default)]
struct SizeGroup {
    der: u64,
    c509: u64,
    ratios: Vec<f64>,
}

impl SizeGroup {
    fn add(&mut self, der: usize, c509: usize) {
        self.der += der as u64;
        self.c509 += c509 as u64;
        self.ratios.push(c509 as f64 / der as f64);
    }

    fn row(&mut self, name: &str) -> String {
        let n = self.ratios.len();
        if n == 0 {
            return format!("{:<34} {:>7}", name, 0);
        }
        self.ratios.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pct = |p: f64| self.ratios[((n - 1) as f64 * p).round() as usize] * 100.0;
        let mean = self.ratios.iter().sum::<f64>() / n as f64 * 100.0;
        format!(
            "{:<34} {:>7} {:>11} {:>11} {:>7.1} {:>6.1} {:>6.1} {:>6.1} {:>6.1} {:>6.1} {:>6.1}",
            name, n, self.der, self.c509,
            self.c509 as f64 / self.der as f64 * 100.0,
            pct(0.0), pct(0.1), pct(0.5), mean, pct(0.9), pct(1.0)
        )
    }
}

fn size_header() -> String {
    format!(
        "{:<34} {:>7} {:>11} {:>11} {:>7} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}\n{}",
        "group", "certs", "DER bytes", "C509 bytes", "total%", "min%", "p10%", "med%", "mean%",
        "p90%", "max%",
        "(total% = C509 bytes / DER bytes; the other columns are the per-certificate C509/DER ratio)"
    )
}

fn summarise(input: &str, outcomes: Vec<(String, HostOutcome)>, opt: &BatchOptions) {
    let ts = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    std::fs::create_dir_all(&opt.out_dir).expect("cannot create the output directory");
    let base = format!("{}/batch_{}", opt.out_dir, ts);
    let mut log = File::create(format!("{}.log", base)).expect("cannot create the batch log");
    let is_host_run = input.starts_with("hosts");

    // Hosts, chains and distinct certificates.
    let mut unreachable: Vec<(String, String)> = Vec::new();
    let mut tls_failed: Vec<(String, String)> = Vec::new();
    let mut reached = 0usize;
    let mut seen = 0usize;
    let mut chains = SizeGroup::default();
    let mut unique: HashMap<String, (CertStat, usize)> = HashMap::new();
    let total = outcomes.len();
    for (host, outcome) in outcomes {
        match outcome {
            HostOutcome::Unreachable(e) => unreachable.push((host, e)),
            HostOutcome::TlsFailure(e) => tls_failed.push((host, e)),
            HostOutcome::Chain(stats) => {
                reached += 1;
                seen += stats.len();
                if stats.iter().all(|s| s.c509_len > 0) && !stats.is_empty() {
                    chains.add(
                        stats.iter().map(|s| s.der.len()).sum(),
                        stats.iter().map(|s| s.c509_len).sum(),
                    );
                }
                for s in stats {
                    match unique.get_mut(&s.fingerprint) {
                        Some(entry) => entry.1 += 1,
                        None => {
                            unique.insert(s.fingerprint.clone(), (s, 1));
                        }
                    }
                }
            }
        }
    }
    let mut certs: Vec<(CertStat, usize)> = unique.into_values().collect();
    certs.sort_by(|a, b| a.0.source.cmp(&b.0.source));

    // Size groups and generic-form tallies over the distinct certificates.
    let mut all = SizeGroup::default();
    let mut ee = SizeGroup::default();
    let mut ca = SizeGroup::default();
    let mut by_alg: BTreeMap<String, SizeGroup> = BTreeMap::new();
    let mut ext_count: BTreeMap<String, usize> = BTreeMap::new();
    let mut att_count: BTreeMap<String, usize> = BTreeMap::new();
    let mut alg_count: BTreeMap<String, usize> = BTreeMap::new();
    let mut failed: Vec<&CertStat> = Vec::new();
    for (s, _) in &certs {
        if let Some(_) = &s.failure {
            failed.push(s);
        }
        if s.c509_len == 0 || s.failure.is_some() {
            continue;
        }
        all.add(s.der.len(), s.c509_len);
        if s.is_ca { ca.add(s.der.len(), s.c509_len) } else { ee.add(s.der.len(), s.c509_len) }
        let role = if s.is_ca { "CA" } else { "EE" };
        by_alg
            .entry(format!("{} {} key, {} sig", role, s.key, s.sig))
            .or_default()
            .add(s.der.len(), s.c509_len);
        let tally = |list: &Vec<String>, map: &mut BTreeMap<String, usize>| {
            let mut ids = list.clone();
            ids.sort();
            ids.dedup();
            for id in ids {
                *map.entry(id).or_default() += 1;
            }
        };
        tally(&s.generic_ext, &mut ext_count);
        tally(&s.generic_att, &mut att_count);
        tally(&s.generic_alg, &mut alg_count);
    }

    // ---- Summary ----
    let w = &mut log;
    let _ = writeln!(w, "C509 batch test {}", ts);
    let _ = writeln!(w, "tool: c509 {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(w, "input: {}", input);
    if !opt.label.is_empty() {
        let _ = writeln!(w, "label: {}", opt.label);
    }
    if is_host_run {
        let _ = writeln!(
            w, "run: {} connections at a time, batches of {} hosts, {} s pause",
            opt.jobs, opt.batch_size, opt.pause_secs
        );
        let _ = writeln!(w, "\nHosts");
        let _ = writeln!(w, "  listed:                   {}", total);
        let _ = writeln!(w, "  chain received:           {}", reached);
        let _ = writeln!(w, "  unreachable (DNS/TCP):    {}", unreachable.len());
        let _ = writeln!(w, "  TLS handshake failed:     {}", tls_failed.len());
        let _ = writeln!(
            w, "  (the handshake validates the chain against the Mozilla root set, so hosts \
               with an invalid chain are in the last line)"
        );
    }
    let _ = writeln!(w, "\nCertificates");
    let _ = writeln!(w, "  received:                 {}", seen);
    let _ = writeln!(w, "  distinct:                 {}", certs.len());
    let _ = writeln!(w, "  lossless round-trip:      {}", certs.len() - failed.len());
    let _ = writeln!(w, "  not lossless:             {}", failed.len());

    let _ = writeln!(w, "\nSize of the distinct certificates that round-trip (C509 type 3 vs DER)");
    let _ = writeln!(w, "{}", size_header());
    let _ = writeln!(w, "{}", all.row("all"));
    let _ = writeln!(w, "{}", ee.row("end-entity"));
    let _ = writeln!(w, "{}", ca.row("CA"));
    let _ = writeln!(w);
    for (name, group) in by_alg.iter_mut() {
        let _ = writeln!(w, "{}", group.row(name));
    }
    if is_host_run {
        let _ = writeln!(w, "\nSize of the chains as sent by the hosts (all certificates of a chain)");
        let _ = writeln!(w, "{}", size_header());
        let _ = writeln!(w, "{}", chains.row("chains"));
    }

    let mut list = |title: &str, map: &BTreeMap<String, usize>, known: &dyn Fn(&str) -> bool| {
        let _ = writeln!(w, "\n{} ({} distinct)", title, map.len());
        let mut rows: Vec<(&String, &usize)> = map.iter().collect();
        rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (oid, n) in rows {
            let note = if known(oid) { "  registered, not CBOR-encodable in this certificate" } else { "" };
            let _ = writeln!(w, "  {:>7}  {}{}", n, oid, note);
        }
    };
    list(
        "Extensions in the generic OID form, by number of certificates",
        &ext_count,
        &|oid| oid_value(oid).map(|v| ext_map(&v).is_some()).unwrap_or(false),
    );
    list(
        "Name attributes in the generic OID form, by number of certificates",
        &att_count,
        &|oid| oid_value(oid).map(|v| att_map(&v).is_some()).unwrap_or(false),
    );
    list("Algorithms in the generic OID form, by number of certificates", &alg_count, &|_| false);

    if !failed.is_empty() {
        let dir = format!("{}_failed", base);
        std::fs::create_dir_all(&dir).expect("cannot create the failure directory");
        let _ = writeln!(w, "\nNot lossless (DER saved in {})", dir);
        for s in &failed {
            let _ = writeln!(
                w, "  {}  {}  {}",
                &s.fingerprint[..16], s.source, s.failure.as_deref().unwrap_or("")
            );
            let _ = std::fs::write(format!("{}/{}.der", dir, s.fingerprint), &s.der);
        }
    }
    if !unreachable.is_empty() || !tls_failed.is_empty() {
        let _ = writeln!(w, "\nHosts without a chain");
        for (h, e) in unreachable.iter().chain(tls_failed.iter()) {
            let _ = writeln!(w, "  {}: {}", h, e);
        }
    }

    // ---- One row per distinct certificate ----
    let mut csv = File::create(format!("{}.csv", base)).expect("cannot create the batch CSV");
    let _ = writeln!(
        csv,
        "sha256,first_source,occurrences,role,key,signature,der_bytes,c509_bytes,lossless,\
         generic_extensions,generic_attributes,failure"
    );
    for (s, n) in &certs {
        let _ = writeln!(
            csv, "{},{},{},{},{},{},{},{},{},{},{},{}",
            s.fingerprint, s.source, n,
            if s.is_ca { "CA" } else { "EE" },
            s.key, s.sig, s.der.len(), s.c509_len,
            s.failure.is_none(),
            s.generic_ext.join(";"), s.generic_att.join(";"),
            s.failure.as_deref().unwrap_or("").replace(',', ";")
        );
    }

    info!("Batch complete: {}.log and .csv", base);
    info!(
        "{} distinct certificates, {} not lossless; C509 is {:.1}% of DER overall",
        certs.len(), failed.len(),
        if all.der > 0 { all.c509 as f64 / all.der as f64 * 100.0 } else { 0.0 }
    );
}

/// DER value octets of a dotted OID (the inverse of `oid_text`).
fn oid_value(text: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u64> = text.split('.').map(|a| a.parse().ok()).collect::<Option<_>>()?;
    if arcs.len() < 2 {
        return None;
    }
    let mut out = Vec::new();
    let mut push = |mut v: u64| {
        let mut stack = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            stack.push((v & 0x7f) as u8 | 0x80);
            v >>= 7;
        }
        stack.reverse();
        out.extend(stack);
    };
    push(arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        push(*a);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_lines() {
        assert_eq!(host_from_line("example.com"), Some("example.com".into()));
        assert_eq!(host_from_line("12,Example.org"), Some("example.org".into()));
        assert_eq!(host_from_line("https://www.example.net,1000"), Some("www.example.net".into()));
        assert_eq!(host_from_line("origin,rank"), None);
        assert_eq!(host_from_line("# comment"), None);
        assert_eq!(host_from_line(""), None);
    }

    #[test]
    fn oid_round_trip() {
        let san = [0x55, 0x1d, 0x11];
        assert_eq!(oid_text(&san), "2.5.29.17");
        assert_eq!(oid_value("2.5.29.17"), Some(san.to_vec()));
        let wisun = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe4, 0x25, 0x01];
        assert_eq!(oid_text(&wisun), "1.3.6.1.4.1.45605.1");
        assert_eq!(oid_value("1.3.6.1.4.1.45605.1"), Some(wisun.to_vec()));
    }
}
