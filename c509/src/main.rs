// DER encoded X.509 to CBOR encoded X.509 (C509)
// Copyright (c) 2021, Ericsson and John Preuß Mattsson <john.mattsson@ericsson.com>
// This version implements draft-ietf-cose-cbor-encoded-cert-01
//
// To read a DER encoded X.509 from file:
// "cargo r f example.cer"
//
// To read a DER encoded X.509 chain/bag from a TLS server:
// "cargo r u www.ietf.org"
// "cargo r u tools.ietf.org"
//
// http://cbor.me/ is recommended to transform beteen CBOR encoding and diagniostic notatation.
//
// This software may be distributed under the terms of the 3-Clause BSD License.

use crate::cbor::*;
use crate::der::*;
use {rustls::*, std::io::Write, webpki, webpki_roots};
use {std::env::args, std::str::from_utf8};

pub const SECG_EVEN: u8 = 0x02;
pub const SECG_ODD: u8 = 0x03;
pub const SECG_UNCOMPRESSED: u8 = 0x04;

struct Cert {
    der: Vec<u8>,
    cbor: Vec<Vec<u8>>,
}

// Make a TLS connection to get server certificate chain
fn get_certs_from_tls(domain_name: String) -> Vec<Cert> {
    let mut config = rustls::ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(&domain_name).unwrap();
    let mut sess = rustls::ClientSession::new(&std::sync::Arc::new(config), dns_name);
    let mut sock = std::net::TcpStream::connect(domain_name + ":443").unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);
    tls.write_all(b"GET / HTTP/1.1").unwrap();
    tls.flush().unwrap();
    let mut certs: Vec<Cert> = Vec::new();
    for cert in tls.sess.get_peer_certificates().unwrap() {
        certs.push(parse_cert(cert.0));
    }
    certs
}

fn main() {
    // get certificate from file or tls server and parse them
    let first_arg = args().nth(1).unwrap();
    let second_arg = args().nth(2).expect("No file/domain name given!");
    let certs = if first_arg == "f" {
        vec![parse_cert(std::fs::read(second_arg).unwrap())]
    } else if first_arg == "u" {
        get_certs_from_tls(second_arg)
    } else {
        panic!("expected f or u");
    };

    // calculate lengths for printing
    let mut der_len = 0;
    let mut cbor_len = 0;
    for cert in &certs {
        der_len += cert.der.len();
        cbor_len += cert.cbor.concat().len();
    }

    // print information
    println!();
    println!("--------------------------------------------------------------------");
    println!("Encoding certificate chain/bag with {} certificates", certs.len());
    println!("{} bytes / {} bytes ({:.2}%)", cbor_len, der_len, 100.0 * cbor_len as f64 / der_len as f64);
    println!("--------------------------------------------------------------------");

    // Print information about individual certs
    for (i, cert) in certs.iter().enumerate() {
        println!();
        println!("--------------------------------------------------------------------");
        println!("Encoding certificate {} of {}", i + 1, certs.len());
        println!("{} bytes / {} bytes ({:.2}%)", cert.cbor.concat().len(), cert.der.len(), 100.0 * cert.cbor.concat().len() as f64 / cert.der.len() as f64);
        println!("--------------------------------------------------------------------");
        println!();
        print("Input: DER encoded X.509 certificate (RFC 5280)", &cert.der);
        print("Output: CBOR encoded X.509 certificate (~C509Certificate)", &cert.cbor.concat());
        print("C509 Certificate Type", &cert.cbor[0]);
        print("Certificate Serial Number", &cert.cbor[1]);
        print("Issuer", &cert.cbor[2]);
        print("Validity Not Before", &cert.cbor[3]);
        print("Validity Not After", &cert.cbor[4]);
        print("Subject", &cert.cbor[5]);
        print("Subject Public Key Algorithm", &cert.cbor[6]);
        print("Subject Public Key", &cert.cbor[7]);
        print("Extentions", &cert.cbor[8]);
        print("Issuer Signature Algorithm", &cert.cbor[9]);
        print("Issuer Signature Value", &cert.cbor[10]);
    }

    println!();
    println!("--------------------------------------------------------------------");
    println!("CBOR COSE_X509 with {} certificates", certs.len());
    println!("--------------------------------------------------------------------");
    println!();

    if certs.len() > 1 {
        let mut cose_x509: Vec<Vec<u8>> = Vec::new();
        for cert in &certs {
            cose_x509.push(cbor_bytes(&cert.der));
        }
        print("COSE_X509", &cbor_array(&cose_x509));
    } else {
        print("COSE_X509", &cbor_bytes(&certs[0].der));
    }

    println!();
    println!("--------------------------------------------------------------------");
    println!("CBOR COSE_C509 with {} certificates", certs.len());
    println!("--------------------------------------------------------------------");
    println!();

    if certs.len() > 1 {
        let mut cose_c509: Vec<Vec<u8>> = Vec::new();
        for cert in &certs {
            cose_c509.push(cbor_array(&cert.cbor));
        }
        print("COSE_C509", &cbor_array(&cose_c509));
    } else {
        print("COSE_C509", &cbor_array(&certs[0].cbor));
    }

    println!();
    println!("--------------------------------------------------------------------");
    println!("TLS 1.3 Certificate message with {} certificates (X509)", certs.len());
    println!("--------------------------------------------------------------------");
    println!();

    let mut tls_x509 = Vec::new();
    for cert in &certs {
        tls_x509.extend( &(cert.der.len() as u32).to_be_bytes()[1..4]);
        tls_x509.extend(&cert.der);
        tls_x509.extend(&[0x00, 0x00]);
    }
    tls_x509 = [ &[0x00], &(tls_x509.len() as u32).to_be_bytes()[1..4], &tls_x509].concat();
    tls_x509 = [ &[0x0b], &(tls_x509.len() as u32).to_be_bytes()[1..4], &tls_x509].concat();
    print("TLS_X509", &tls_x509);

    println!();
    println!("--------------------------------------------------------------------");
    println!("TLS 1.3 CompressedCertificate message (X509 + Brotli)");
    println!("--------------------------------------------------------------------");
    println!();

    let mut tls_x509_brotli = brotli(&tls_x509);
    tls_x509_brotli = [ &(tls_x509_brotli.len() as u32).to_be_bytes()[1..4], &tls_x509_brotli].concat();
    tls_x509_brotli = [ &[0x00, 0x02], &(tls_x509.len() as u32).to_be_bytes()[1..4], &tls_x509_brotli].concat();
    tls_x509_brotli = [ &[0x19], &(tls_x509_brotli.len() as u32).to_be_bytes()[1..4], &tls_x509_brotli].concat();
    print("Brotli TLS_X509", &tls_x509_brotli);

    println!();
    println!("--------------------------------------------------------------------");
    println!("TLS 1.3 Certificate Message with {} certificates (C509)", certs.len());
    println!("--------------------------------------------------------------------");
    println!();

    let mut tls_c509 = Vec::new();
    for cert in &certs {
        tls_c509.extend( &(cert.cbor.concat().len() as u32).to_be_bytes()[1..4]);
        tls_c509.extend(&cert.cbor.concat());
        tls_c509.extend(&[0x00, 0x00]);
    }
    tls_c509 = [ &[0x00], &(tls_c509.len() as u32).to_be_bytes()[1..4], &tls_c509].concat();
    tls_c509 = [ &[0x0b], &(tls_c509.len() as u32).to_be_bytes()[1..4], &tls_c509].concat();
    print("TLS_C509", &tls_c509);

    println!();
    println!("--------------------------------------------------------------------");
    println!("TLS 1.3 CompressedCertificate message (C509 + Brotli)");
    println!("--------------------------------------------------------------------");
    println!();

    let mut tls_c509_brotli = brotli(&tls_c509);
    tls_c509_brotli = [ &(tls_c509_brotli.len() as u32).to_be_bytes()[1..4], &tls_c509_brotli].concat();
    tls_c509_brotli = [ &[0x00, 0x02], &(tls_c509.len() as u32).to_be_bytes()[1..4], &tls_c509_brotli].concat();
    tls_c509_brotli = [ &[0x19], &(tls_c509_brotli.len() as u32).to_be_bytes()[1..4], &tls_c509_brotli].concat();
    print("Brotli TLS_C509", &tls_c509_brotli);
}

// Brotli compression
pub fn brotli(input: &[u8]) -> Vec<u8> {
    let mut writer = brotli::CompressorWriter::new( Vec::new(), 4096, 11, 22);
    writer.write_all(input).unwrap();
    writer.into_inner()
}

// Parse a DER encoded X509 and encode it as C509
fn parse_cert(input: Vec<u8>) -> Cert {
    let mut output = Vec::new();

    // der_tlv Certificate
    let certificate = der_structure(&input, ASN1_SEQ);
    let tbs_certificate = der_structure(certificate[0], ASN1_SEQ);
    let version = der_tlv(tbs_certificate[0], 0xa0);
    let serial_number = der_tlv(tbs_certificate[1], ASN1_UINT);
    let signature = tbs_certificate[2];
    let issuer = tbs_certificate[3];
    let validity = der_structure(tbs_certificate[4], ASN1_SEQ);
    let subject = tbs_certificate[5];
    let subject_public_key_info = der_structure(tbs_certificate[6], ASN1_SEQ);
    let extensions = der_tlv(tbs_certificate[7], 0xa3);
    let signature_algorithm = certificate[1];
    let signature_value = der_tlv(certificate[2], ASN1_BIT_STR);

    // version
    assert!(der_tlv(version, ASN1_UINT)[0] == 2, "Expected v3!");
    output.push(cbor_uint(1));

    // serial_number
    output.push(cbor_bytes(serial_number));

    // signature
    assert!(signature_algorithm == signature, "Expected signature_algorithm == signature!");

    // issuer
    output.push(cbor_name(issuer));

    // validity
    output.push(cbor_time(validity[0]));
    output.push(cbor_time(validity[1]));

    // subject
    output.push(cbor_name(subject));

    // subjectPublicKeyInfo
    let subject_public_key = der_tlv(subject_public_key_info[1], ASN1_BIT_STR);
    if let Some(pk_type) = pk_map(subject_public_key_info[0]) {
        output.push(cbor_int(pk_type as i64));
        // Special handling for RSA
        if pk_type == PK_RSA {
            let rsa_pk = der_structure(subject_public_key, ASN1_SEQ);
            let n = cbor_tlv(rsa_pk[0], ASN1_UINT);
            let e = cbor_tlv(rsa_pk[1], ASN1_UINT);
            if e == [0x43, 0x01, 0x00, 0x01] {
                output.push(n);
            } else {
                output.push(cbor_array(&[n, e]));
            }
        // Special handling for ECDSA
        } else if (1..3).contains(&pk_type) {
            let coord_size = (subject_public_key.len() - 1) / 2;
            let secg_byte = subject_public_key[0];
            let x = &subject_public_key[1..1 + coord_size];
            if secg_byte == SECG_UNCOMPRESSED {
                let y = &subject_public_key[1 + coord_size..];
                if y[coord_size - 1] & 1 == 0 {
                    output.push(cbor_bytes(&[&[SECG_EVEN], x].concat()));
                } else {
                    output.push(cbor_bytes(&[&[SECG_ODD], x].concat()));
                }
            } else if secg_byte == SECG_EVEN || secg_byte == SECG_ODD as u8 {
                output.push(cbor_bytes(&[&[-(secg_byte as i8) as u8], x].concat()));
            } else {
                panic!("Expected SECG byte to be 2, 3, or 4!")
            }
        } else {
            output.push(cbor_bytes(subject_public_key));
        }
    } else {
        output.push(cbor_alg_id(signature_algorithm));
        output.push(cbor_bytes(subject_public_key));
    }

    // issuerUniqueID, subjectUniqueID

    // extensions
    let extensions = der_structure(extensions, ASN1_SEQ);
    let mut vec = Vec::new();
    for e in &extensions {
        let extension = der_structure(e, ASN1_SEQ);
        let oid = der_tlv(extension[0], ASN1_OID);
        let mut crit_sign = 1;
        if extension.len() == 3 {
            assert!(der_tlv(extension[1], ASN1_BOOL) == [0xff], "Expected critical == true");
            crit_sign = -1;
        }
        let extn_value = der_tlv(extension[extension.len() - 1], ASN1_OCTET_STR);
        if let Some(ext_type) = ext_map(oid) {
            vec.push(cbor_int(crit_sign * ext_type as i64));
            vec.push(match ext_type {
                EXT_SUBJECT_KEY_ID => cbor_tlv(extn_value, ASN1_OCTET_STR),
                EXT_KEY_USAGE => cbor_ext_key_use(extn_value, crit_sign * extensions.len() as i64),
                EXT_SUBJECT_ALT_NAME => cbor_general_names(extn_value, ASN1_SEQ, 2),
                EXT_BASIC_CONSTRAINTS => cbor_ext_bas_con(extn_value),
                EXT_CRL_DIST_POINT => cbor_ext_crl_dist(extn_value),
                EXT_CERT_POLICIES => cbor_ext_cert_policies(extn_value),
                EXT_AUTH_KEY_ID => cbor_ext_auth_key_id(extn_value),
                EXT_EXT_KEY_USAGE => cbor_ext_eku(extn_value),
                EXT_AUTH_INFO => cbor_ext_aia(extn_value),
                EXT_SCT_LIST => cbor_ext_sct(extn_value, &cbor_time(validity[0])[1..5]),
//                let validityNotBefore = cbor_time(validity[0])[1..5];
                _ => panic!("Unexpected extension'"),
            });
        } else {
            let crit = if crit_sign == 1 { cbor_simple(CBOR_TRUE) } else { cbor_simple(CBOR_FALSE) };
            vec.push(cbor_bytes(oid));
            vec.push(crit);
            vec.push(cbor_bytes(extn_value));
        }
    }
    output.push(cbor_opt_array(&vec, EXT_KEY_USAGE as u8));

    // signatureAlgorithm, signatureValue
    if let Some(sig_type) = sig_map(signature_algorithm) {
        output.push(cbor_int(sig_type as i64));
        // Special handling for ECDSA
        if (0..2).contains(&sig_type) {
            let signature_seq = der_structure(signature_value, ASN1_SEQ);
            let r = der_tlv(signature_seq[0], ASN1_UINT).to_vec();
            let s = der_tlv(signature_seq[1], ASN1_UINT).to_vec();
            let max = std::cmp::max(r.len(), s.len());
            let signature_ecdsa = &[vec![0; max - r.len()], r, vec![0; max - s.len()], s].concat();
            output.push(cbor_bytes(signature_ecdsa));
        } else {
            output.push(cbor_bytes(signature_value));
        }
    } else {
        output.push(cbor_alg_id(signature_algorithm));
        output.push(cbor_bytes(signature_value));
    }

    Cert { der: input, cbor: output }
}

fn cbor_opt_array(vec: &[Vec<u8>], t: u8) -> Vec<u8> {
    if vec.len() == 2 && vec[0] == [t] {
        vec[1].clone()
    } else {
        cbor_array(&vec)
    }
}

// CBOR encode a DER encoded Name field
fn cbor_name(der: &[u8]) -> Vec<u8> {
    let name = der_structure(der, ASN1_SEQ);
    let mut vec = Vec::new();
    for rdn in &name {
        let attributes = der_structure(rdn, ASN1_SET);
        assert!(attributes.len() == 1, "Expected 1 attribute per rdn");
        for item in attributes {
            let attribute = der_structure(item, ASN1_SEQ);
            let oid = der_tlv(attribute[0], ASN1_OID);
            if let Some(att_type) = att_map(oid) {
                let (sign, att_value) = if attribute[1][0] == ASN1_PRINT_STR { (-1, der_tlv(&attribute[1], ASN1_PRINT_STR)) } else { (1, der_tlv(&attribute[1], ASN1_UTF8_STR)) };
                vec.push(cbor_int(sign * att_type as i64));
                vec.push(cbor_text(from_utf8(att_value).unwrap()));
            } else {
                vec.push(cbor_bytes(oid));
                vec.push(cbor_bytes(attribute[1]));
            }
        }
    }

    let eui_64 = regex::Regex::new(r"^([A-F\d]{2}-){7}[A-F\d]{2}$").unwrap();
    if vec.len() == 2 && vec[0] == [ATT_COMMON_NAME as u8] {
        vec.remove(0);
        if eui_64.is_match(from_utf8(&vec[0][1..]).unwrap()) {
            vec[0].retain(|&x| x != b'-' && x != 0x77); // 0x77 = text string length 23
            if &vec[0][6..10] == b"FFFE" {
                vec[0].drain(6..10);
            }
            vec[0] = cbor_bytes(&hex::decode(&vec[0]).unwrap());
        }
        return vec[0].clone();
    }
    cbor_array(&vec)
}

// CBOR encode a DER encoded Time field
fn cbor_time(der: &[u8]) -> Vec<u8> {
    let time_string = if der[0] == ASN1_UTC_TIME as u8 { [b"20", der_tlv(&der, ASN1_UTC_TIME)].concat() } else { der_tlv(&der, ASN1_GEN_TIME).to_vec() };
    let time_string = from_utf8(&time_string).unwrap();
    if time_string == "99991231235959Z" {
        cbor_simple(CBOR_NULL)
    } else {
        cbor_uint(chrono::NaiveDateTime::parse_from_str(time_string, "%Y%m%d%H%M%SZ").unwrap().timestamp() as u64)
    }
}

// CBOR encode a DER encoded Algorithm Identifier
fn cbor_alg_id(der: &[u8]) -> Vec<u8> {
    let ai = der_structure(der, ASN1_SEQ);
    cbor_array(&[cbor_bytes(&der_tlv(&ai[0], ASN1_OID)), cbor_bytes(&ai[1])])
}

// CBOR encode a Key Usage Extension
fn cbor_ext_key_use(der: &[u8], signed_nr_ext: i64) -> Vec<u8> {
    assert!(der[0] == ASN1_BIT_STR, "Expected 0x03");
    let len = der[1];
    let shift = der[2];
    assert!((2..3).contains(&len), "Expected length 2 or 3");
    let mut v = if len == 2 { der[3] as u64 } else { ((der[3] as u64) << 8) + der[4] as u64 };
    v >>= shift;
    if signed_nr_ext == -1 {
        return cbor_int(-(v as i64));
    }
    cbor_uint(v)
}

// CBOR encode a General Names structure (used in e.g. SAN)
// special handling for a single dnsname
fn cbor_general_names(der: &[u8], t: u8, opt: u8) -> Vec<u8> {
    let gns = der_structure(der, t);
    let mut vec = Vec::new();
    for gn in &gns {
        vec.push(cbor_uint(gn[0] as u64 & 0x0f));
        match gn[0] {
            0x81 => vec.push(cbor_tlv_text(gn, gn[0])),
            0x82 => vec.push(cbor_tlv_text(gn, gn[0])),
            0xa4 => vec.push(cbor_name(der_tlv(gn, gn[0]))),
            0x86 => vec.push(cbor_tlv_text(gn, gn[0])),
            0x87 => vec.push(cbor_tlv(gn, gn[0])),
            0x88 => vec.push(cbor_tlv(gn, gn[0])),
            _ => panic!("Unknown general name"),
        }
    }
    cbor_opt_array(&vec, opt)
}

// CBOR encode a Basic Constraints extension
fn cbor_ext_bas_con(der: &[u8]) -> Vec<u8> {
    let bc = der_structure(der, ASN1_SEQ);
    match bc.len() {
        0 => cbor_int(-2),
        1 => {
            assert!(der_tlv(bc[0], ASN1_BOOL) == [0xff], "Expected cA == true");
            cbor_int(-1)
        }
        2 => {
            assert!(der_tlv(bc[0], ASN1_BOOL) == [0xff], "Expected cA == true");
            let path_len = der_tlv(bc[1], ASN1_UINT);
            assert!(path_len.len() == 1, "Expected path length < 256");
            cbor_uint(path_len[0] as u64)
        }
        _ => panic!("Error parsing basic constraints"),
    }
}

// CBOR encodes a CRL distribution list extension
fn cbor_ext_crl_dist(der: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for dist in der_structure(der, ASN1_SEQ) {
        let dist = der_tlv(dist, ASN1_SEQ);
        let dist = der_tlv(dist, 0xa0);
        let dist = der_tlv(dist, 0xa0);
        vec.push(cbor_tlv_text(dist, 0x86));
    }
    if vec.len() > 1 {
        return cbor_array(&vec);
    } else {
        return vec[0].clone();
    }
}

// CBOR encodes a Certificate Policies extension
fn cbor_ext_cert_policies(der: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for pi in der_structure(der, ASN1_SEQ) {
        let pi = der_structure(pi, ASN1_SEQ);
        assert!((1..3).contains(&pi.len()), "expected length 1 or 2");
        let oid = der_tlv(pi[0], ASN1_OID);
        if let Some(cp_type) = cp_map(oid) {
            vec.push(cbor_int(cp_type as i64));
        } else {
            vec.push(cbor_bytes(oid));
        }
        if pi.len() == 2 {
            let pqi = der_structure(pi[1], ASN1_SEQ);
            assert!(pqi.len() == 1, "expected length 1");
            let pqi = der_structure(pqi[0], ASN1_SEQ);
            assert!(der_tlv(pqi[0], ASN1_OID) == [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01], "unexpected oid");
            vec.push(cbor_tlv_text(pqi[1], ASN1_IA5_SRT));
        }
    }
    cbor_array(&vec)
}

// CBOR encodes a Authority Key Identifier extension
fn cbor_ext_auth_key_id(der: &[u8]) -> Vec<u8> {
    let id = der_structure(der, ASN1_SEQ);
    match id.len() {
        1 => cbor_tlv(id[0], 0x80),
        3 => cbor_array(&[cbor_tlv(id[0], 0x80), cbor_general_names(id[1], 0xa1, 0xff), cbor_tlv(id[2], 0x82)]),
        _ => panic!("Error parsing auth key id"),
    }
}

// CBOR encodes a extended key usage extention
fn cbor_ext_eku(der: &[u8]) -> Vec<u8> {
    let ekus = der_structure(der, ASN1_SEQ);
    let mut vec = Vec::new();
    for eku in ekus {
        let oid = der_tlv(eku, ASN1_OID);
        if let Some(eku_type) = eku_map(oid) {
            vec.push(cbor_int(eku_type as i64));
        } else {
            vec.push(cbor_bytes(oid));
        }
    }
    cbor_array(&vec)
}

// CBOR encodes a authority Info Access extention
fn cbor_ext_aia(der: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for aia in der_structure(der, ASN1_SEQ) {
        let aia = der_structure(aia, ASN1_SEQ);
        assert!(aia.len() == 2, "expected length 2");
        match der_tlv(aia[0], ASN1_OID) {
            [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01] => vec.push(cbor_uint(1)),
            [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02] => vec.push(cbor_uint(2)),
            _ => panic!("Unexpected OID"),
        }
        vec.push(cbor_tlv_text(aia[1], 0x86));
    }
    cbor_array(&vec)
}

// CBOR encodes a SCT extention
// https://letsencrypt.org/2018/04/04/sct-encoding.html
fn cbor_ext_sct(der: &[u8], v: &[u8]) -> Vec<u8> {
    let mut temp = &der_tlv(der, ASN1_OCTET_STR)[2..];
    let mut scts = Vec::new();
    while !temp.is_empty() {
        let end = ((temp[0] as usize) << 8) + (temp[1] as usize); 
        let (value, temp2) = (&temp[2..2+end], &temp[2+end..]);
        scts.push(value);
        temp = temp2;
    }
    let mut vec = Vec::new();
    for sct in scts {
        assert!(sct[0] == 0, "expected SCT version 1");
        vec.push(cbor_bytes(&sct[1..33]));
        let s = &sct[33..41];
        let a = ((v[0] as u64) << 24) + ((v[1] as u64) << 16) + ((v[2] as u64) << 8) + (v[3] as u64);
        let b = ((s[0] as u64) << 24) + ((s[1] as u64) << 16) + ((s[2] as u64) << 8) + (s[3] as u64);
        let c = ((s[4] as u64) << 24) + ((s[5] as u64) << 16) + ((s[6] as u64) << 8) + (s[7] as u64);
        vec.push(cbor_uint( (b << 32) + c - 1000 * a ));
        assert!(sct[41] == 0, "expected no SCT extentsions");
        assert!(sct[42] == 0, "expected no SCT extentsions");
        assert!(sct[43] == 4, "expected SCT SHA-256 ECDSA");
        assert!(sct[44] == 3, "expected SCT SHA-256 ECDSA");
        vec.push(cbor_int(SIG_ECDSA_SHA256 as i64));
        let signature_seq = der_structure(&sct[47..], ASN1_SEQ);
        let r = der_tlv(signature_seq[0], ASN1_UINT).to_vec();
        let s = der_tlv(signature_seq[1], ASN1_UINT).to_vec();
        let max = std::cmp::max(r.len(), s.len());
        let signature_ecdsa = &[vec![0; max - r.len()], r, vec![0; max - s.len()], s].concat();
        vec.push(cbor_bytes(signature_ecdsa));
    }
    cbor_array(&vec)
}

pub fn cbor_tlv(der: &[u8], tag: u8) -> Vec<u8> {
    cbor_bytes(der_tlv(der, tag))
}

pub fn cbor_tlv_text(der: &[u8], tag: u8) -> Vec<u8> {
    cbor_text(der_tlv_text(der, tag))
}

// Print a vec to cout
fn print(s: &str, v: &[u8]) {
    print!("{} ({} bytes)", s, v.len());
    for (i, byte) in v.iter().enumerate() {
        print!("{}{:02X}", if i % 23 == 0 { "\n" } else { " " }, byte);
    }
    println!("\n");
}


// DER parsing functions and maps for OID to int
pub mod der {
    // Universal ASN1 tags
    pub const ASN1_BOOL: u8 = 0x01;
    pub const ASN1_UINT: u8 = 0x02;
    pub const ASN1_BIT_STR: u8 = 0x03;
    pub const ASN1_OCTET_STR: u8 = 0x04;
    pub const ASN1_OID: u8 = 0x06;
    pub const ASN1_UTF8_STR: u8 = 0x0C;
    pub const ASN1_PRINT_STR: u8 = 0x13;
    pub const ASN1_IA5_SRT: u8 = 0x16;
    pub const ASN1_UTC_TIME: u8 = 0x17;
    pub const ASN1_GEN_TIME: u8 = 0x18;
    pub const ASN1_SEQ: u8 = 0x30;
    pub const ASN1_SET: u8 = 0x31;

    // C509 Certificate Attributes Registry
    pub const ATT_COMMON_NAME: u16 = 1;
    pub const ATT_SUR_NAME: u16 = 2;
    pub const ATT_SERIAL_NUMBER: u16 = 3;
    pub const ATT_COUNTRY: u16 = 4;
    pub const ATT_LOCALITY: u16 = 5;
    pub const ATT_STATE_OR_PROVINCE: u16 = 6;
    pub const ATT_STREET_ADDRESS: u16 = 7;
    pub const ATT_ORGANIZATION: u16 = 8;
    pub const ATT_ORGANIZATION_UNIT: u16 = 9;
    pub const ATT_TITLE: u16 = 10;
    pub const ATT_POSTAL_CODE: u16 = 11;
    pub const ATT_GIVEN_NAME: u16 = 12;
    pub const ATT_INITIALS: u16 = 13;
    pub const ATT_GENERATION_QUALIFIER: u16 = 14;
    pub const ATT_DN_QUALIFIER: u16 = 15;
    pub const ATT_PSEUDONYM: u16 = 16;
    pub const ATT_ORGANIZATION_IDENTIFIER: u16 = 17;

    pub fn att_map(oid: &[u8]) -> Option<u16> {
        match oid {
            [0x55, 0x04, ..] => match oid[2] {
                0x03 => Some(ATT_COMMON_NAME),
                0x04 => Some(ATT_SUR_NAME),
                0x05 => Some(ATT_SERIAL_NUMBER),
                0x06 => Some(ATT_COUNTRY),
                0x07 => Some(ATT_LOCALITY),
                0x08 => Some(ATT_STATE_OR_PROVINCE),
                0x09 => Some(ATT_STREET_ADDRESS),
                0x0A => Some(ATT_ORGANIZATION),
                0x0B => Some(ATT_ORGANIZATION_UNIT),
                0x0C => Some(ATT_TITLE),
                0x11 => Some(ATT_POSTAL_CODE),
                0x2A => Some(ATT_GIVEN_NAME),
                0x2B => Some(ATT_INITIALS),
                0x2C => Some(ATT_GENERATION_QUALIFIER),
                0x2E => Some(ATT_DN_QUALIFIER),
                0x41 => Some(ATT_PSEUDONYM),
                0x61 => Some(ATT_ORGANIZATION_IDENTIFIER),
                _ => None,
            },
            _ => None,
        }
    }

    // C509 Certificate Policies Registry
    pub const CP_DV: i32 = 1;
    pub const CP_OV: i32 = 2;
    pub const CP_IV: i32 = 3;
    pub const CP_EV: i32 = 4;


    pub fn cp_map(ai: &[u8]) -> Option<i32> {
        match ai {
            [0x67, 0x81, 0x0C, 0x01, 0x02, 0x01] => Some(CP_DV),
            [0x67, 0x81, 0x0C, 0x01, 0x02, 0x02] => Some(CP_OV),
            [0x67, 0x81, 0x0C, 0x01, 0x02, 0x03] => Some(CP_IV),
            [0x67, 0x81, 0x0C, 0x01, 0x01] => Some(CP_EV),
            _ => None,
        }
    }

    // C509 Certificate Public Key Algorithms Registry
    pub const PK_RSA: i32 = 0;
    pub const PK_SECP256R: i32 = 1;
    pub const PK_SECP384R: i32 = 2;
    pub const PK_SECP521R: i32 = 3;

    pub fn pk_map(ai: &[u8]) -> Option<i32> {
        match ai {
            [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00] => Some(PK_RSA),
            [0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] => Some(PK_SECP256R),
            [0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22] => Some(PK_SECP384R),
            [0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23] => Some(PK_SECP521R),
            _ => None,
        }
    }

    // C509 Certificate Signature Algorithms Registry
    pub const SIG_RSA_V15_SHA1: i32 = -256;
    pub const SIG_ECDSA_SHA256: i32 = 0;
    pub const SIG_ECDSA_SHA384: i32 = 1;
    pub const SIG_ECDSA_SHA512: i32 = 2;
    pub const SIG_RSA_V15_SHA256: i32 = 23;
    pub const SIG_RSA_V15_SHA384: i32 = 24;
    pub const SIG_RSA_V15_SHA512: i32 = 25;

    pub fn sig_map(ai: &[u8]) -> Option<i32> {
        match ai {
            [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05, 0x00] => Some(SIG_RSA_V15_SHA1),
            [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02] => Some(SIG_ECDSA_SHA256),
            [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03] => Some(SIG_ECDSA_SHA384),
            [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04] => Some(SIG_ECDSA_SHA512),
            [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00] => Some(SIG_RSA_V15_SHA256),
            [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, 0x05, 0x00] => Some(SIG_RSA_V15_SHA384),
            [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D, 0x05, 0x00] => Some(SIG_RSA_V15_SHA512),
            _ => None,
        }
    }

    // C509 Certificate Extensions Registry
    pub const EXT_SUBJECT_KEY_ID: u16 = 1;
    pub const EXT_KEY_USAGE: u16 = 2;
    pub const EXT_SUBJECT_ALT_NAME: u16 = 3;
    pub const EXT_BASIC_CONSTRAINTS: u16 = 4;
    pub const EXT_CRL_DIST_POINT: u16 = 5;
    pub const EXT_CERT_POLICIES: u16 = 6;
    pub const EXT_AUTH_KEY_ID: u16 = 7;
    pub const EXT_EXT_KEY_USAGE: u16 = 8;
    pub const EXT_AUTH_INFO: u16 = 9;
    pub const EXT_SCT_LIST: u16 = 10;

    pub fn ext_map(oid: &[u8]) -> Option<u16> {
        match oid {
            [0x55, 0x1D, ..] => match oid[2] {
                0x0E => Some(EXT_SUBJECT_KEY_ID),
                0x0F => Some(EXT_KEY_USAGE),
                0x11 => Some(EXT_SUBJECT_ALT_NAME),
                0x13 => Some(EXT_BASIC_CONSTRAINTS),
                0x1F => Some(EXT_CRL_DIST_POINT),
                0x20 => Some(EXT_CERT_POLICIES),
                0x23 => Some(EXT_AUTH_KEY_ID),
                0x25 => Some(EXT_EXT_KEY_USAGE),
                _ => None,
            },
            [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01] => Some(EXT_AUTH_INFO),
            [0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02] => Some(EXT_SCT_LIST),
            _ => None,
        }
    }

    // C509 Certificate Extended Key Usages Registry
    pub const EKU_TLS_SERVER: u16 = 1;
    pub const EKU_TLS_CLIENT: u16 = 2;
    pub const EKU_CODE_SIGN: u16 = 3;
    pub const EKU_EMAIL_PROT: u16 = 4;
    pub const EKU_TIME_STAMP: u16 = 8;
    pub const EKU_OCSP_SIGN: u16 = 9;

    pub fn eku_map(oid: &[u8]) -> Option<u16> {
        match oid {
            [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, ..] => match oid[7] {
                0x01 => Some(EKU_TLS_SERVER),
                0x02 => Some(EKU_TLS_CLIENT),
                0x03 => Some(EKU_CODE_SIGN),
                0x04 => Some(EKU_EMAIL_PROT),
                0x08 => Some(EKU_TIME_STAMP),
                0x09 => Some(EKU_OCSP_SIGN),
                _ => None,
            },
            _ => None,
        }
    }

    // Parse a DER TLV and returns the value
    pub fn der_tlv(der: &[u8], tag: u8) -> &[u8] {
        assert!(der[0] == tag, "Unexpected type!");
        let (temp, none) = der_internal(der, true);
        assert!(none.is_empty(), "Expected empty slice!");
        if temp.len() > 1 {
            if temp[0] == 0 && (tag == ASN1_UINT || tag == ASN1_BIT_STR) {
                return &temp[1..];
            }
            assert!(tag != ASN1_BIT_STR, "Expected zero unused bits!");
        }
        &temp[..]
    }

    // Parse a DER TLV and returns the value as a string
    pub fn der_tlv_text(der: &[u8], tag: u8) -> &str {
        std::str::from_utf8(der_tlv(der, tag)).unwrap()
    }

    // Parse a DER TLV structure and returns the value as a vector
    pub fn der_structure(der: &[u8], tag: u8) -> Vec<&[u8]> {
        let mut vec = Vec::new();
        let mut temp = der_tlv(der, tag);
        while !temp.is_empty() {
            let (value, temp2) = der_internal(temp, false);
            vec.push(value);
            temp = temp2;
        }
        vec
    }

    // DER parsing helper function
    // if trim == true, only value is returned
    fn der_internal(der: &[u8], trim: bool) -> (&[u8], &[u8]) {
        assert!(der[1] < 0x84, "Did not expected length >= 2^24");
        let (start, end) = match der[1] {
            0x80 => panic!("Indefinite length encoding!"),
            0x81 => (3, 3 + der[2] as usize),
            0x82 => (4, 4 + ((der[2] as usize) << 8) + der[3] as usize),
            0x83 => (5, 5 + ((der[2] as usize) << 16) + ((der[3] as usize) << 8) + der[4] as usize),
            _ => (2, 2 + der[1] as usize),
        };
        (&der[trim as usize * start..end], &der[end..])
    }
}


// Determinist CBOR encoding (RFC 8949)
pub mod cbor {
    // CBOR encodes an unsigned interger
    pub fn cbor_uint(u: u64) -> Vec<u8> {
        cbor_type_arg(0, u)
    }

    // CBOR encodes an signed integer
    pub fn cbor_int(i: i64) -> Vec<u8> {
        if i < 0 {
            cbor_type_arg(1, -i as u64 - 1)
        } else {
            cbor_uint(i as u64)
        }
    }

    // CBOR encodes a byte string
    pub fn cbor_bytes(v: &[u8]) -> Vec<u8> {
        [&cbor_type_arg(2, v.len() as u64), v].concat()
    }

    // CBOR encodes a text string
    pub fn cbor_text(s: &str) -> Vec<u8> {
        [&cbor_type_arg(3, s.len() as u64), s.as_bytes()].concat()
    }

    // CBOR encodes an array
    pub fn cbor_array(v: &[Vec<u8>]) -> Vec<u8> {
        [cbor_type_arg(4, v.len() as u64), v.concat()].concat()
    }

    pub const CBOR_FALSE: u8 = 20;
    pub const CBOR_TRUE: u8 = 21;
    pub const CBOR_NULL: u8 = 22;

    // CBOR encodes a simple value
    pub fn cbor_simple(u: u8) -> Vec<u8> {
        cbor_type_arg(7, u as u64)
    }

    // CBOR encoding helper funtion
    fn cbor_type_arg(t: u8, a: u64) -> Vec<u8> {
        let mut vec = vec![t << 5];
        if a < 24 {
            vec[0] |= a as u8;
        } else if a < u8::MAX as u64 {
            vec[0] |= 24;
            vec.extend(&(a as u8).to_be_bytes());
        } else if a < u16::MAX as u64 {
            vec[0] |= 25;
            vec.extend(&(a as u16).to_be_bytes());
        } else if a < u32::MAX as u64 {
            vec[0] |= 26;
            vec.extend(&(a as u32).to_be_bytes());
        } else {
            vec[0] |= 27;
            vec.extend(&a.to_be_bytes());
        }
        vec
    }
}