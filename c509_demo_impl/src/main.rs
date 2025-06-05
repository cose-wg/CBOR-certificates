// DER encoded X.509 to CBOR encoded X.509 (C509)
// Copyright (c) 2021--2025, Ericsson and John Preuß Mattsson <john.mattsson@ericsson.com> + RISE and Joel Höglund <joel.hoglund@ri.se>
// This version implements a critical subset of draft-ietf-cose-cbor-encoded-cert-11
//
// Software license:  
//
// This software may be distributed under the terms of the 3-Clause BSD License.
//
// To read a DER encoded X.509 from file and encode as C509:
// "cargo r f <der encoded certificate>"
// -- A few sample certificates are present in ../test_certs
//
// To read a CBOR encoded C509 from file and encode as X.509 (with hex encoded, plain text input, see ../test_certs for examples):
// "cargo r c <cbor encoded certificate>"
//
// To read a DER encoded X.509 chain/bag from a TLS server:
// "cargo r u www.ietf.org"
// "cargo r u tools.ietf.org"
//
// To read a DER encoded X.509 from file and encode as C509, 
// encode back to X.509 and compare the results:
// "cargo r l <der encoded certificate>"
//
// To read a DER encoded X.509 from URL and encode as C509, 
// encode back to X.509 and compare the results:
// "cargo r ll <URL>"
//
// To read URLs from a text list, and perform ll for each URL on the list:
// "cargo r t <text list if URLs>"
//
// + run with RUST_LOG=<debug level> to change from default info level
//
// Please note that running the converter with options l, ll or t assumes there are output folders "could_convert"
// and "failed_convert" available for outputting log files. 
//
// Version 0.45, May 2025
//
// For misc. resources, a minimal update history, and know limitations, please see README_software_prototype.md
//
use crate::help::*;
use crate::lder::*;
use bit_reverse::LookupReverse;
use lcbor::*;
//use hex::FromHex; //used for testing
use std::env;
//use std::process;  //used for testing
use {rustls::*, std::io::Write, webpki, webpki_roots};
use {std::env::args, std::io::Cursor, std::str::from_utf8};
//At least during development both cbor and serde_cbor:
use serde_cbor::Value;
//use serde_bytes::Bytes

use asn1_rs::{oid, Oid};
//use asn1_rs::{BitString, Sequence, Integer, FromBer, ToDer};
use asn1_rs::ToDer;
//Needed to decompress point compressed keys
use num_bigint::{BigInt, Sign};
use num_traits::{pow, One, Zero};

use std::fs::read_to_string; //for reading host names from file
use std::fs::File;

use log::{trace, debug, info, warn};
use env_logger::Env;
use std::panic; //TODO, only for mass testing using URL lists 

pub const SECG_EVEN: u8 = 0x02;
pub const SECG_ODD: u8 = 0x03;
pub const SECG_UNCOMPRESSED: u8 = 0x04;
pub const SECG_EVEN_COMPRESSED: u8 = 0xfe;
pub const SECG_ODD_COMPRESSED: u8 = 0xfd;
pub const C509_TYPE_NATIVE: u8 = 0x02; 
pub const C509_TYPE_X509_ENCODED: u8 = 0x03; 
struct Cert {
    der: Vec<u8>,
    cbor: Vec<Vec<u8>>,
}
pub const PRINT_INPUT: bool = true;
pub const PRINT_OUTPUT: bool = false;
pub const PRINT_COSE: bool = true;
pub const PRINT_TLS: bool = false;

pub const WRITE_X509: bool = true;
pub const WRITE_C509: bool = true;
static mut GLOBAL_BATCH_MODE: bool = false; //used to ignore some errors while batch testing

/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
fn main() {
  
   env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .init();

    info!("Logger initialized!");

    env::set_var("RUST_BACKTRACE", "1");
    /*
      Below is a designated test area
    */
    /*
    let test: bool = false;
    if test {
        //let test_key = "03B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB";
        let test_key = "03963ECDD84DCD1B93A1CF432D1A7217D6C63BDE3355A02F8CFB5AD8994CD44E20";
        //let test_key = "fd963ECDD84DCD1B93A1CF432D1A7217D6C63BDE3355A02F8CFB5AD8994CD44E20";
        //let test_key = "02C8B421F11C25E47E3AC57123BF2D9FDC494F028BC351CC80C03F150BF50CFF95";
        let byte_array = hex::decode(test_key).expect("Decoding failed");
        /*  let public_key = PublicKey::from_slice(&[
          0x02,
          0xc6, 0x6e, 0x7d, 0x89, 0x66, 0xb5, 0xc5, 0x55,
          0xaf, 0x58, 0x05, 0x98, 0x9d, 0xa9, 0xfb, 0xf8,
          0xdb, 0x95, 0xe1, 0x56, 0x31, 0xce, 0x35, 0x8c,
          0x3a, 0x17, 0x10, 0xc9, 0x62, 0x67, 0x90, 0x63,
        ]).expect("public keys must be 33 or 65 bytes, serialized according to SEC 2");*/
        //let public_key = PublicKey::from_slice(byte_array.as_slice()).expect("public keys must be 33 or 65 bytes, serialized according to SEC 2");
        //let uc = check_and_decompress_ecc_key(byte_array);
        //let uc = public_key.serialize_uncompressed();
        //println!("public_key.to_string() : {}", public_key.to_string());
        //println!("uc : {:02x?}", uc);
        std::process::exit(0);
    }
    */
    
    let help_message = r#"
No option given!
Options are:
 f  read X.509 from crt file and encode as C509. 
 c  read C509 from hex file and encode as X.509
 u  read X.509 from URL and encode as C509
 l  read X.509 from crt file, encode as C509, encode back to X.509 and compare the results
 ll same as l, but from an URL
 t  read URLs from file and perform ll for each URL 
"#;
    // get a single certificate from file or a chain/bag from a tls server and parse them
   // let first_arg = args().nth(1).expect("No option given!\nOptions are:\n\tf\tread X.509 from crt file and covert to\n\tc\tread X.509 from crt file");
    let first_arg = args().nth(1).expect(help_message);
    let second_arg = args().nth(2).expect("No file/domain name given!");
    let certs = match &first_arg[..] {
        "f" => vec![parse_x509_cert(std::fs::read(second_arg).expect("No such file!"))],
        "c" => vec![parse_c509_cert(cleanup(std::fs::read(second_arg).expect("No such file!")), true)],
        "l" => vec![loop_on_x509_cert(std::fs::read(second_arg).expect("No such file!"), "", 0, 0)],
        "ll" => loop_on_certs_from_tls(&second_arg, 0),
        "u" => get_certs_from_tls(second_arg),
        "t" => { unsafe { GLOBAL_BATCH_MODE = true; read_hosts_from_file(&second_arg) } },
        _ => panic!("expected f, c, u, l, ll or t"),
    };
    print_information(&certs);
}
/******************************************************************************************************/
/******************************************************************************************************/
// make a TLS connection to get server certificate chain/bag
fn get_certs_from_tls(domain_name: String) -> Vec<Cert> {
    let mut config = rustls::ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(&domain_name).unwrap();
    let mut sess = rustls::ClientSession::new(&std::sync::Arc::new(config), dns_name);
    let mut sock = std::net::TcpStream::connect(domain_name + ":443").unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);
    tls.write_all(b"GET / HTTP/1.1").unwrap();
    tls.flush().unwrap();
    tls.sess.get_peer_certificates().unwrap().iter().map(|c| parse_x509_cert(c.0.clone())).collect()
}
/******************************************************************************************************/
/******************************************************************************************************/

// make a TLS connection to get server certificate chain/bag
fn loop_on_certs_from_tls(domain_name: &String, no: i64) -> Vec<Cert> {
    let mut config = rustls::ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(&domain_name).unwrap();
    let mut sess = rustls::ClientSession::new(&std::sync::Arc::new(config), dns_name);
    let conn_addr = domain_name.to_owned() + ":443";

    let sock_test = std::net::TcpStream::connect(conn_addr);
    //let mut sock: std::net::TcpStream; // = std::net::TcpStream::connect(conn_addr).unwrap();
                                       // let mut fail_now = false;
    if let Ok(mut stream) = sock_test {
        
        //sock = stream;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(10))).unwrap(); //TODO

        let mut tls = rustls::Stream::new(&mut sess, &mut stream);
        
        if let Ok(_) = tls.write_all(b"GET / HTTP/1.1") {
            tls.flush().unwrap();
            let mut ugly_counter = 0;
            tls.sess
                .get_peer_certificates()
                .unwrap()
                .iter()
                .map(|c| {
                    loop_on_x509_cert(c.0.clone(), domain_name.as_str(), no, {
                        ugly_counter += 1;
                        ugly_counter
                    })
                })
                .collect()
        } else {
            warn!("Error writing to {}, skipping", domain_name);
            Vec::new()
        }

  } else {
        warn!("Error opening {}, skipping", domain_name);
        Vec::new()
  }
}
/******************************************************************************************************/
/******************************************************************************************************/
// Parse a DER encoded X509 and encode it as C509, re-encode back to X.509 and check if successful
fn loop_on_x509_cert(input: Vec<u8>, host: &str, no: i64, sub_no: u8) -> Cert {
    let oi = input.clone();
    let ooi = input.clone();
    let parsed_cert = parse_x509_cert(input);
    let reversed_cert = parse_c509_cert(lcbor_array(&parsed_cert.cbor), false);
    //let rev_copy = reversed_cert.der.clone();

    let ndate = chrono::Local::now();
    let ts = ndate.format("%Y-%m-%d_%H:%M:%S.%s");

    let correct_input_path = "../could_convert/".to_string() + host + "_" + &sub_no.to_string() + "_" + &ts.to_string();
    let failed_input_path = "../failed_convert/".to_string() + host + "_" + &sub_no.to_string() + "_" + &ts.to_string();
    let write_path; 

    if reversed_cert.der == oi {
        info!("The input X.509 certificate for host {} with number {} was successfully encoded and reconstructed. {} vs {}\nStoring file as {}", host, no, oi.len(), reversed_cert.der.len(), correct_input_path);
        write_path = &correct_input_path;
    } else {
        print_str_warning("File re-encoding failure");
        warn!("The input X.509 certificate for host {} with number {} COULD NOT be encoded and reconstructed. {} vs {}\nStoring file as {}", host, no, oi.len(), reversed_cert.der.len(), failed_input_path);
        write_path = &failed_input_path;
    }
    let write_input_path = write_path.to_owned() + ".input.hex";
    let write_output_path = write_path.to_owned() + ".output.hex";
    let mut input_file = File::create(write_input_path).expect("File not found");
    let mut output_file = File::create(write_output_path).expect("File not found");

    for byte in oi {
        let _ = write!(input_file, "{:02X} ", byte); // Writes each byte as a 2-digit uppercase hex
    }
    for byte in reversed_cert.der {
        let _ = write!(output_file, "{:02X} ", byte); // Writes each byte as a 2-digit uppercase hex
    }
    Cert { der: ooi, cbor: Vec::new() }
}
/******************************************************************************************************/
/******************************************************************************************************/
fn read_hosts_from_file(filename: &str) -> Vec<Cert> {
    let host_vector: Vec<String> = {
        read_to_string(filename)
            .unwrap() // Panic on possible file-reading errors
            .lines() // Split the string into an iterator of string slices
            .map(String::from) // Convert each slice into a String
            .collect() // Gather them together into a vector
    };
    let mut counter = 0;
    for host in host_vector {
        info!("Testing {} with number {}", host, counter);
        loop_on_certs_from_tls(&host, counter);
        counter += 1;
    }
    //Cert { der: Vec::new(), cbor: Vec::new() }
    Vec::new()
}

/******************************************************************************************************/
/******************************************************************************************************/
// Parse a DER encoded X509 and encode it as C509
fn parse_x509_cert(input: Vec<u8>) -> Cert {
    trace!("Parsing x.509: {:02x?}", input);
    let mut output = Vec::new();
    // der Certificate
    let certificate = lder_vec_len(&input, ASN1_SEQ, 3);
    let tbs_certificate = lder_vec_len(certificate[0], ASN1_SEQ, 8);
    let version = lder(tbs_certificate[0], 0xa0);
    let serial_number = lder_uint(tbs_certificate[1]);
    let signature_algorithm = certificate[1];
    let signature = tbs_certificate[2];
    let issuer = tbs_certificate[3];
    let validity = lder_vec_len(tbs_certificate[4], ASN1_SEQ, 2);
    let not_before = validity[0];
    let not_after = validity[1];
    let subject = tbs_certificate[5];
    let subject_public_key_info = lder_vec_len(tbs_certificate[6], ASN1_SEQ, 2);
    let spki_algorithm = subject_public_key_info[0]; //TODO, update?
    let subject_public_key = lder(subject_public_key_info[1], ASN1_BIT_STR);
    let extensions = lder_vec(lder(tbs_certificate[7], 0xa3), ASN1_SEQ); //0xa3 = [3] EXPLICIT, mandatory start of ext.seq if present
    let signature_value = lder(certificate[2], ASN1_BIT_STR);
    // version
    assert!(lder(version, ASN1_INT)[0] == 2, "Expected v3!");
    output.push(lcbor_uint(C509_TYPE_X509_ENCODED as u64));
    // serial_number
    output.push(lcbor_bytes(serial_number));
    
    // signatureAlg.
    if let Some(sig_type) = sig_map(signature_algorithm) {
        output.push(lcbor_int(sig_type));
    } else {
        let oid = lder(lder_vec(signature_algorithm, ASN1_SEQ)[0], ASN1_OID);
        print_warning("No C509 int regisered for signature algorithm identifier, oid", &signature_algorithm, oid);
        output.push(cbor_alg_id(signature_algorithm));
    }
    
    // signature
    assert!(signature_algorithm == signature, "Expected signature_algorithm == signature!");
    // issuer
    output.push(cbor_name(issuer));
    // validity
    let c_not_before = cbor_time(not_before, 0);
    let c_not_after = cbor_time(not_after, 0);
    
    if c_not_after < c_not_before {
      warn!("Pre-2000 time bug, trying to circumvent");
      output.push(cbor_time(not_before, 1));
      
    } else {
      output.push(c_not_before);
    }
    output.push(c_not_after);
    // subject
    output.push(cbor_name(subject));
    // subjectPublicKeyInfo
    assert!(subject_public_key[0] == 0, "expected 0 unused bits");
    let subject_public_key = &subject_public_key[1..];
    if let Some(pk_type) = pk_map(spki_algorithm) {
        output.push(lcbor_int(pk_type));
        // Special handling for RSA
        if pk_type == PK_RSA_ENC {
            let rsa_pk = lder_vec_len(subject_public_key, ASN1_SEQ, 2);
            let n = lcbor_bytes(lder_uint(rsa_pk[0]));
            let e = lcbor_bytes(lder_uint(rsa_pk[1]));
            if e == [0x43, 0x01, 0x00, 0x01] {
                //check for exponent == 65537
                output.push(n);
            } else {
                output.push(lcbor_array(&[n, e]));
            }
        // Special handling for ECDSA
        /*
        Please note:
        For elliptic curve public keys in Weierstraß form (id-ecPublicKey), keys may be point compressed
        as defined in Section 2.3.3 of [SECG]. Native C509 certificates with Weierstraß form keys use the
        octets 0x02, 0x03, and 0x04 as defined in [SECG]. If a DER encoded certificate with a uncompressed
        public key of type id-ecPublicKey is CBOR encoded with point compression, the octets 0xfe and 0xfd
        are used instead of 0x02 and 0x03 in the CBOR encoding to represent even and odd y-coordinate,
        respectively.
        */
        } else if [PK_SECP256R, PK_SECP384R, PK_SECP521R, PK_BRAINPOOL256R1, PK_BRAINPOOL384R1, PK_BRAINPOOL512R1, PK_FRP256V1].contains(&pk_type) {
            assert!(subject_public_key.len() % 2 == 1, "Expected odd subject public key length!");
            let coord_size = (subject_public_key.len() - 1) / 2;
            let secg_byte = subject_public_key[0];
            let x = &subject_public_key[1..1 + coord_size];
            if secg_byte == SECG_UNCOMPRESSED {
                let y = &subject_public_key[1 + coord_size..];
                if y[coord_size - 1] & 1 == 0 {
                    output.push(lcbor_bytes(&[&[SECG_EVEN_COMPRESSED], x].concat()));
                } else {
                    output.push(lcbor_bytes(&[&[SECG_ODD_COMPRESSED], x].concat()));
                }
            } else if secg_byte == SECG_EVEN || secg_byte == SECG_ODD as u8 {
                output.push(lcbor_bytes(&[&[-(secg_byte as i8) as u8], x].concat()));
            } else {
                panic!("Expected SECG byte to be 2, 3, or 4!")
            }
        } else {
            output.push(lcbor_bytes(subject_public_key));
        }
    } else {
        let oid = lder(lder_vec(spki_algorithm, ASN1_SEQ)[0], ASN1_OID);
        print_warning("No C509 int registered for public key algorithm identifier, oid", &spki_algorithm, oid);
        output.push(cbor_alg_id(spki_algorithm));
        output.push(lcbor_bytes(subject_public_key));
    }
    // issuerUniqueID, subjectUniqueID -- not supported
    // extensions
    let mut vec = Vec::new();
    for e in &extensions {
        let extension = lder_vec(e, ASN1_SEQ);
        assert!(extension.len() < 4, "Expected length 2 or 3");
        let oid = lder(extension[0], ASN1_OID);
        let mut crit_sign = 1;
        if extension.len() == 3 {
            assert!(lder(extension[1], ASN1_BOOL) == [0xff], "Expected critical == true");
            crit_sign = -1;
        }
        let extn_value = lder(extension[extension.len() - 1], ASN1_OCTET_STR);
        if let Some(ext_type) = ext_map(oid) {
            //println!("Working on {}. extensions.len() = {}, crit status: {:?}", ext_type, extensions.len(), cbor_int(crit_sign * ext_type as i64));
            //Note: We need look-ahead for the keyUsage only case and surpress the crit.sign, as it will be respresented by a negative keyUsage value only
            if extensions.len() == 1 && ext_type == EXT_KEY_USAGE {
                vec.push(lcbor_int(ext_type as i64));
            } else {
                vec.push(lcbor_int(crit_sign * ext_type as i64));
            }
            vec.push(match ext_type {
                EXT_SUBJECT_KEY_ID => lcbor_bytes(lder(extn_value, ASN1_OCTET_STR)),
                EXT_KEY_USAGE => cbor_ext_key_use(extn_value, crit_sign * extensions.len() as i64),
                EXT_SUBJECT_ALT_NAME => cbor_general_names(extn_value, ASN1_SEQ, 2),
                EXT_BASIC_CONSTRAINTS => cbor_ext_bas_con(extn_value),
                EXT_CRL_DIST_POINTS => cbor_ext_crl_dist(extn_value),
                EXT_CERT_POLICIES => cbor_ext_cert_policies(extn_value),
                EXT_AUTH_KEY_ID => cbor_ext_auth_key_id(extn_value),
                EXT_EXT_KEY_USAGE => cbor_ext_eku(extn_value),
                EXT_AUTH_INFO => cbor_ext_info_access(extn_value),
                EXT_SCT_LIST => cbor_ext_sct(extn_value, not_before),
                EXT_SUBJECT_DIRECTORY_ATTR => cbor_store_only(extn_value, extension[0], oid), //cbor_ext_directory_attr(extn_value),
                EXT_ISSUER_ALT_NAME => cbor_general_names(extn_value, ASN1_SEQ, 2),           //Note: "Issuer Alternative Name (issuerAltName). extensionValue is encoded exactly like subjectAltName."
                EXT_NAME_CONSTRAINTS => cbor_store_only(extn_value, extension[0], oid),       //cbor_ext_name_constraints(extn_value),  //Sample certificates welcome
                EXT_POLICY_MAPPINGS => cbor_store_only(extn_value, extension[0], oid),        //cbor_ext_policy_mappings(extn_value),   //Sample certificates welcome
                EXT_POLICY_CONSTRAINTS => cbor_store_only(extn_value, extension[0], oid),     //cbor_ext_policy_constraints(extn_value),  //Sample certificates welcome
                EXT_FRESHEST_CRL => cbor_ext_crl_dist(extn_value),                            //Note: "Freshest CRL (freshestCRL). extensionValue is encoded exactly like cRLDistributionPoints"
                EXT_INHIBIT_ANYPOLICY => cbor_store_only(extn_value, extension[0], oid),      //cbor_ext_inhibit_anypolicy(extn_value),   //Sample certificates welcome
                EXT_SUBJECT_INFO_ACCESS => cbor_ext_info_access(extn_value),
                EXT_IP_RESOURCES => cbor_ext_ip_res(extn_value),
                EXT_AS_RESOURCES => cbor_ext_as_res(extn_value),
                EXT_IP_RESOURCES_V2 => cbor_ext_ip_res(extn_value),
                EXT_AS_RESOURCES_V2 => cbor_ext_as_res(extn_value),
                EXT_BIOMETRIC_INFO => lcbor_bytes(extn_value),            //Store only
                EXT_PRECERT_SIGNING_CERT => lcbor_bytes(extn_value),      //Store only
                EXT_OCSP_NO_CHECK => lcbor_bytes(extn_value),             //Store only
                EXT_QUALIFIED_CERT_STATEMENTS => lcbor_bytes(extn_value), //Store only
                EXT_S_MIME_CAPABILITIES => lcbor_bytes(extn_value),       //Store only
                EXT_TLS_FEATURES => lcbor_bytes(extn_value),              //Store only
                _ => panic!("Unexpected extension'"),
            });
        } else {
            print_warning("No C509 int registered for extension oid", extension[0], oid);
            vec.push(lcbor_bytes(oid));
            if crit_sign == -1 {
                vec.push(lcbor_simple(CBOR_TRUE));
            }
            vec.push(lcbor_bytes(extn_value));
        }
    }
    /*
    Optimisation: if only a keyUsage field is present, skip the array for extensions.
    This requires the minus sign of the EXT_KEY_USAGE value (2) to be surpressed above
    */
    output.push(cbor_opt_array(&vec, EXT_KEY_USAGE as u8));
    // now only signatureValue
    assert!(signature_value[0] == 0, "expected 0 unused bits");
    let signature_value = &signature_value[1..];
    if let Some(sig_type) = sig_map(signature_algorithm) {
        // Special handling for ECDSA
        if [SIG_ECDSA_SHA1, SIG_ECDSA_SHA256, SIG_ECDSA_SHA384, SIG_ECDSA_SHA512, SIG_ECDSA_SHAKE128, SIG_ECDSA_SHAKE256].contains(&sig_type) {
            output.push(cbor_ecdsa(signature_value));
        } else {
            output.push(lcbor_bytes(signature_value));
        }
    } else {
        output.push(lcbor_bytes(signature_value));
    }
    Cert { der: input, cbor: output }
}
/******************************************************************************************************/
// CBOR encode a DER encoded Name field
fn cbor_name(b: &[u8]) -> Vec<u8> {
    let name = lder_vec(b, ASN1_SEQ);
    let mut vec = Vec::new();
    for rdn in &name {
        let attributes = lder_vec_len(rdn, ASN1_SET, 1);
        for item in attributes {
            let attribute = lder_vec_len(item, ASN1_SEQ, 2);
            let oid = lder(attribute[0], ASN1_OID);
            let der_value = attribute[1];
            if let Some(att_type) = att_map(oid) {
                if att_type == ATT_EMAIL || att_type == ATT_DOMAIN_COMPONENT {
                    vec.push(lcbor_int(att_type as i64));
                    let att_value = lder(der_value, ASN1_IA5_SRT);
                    vec.push(lcbor_text(att_value));
                } else {
                    let (sign, att_value) = if der_value[0] == ASN1_PRINT_STR { (-1, lder(der_value, ASN1_PRINT_STR)) } else { (1, lder(der_value, ASN1_UTF8_STR)) };
                    vec.push(lcbor_int(sign * att_type as i64));
                    vec.push(lcbor_text(att_value));
                }
            } else {
                print_warning("No C509 int regisered for attribute oid", attribute[0], oid);
                vec.push(lcbor_bytes(oid));
                vec.push(lcbor_bytes(der_value));
            }
        }
    }
    /*
    If Name contains a single Attribute containing an utf8String encoded 'common name' it is encoded as follows:
    *If the text string has an even length {{{≥}}} 2 and contains only the symbols '0'–'9' or 'a'–'f',
     it is encoded as a CBOR byte string, prefixed with an initial byte set to '00'.
    *If the text string contains an EUI-64 of the form "HH-HH-HH-HH-HH-HH-HH-HH" where 'H' is one of
     the symbols '0'–'9' or 'A'–'F' it is encoded as a CBOR byte string prefixed with an initial byte set to
     '01', for a total length of 9. An EUI-64 mapped from a 48-bit MAC address (i.e., of the form
     "HH-HH-HH-FF-FE-HH-HH-HH) is encoded as a CBOR byte string prefixed with an initial byte set to '01',
     for a total length of 7.
    *Otherwise it is encoded as a CBOR text string.
    */
    let eui_64 = regex::Regex::new(r"^([A-F\d]{2}-){7}[A-F\d]{2}$").unwrap();
    let is_hex = regex::Regex::new(r"^(?:[A-Fa-f0-9]{2})*$").unwrap();
    if vec.len() == 2 && vec[0] == [ATT_COMMON_NAME as u8] {
        //let cn = from_utf8(&vec[0][1..]).unwrap();
        vec.remove(0);
        if eui_64.is_match(from_utf8(&vec[0][1..]).unwrap()) {
            vec[0].retain(|&x| x != b'-' && x != 0x77); // 0x77 = text string length 23
            if &vec[0][6..10] == b"FFFE" {
                vec[0].drain(6..10);
            }
            vec[0].insert(0, '1' as u8);
            vec[0].insert(0, '0' as u8);
            vec[0] = lcbor_bytes(&hex::decode(&vec[0]).unwrap());
        } else if is_hex.is_match(from_utf8(&vec[0][1..]).unwrap()) {
            vec[0][0] = '0' as u8; //overwrite the added utf8 text marker at the start
            vec[0].insert(0, '0' as u8);
            vec[0] = lcbor_bytes(&hex::decode(&vec[0]).unwrap());
        }
        return vec[0].clone();
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
// CBOR encode a DER encoded Time field (ruturns ~biguint)
fn cbor_time(b: &[u8], pre_y2k_flag: u8) -> Vec<u8> {
  
    let time_string = if pre_y2k_flag == 1 {
        if b[0] == ASN1_UTC_TIME as u8 { [b"19", lder(b, ASN1_UTC_TIME)].concat() } else { lder(b, ASN1_GEN_TIME).to_vec() }
    } else { //the normal case 
        if b[0] == ASN1_UTC_TIME as u8 { [b"20", lder(b, ASN1_UTC_TIME)].concat() } else { lder(b, ASN1_GEN_TIME).to_vec() }
    };
    
    let time_string = from_utf8(&time_string).unwrap();
    match time_string {
        ASN1_GEN_TIME_MAX => lcbor_simple(CBOR_NULL),
        _ => { let dummy = lcbor_uint(chrono::NaiveDateTime::parse_from_str(time_string, "%Y%m%d%H%M%SZ").unwrap().timestamp() as u64);
              trace!("time_string, res time: {:?}, {:?}", time_string, dummy);
              dummy
            },
    }
}
// CBOR encode a DER encoded Algorithm Identifier
fn cbor_alg_id(b: &[u8]) -> Vec<u8> {
    let ai = lder_vec(b, ASN1_SEQ);
    assert!(ai.len() < 3, "Expected length 1 or 2");
    let oid = lcbor_bytes(lder(ai[0], ASN1_OID));
    if ai.len() == 1 {
        oid
    } else {
        let par = lcbor_bytes(ai[1]);
        lcbor_array(&[oid, par])
    }
}
// CBOR encodes a DER encoded ECDSA signature value
fn cbor_ecdsa(b: &[u8]) -> Vec<u8> {
    let signature_seq = lder_vec(b, ASN1_SEQ);
    let r = lder_uint(signature_seq[0]).to_vec();
    let s = lder_uint(signature_seq[1]).to_vec();
    let max = std::cmp::max(r.len(), s.len());
    lcbor_bytes(&[vec![0; max - r.len()], r, vec![0; max - s.len()], s].concat())
}
fn cbor_opt_array(vec: &[Vec<u8>], t: u8) -> Vec<u8> {
    if vec.len() == 2 && vec[0] == [t] {
        vec[1].clone()
    } else {
        lcbor_array(&vec)
    }
}
/******************************************************************************************************/
/*
Below is a list of encoding functions for the supported extensions listed in C509 Extensions Registry
*/
/*
  Placeholder function to store the raw extension value as bytes
*/
fn cbor_store_only(b: &[u8], v: &[u8], oid: &[u8]) -> Vec<u8> {
    print_warning("Warning, currently storing raw data for extension with oid", v, oid);
    lcbor_bytes(b)
}
/*
CBOR encode GeneralNames
Used for and in:
EXT_SUBJECT_ALT_NAME
Authority Key Identifier extension
Note: no wrapping array if content is a single name of type opt
*/
fn cbor_general_names(b: &[u8], t: u8, opt: u8) -> Vec<u8> {
    let unwrap = opt;
    let names = lder_vec(b, t);
    let mut vec = Vec::new();
    for name in names {
        trace!("cbor_general_names, handling name: {:02x?}", name);
        let value = lder(name, name[0]);
        let context_tag = name[0] as u64 & 0x0f;
        trace!("cbor_general_names, storing context tag: {}", context_tag); //debug
        //ongoing: special handling of otherName:
        if context_tag == 0 {
            let inner_value = &value[12..]; //TODO, check handling of long values
            match value {
                [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, ..] => match value[9] {
                    0x0B => {
                        vec.push(lcbor_int(-3));
                        vec.push(lcbor_bytes(inner_value));
                    }
                    0x09 => {
                        vec.push(lcbor_int(-2));
                        vec.push(cbor_other_name_mail(inner_value));
                    }
                    0x04 => {
                        vec.push(lcbor_int(-1));
                        vec.push(cbor_other_name_hw(inner_value));
                    }
                    _ => {
                        vec.push(lcbor_int(0));
                        vec.push(cbor_other_name(value))
                    } //resort to generic otherName encoding, [ ~oid, bytes ]
                },
                _ => {
                    vec.push(lcbor_int(0));
                    vec.push(cbor_other_name(value))
                } //same as above
            }
        } else {
            vec.push(lcbor_uint(context_tag));
            vec.push(match context_tag {
                1 => lcbor_text(value),  // rfc822Name
                2 => lcbor_text(value),  // dNSName
                4 => cbor_name(value),   // Name (TODO a4?)
                6 => lcbor_text(value),  // uniformResourceIdentifier
                7 => lcbor_bytes(value), // iPAddress
                8 => lcbor_bytes(value), // registeredID : should be stored as ~oid
                _ => panic!("Unknown general name"),
            })
        }
    }
    cbor_opt_array(&vec, unwrap)
}
/******************************************************************************************************/
/*
CBOR encoding of the general otherName format
ASN.1 input description
-- AnotherName replaces OTHER-NAME ::= TYPE-IDENTIFIER, as
-- TYPE-IDENTIFIER is not supported in the '88 ASN.1 syntax
 AnotherName ::= SEQUENCE {
 type-id  OBJECT IDENTIFIER,
 value  [0] EXPLICIT ANY DEFINED BY type-id }
CDDL
[ ~oid, bytes ]
*/
fn cbor_other_name(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    let (oid_raw, rest) = lder_split(b, false);
    let oid = lder(oid_raw, ASN1_OID);
    let raw_value = lder(rest, ASN1_INDEX_ZERO);
    //let (choice, value_raw) = der_split(rest, false);
    //Since the raw value can be of any type, we just store it as a byte string without parsing
    vec.push(lcbor_bytes(oid));
    vec.push(lcbor_bytes(raw_value));
    lcbor_array(&vec)
}
/******************************************************************************************************/
/*
Notes on the OtherNames with special encodings:
***********************************
otherName with BundleEID
 ASN.1
ID: -3
1.3.6.1.5.5.7.8.11
06 08 2B 06 01 05 05 07 08 0B
Value: eid-structure from RFC 9171
https://www.rfc-editor.org/rfc/rfc9171.html
 Each BP endpoint ID (EID) SHALL be represented as a CBOR array comprising two items.
The first item of the array SHALL be the code number identifying the endpoint ID's URI scheme,
as defined in the registry of URI scheme code numbers for the Bundle Protocol. Each URI scheme
code number SHALL be represented as a CBOR unsigned integer.
The second item of the array SHALL be the applicable CBOR encoding of the scheme-specific part
of the EID, defined as noted in the references(s) for the URI scheme code number registry entry
for the EID's URI scheme.
eid-structure = [
uri-code: uint,
SSP: any
]
SSP: [
nodenum: uint,
servicenum: uint
]
https://www.rfc-editor.org/rfc/rfc9174.html
 This non-normative example demonstrates an otherName with a name form of
BundleEID to encode the node ID "dtn://example/".
The hexadecimal form of the DER encoding of the otherName is as follows:
a01c06082b0601050507080ba010160e64746e3a2f2f6578616d706c652f
And the text decoding in Figure 28 is an output of Peter Gutmann's "dumpasn1" program.
0  28: [0] {
2   8:   OBJECT IDENTIFIER '1 3 6 1 5 5 7 8 11'
12  16:   [0] {
14  14:   IA5String 'dtn://example/'
   :   }
   :   }
*/
fn _cbor_other_name_bundle(b: &[u8]) -> Vec<u8> {
    /*
    TODO: agree on a possibly more fine grained parsing of the structure contained in the value.
    For now just store the content as a byte string
    let mut vec = Vec::new();
    let mut value;
    match b[0] {
     ASN1_IA5_SRT => { value = der(b, ASN1_IA5_SRT)
     },
     ASN1_UTF8_STR => { value = der(b, ASN1_UTF8_STR)
     },
     _ => panic!("Unknown general value type"),
    }
    */
    let mut vec = Vec::new();
    vec.push(lcbor_bytes(b));
    lcbor_array(&vec)
}
/*
otherName with SmtpUTF8Mailbox
ID -2
1.3.6.1.5.5.7.8.9
06 08 2B 06 01 05 05 07 08 09
https://www.rfc-editor.org/rfc/rfc8398.html
SmtpUTF8Mailbox ::= UTF8String (SIZE (1..MAX))
This non-normative example demonstrates using SmtpUTF8Mailbox as an
otherName in GeneralName to encode the email address
"u+8001u+5E2B@example.com".
The hexadecimal DER encoding of the email address is:
A022060A 2B060105 05070012 0809A014 0C12E880 81E5B8AB 40657861
6D706C65 2E636F6D
The text decoding is:
  0  34: [0] {
  2  10:   OBJECT IDENTIFIER '1 3 6 1 5 5 7 0 18 8 9'
 14  20:   [0] {
 16  18:   UTF8String '..@example.com'
   :   }
   :   }
*WARNING* the OID in this example does not match the OID found in OID databases
*/
fn cbor_other_name_mail(b: &[u8]) -> Vec<u8> {
    // let mut vec = Vec::new();
    let value;
    value = lder(b, ASN1_UTF8_STR);
    lcbor_text(value)
    //cbor_array(&vec)
}
/*
otherName with hardwareModuleName
 Note: this is used in the DevID certificates
 ASN.1
 ID: -1
1.3.6.1.5.5.7.8.4
06 08 2B 06 01 05 05 07 08 04
Value: [ ~oid, bytes ]
https://www.rfc-editor.org/rfc/rfc4108.html
A HardwareModuleName is composed of an object identifier and an octet string:
HardwareModuleName ::= SEQUENCE {
hwType OBJECT IDENTIFIER,
hwSerialNum OCTET STRING }
*/
fn cbor_other_name_hw(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    let another_name_vec = lder_vec(b, ASN1_SEQ);
    let type_id = lder(another_name_vec[0], ASN1_OID);
    let value = lder(another_name_vec[1], ASN1_OCTET_STR);
    vec.push(lcbor_bytes(type_id));
    vec.push(lcbor_bytes(value));
    lcbor_array(&vec)
}
/******************************************************************************************************/
/*
CBOR encodes a Autonomous System Identifier extension
ASN.1 input
 id-pe-autonomousSysIds  OBJECT IDENTIFIER ::= { id-pe 8 }
ASIdentifiers   ::= SEQUENCE
{
asnum   [0] EXPLICIT ASIdentifierChoice OPTIONAL,
rdi   [1] EXPLICIT ASIdentifierChoice OPTIONAL
}
ASIdentifierChoice  ::= CHOICE
{
inherit   NULL, -- inherit from issuer --
asIdsOrRanges   SEQUENCE OF ASIdOrRange
}
ASIdOrRange   ::= CHOICE {
id  ASId,
range   ASRange
}
ASRange   ::= SEQUENCE {
min   ASId,
max   ASId
}
ASId  ::= INTEGER
-- see https://www.rfc-editor.org/rfc/rfc3779.html
   CDDL
 AsIdsOrRanges = uint / [uint, uint]
ASIdentifiers = [ + AsIdsOrRanges ] / null
 NOTE
If rdi is not present, the extension value can be CBOR encoded.
Each ASId is encoded as an uint. With the exception of the first
ASId, the ASid is encoded as the difference to the previous ASid.
*/
fn cbor_ext_as_res(b: &[u8]) -> Vec<u8> {
    let as_identifiers = lder(b, ASN1_SEQ);
    let asnum = lder(as_identifiers, ASN1_INDEX_ZERO);
    let mut vec = Vec::new();
    let mut last = 0u64;
    if asnum == [0x05, 0x00] {
        return lcbor_simple(CBOR_NULL);
    }
    for elem in lder_vec(asnum, ASN1_SEQ) {
        if elem[0] == ASN1_INT {
            let asid = be_bytes_to_u64(lder_uint(elem));
            vec.push(lcbor_uint(asid - last));
            last = asid;
        } else if elem[0] == ASN1_SEQ {
            let mut range = Vec::new();
            for elem2 in lder_vec_len(elem, ASN1_SEQ, 2) {
                let asid = be_bytes_to_u64(lder_uint(elem2));
                range.push(lcbor_uint(asid - last));
                last = asid;
            }
            vec.push(lcbor_array(&range));
        } else {
            panic!("Expected INT or SEQ");
        }
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
/*
CBOR encodes a Authority Key Identifier extension
Description:
Authority Key Identifier (authorityKeyIdentifier). If the authority key identifier
contains all of keyIdentifier, certIssuer, and certSerialNumberm or if only keyIdentifier
is present the extension value can be CBOR encoded. If all three are present a CBOR array
is used, if only keyIdentifier is present, the array is omitted
CDDL
KeyIdentifierArray = [
 keyIdentifier: KeyIdentifier / null,
 authorityCertIssuer: GeneralNames,
 authorityCertSerialNumber: CertificateSerialNumber
]
AuthorityKeyIdentifier = KeyIdentifierArray / KeyIdentifier
*/
fn cbor_ext_auth_key_id(b: &[u8]) -> Vec<u8> {
    let aki = lder_vec(b, ASN1_SEQ);
    
    match aki.len() {
      1 => lcbor_bytes(lder(aki[0], 0x80)), //assuming only a keyIdentifier is present, will fail otherwise
      3 => {
        let ki = lcbor_bytes(lder(aki[0], 0x80));
        lcbor_array(&[ki, cbor_general_names(aki[1], 0xa1, 0xff), lcbor_bytes(lder(aki[2], 0x82))])
        //above will fail if the AKI doesn't follow the outlined order. Might add back panic::catch_unwind(|| -> Vec<u8>  for batch testing
      }
      _ => {
        warn!("Error parsing Authority Key Identifier extension.\nCan only handle AKI with either only KeyIdentifier or KeyIdentifier, authorityCertIssuer and authorityCertSerialNumber all present");
        unsafe {
          if GLOBAL_BATCH_MODE {
            warn!("In batch mode, return empty vector to create a convert failure, but continue working");
            Vec::new()
          } else {
            panic!("Error parsing auth key id")
          } 
        }
      }
    }
}
/******************************************************************************************************/
/*
CBOR encode a Basic Constraints extension
Description
Basic Constraints (basicConstraints). If 'cA' = false then extensionValue = -2, if 'cA' = true and
'pathLenConstraint' is not present then extensionValue = -1, and if 'cA' = true and 'pathLenConstraint'
is present then extensionValue = pathLenConstraint.
CDDL
 BasicConstraints = int
*/
fn cbor_ext_bas_con(b: &[u8]) -> Vec<u8> {
    let bc = lder_vec(b, ASN1_SEQ);
    //println!("match bc.len(): {}", bc.len());
    match bc.len() {
        0 => lcbor_int(-2),
        1 => {
            assert!(lder(bc[0], ASN1_BOOL) == [0xff], "Expected cA == true");
            lcbor_int(-1)
        }
        2 => {
            assert!(lder(bc[0], ASN1_BOOL) == [0xff], "Expected cA == true");
            let path_len = lder_uint(bc[1]);
            assert!(path_len.len() == 1, "Expected path length < 256");
            lcbor_uint(path_len[0] as u64)
        }
        _ => panic!("Error parsing basic constraints"),
    }
}
/******************************************************************************************************/
/*
CBOR encodes a Certificate Policies extension
ASN.1 input
CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
PolicyInformation ::= SEQUENCE {
policyIdentifier   CertPolicyId,
policyQualifiers   SEQUENCE SIZE (1..MAX) OF
  PolicyQualifierInfo OPTIONAL }
CertPolicyId ::= OBJECT IDENTIFIER
CERT-POLICY-QUALIFIER ::= TYPE-IDENTIFIER
PolicyQualifierInfo ::= SEQUENCE {
  policyQualifierId  CERT-POLICY-QUALIFIER.
  &id({PolicyQualifierId}),
  qualifier   CERT-POLICY-QUALIFIER.
  &Type({PolicyQualifierId}{@policyQualifierId})}
PolicyQualifierId CERT-POLICY-QUALIFIER ::=
{ pqid-cps | pqid-unotice, ... }
 CDDL
 PolicyIdentifier = int / ~oid
PolicyQualifierInfo = (
policyQualifierId: int / ~oid,
qualifier: text,
)
CertificatePolicies = [
+ ( PolicyIdentifier, ? [ + PolicyQualifierInfo ] )
]
 NOTE
If noticeRef is not used and any explicitText are encoded as UTF8String, the extension value can be CBOR encoded.
OIDs registered in C509 are encoded as an int. The policyQualifierId is encoded as an CBOR int or an unwrapped
CBOR OID tag (RFC9090).
*/
fn cbor_ext_cert_policies(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for pi in lder_vec(b, ASN1_SEQ) {
        let pi = lder_vec(pi, ASN1_SEQ);
        assert!(pi.len() == 1 || pi.len() == 2, "expected length 1 or 2");
        let oid = lder(pi[0], ASN1_OID);
        if let Some(cp_type) = cp_map(oid) {
            vec.push(lcbor_int(cp_type));
        } else {
            print_warning("No C509 int registered for Certificate Policy OID", pi[0], oid);
            vec.push(lcbor_bytes(oid));
        }
        if pi.len() == 2 {
            let mut vec2 = Vec::new();
            for pqi in lder_vec(pi[1], ASN1_SEQ) {
                let pqi = lder_vec_len(pqi, ASN1_SEQ, 2);
                let oid = lder(pqi[0], ASN1_OID);
                if let Some(pq_type) = pq_map(oid) {
                    vec2.push(lcbor_int(pq_type));
                    if pq_type == PQ_CPS {
                        let text = lder(pqi[1], ASN1_IA5_SRT);
                        trace!("cbor_ext_cert_policies, encoded text {:02x?}", text);
                        vec2.push(lcbor_text(text));
                    } else if pq_type == PQ_UNOTICE {
                        let text = {
                          let explicit_note = lder(pqi[1], ASN1_SEQ);
                          match explicit_note[0] {
                            ASN1_UTF8_STR => lder(explicit_note, ASN1_UTF8_STR),
                            _ => {
                              warn!("In Certificate Policies extension: can only handle explicitText of type utf8");
                              unsafe {
                                if GLOBAL_BATCH_MODE {
                                  explicit_note //will cause matching to fail later
                                } else {
                                  panic!("Abort");
                                }
                              }
                            }
                          }
                          
                        };
                        vec2.push(lcbor_text(text));
                    } else {
                        panic!("unexpected qualifier oid");
                    }
                } else {
                    print_warning("No C509 int registered for Policy Qualifier OID", pqi[0], oid);
                    vec2.push(lcbor_bytes(oid));
                }
            }
            vec.push(lcbor_array(&vec2));
        }
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
/**
CBOR encodes a CRL distribution list extension
CDDL
DistributionPointName = [ 2* text ] / text
CRLDistributionPoints = [ + DistributionPointName ]
 NOTE
CRL Distribution Points (cRLDistributionPoints). If the CRL Distribution Points is a sequence of
DistributionPointName, where each DistributionPointName only contains uniformResourceIdentifiers,
the extension value can be CBOR encoded. extensionValue is encoded as follows:
*/
fn cbor_ext_crl_dist(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for dists in lder_vec(b, ASN1_SEQ) {
        let dists = lder(dists, ASN1_SEQ);
        let dists = panic::catch_unwind(|| -> &[u8] { 
          lder(dists, 0xa0)
        }); //only for batch testing
        
        match dists {
          Ok(_) => {
            let dists = dists.unwrap();
            let mut vec2 = Vec::new();
            for dist in lder_vec(dists, 0xa0) {
                vec2.push(lcbor_text(lder(dist, 0x86)));
            }
            if vec2.len() > 1 {
                vec.push(lcbor_array(&vec2))
            } else {
                vec.push(vec2[0].clone())
            }

          }
          Err(_) => {
            warn!("Caught a panic from a failed assertion while handling CRL distribution list extension!");
            unsafe {
            if GLOBAL_BATCH_MODE {
              warn!("In batch mode, return empty vector to create a convert failure, but continue working");
            } else {
              panic!("Error parsing")
            } 
            }

          }
        }
         
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
// CBOR encodes a extended key usage extension
fn cbor_ext_eku(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for eku in lder_vec(b, ASN1_SEQ) {
        let oid = lder(eku, ASN1_OID);
        if let Some(eku_type) = eku_map(oid) {
            vec.push(lcbor_uint(eku_type));
        } else {
            print_warning("No C509 int registered for EKU OID", eku, oid);
            vec.push(lcbor_bytes(oid));
        }
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
// CBOR encodes a authority/subject Info Access extension
fn cbor_ext_info_access(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for access_desc in lder_vec(b, ASN1_SEQ) {
        let access_desc = lder_vec_len(access_desc, ASN1_SEQ, 2);
        let oid = lder(access_desc[0], ASN1_OID);
        let access_location = lcbor_text(lder(access_desc[1], 0x86));
        if let Some(access_type) = info_map(oid) {
            vec.push(lcbor_int(access_type));
        } else {
            print_warning("No C509 int registered for Info Access OID", access_desc[0], oid);
            vec.push(lcbor_bytes(oid));
        }
        vec.push(access_location);
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
/******************************************************************************************************/
// CBOR encodes a Range of IP Addresses
fn cbor_ext_ip_res(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    let mut last = Vec::new();
    for block in lder_vec(b, ASN1_SEQ) {
        let family = lder_vec_len(block, ASN1_SEQ, 2);
        let afi = lder(family[0], ASN1_OCTET_STR);
        assert!(afi.len() == 2, "expected afi and no safi");
        vec.push(lcbor_uint(be_bytes_to_u64(afi)));
        // NULL
        let mut fam = Vec::new();
        for aor in lder_vec(family[1], ASN1_SEQ) {
            if aor[0] == ASN1_BIT_STR {
                let ip = lder(aor, ASN1_BIT_STR);
                let unused_bits = ip[0];
                let ip_bytes = &ip[1..];
                if ip_bytes.len() == last.len() {
                    let diff = be_bytes_to_u64(ip_bytes) as i64 - be_bytes_to_u64(&last) as i64;
                    fam.push(lcbor_int(diff));
                } else {
                    fam.push(lcbor_bytes(&ip_bytes));
                }
                last = ip_bytes.to_vec();
                fam.push(lcbor_uint(unused_bits as u64));
            } else if aor[0] == ASN1_SEQ {
                let mut range = Vec::new();
                let range_der = lder_vec_len(aor, ASN1_SEQ, 2);
                let ip = lder(range_der[0], ASN1_BIT_STR);
                let ip_bytes = &ip[1..];
                if ip_bytes.len() == last.len() {
                    let diff = be_bytes_to_u64(ip_bytes) as i64 - be_bytes_to_u64(&last) as i64;
                    range.push(lcbor_int(diff));
                } else {
                    range.push(lcbor_bytes(&ip_bytes));
                }
                last = ip_bytes.to_vec();
                let ip = lder(range_der[1], ASN1_BIT_STR);
                let unused_bits = ip[0];
                let mut ip_bytes = ip[1..].to_vec();
                let l = ip_bytes.len();
                ip_bytes[l - 1] |= (2u16.pow(unused_bits as u32) - 1) as u8;
                if ip_bytes.len() == last.len() {
                    let diff = be_bytes_to_u64(&ip_bytes) as i64 - be_bytes_to_u64(&last) as i64;
                    range.push(lcbor_int(diff));
                } else {
                    range.push(lcbor_bytes(&ip_bytes));
                }
                last = ip_bytes.to_vec();
                fam.push(lcbor_array(&range));
            } else {
                panic!("Expected INT or SEQ");
            }
        }
        vec.push(lcbor_array(&fam));
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
/*
CBOR encode EXT_KEY_USAGE - 2 - Key Usage Extension
*/
fn cbor_ext_key_use(bs: &[u8], signed_nr_ext: i64) -> Vec<u8> {
    assert!(bs[0] == ASN1_BIT_STR, "Expected 0x03");
    let len = bs[1];
    assert!((2..4).contains(&len), "Expected key usage ASN.1 field len to be 2 or 3 bytes");
    //Note: at encoding time we don't need to handle bs[2] / the number of free bytes
    let v = bs[3].swap_bits();
    if len == 3 {
        assert!(bs[4] == 128, "Error in KeyUsage bitstring, more than 9 bits used");
        let w = (v as u64) + 256;
        if signed_nr_ext == -1 {
            return lcbor_int(-(w as i64));
        }
        return lcbor_uint(w as u64);
    }
    if signed_nr_ext == -1 {
        return lcbor_int(-(v as i64));
    }
    lcbor_uint(v as u64)
}
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
// CBOR encodes a SCT extention
// https://letsencrypt.org/2018/04/04/sct-encoding.html
// refactor signature calculation
fn cbor_ext_sct(b: &[u8], not_before: &[u8]) -> Vec<u8> {
    let mut temp = &lder(b, ASN1_OCTET_STR)[2..];
    let mut scts = Vec::new();
    while !temp.is_empty() {
        let end = ((temp[0] as usize) << 8) + (temp[1] as usize);
        let (value, temp2) = (&temp[2..2 + end], &temp[2 + end..]);
        scts.push(value);
        temp = temp2;
    }
    let mut vec = Vec::new();
    for sct in scts {
        assert!(sct[0] == 0, "expected SCT version 1");
        vec.push(lcbor_bytes(&sct[1..33]));
        let ts = be_bytes_to_u64(&sct[33..41]) as i64;
        let not_before_ms = 1000 * be_bytes_to_u64(&cbor_time(not_before, 0)[1..]) as i64;
        vec.push(lcbor_int(ts - not_before_ms));
        assert!(sct[41..43] == [0, 0], "expected no SCT extentsions");
        assert!(sct[43..45] == [4, 3], "expected SCT SHA-256 ECDSA");
        vec.push(lcbor_int(SIG_ECDSA_SHA256 as i64));

        let signature_seq = lder_vec(&sct[47..], ASN1_SEQ);
        trace!("ENCODING EXT_SCT_LIST TO CBOR: working with signature_seq of len {}: {:02x?}", signature_seq.len(), signature_seq);
        let r = lder_uint(signature_seq[0]).to_vec();
        let s = lder_uint(signature_seq[1]).to_vec();
        let max = std::cmp::max(r.len(), s.len());
        let signature_ecdsa = &[vec![0; max - r.len()], r, vec![0; max - s.len()], s].concat();
        trace!("ENCODING EXT_SCT_LIST TO CBOR: pushing signature of len {}: {:02x?}", signature_ecdsa.len(), signature_ecdsa);
        vec.push(lcbor_bytes(signature_ecdsa));
    }
    lcbor_array(&vec)
}
/*
Above is the list of encoding functions for the supported extensions listed in C509 Extensions Registry
*/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
fn print_information(certs: &[Cert]) {
    // calculate lengths for printing
    let der_len: u64 = certs.iter().map(|v| v.der.len() as u64).sum();
    let cbor_len: u64 = certs.iter().map(|v| v.cbor.concat().len() as u64).sum();
    // print general information
    let row1 = format!("Encoding certificate chain/bag with {} certificates", certs.len());
    let row2 = format!("{} bytes / {} bytes ({:.2}%)", cbor_len, der_len, 100.0 * cbor_len as f64 / der_len as f64);
    print_info(&[row1, row2]);
    // Print information about individual certs
    for (i, cert) in certs.iter().enumerate() {
        let row1 = format!("Encoding certificate {} of {}", i + 1, certs.len());
        let row2 = format!("{} bytes / {} bytes ({:.2}%)", cert.cbor.concat().len(), cert.der.len(), 100.0 * cert.cbor.concat().len() as f64 / cert.der.len() as f64);
        print_info(&[row1, row2]);
        if PRINT_INPUT {
            print_vec("Input: DER encoded X.509 certificate (RFC 5280)", &cert.der);
        }
        if PRINT_OUTPUT {
            print_vec("Output: CBOR encoded X.509 certificate (~C509Certificate)", &cert.cbor.concat());
            print_vec("C509 Certificate Type", &cert.cbor[0]);
            print_vec("Certificate Serial Number", &cert.cbor[1]);
            print_vec("Issuer", &cert.cbor[2]);
            print_vec("Validity Not Before", &cert.cbor[3]);
            print_vec("Validity Not After", &cert.cbor[4]);
            print_vec("Subject", &cert.cbor[5]);
            print_vec("Subject Public Key Algorithm", &cert.cbor[6]);
            print_vec("Subject Public Key", &cert.cbor[7]);
            print_vec("Extentions", &cert.cbor[8]);
            print_vec("Issuer Signature Algorithm", &cert.cbor[9]);
            print_vec("Issuer Signature Value", &cert.cbor[10]);
        }
    }
    if PRINT_COSE {
        // COSE_X509
        // ======================================================
        let row1 = format!("CBOR COSE_X509 with {} certificates", certs.len());
        print_info(&[row1]);
        if certs.len() > 1 {
            let mut cose_x509: Vec<Vec<u8>> = Vec::new();
            for cert in certs {
                cose_x509.push(lcbor_bytes(&cert.der));
            }
            print_vec("COSE_X509", &lcbor_array(&cose_x509));
        } else if certs.len() > 0 {
            print_vec("COSE_X509", &lcbor_bytes(&certs[0].der));
        } else {
          println!("Operation failed, exiting");
          std::process::exit(0);
        }
        // COSE_C509
        // ======================================================
        let row1 = format!("CBOR COSE_C509 with {} certificates", certs.len());
        print_info(&[row1]);
        if certs.len() > 1 {
            let mut cose_c509: Vec<Vec<u8>> = Vec::new();
            for cert in certs {
                cose_c509.push(lcbor_array(&cert.cbor));
                println!("COSE_C509 individual certificate");
                print_vec_compact(&lcbor_array(&cert.cbor));
                println!("\n");
            }
            
            print_vec("\nCOSE_C509 chain", &lcbor_array(&cose_c509));
            
        } else {
            print_vec("COSE_C509", &lcbor_array(&certs[0].cbor));
            print_vec_compact(&lcbor_array(&certs[0].cbor));
            println!("");
        }
        // // COSE_C509 Uncompressed
        // // ======================================================
        // let row1 = format!("CBOR COSE_C509 Uncompressed with {} certificates", certs.len());
        // print_info(&[row1]);
        // let mut cose_c509: Vec<Vec<u8>> = vec![cbor_uint(0)];
        // for cert in certs {
        //  cose_c509.push(cbor_array(&cert.cbor));
        // }
        // print_vec("COSE_C509 Uncompressed", &cbor_array(&cose_c509));
        // // COSE_C509 Brotli
        // // ======================================================
        // let row1 = format!("CBOR COSE_C509 Brotli with {} certificates", certs.len());
        // print_info(&[row1]);
        // let mut cose_c509: Vec<Vec<u8>> = vec![cbor_uint(1)];
        // let mut certs2: Vec<Vec<u8>> = Vec::new();
        // for cert in certs {
        //  certs2.push(cbor_array(&cert.cbor));
        // }
        // cose_c509.push(cbor_bytes(&brotli(&certs2.concat())));
        // print_vec("COSE_C509 Brotli", &cbor_array(&cose_c509));
    }
    if PRINT_TLS {
        // TLS 1.3 Certificate message (X509)
        // ======================================================
        let row1 = format!("TLS 1.3 Certificate message with {} certificates (X509)", certs.len());
        print_info(&[row1]);
        let mut tls_x509 = Vec::new();
        for cert in certs {
            tls_x509.extend(&(cert.der.len() as u32).to_be_bytes()[1..4]);
            tls_x509.extend(&cert.der);
            tls_x509.extend(&[0x00, 0x00]);
        }
        tls_x509 = [&[0x00], &(tls_x509.len() as u32).to_be_bytes()[1..4], &tls_x509].concat();
        tls_x509 = [&[0x0b], &(tls_x509.len() as u32).to_be_bytes()[1..4], &tls_x509].concat();
        print_vec("TLS_X509", &tls_x509);
        // TLS 1.3 CompressedCertificate message (X509 + Brotli)
        // ======================================================
        let row1 = "TLS 1.3 CompressedCertificate message (X509 + Brotli)".to_string();
        print_info(&[row1]);
        let mut tls_x509_brotli = brotli(&tls_x509);
        tls_x509_brotli = [&(tls_x509_brotli.len() as u32).to_be_bytes()[1..4], &tls_x509_brotli].concat();
        tls_x509_brotli = [&[0x00, 0x02], &(tls_x509.len() as u32).to_be_bytes()[1..4], &tls_x509_brotli].concat();
        tls_x509_brotli = [&[0x19], &(tls_x509_brotli.len() as u32).to_be_bytes()[1..4], &tls_x509_brotli].concat();
        print_vec("Brotli TLS_X509", &tls_x509_brotli);
        // TLS 1.3 Certificate message (C509)
        // ======================================================
        let row1 = format!("TLS 1.3 Certificate message with {} certificates (C509)", certs.len());
        print_info(&[row1]);
        let mut tls_c509 = Vec::new();
        for cert in certs {
            tls_c509.extend(&(cert.cbor.concat().len() as u32).to_be_bytes()[1..4]);
            tls_c509.extend(&cert.cbor.concat());
            tls_c509.extend(&[0x00, 0x00]);
        }
        tls_c509 = [&[0x00], &(tls_c509.len() as u32).to_be_bytes()[1..4], &tls_c509].concat();
        tls_c509 = [&[0x0b], &(tls_c509.len() as u32).to_be_bytes()[1..4], &tls_c509].concat();
        print_vec("TLS_C509", &tls_c509);
        // TLS 1.3 CompressedCertificate message (X509 + Brotli)
        // ======================================================
        let row1 = "TLS 1.3 CompressedCertificate message (C509 + Brotli)".to_string();
        print_info(&[row1]);
        let mut tls_c509_brotli = brotli(&tls_c509);
        tls_c509_brotli = [&(tls_c509_brotli.len() as u32).to_be_bytes()[1..4], &tls_c509_brotli].concat();
        tls_c509_brotli = [&[0x00, 0x02], &(tls_c509.len() as u32).to_be_bytes()[1..4], &tls_c509_brotli].concat();
        tls_c509_brotli = [&[0x19], &(tls_c509_brotli.len() as u32).to_be_bytes()[1..4], &tls_c509_brotli].concat();
        print_vec("Brotli TLS_C509", &tls_c509_brotli);
    }
}
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
// ======================================================
// C509 maps for OID and ALD_ID to int
// ======================================================
// C509 Certificate Attributes Registry
// ======================================================
pub const ATT_EMAIL: u32 = 0;
pub const ATT_COMMON_NAME: u32 = 1; // CN
pub const ATT_SUR_NAME: u32 = 2; // SN
pub const ATT_SERIAL_NUMBER: u32 = 3;
pub const ATT_COUNTRY: u32 = 4; // C
pub const ATT_LOCALITY: u32 = 5; // L
pub const ATT_STATE_OR_PROVINCE: u32 = 6; // ST
pub const ATT_STREET_ADDRESS: u32 = 7;
pub const ATT_ORGANIZATION: u32 = 8; // O
pub const ATT_ORGANIZATION_UNIT: u32 = 9; // OU
pub const ATT_TITLE: u32 = 10; // T
pub const ATT_BUSINESS: u32 = 11;
pub const ATT_POSTAL_CODE: u32 = 12; // PC
pub const ATT_GIVEN_NAME: u32 = 13;
pub const ATT_INITIALS: u32 = 14;
pub const ATT_GENERATION_QUALIFIER: u32 = 15;
pub const ATT_DN_QUALIFIER: u32 = 16;
pub const ATT_PSEUDONYM: u32 = 17;
pub const ATT_ORGANIZATION_IDENTIFIER: u32 = 18;
pub const ATT_INC_LOCALITY: u32 = 19;
pub const ATT_INC_STATE: u32 = 20;
pub const ATT_INC_COUNTRY: u32 = 21;
pub const ATT_DOMAIN_COMPONENT: u32 = 22; // DC
pub const ATT_POSTAL_ADDRESS: u32 = 24; //postalAddress,  55 04 10
pub const ATT_NAME: u32 = 25; //name,   55 04 29
pub const ATT_TELEPHONE_NUMBER: u32 = 26; //telephoneNumber 55 04 14
pub const ATT_DIR_MAN_DOMAIN_NAME: u32 = 27; //dmdName  55 04 36
pub const ATT_USER_ID: u32 = 28; //uid   09 92 26 89 93 F2 2C 64 01 01
pub const ATT_UNSTRUCTURED_NAME: u32 = 29; //unstructuredName   2A 86 48 86 F7 0D 01 09 02
pub const ATT_UNSTRUCTURED_ADDRESS: u32 = 30; //unstructuredAddress   2A 86 48 86 F7 0D 01 09 08 00
pub fn att_map(oid: &[u8]) -> Option<u32> {
    match oid {
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, ..] => match oid[9..] {
            [0x01] => Some(ATT_USER_ID),
            [0x19] => Some(ATT_DOMAIN_COMPONENT),
            _ => None,
        },
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, ..] => match oid[8..] {
            [0x01] => Some(ATT_EMAIL),
            [0x02] => Some(ATT_UNSTRUCTURED_NAME),
            [0x08, 0x00] => Some(ATT_UNSTRUCTURED_ADDRESS),
            _ => None,
        },
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, ..] => match oid[10..] {
            [0x01] => Some(ATT_INC_LOCALITY),
            [0x02] => Some(ATT_INC_STATE),
            [0x03] => Some(ATT_INC_COUNTRY),
            _ => None,
        },
        [0x55, 0x04, ..] => match oid[2..] {
            [0x03] => Some(ATT_COMMON_NAME),
            [0x04] => Some(ATT_SUR_NAME),
            [0x05] => Some(ATT_SERIAL_NUMBER),
            [0x06] => Some(ATT_COUNTRY),
            [0x07] => Some(ATT_LOCALITY),
            [0x08] => Some(ATT_STATE_OR_PROVINCE),
            [0x09] => Some(ATT_STREET_ADDRESS),
            [0x10] => Some(ATT_POSTAL_ADDRESS),
            [0x14] => Some(ATT_TELEPHONE_NUMBER),
            [0x0A] => Some(ATT_ORGANIZATION),
            [0x0B] => Some(ATT_ORGANIZATION_UNIT),
            [0x0C] => Some(ATT_TITLE),
            [0x0F] => Some(ATT_BUSINESS),
            [0x11] => Some(ATT_POSTAL_CODE),
            [0x29] => Some(ATT_NAME),
            [0x2A] => Some(ATT_GIVEN_NAME),
            [0x2B] => Some(ATT_INITIALS),
            [0x2C] => Some(ATT_GENERATION_QUALIFIER),
            [0x2E] => Some(ATT_DN_QUALIFIER),
            [0x36] => Some(ATT_DIR_MAN_DOMAIN_NAME),
            [0x41] => Some(ATT_PSEUDONYM),
            [0x61] => Some(ATT_ORGANIZATION_IDENTIFIER),
            _ => None,
        },
        _ => None,
    }
}
// C509 Certificate Public Key Algorithms Registry
// Ongoing / still TODO: find test certs for PK_SM2P256V1
// ======================================================
// PK_RSA_ENC PK_SECP256R PK_SECP384R PK_SECP521R PK_X25519 PK_X448 PK_ED25519 PK_ED448 PK_HSS_LMS PK_XMSS PK_XMSS_MT PK_BRAINPOOL256R1 PK_BRAINPOOL384R1 PK_BRAINPOOL512R1 PK_FRP256V1 PK_SM2P256V1
// ======================================================
pub const PK_RSA_ENC: i64 = 0;
pub const PK_SECP256R: i64 = 1;
pub const PK_SECP384R: i64 = 2;
pub const PK_SECP521R: i64 = 3;
pub const PK_X25519: i64 = 8;
pub const PK_X448: i64 = 9;
pub const PK_ED25519: i64 = 10;
pub const PK_ED448: i64 = 11;
pub const PK_HSS_LMS: i64 = 16;
pub const PK_XMSS: i64 = 17;
pub const PK_XMSS_MT: i64 = 18;
pub const PK_BRAINPOOL256R1: i64 = 24;
pub const PK_BRAINPOOL384R1: i64 = 25;
pub const PK_BRAINPOOL512R1: i64 = 26;
pub const PK_FRP256V1: i64 = 27;
pub const PK_SM2P256V1: i64 = 28; //06 07 2A 86 48 CE 3D 02 01 06 08 2A 81 1C CF 55 01 82 2D
pub fn pk_map(alg_id: &[u8]) -> Option<i64> {
    let value = lder(alg_id, ASN1_SEQ);
    match value {
        [0x06, 0x03, 0x2B, 0x65, ..] => match value[4..] {
            [0x6E] => Some(PK_X25519),
            [0x6F] => Some(PK_X448),
            [0x70] => Some(PK_ED25519),
            [0x71] => Some(PK_ED448),
            _ => None,
        },
        [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, ..] => match lder(&value[9..], ASN1_OID) {
            [0x2A, 0x81, 0x7A, 0x01, 0x81, 0x5F, 0x65, 0x82, 0x00, 0x01] => Some(PK_FRP256V1),
            [0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D] => Some(PK_SM2P256V1),
            [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] => Some(PK_SECP256R),
            [0x2B, 0x81, 0x04, 0x00, 0x22] => Some(PK_SECP384R),
            [0x2B, 0x81, 0x04, 0x00, 0x23] => Some(PK_SECP521R),
            [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07] => Some(PK_BRAINPOOL256R1),
            [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B] => Some(PK_BRAINPOOL384R1),
            [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D] => Some(PK_BRAINPOOL512R1),
            _ => None,
        },
        [0x06, 0x09, 0x04, 0x00, 0x7F, 0x00, 0x0F, 0x01, 0x01, ..] => match value[4..] {
            [0x0D, 0x00] => Some(PK_XMSS),
            [0x0E, 0x00] => Some(PK_XMSS_MT),
            _ => None,
        },
        [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00] => Some(PK_RSA_ENC),
        [0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x11] => Some(PK_HSS_LMS),
        _ => None,
    }
}
//*****************************************************************************************************************************************************
// C509 Certificate Signature Algorithms Registry
// Ongoing / still TODO: find tests for 16--18 + 45
// ======================================================
pub const SIG_RSA_V15_SHA1: i64 = -256;
pub const SIG_ECDSA_SHA1: i64 = -255;
pub const SIG_ECDSA_SHA256: i64 = 0;
pub const SIG_ECDSA_SHA384: i64 = 1;
pub const SIG_ECDSA_SHA512: i64 = 2;
pub const SIG_ECDSA_SHAKE128: i64 = 3;
pub const SIG_ECDSA_SHAKE256: i64 = 4;
pub const SIG_ED25519: i64 = 12;
pub const SIG_ED448: i64 = 13;
pub const SIG_SHA256_HMAC_SHA256: i64 = 14; //TODO
pub const SIG_SHA384_HMAC_SHA384: i64 = 15; //TODO
pub const SIG_SHA512_HMAC_SHA512: i64 = 16; //TODO
pub const SIG_RSA_V15_SHA256: i64 = 23;
pub const SIG_RSA_V15_SHA384: i64 = 24;
pub const SIG_RSA_V15_SHA512: i64 = 25;
pub const SIG_RSA_PSS_SHA256: i64 = 26;
pub const SIG_RSA_PSS_SHA384: i64 = 27;
pub const SIG_RSA_PSS_SHA512: i64 = 28;
pub const SIG_RSA_PSS_SHAKE128: i64 = 29;
pub const SIG_RSA_PSS_SHAKE256: i64 = 30;
pub const SIG_HSS_LMS: i64 = 42; //30 0D 06 0B 2A 86 48 86 F7 0D 01 09 10 03 11
pub const SIG_XMSS: i64 = 43; //30 0B 06 09 04 00 7F 00 0F 01 01 0D 00
pub const SIG_XMSS_MT: i64 = 44; //30 0B 06 09 04 00 7F 00 0F 01 01 0E 00
pub const SIG_SM2_V15_SM3: i64 = 45; //30 0A 06 08 2A 81 1C CF 55 01 83 75
pub fn sig_map(alg_id: &[u8]) -> Option<i64> {
    let value = lder(alg_id, ASN1_SEQ);
    match value {
        [0x06, 0x03, 0x2B, 0x65, ..] => match value[4..] {
            [0x70] => Some(SIG_ED25519),
            [0x71] => Some(SIG_ED448),
            _ => None,
        },
        [0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75] => Some(SIG_SM2_V15_SM3),
        [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, ..] => match value[9..] {
            [0x01] => Some(SIG_ECDSA_SHA1),
            [0x02] => Some(SIG_ECDSA_SHA256),
            [0x03] => Some(SIG_ECDSA_SHA384),
            [0x04] => Some(SIG_ECDSA_SHA512),
            _ => None,
        },
        [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, ..] => match value[9..] {
            [0x20] => Some(SIG_ECDSA_SHAKE128),
            [0x21] => Some(SIG_ECDSA_SHAKE256),
            [0x1E] => Some(SIG_RSA_PSS_SHAKE128),
            [0x1F] => Some(SIG_RSA_PSS_SHAKE256),
            _ => None,
        },
        [0x06, 0x09, 0x04, 0x00, 0x7f, 0x00, 0x0f, 0x01, 0x01, ..] => match value[9..] {
            [0x0d, 0x00] => Some(SIG_XMSS),
            [0x0e, 0x00] => Some(SIG_XMSS_MT),
            _ => None,
        },
        [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, ..] => match value[10..] {
            [0x05, 0x05, 0x00] => Some(SIG_RSA_V15_SHA1),
            [0x0A, 0x30, 0x34, 0xA0, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, ..] => match value[27..] {
                [0x01, 0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20] => {
                    Some(SIG_RSA_PSS_SHA256)
                }
                [0x02, 0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x30] => {
                    Some(SIG_RSA_PSS_SHA384)
                }
                [0x03, 0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x40] => {
                    Some(SIG_RSA_PSS_SHA512)
                }
                _ => None,
            },
            [0x0B, 0x05, 0x00] => Some(SIG_RSA_V15_SHA256),
            [0x0C, 0x05, 0x00] => Some(SIG_RSA_V15_SHA384),
            [0x0D, 0x05, 0x00] => Some(SIG_RSA_V15_SHA512),
            _ => None,
        },
        [0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x11] => Some(SIG_HSS_LMS),
        _ => None,
    }
}
// C509 Certificate Extensions Registry *updated*
// ======================================================
pub const EXT_SUBJECT_KEY_ID: u16 = 1;
pub const EXT_KEY_USAGE: u16 = 2;
pub const EXT_SUBJECT_ALT_NAME: u16 = 3;
pub const EXT_BASIC_CONSTRAINTS: u16 = 4;
pub const EXT_CRL_DIST_POINTS: u16 = 5;
pub const EXT_CERT_POLICIES: u16 = 6;
pub const EXT_AUTH_KEY_ID: u16 = 7;
pub const EXT_EXT_KEY_USAGE: u16 = 8;
pub const EXT_AUTH_INFO: u16 = 9;
pub const EXT_SCT_LIST: u16 = 10;
pub const EXT_SUBJECT_DIRECTORY_ATTR: u16 = 24; //0x09
pub const EXT_ISSUER_ALT_NAME: u16 = 25; //0x12
pub const EXT_NAME_CONSTRAINTS: u16 = 26; //0x1E
pub const EXT_POLICY_MAPPINGS: u16 = 27; //21
pub const EXT_POLICY_CONSTRAINTS: u16 = 28; //24
pub const EXT_FRESHEST_CRL: u16 = 29; //2e
pub const EXT_INHIBIT_ANYPOLICY: u16 = 30; //36
pub const EXT_SUBJECT_INFO_ACCESS: u16 = 31; //5-0b
pub const EXT_IP_RESOURCES: u16 = 32; //5-07
pub const EXT_AS_RESOURCES: u16 = 33; //5-08
pub const EXT_IP_RESOURCES_V2: u16 = 34; //5-1c
pub const EXT_AS_RESOURCES_V2: u16 = 35; //5-1d
pub const EXT_BIOMETRIC_INFO: u16 = 36; //5-02
pub const EXT_PRECERT_SIGNING_CERT: u16 = 37; //4-04
pub const EXT_OCSP_NO_CHECK: u16 = 38; //2B 06 01 05 05 07 30 01 05
pub const EXT_QUALIFIED_CERT_STATEMENTS: u16 = 39; //5-03
pub const EXT_S_MIME_CAPABILITIES: u16 = 40; //2A 86 48 86 F7 0D 01 09 0F
pub const EXT_TLS_FEATURES: u16 = 41; //5-18
pub const EXT_CHALLENGE_PASSWORD: u16 = 255;
pub fn ext_map(oid: &[u8]) -> Option<u16> {
    match oid {
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, ..] => match oid[9] {
            0x02 => Some(EXT_SCT_LIST),
            0x04 => Some(EXT_PRECERT_SIGNING_CERT),
            _ => None,
        },
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, ..] => match oid[7] {
            0x01 => Some(EXT_AUTH_INFO),
            0x02 => Some(EXT_BIOMETRIC_INFO),
            0x03 => Some(EXT_QUALIFIED_CERT_STATEMENTS),
            0x07 => Some(EXT_IP_RESOURCES),
            0x08 => Some(EXT_AS_RESOURCES),
            0x0B => Some(EXT_SUBJECT_INFO_ACCESS),
            0x18 => Some(EXT_TLS_FEATURES),
            0x1C => Some(EXT_IP_RESOURCES_V2),
            0x1D => Some(EXT_AS_RESOURCES_V2),
            _ => None,
        },
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05] => Some(EXT_OCSP_NO_CHECK),
        [0x2B, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0F] => Some(EXT_S_MIME_CAPABILITIES),
        [0x55, 0x1D, ..] => match oid[2] {
            0x09 => Some(EXT_SUBJECT_DIRECTORY_ATTR),
            0x0E => Some(EXT_SUBJECT_KEY_ID),
            0x0F => Some(EXT_KEY_USAGE),
            0x11 => Some(EXT_SUBJECT_ALT_NAME),
            0x12 => Some(EXT_ISSUER_ALT_NAME),
            0x13 => Some(EXT_BASIC_CONSTRAINTS),
            0x1E => Some(EXT_NAME_CONSTRAINTS),
            0x1F => Some(EXT_CRL_DIST_POINTS),
            0x20 => Some(EXT_CERT_POLICIES),
            0x21 => Some(EXT_POLICY_MAPPINGS),
            0x23 => Some(EXT_AUTH_KEY_ID),
            0x24 => Some(EXT_POLICY_CONSTRAINTS),
            0x25 => Some(EXT_EXT_KEY_USAGE),
            0x2E => Some(EXT_FRESHEST_CRL),
            0x36 => Some(EXT_INHIBIT_ANYPOLICY),
            _ => None,
        },
        _ => None,
    }
}
// C509 Certificate Extended Key Usages Registry
// ======================================================
pub const EKU_TLS_SERVER: u64 = 1;
pub const EKU_TLS_CLIENT: u64 = 2;
pub const EKU_CODE_SIGNING: u64 = 3;
pub const EKU_EMAIL_PROTECTION: u64 = 4;
pub const EKU_TIME_STAMPING: u64 = 8;
pub const EKU_OCSP_SIGNING: u64 = 9;
/* Updated */
pub const EKU_ANY_EKU: u64 = 0; //55 1D 25 00
pub const EKU_KERBEROS_PKINIT_CLIENT_AUTH: u64 = 10; //2B 06 01 05 02 03 04
pub const EKU_KERBEROS_PKINIT_KDC: u64 = 11; //2B 06 01 05 02 03 05
pub const EKU_SSH_CLIENT: u64 = 12; //15
pub const EKU_SSH_SERVER: u64 = 13; //16
pub const EKU_BUNDLE_SECURITY: u64 = 14; //23
pub const EKU_CMC_CERT_AUTHORITY: u64 = 15; //1b
pub const EKU_CMC_REG_AUTHORITY: u64 = 16; //1c
pub const EKU_CMC_ARCHIVE_SERVER: u64 = 17; //1d
pub const EKU_CMC_KEY_GEN_AUTHORITY: u64 = 18; //20
pub fn eku_map(oid: &[u8]) -> Option<u64> {
    match oid {
        [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, ..] => match oid[6] {
            0x04 => Some(EKU_KERBEROS_PKINIT_CLIENT_AUTH),
            0x05 => Some(EKU_KERBEROS_PKINIT_KDC),
            _ => None,
        },
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, ..] => match oid[7] {
            0x01 => Some(EKU_TLS_SERVER),
            0x02 => Some(EKU_TLS_CLIENT),
            0x03 => Some(EKU_CODE_SIGNING),
            0x04 => Some(EKU_EMAIL_PROTECTION),
            0x08 => Some(EKU_TIME_STAMPING),
            0x09 => Some(EKU_OCSP_SIGNING),
            0x15 => Some(EKU_SSH_CLIENT),
            0x16 => Some(EKU_SSH_SERVER),
            0x1b => Some(EKU_CMC_CERT_AUTHORITY),
            0x2c => Some(EKU_CMC_REG_AUTHORITY),
            0x2d => Some(EKU_CMC_ARCHIVE_SERVER),
            0x20 => Some(EKU_CMC_ARCHIVE_SERVER),
            0x23 => Some(EKU_BUNDLE_SECURITY),
            _ => None,
        },
        [0x55, 0x1D, 0x25, 0x00] => Some(EKU_ANY_EKU),
        _ => None,
    }
}
// C509 Certificate Policies Registry
// ======================================================
//TODO: check/test CP_RSP_ROLE_DS_AUTH
pub const CP_ANY_POLICY: i64 = 0;
pub const CP_DOMAIN_VALIDATION: i64 = 1; // DV
pub const CP_ORGANIZATION_VALIDATION: i64 = 2; // OV
pub const CP_INDIVIDUAL_VALIDATION: i64 = 3; // IV
pub const CP_EXTENDED_VALIDATION: i64 = 4; // EV
pub const CP_RESOURCE_PKI: i64 = 7; // RPKI
pub const CP_RESOURCE_PKI_ALT: i64 = 8;
pub const CP_RSP_ROLE_CI: i64 = 10; // Certificate Issuer
pub const CP_RSP_ROLE_EUICC: i64 = 11;
pub const CP_RSP_ROLE_EUM: i64 = 12; // eUICC Manufacturer
pub const CP_RSP_ROLE_DP_TLS: i64 = 13; // SM-DP+ TLS
pub const CP_RSP_ROLE_DP_AUTH: i64 = 14; // SM-DP+ Authentication
pub const CP_RSP_ROLE_DP_PB: i64 = 15; // SM-DP+ Profile Binding
pub const CP_RSP_ROLE_DS_TLS: i64 = 16; // SM-DS TLS
pub const CP_RSP_ROLE_DS_AUTH: i64 = 17; // SM-DS Authentication, 06 07 67 81 12 01 02 01 07
pub fn cp_map(oid: &[u8]) -> Option<i64> {
    match oid {
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0E, ..] => match oid[7..] {
            [0x02] => Some(CP_RESOURCE_PKI),
            [0x03] => Some(CP_RESOURCE_PKI_ALT),
            _ => None,
        },
        [0x55, 0x1D, 0x20, 0x00] => Some(CP_ANY_POLICY),
        [0x67, 0x81, 0x0C, 0x01, ..] => match oid[4..] {
            [0x01] => Some(CP_EXTENDED_VALIDATION),
            [0x02, 0x01] => Some(CP_DOMAIN_VALIDATION),
            [0x02, 0x02] => Some(CP_ORGANIZATION_VALIDATION),
            [0x02, 0x03] => Some(CP_INDIVIDUAL_VALIDATION),
            _ => None,
        },
        [0x67, 0x81, 0x12, 0x01, 0x02, 0x01, ..] => match oid[6..] {
            [0x00] => Some(CP_RSP_ROLE_CI),
            [0x01] => Some(CP_RSP_ROLE_EUICC),
            [0x02] => Some(CP_RSP_ROLE_EUM),
            [0x03] => Some(CP_RSP_ROLE_DP_TLS),
            [0x04] => Some(CP_RSP_ROLE_DP_AUTH),
            [0x05] => Some(CP_RSP_ROLE_DP_PB),
            [0x06] => Some(CP_RSP_ROLE_DS_TLS),
            [0x07] => Some(CP_RSP_ROLE_DS_AUTH),
            _ => None,
        },
        _ => None,
    }
}
// C509 Policies Qualifiers Registry
// ======================================================
pub const PQ_CPS: i64 = 1;
pub const PQ_UNOTICE: i64 = 2;
pub fn pq_map(oid: &[u8]) -> Option<i64> {
    match oid {
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, ..] => match oid[7..] {
            [0x01] => Some(PQ_CPS),
            [0x02] => Some(PQ_UNOTICE),
            _ => None,
        },
        _ => None,
    }
}
// C509 Information Access Registry
// ======================================================
pub const INFO_OCSP: i64 = 1;
pub const INFO_CA_ISSUERS: i64 = 2;
pub const INFO_TIME_STAMPING: i64 = 3;
pub const INFO_CA_REPOSITORY: i64 = 5;
pub const INFO_RPKI_MANIFEST: i64 = 10;
pub const INFO_SIGNED_OBJECT: i64 = 11;
pub const INFO_RPKI_NOTIFY: i64 = 13;
pub fn info_map(oid: &[u8]) -> Option<i64> {
    match oid {
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, ..] => match oid[7..] {
            [0x01] => Some(INFO_OCSP),
            [0x02] => Some(INFO_CA_ISSUERS),
            [0x03] => Some(INFO_TIME_STAMPING),
            [0x05] => Some(INFO_CA_REPOSITORY),
            [0x0A] => Some(INFO_RPKI_MANIFEST),
            [0x0B] => Some(INFO_SIGNED_OBJECT),
            [0x0D] => Some(INFO_RPKI_NOTIFY),
            _ => None,
        },
        _ => None,
    }
}
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/*
Note, about asn1-rs:
Format:
const SOME_STATIC_OID: Oid<'static> = oid!(1.2.456);
Due to limitations with procedural macros and constants used in patterns, you cannot directly use the
oid! macro in patterns. However, you can compare the DER encoded forms directly:
*/
// C509 Certificate Attributes Registry
// ======================================================
pub const ATT_EMAIL_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .9 .1);
pub const ATT_COMMON_NAME_OID: Oid<'static> = oid!(2.5.4 .3);
pub const ATT_SUR_NAME_OID: Oid<'static> = oid!(2.5.4 .4);
pub const ATT_SERIAL_NUMBER_OID: Oid<'static> = oid!(2.5.4 .5);
pub const ATT_COUNTRY_OID: Oid<'static> = oid!(2.5.4 .6);
pub const ATT_LOCALITY_OID: Oid<'static> = oid!(2.5.4 .7);
pub const ATT_STATE_OR_PROVINCE_OID: Oid<'static> = oid!(2.5.4 .8);
pub const ATT_STREET_ADDRESS_OID: Oid<'static> = oid!(2.5.4 .9);
pub const ATT_ORGANIZATION_OID: Oid<'static> = oid!(2.5.4 .10);
pub const ATT_ORGANIZATION_UNIT_OID: Oid<'static> = oid!(2.5.4 .11);
pub const ATT_TITLE_OID: Oid<'static> = oid!(2.5.4 .12);
pub const ATT_BUSINESS_OID: Oid<'static> = oid!(2.5.4 .15);
pub const ATT_POSTAL_CODE_OID: Oid<'static> = oid!(2.5.4 .17);
pub const ATT_GIVEN_NAME_OID: Oid<'static> = oid!(2.5.4 .42);
pub const ATT_INITIALS_OID: Oid<'static> = oid!(2.5.4 .43);
pub const ATT_GENERATION_QUALIFIER_OID: Oid<'static> = oid!(2.5.4 .44);
pub const ATT_DN_QUALIFIER_OID: Oid<'static> = oid!(2.5.4 .46);
pub const ATT_PSEUDONYM_OID: Oid<'static> = oid!(2.5.4 .65);
pub const ATT_ORGANIZATION_IDENTIFIER_OID: Oid<'static> = oid!(2.5.4 .97);
pub const ATT_INC_LOCALITY_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .311 .60 .2 .1 .1);
pub const ATT_INC_STATE_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .311 .60 .2 .1 .2);
pub const ATT_INC_COUNTRY_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .311 .60 .2 .1 .3);
pub const ATT_DOMAIN_COMPONENT_OID: Oid<'static> = oid!(0.9.2342 .19200300 .100 .1 .25);
pub const ATT_POSTAL_ADDRESS_OID: Oid<'static> = oid!(2.5.4 .16);
pub const ATT_NAME_OID: Oid<'static> = oid!(2.5.4 .41);
pub const ATT_TELEPHONE_NUMBER_OID: Oid<'static> = oid!(2.5.4 .20);
pub const ATT_DIR_MAN_DOMAIN_NAME_OID: Oid<'static> = oid!(2.5.4 .54);
pub const ATT_USER_ID_OID: Oid<'static> = oid!(0.9.2342 .19200300 .100 .1 .1);
pub const ATT_UNSTRUCTURED_NAME_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .9 .2);
pub const ATT_UNSTRUCTURED_ADDRESS_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .9 .8);
// X.509 Certificate Extensions Registry
// ======================================================
pub const EXT_SUBJECT_KEY_ID_OID: Oid<'static> = oid!(2.5.29 .14);
pub const EXT_KEY_USAGE_OID: Oid<'static> = oid!(2.5.29 .15);
pub const EXT_SUBJECT_ALT_NAME_OID: Oid<'static> = oid!(2.5.29 .17);
pub const EXT_BASIC_CONSTRAINTS_OID: Oid<'static> = oid!(2.5.29 .19);
pub const EXT_CRL_DIST_POINTS_OID: Oid<'static> = oid!(2.5.29 .31);
pub const EXT_CERT_POLICIES_OID: Oid<'static> = oid!(2.5.29 .32);
pub const EXT_AUTH_KEY_ID_OID: Oid<'static> = oid!(2.5.29 .35);
pub const EXT_EXT_KEY_USAGE_OID: Oid<'static> = oid!(2.5.29 .37);
pub const EXT_AUTH_INFO_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .1);
pub const EXT_SCT_LIST_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .11129 .2 .4 .2);
pub const EXT_SUBJECT_DIRECTORY_ATTR_OID: Oid<'static> = oid!(2.5.29 .9);
pub const EXT_ISSUER_ALT_NAME_OID: Oid<'static> = oid!(2.5.29 .18);
pub const EXT_NAME_CONSTRAINTS_OID: Oid<'static> = oid!(2.5.29 .30);
pub const EXT_POLICY_MAPPINGS_OID: Oid<'static> = oid!(2.5.29 .33);
pub const EXT_POLICY_CONSTRAINTS_OID: Oid<'static> = oid!(2.5.29 .36);
pub const EXT_FRESHEST_CRL_OID: Oid<'static> = oid!(2.5.29 .46);
pub const EXT_INHIBIT_ANYPOLICY_OID: Oid<'static> = oid!(2.5.29 .54);
pub const EXT_SUBJECT_INFO_ACCESS_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .11);
pub const EXT_IP_RESOURCES_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .7);
pub const EXT_AS_RESOURCES_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .8);
pub const EXT_IP_RESOURCES_V2_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .28);
pub const EXT_AS_RESOURCES_V2_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .29);
pub const EXT_BIOMETRIC_INFO_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .2);
pub const EXT_PRECERT_SIGNING_CERT_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .11129 .2 .4 .4);
pub const EXT_OCSP_NO_CHECK_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .1 .5);
pub const EXT_QUALIFIED_CERT_STATEMENTS_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .3);
pub const EXT_S_MIME_CAPABILITIES_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .9 .15);
pub const EXT_TLS_FEATURES_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .24);
pub const EXT_CHALLENGE_PASSWORD_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .2);
// X.509 Certificate Policies Registry
// ======================================================
//TODO: check/test CP_RSP_ROLE_DS_AUTH
pub const CP_ANY_POLICY_OID: Oid<'static> = oid!(2.5.29 .32 .0);
pub const CP_DOMAIN_VALIDATION_OID: Oid<'static> = oid!(2.23.140 .1 .2 .1);
pub const CP_ORGANIZATION_VALIDATION_OID: Oid<'static> = oid!(2.23.140 .1 .2 .2);
pub const CP_INDIVIDUAL_VALIDATION_OID: Oid<'static> = oid!(2.23.140 .1 .2 .3);
pub const CP_EXTENDED_VALIDATION_OID: Oid<'static> = oid!(2.23.140 .1 .1);
pub const CP_RESOURCE_PKI_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .14 .2);
pub const CP_RESOURCE_PKI_ALT_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .14 .3);
pub const CP_RSP_ROLE_CI_OID: Oid<'static> = oid!(2.23.146 .1 .2 .1 .0);
pub const CP_RSP_ROLE_EUICC_OID: Oid<'static> = oid!(2.23.146 .1 .2 .1 .1);
pub const CP_RSP_ROLE_EUM_OID: Oid<'static> = oid!(2.23.146 .1 .2 .1 .2);
pub const CP_RSP_ROLE_DP_TLS_OID: Oid<'static> = oid!(2.23.146 .1 .2 .1 .3);
pub const CP_RSP_ROLE_DP_AUTH_OID: Oid<'static> = oid!(2.23.146 .1 .2 .1 .4);
pub const CP_RSP_ROLE_DP_PB_OID: Oid<'static> = oid!(2.23.146 .1 .2 .1 .5);
pub const CP_RSP_ROLE_DS_TLS_OID: Oid<'static> = oid!(2.23.146 .1 .2 .1 .6);
pub const CP_RSP_ROLE_DS_AUTH_OID: Oid<'static> = oid!(2.23.146 .1 .2 .1 .7);
// X.5509 Policies Qualifiers Registry
// ======================================================
pub const PQ_CPS_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .2 .1);
pub const PQ_UNOTICE_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .2 .2);
// X.509 Information Access Registry
// ======================================================
pub const INFO_OCSP_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .1);
pub const INFO_CA_ISSUERS_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .2);
pub const INFO_TIME_STAMPING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .3);
pub const INFO_CA_REPOSITORY_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .5);
pub const INFO_RPKI_MANIFEST_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .10);
pub const INFO_SIGNED_OBJECT_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .11);
pub const INFO_RPKI_NOTIFY_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .13);
// X.509 Certificate Extended Key Usages Registry
// ======================================================
pub const EKU_ANY_EKU_OID: Oid<'static> = oid!(2.5.29 .37 .0);
pub const EKU_TLS_SERVER_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .1);
pub const EKU_TLS_CLIENT_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .2);
pub const EKU_CODE_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .3);
pub const EKU_EMAIL_PROTECTION_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .4);
pub const EKU_TIME_STAMPING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .8);
pub const EKU_OCSP_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .9);
pub const EKU_KERBEROS_PKINIT_CLIENT_AUTH_OID: Oid<'static> = oid!(1.3.6 .1 .5 .2 .3 .4);
pub const EKU_KERBEROS_PKINIT_KDC_OID: Oid<'static> = oid!(1.3.6 .1 .5 .2 .3 .5);
pub const EKU_SSH_CLIENT_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .21);
pub const EKU_SSH_SERVER_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .22);
pub const EKU_BUNDLE_SECURITY_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .35);
pub const EKU_CMC_CERT_AUTHORITY_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .27);
pub const EKU_CMC_REG_AUTHORITY_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .28);
pub const EKU_CMC_ARCHIVE_SERVER_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .29);
pub const EKU_CMC_KEY_GEN_AUTHORITY_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .32);
// X.509 General Names Registry
// ======================================================
pub const OTHER_NAME_WITH_HW_MODULE_NAME_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .8 .4);
// X.509 Certificate Signature Algorithms Registry
// ======================================================
pub const SIG_RSA_V15_SHA1_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .5); //Don't use
pub const SIG_ECDSA_SHA1_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .1); //Don't use
pub const SIG_ECDSA_SHA256_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .2);
pub const SIG_ECDSA_SHA384_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .3);
pub const SIG_ECDSA_SHA512_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .4);
pub const SIG_ECDSA_SHAKE128_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .6 .32);
pub const SIG_ECDSA_SHAKE256_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .6 .33);
pub const SIG_ED25519_OID: Oid<'static> = oid!(1.3.101 .112);
pub const SIG_ED448_OID: Oid<'static> = oid!(1.3.101 .113);
pub const SIG_SHA256_HMAC_SHA256_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .6 .26);
pub const SIG_SHA384_HMAC_SHA384_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .6 .27);
pub const SIG_SHA512_HMAC_SHA512_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .6 .28);
pub const SIG_RSA_V15_SHA256_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .11);
pub const SIG_RSA_V15_SHA384_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .12);
pub const SIG_RSA_V15_SHA512_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .13);
pub const SIG_RSA_PSS_SHA256_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .10); //TODO, param
pub const SIG_RSA_PSS_SHA384_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .10); //TODO, param
pub const SIG_RSA_PSS_SHA512_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .11); //TODO, param
pub const SIG_RSA_PSS_SHAKE128_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .6 .30);
pub const SIG_RSA_PSS_SHAKE256_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .6 .31);
pub const SIG_HSS_LMS_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .9 .16 .3 .17);
pub const SIG_XMSS_OID: Oid<'static> = oid!(0.4.0 .127 .0 .15 .1 .1 .13 .0);
pub const SIG_XMSS_MT_OID: Oid<'static> = oid!(0.4.0 .127 .0 .15 .1 .1 .14 .0);
pub const SIG_SM2_V15_SM3_OID: Oid<'static> = oid!(1.2.156 .10197 .1 .501);
// X.509 Certificate Public Key Algorithms Registry
// Ongoing / still TODO: find test certs for PK_SM2P256V1
// ======================================================
pub const PK_RSA_ENC_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .1);
pub const PK_SECP256R_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
pub const PK_SECP256R_PARAM_OID: Oid<'static> = oid!(1.2.840 .10045 .3 .1 .7);
pub const PK_SECP384R_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
pub const PK_SECP384R_PARAM_OID: Oid<'static> = oid!(1.3.132 .0 .34);
pub const PK_SECP521R_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
pub const PK_SECP521R_PARAM_OID: Oid<'static> = oid!(1.3.132 .0 .35);
pub const PK_X25519_OID: Oid<'static> = oid!(1.3.101 .110);
pub const PK_X448_OID: Oid<'static> = oid!(1.3.101 .111);
pub const PK_ED25519_OID: Oid<'static> = oid!(1.3.101 .112);
pub const PK_ED448_OID: Oid<'static> = oid!(1.3.101 .113);
pub const PK_HSS_LMS_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .9 .16 .3 .17);
pub const PK_XMSS_OID: Oid<'static> = oid!(0.4.0 .127 .0 .15 .1 .1 .13 .0);
pub const PK_XMSS_MT_OID: Oid<'static> = oid!(0.4.0 .127 .0 .15 .1 .1 .14 .0);
pub const PK_BRAINPOOL256R1_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
pub const PK_BRAINPOOL256R1_PARAM_OID: Oid<'static> = oid!(1.3.36 .3 .3 .2 .8 .1 .1 .7);
pub const PK_BRAINPOOL384R1_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
pub const PK_BRAINPOOL384R1_PARAM_OID: Oid<'static> = oid!(1.3.36 .3 .3 .2 .8 .1 .1 .11);
pub const PK_BRAINPOOL512R1_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
pub const PK_BRAINPOOL512R1_PARAM_OID: Oid<'static> = oid!(1.3.36 .3 .3 .2 .8 .1 .1 .13);
pub const PK_FRP256V1_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
pub const PK_FRP256V1_PARAM_OID: Oid<'static> = oid!(1.2.250 .1 .223 .101 .256 .1);
pub const PK_SM2P256V1_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
pub const PK_SM2P256V1_PARAM_OID: Oid<'static> = oid!(1.2.156 .10197 .1 .301);
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
// Parse a HEX encoded C509 and encode it as X.509
fn parse_c509_cert(input: Vec<u8>, is_str: bool) -> Cert {
    let bytes = {
        if is_str == true {
            match hex::decode(input) {
                Ok(b) => {
                    debug!("Decoded bytes: {:x?}", b);
                    b
                }
                Err(err) => {
                    eprintln!("Error decoding hex string: {}", err);
                    Vec::new()
                }
            }
        } else {
            input
        }
    };
    //let input = raw_input.insert(0, 0x8b);
    let empty_vec: Vec<Value> = Vec::new();
    let x509_certificate: Vec<u8>;
    let mut certificate_vec: Vec<Vec<u8>> = Vec::new();
    let mut tbs_cert_vec: Vec<Vec<u8>> = Vec::new();
    let dummy: Vec<Vec<u8>> = Vec::new();

    let cursor = Cursor::new(bytes);
    match serde_cbor::de::from_reader(cursor) {
        Ok(value) => {
            if let Value::Array(elements) = value {
                debug!("CBOR array contains {} elements", elements.len());
                //We expect the elements to follow the order given by the C509 CDDL format
                //The first value should be an integer, representing the type/version
                trace!("Element: {:?}", elements[0]);
                match elements[0] {
                    Value::Integer(version) => {
                        debug!("Type with CBOR integer value: {}", version); // {}", i);
                        if version != C509_TYPE_X509_ENCODED as i128 {
                            panic!("The version value can only handle certs of type {}", C509_TYPE_X509_ENCODED);
                        }
                        tbs_cert_vec.push(ASN1_X509_VERSION_3.to_vec());
                    }
                    _ => {
                        panic!("The version value is not an integer.");
                    }
                }
                //The second value should be a byte array, representing the serialNumber
                let serial_number = match &elements[1] {
                    Value::Bytes(b) => b,
                    _ => {
                        panic!("The value of the serial number is not a byte array.");
                    }
                };

                let bytes = &&(**serial_number); //TODO: reformat, eventually
                let parsed_serial_number = lder_to_pos_int(bytes.to_vec());
                debug!("Done parsing serial number;\n{:02x?}", parsed_serial_number);
                //std::process::exit(0);
                tbs_cert_vec.push(parsed_serial_number);

                //Please note that in the reconstructed X.509 the third element is the "signature AlgorithmIdentifier"
                let (sig_alg, sig_val) = parse_cbor_sig_info(&elements[2], &elements[10]);
                debug!("Done parsing sig_alg & sig_val: {:02x?}", sig_val);
                tbs_cert_vec.push(sig_alg.clone());

                //The fourth value in the cbor array should be the issuer
                let issuer = parse_cbor_name(&elements[3], &empty_vec);
                debug!("Done parsing issuer;\n{:02x?}", issuer);
                tbs_cert_vec.push(issuer);

                //The fifth and sixth values should be the val.period
                let (not_before, not_before_int) = parse_cbor_time(&elements[4]);
                let validity: Vec<u8> = lder_to_two_seq(not_before, parse_cbor_time(&elements[5]).0);
                debug!("Done parsing validity time:\n{:02x?}", validity);
                tbs_cert_vec.push(validity);

                //The seventh value should be the cbor encoded subject
                let subject = parse_cbor_name(&elements[6], &empty_vec);
                debug!("Done parsing subject: {:02x?}", subject);
                tbs_cert_vec.push(subject);

                //The eighth value should be the subjectPublicKeyAlgorithm -- which in the reconstructed X.509 is combined inside the subjectPublicKeyInfo
                let (subject_pka, subject_pka_oid) = map_pk_id_to_oid(&elements[7]);
                let spka = lder_to_generic(subject_pka_oid, ASN1_SEQ);
                debug!("Done parsing subject_pka:\n{:02x?}", spka);
                //The ninth value should be the subjectPublicKey
                let subject_pub_key_info = parse_cbor_pub_key(&elements[8], subject_pka.unwrap());
                debug!("Done parsing subject_pub_key_info: {:02x?}", subject_pub_key_info);
                tbs_cert_vec.push(subject_pub_key_info);

                //issuerUniqueID + subjectUniqueID. -- Not supported in current draft
                //The tenth value should be the extension / ext.array
                let extensions = parse_cbor_extensions(&elements[9], not_before_int);
                trace!("Done parsing extensions: {:02x?}", extensions);

                tbs_cert_vec.push(extensions);

                let ccopy = lder_to_seq(tbs_cert_vec);

                certificate_vec.push(ccopy);
                //time to add the sign.algorithm - again, but this time to the outer asn1.seq
                certificate_vec.push(sig_alg);
                //... and the actual reconstructed signature
                certificate_vec.push(sig_val);

            /*
            What to reverse for issuerSignatureValue:
            Encoding of issuerSignatureValue
            If the two INTEGER value fields have different lengths, the shorter INTEGER value field is padded with
            zeroes so that the two fields have the same length. The resulting byte string is encoded as a CBOR byte string.
            For ECDSA signatures, the SEQUENCE and INTEGER type and length fields as well as the any leading 0x00 byte
            (to indicate that the number is not negative) are omitted. If the two INTEGER value fields have different
            lengths, the shorter INTEGER value field is padded with zeroes so that the two fields have the same length.
            The resulting byte string is encoded as a CBOR byte string.
            */
            } else {
                panic!("The value is not a CBOR array.");
            }
        }
        Err(err) => {
            eprintln!("Error decoding CBOR data: {}", err);
        }
    }
    x509_certificate = lder_to_seq(certificate_vec);
    info!("Done reconstructing X.509! Size is {}", x509_certificate.len());

    Cert { der: x509_certificate, cbor: dummy }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//Comment, the OID-parsing could happen anywhere
pub fn map_pk_id_to_oid(input: &Value) -> (Option<i64>, Vec<u8>) {
    trace!("map_pk_id_to_oid, parsing {:?}", input);
    //  Some(42)
    match input {
        Value::Integer(alg_id) => match *alg_id as i64 {
            PK_RSA_ENC => (Some(PK_RSA_ENC), lder_to_generic(PK_RSA_ENC_OID.as_bytes().to_vec(), ASN1_OID).clone()),
            PK_SECP256R => (Some(PK_SECP256R), lder_to_generic(PK_SECP256R_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_SECP384R => (Some(PK_SECP384R), lder_to_generic(PK_SECP384R_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_SECP521R => (Some(PK_SECP521R), lder_to_generic(PK_SECP521R_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_X25519 => (Some(PK_X25519), lder_to_generic(PK_X25519_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_X448 => (Some(PK_X448), lder_to_generic(PK_X448_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_ED25519 => (Some(PK_ED25519), lder_to_generic(PK_ED25519_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_ED448 => (Some(PK_ED448), lder_to_generic(PK_ED448_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_HSS_LMS => (Some(PK_HSS_LMS), lder_to_generic(PK_HSS_LMS_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_XMSS => (Some(PK_XMSS), lder_to_generic(PK_XMSS_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_XMSS_MT => (Some(PK_XMSS_MT), lder_to_generic(PK_XMSS_MT_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_BRAINPOOL256R1 => (Some(PK_BRAINPOOL256R1), lder_to_generic(PK_BRAINPOOL256R1_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_BRAINPOOL384R1 => (Some(PK_BRAINPOOL384R1), lder_to_generic(PK_BRAINPOOL384R1_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_BRAINPOOL512R1 => (Some(PK_BRAINPOOL512R1), lder_to_generic(PK_BRAINPOOL512R1_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_FRP256V1 => (Some(PK_FRP256V1), lder_to_generic(PK_FRP256V1_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_SM2P256V1 => (Some(PK_SM2P256V1), lder_to_generic(PK_SM2P256V1_OID.as_bytes().to_vec(), ASN1_OID)),
            _ => panic!("Unknown pk type: {}", alg_id),
        },
        _ => panic!("Could not parse pk type"),
    }
    //(None, Vec::new())
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
static EUI_64_CHUNK: &str = "-FF-FE";
fn parse_cbor_eui64(cn: &[u8]) -> Vec<u8> {
    trace!("parse_cbor_eui64, input: {:x?}", cn);
    let mut my_string: String = String::from("");
    for i in 0..cn.len() {
        my_string.push_str(&format!("{:02X}", cn[i]));
        if i == 2 && cn.len() == 6 {
            my_string.push_str(EUI_64_CHUNK);
        }
        if i < cn.len() - 1 {
            my_string.push('-');
        }
    }
    debug!("parse_cbor_eui64: {:x?}", my_string);
    my_string.into_bytes()
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_name<'a>(input: &'a Value, _empty_vec: &'a Vec<Value>) -> Vec<u8> {
    trace!("parse_cbor_name, incoming value: {:x?}", input);
    let mut result_vec = Vec::new();

    match input {
        Value::Text(name) => {
            trace!("CBOR name: {:x?}", name);
            let cn = name.as_bytes();

            let attr_type_and_val = lder_to_two_seq(ATT_COMMON_NAME_OID.to_der_vec().unwrap(), lder_to_generic(cn.to_vec(), ASN1_UTF8_STR));
            result_vec.push(lder_to_generic(attr_type_and_val, ASN1_SET));
        }
        Value::Bytes(b) => {
            trace!("CBOR bytes: {:x?}", b);
            let cn = match b[0] {
                0x00 => parse_cbor_eui64(&b[1..b.len()]),
                0x01 => parse_cbor_eui64(&b[1..b.len()]),
                _ => panic!("Unknown Name format'"),
            };
            let attr_type_and_val = lder_to_two_seq(ATT_COMMON_NAME_OID.to_der_vec().unwrap(), lder_to_generic(cn, ASN1_UTF8_STR));
            result_vec.push(lder_to_generic(attr_type_and_val, ASN1_SET));
        }
        Value::Array(name_elements) => {
            for i in (0..name_elements.len()).step_by(2) {
                let attr_type_and_val = match name_elements[i] {
                    Value::Integer(attribute) => {
                        trace!("parse_cbor_name, CBOR int: {}", attribute);
                        let (oid, tag) = match attribute.abs() as u32 {
                            ATT_EMAIL => (ATT_EMAIL_OID, ASN1_IA5_SRT),
                            ATT_COMMON_NAME => (ATT_COMMON_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_SUR_NAME => (ATT_SUR_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_SERIAL_NUMBER => (ATT_SERIAL_NUMBER_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_COUNTRY => (ATT_COUNTRY_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_LOCALITY => (ATT_LOCALITY_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_STATE_OR_PROVINCE => (ATT_STATE_OR_PROVINCE_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_STREET_ADDRESS => (ATT_STREET_ADDRESS_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_ORGANIZATION => (ATT_ORGANIZATION_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_ORGANIZATION_UNIT => (ATT_ORGANIZATION_UNIT_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_TITLE => (ATT_TITLE_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_BUSINESS => (ATT_BUSINESS_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_POSTAL_CODE => (ATT_POSTAL_CODE_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_GIVEN_NAME => (ATT_GIVEN_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_INITIALS => (ATT_INITIALS_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_DN_QUALIFIER => (ATT_DN_QUALIFIER_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_ORGANIZATION_IDENTIFIER => (ATT_ORGANIZATION_IDENTIFIER_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_INC_LOCALITY => (ATT_INC_LOCALITY_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_INC_STATE => (ATT_INC_STATE_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_INC_COUNTRY => (ATT_INC_COUNTRY_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_DOMAIN_COMPONENT => (ATT_DOMAIN_COMPONENT_OID, ASN1_IA5_SRT),
                            ATT_POSTAL_ADDRESS => (ATT_POSTAL_ADDRESS_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_NAME => (ATT_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_TELEPHONE_NUMBER => (ATT_TELEPHONE_NUMBER_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_DIR_MAN_DOMAIN_NAME => (ATT_DIR_MAN_DOMAIN_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_USER_ID => (ATT_USER_ID_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_UNSTRUCTURED_NAME => (ATT_UNSTRUCTURED_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_UNSTRUCTURED_ADDRESS => (ATT_UNSTRUCTURED_ADDRESS_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),

                            _ => panic!("Unknown attribute format: {}", attribute),
                        };
                        let value = match &name_elements[i + 1] {
                            Value::Text(text_value) => text_value.as_bytes(),
                            _ => panic!("Unknown attribute value format'"),
                        };
                        lder_to_two_seq(oid.to_der_vec().unwrap(), lder_to_generic(value.to_vec(), tag))

                    }
                    _ => panic!("Unknown attribute format'"),
                };

                result_vec.push(lder_to_generic(attr_type_and_val, ASN1_SET));
            }
        }
        _ => {
            panic!("Unknown RelativeDistinguishedName value.");
        }
    };
    lder_to_seq(result_vec)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
Warning, CURRENTLY KNOWN BUG:
*/
fn parse_cbor_time(input: &Value) -> (Vec<u8>, i64) {
    // Format DateTime as "%Y%m%d%H%M%SZ"
    //let formatted_date = dt.format("%Y%m%d%H%M%SZ").to_string();
    let mut type_flag = ASN1_UTC_TIME;
    let (formatted_date, time_val) = match input {
        Value::Integer(val) => {

            trace!("parse_cbor_time, incoming ts: {}", *val);
            let ts = chrono::TimeZone::timestamp(&chrono::Utc, *val as i64, 0);
            if ASN1_UTC_TIME_MAX < *val as i64 {
                type_flag = ASN1_GEN_TIME;
                //using four digit year format to match GEN time format
                (ts.format("%Y%m%d%H%M%SZ").to_string(), *val)
            } //else if (*val as i64) < ASN1_UTC_TIME_Y2K {            panic!("Unresolved pre 2000 date handling bug, aborting");            }
            else {
                //using two digit year format to match UTC time format
                (ts.format("%y%m%d%H%M%SZ").to_string(), *val)
            }
        }
        Value::Null => {
            debug!("parse_cbor_time, found CBOR NULL");
            type_flag = ASN1_GEN_TIME;
            (ASN1_GEN_TIME_MAX.to_string(), 0)
        }
        _ => {
            panic!("Unknown time value.");
        }
    };
    trace!("parse_cbor_time custom format: {}", formatted_date);
    (lder_to_time(formatted_date, type_flag), time_val as i64)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
pub fn parse_cbor_pub_key(pub_key: &Value, key_type: i64) -> Vec<u8> {
    //  Some(42)

    let mut pub_key_vec= Vec::new();
    let mut result = Vec::new();
    match pub_key {
        Value::Bytes(pub_key_array) => {
            pub_key_vec = pub_key_array.to_vec();
            //Good
        }
        _ => debug!("parse_cbor_pub_key received key in non-byte format {:?}", pub_key),
    }

    let dummy = {
        match key_type {
            PK_RSA_ENC => {
                result.push(lder_to_two_seq(lder_to_generic(PK_RSA_ENC_OID.as_bytes().to_vec(), ASN1_OID), ASN1_NULL.to_vec()));
                check_and_reconstruct_pub_key_rsa(pub_key, PK_RSA_ENC)
            }
            PK_SECP256R => {
                result.push(lder_to_two_seq(lder_to_generic(PK_SECP256R_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_SECP256R_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_SECP256R)
            }
            PK_SECP384R => {
                result.push(lder_to_two_seq(lder_to_generic(PK_SECP384R_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_SECP384R_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_SECP384R)
            }
            PK_SECP521R => {
                result.push(lder_to_two_seq(lder_to_generic(PK_SECP521R_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_SECP521R_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_SECP521R)
            }
            PK_X25519 => {
                result.push(lder_to_generic(lder_to_generic(PK_X25519_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_X25519)
            }
            PK_X448 => {
                result.push(lder_to_generic(lder_to_generic(PK_X448_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_X448)
            }
            PK_ED25519 => {
                result.push(lder_to_generic(lder_to_generic(PK_ED25519_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_ED25519)
            }
            PK_ED448 => {
                result.push(lder_to_generic(lder_to_generic(PK_ED448_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_ED448)
            }
            PK_HSS_LMS => {
                result.push(lder_to_generic(lder_to_generic(PK_HSS_LMS_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_mac(pub_key_vec, PK_HSS_LMS)
            }
            PK_XMSS => {
                result.push(lder_to_generic(lder_to_generic(PK_XMSS_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_mac(pub_key_vec, PK_XMSS)
            }
            PK_XMSS_MT => {
                result.push(lder_to_generic(lder_to_generic(PK_XMSS_MT_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_mac(pub_key_vec, PK_XMSS_MT)
            }
            PK_BRAINPOOL256R1 => {
                result.push(lder_to_two_seq(lder_to_generic(PK_BRAINPOOL256R1_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_BRAINPOOL256R1_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_BRAINPOOL256R1)
            }
            PK_BRAINPOOL384R1 => {
                result.push(lder_to_two_seq(lder_to_generic(PK_BRAINPOOL384R1_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_BRAINPOOL384R1_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_BRAINPOOL384R1)
            }
            PK_BRAINPOOL512R1 => {
                result.push(lder_to_two_seq(lder_to_generic(PK_BRAINPOOL512R1_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_BRAINPOOL512R1_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_BRAINPOOL512R1)
            }
            PK_FRP256V1 => {
                result.push(lder_to_two_seq(lder_to_generic(PK_FRP256V1_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_FRP256V1_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_FRP256V1)
            }
            PK_SM2P256V1 => {
                result.push(lder_to_two_seq(lder_to_generic(PK_SM2P256V1_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_SM2P256V1_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_SM2P256V1)
            }
            _ => {
                panic!("Could not parse public key");
            }
        }
    }; //end of let dummy
    result.push(dummy);
    lder_to_seq(result)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn check_and_reconstruct_pub_key_ecc(pub_key: Vec<u8>, ecc_type_id: i64) -> Vec<u8> {
    let mut result = Vec::new();

    match pub_key.get(0).unwrap() as &u8 {
        &SECG_EVEN_COMPRESSED => {
            result.push(SECG_UNCOMPRESSED);
            result.extend_from_slice(&pub_key[1..pub_key.len()]);
            result.extend(decompress_ecc_key(pub_key[1..pub_key.len()].to_vec(), true, ecc_type_id));
        }
        &SECG_ODD_COMPRESSED => {
            result.push(SECG_UNCOMPRESSED);
            result.extend_from_slice(&pub_key[1..pub_key.len()]);
            result.extend(decompress_ecc_key(pub_key[1..pub_key.len()].to_vec(), false, ecc_type_id));
        }
        &SECG_EVEN | &SECG_ODD => result = pub_key, //dontdostuff, just return the key input for now

        _ => panic!("Expected public key to start with a compression indicator, but it started with {:?}", pub_key.get(0)),
    }

    //  if <criteria> TODO  result.insert(0, 0x00);
    lder_to_bit_str(result)
}

//https://github.com/RustCrypto/elliptic-curves/
fn decompress_ecc_key(pub_key_x: Vec<u8>, is_even: bool, ecc_type_id: i64) -> Vec<u8> {
    //let public_key = PublicKey::from_slice(pub_key_input.as_slice()).expect("Can only handle public keys of len 33 or 65 bytes, serialized according to SEC 2");
    //public_key.serialize_uncompressed().to_vec()
    //P-256
    //y^2 ≡ x^3+ax+b
    // let ms = { if is_even == true { Sign::Plus } else { Sign::Minus } };
    let x = BigInt::from_bytes_be(Sign::Plus, &pub_key_x);
    let mc = {
        match ecc_type_id {
            PK_SECP256R => ECCCurve {
                p: BigInt::parse_bytes(b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16).unwrap(),
                a: BigInt::parse_bytes(b"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16).unwrap(),
                b: BigInt::parse_bytes(b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16).unwrap(),
                l: 32,
            },
            PK_SECP384R => {
                //https://neuromancer.sk/std/secg/secp384r1
                ECCCurve {
                    p: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16).unwrap(),
                    a: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16).unwrap(),
                    b: BigInt::parse_bytes(b"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16).unwrap(),
                    l: 48,
                }
            }
            PK_SECP521R => {
                //https://neuromancer.sk/std/secg/secp384r1
                ECCCurve {
                    p: BigInt::parse_bytes(b"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
                    a: BigInt::parse_bytes(b"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", 16).unwrap(),
                    b: BigInt::parse_bytes(b"0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16).unwrap(),
                    l: 64,
                }
            }
            _ => panic!("Cannot handle ECC curve of type {}", ecc_type_id),
        }
    };
    //let big_int = &&x;
    let y2 = (pow(x.clone(), 3) + &mc.a * &x.clone() + &mc.b) % &mc.p;
    let mut y = y2.modpow(&((&mc.p + BigInt::one()) / BigInt::from(4)), &mc.p);

    let y_is_even = y.clone() % 2 == BigInt::zero();
    //  let mut ys = y.clone();
    //let mut y_inv = y.clone();

    //  if (y[y.len() - 1] & 1 == 0 && is_even == false) || y[y.len() - 1] & 1 == 1 && is_even == true {
    if y_is_even != is_even {
        y = &mc.p - &y;
        trace!("decompress_ecc_key: inverting y!");
    }
    //let mut y_inv = &mc.p-&y;
    //let y_inv = &mc.p-&y;
    let (_, mut yb) = y.to_bytes_be();

    if yb.len() < mc.l { //TODO: currently assuming only one leading 0
        yb.insert(0, 0);
    } 
    trace!("decompress_ecc_key: resulting y:\n{:02x?}", yb);
    yb
    //std::process::exit(0);
}

//***************************************************************************************************************************************

fn check_and_reconstruct_pub_key_rsa(pub_key: &Value, _key_id: i64) -> Vec<u8> {
    let modulus;
    let exponent;

    match pub_key {
        Value::Array(pub_key_arr) => {
            assert!(pub_key_arr.len() == 2, "Public key must have two components");
            modulus = lder_to_pos_int(get_as_bytes(pub_key_arr.get(0).unwrap()));
            exponent = lder_to_pos_int(get_as_bytes(pub_key_arr.get(1).unwrap()));
        }
        Value::Bytes(pub_key_mod_only) => {
            //  let my_integer = Integer::from_bytes_be(pub_key_mod_only);
            modulus = lder_to_pos_int(pub_key_mod_only.to_vec());
            exponent = ASN1_65537.to_vec();
        }
        _ => {
            panic!("Could not decode rsa pub key: {:?}", pub_key);
        }
    }
    lder_to_bit_str(lder_to_two_seq(modulus, exponent))
}
fn check_and_reconstruct_pub_key_mac(_pub_key: Vec<u8>, _key_id: i64) -> Vec<u8> {
    panic!("Reconstruction of mac based pub keys not yet supported");
}

//***************************************************************************************************************************************
//***************************************************************************************************************************************

//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_extensions(input: &Value, ts_offset: i64) -> Vec<u8> {
    //let mut parsed_extensions = Vec::new();
    let mut parsed_extensions_arr = Vec::new();
    match input {
        Value::Integer(val) => {
            trace!("parse_cbor_extensions, received CBOR int: {:x?}", val);
            parsed_extensions_arr.push(parse_cbor_ext_key_usage(input, *val < 0));
        }
        Value::Array(extension_array) => {
            //trace!("CBOR array: {:x?}", extension_array);
            for i in (0..extension_array.len()).step_by(2) {
                //trace!("Current values: {} {:?} {:?}", i, extension_array[i], extension_array[i+1]);
                parsed_extensions_arr.push({
                    match &extension_array[i] {
                        Value::Integer(ext_type) => {
                            trace!("parse_cbor_extensions, found ext of int type {}", ext_type);
                            match (ext_type.abs()) as u16 {
                                EXT_SUBJECT_KEY_ID => {
                                    let dummy = parse_cbor_ext_subject_key_id(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_SUBJECT_KEY_ID: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_KEY_USAGE => {
                                    let dummy = parse_cbor_ext_key_usage(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_KEY_USAGE: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_SUBJECT_ALT_NAME => {
                                    let dummy = parse_cbor_ext_subject_alt_name(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_SUBJECT_ALT_NAME size: {}", dummy.len());
                                    dummy
                                }
                                EXT_BASIC_CONSTRAINTS => {
                                    let dummy = parse_cbor_ext_basic_constraints(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_BASIC_CONSTRAINTS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_CRL_DIST_POINTS => {
                                    let dummy = parse_cbor_ext_crl_dist_points(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_CRL_DIST_POINTS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_CERT_POLICIES => {
                                    let dummy = parse_cbor_ext_cert_policies(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_CERT_POLICIES: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_AUTH_KEY_ID => {
                                    let dummy = parse_cbor_ext_auth_key_id(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_AUTH_KEY_ID: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_EXT_KEY_USAGE => {
                                    let dummy = parse_cbor_ext_ext_key_usage(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_EXT_KEY_USAGE: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_AUTH_INFO => {
                                    let dummy = parse_cbor_ext_auth_info(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_AUTH_INFO: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_SCT_LIST => {
                                    let dummy = parse_cbor_ext_sct_list(&extension_array[i + 1], *ext_type < 0, ts_offset);
                                    debug!("parse_cbor_extensions, EXT_SCT_LIST: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_SUBJECT_DIRECTORY_ATTR => {
                                    let dummy = parse_cbor_ext_subject_directory_attr(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_SUBJECT_DIRECTORY_ATTR: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_ISSUER_ALT_NAME => {
                                    let dummy = parse_cbor_ext_issuer_alt_name(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_ISSUER_ALT_NAME: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_NAME_CONSTRAINTS => {
                                    let dummy = parse_cbor_ext_name_constraints(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_NAME_CONSTRAINTS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_POLICY_MAPPINGS => {
                                    let dummy = parse_cbor_ext_policy_mappings(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_POLICY_MAPPINGS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_POLICY_CONSTRAINTS => {
                                    let dummy = parse_cbor_ext_policy_constraints(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_POLICY_CONSTRAINTS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_FRESHEST_CRL => {
                                    let dummy = parse_cbor_ext_freshest_crl(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_FRESHEST_CRL: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_INHIBIT_ANYPOLICY => {
                                    let dummy = parse_cbor_ext_inhibit_anypolicy(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_INHIBIT_ANYPOLICY: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_SUBJECT_INFO_ACCESS => {
                                    let dummy = parse_cbor_ext_subject_info_access(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_SUBJECT_INFO_ACCESS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_IP_RESOURCES => {
                                    let dummy = parse_cbor_ext_ip_resources(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_IP_RESOURCES: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_AS_RESOURCES => {
                                    let dummy = parse_cbor_ext_as_resources(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_AS_RESOURCES: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_IP_RESOURCES_V2 => {
                                    let dummy = parse_cbor_ext_ip_resources_v2(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_IP_RESOURCES_V2: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_AS_RESOURCES_V2 => {
                                    let dummy = parse_cbor_ext_as_resources_v2(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_AS_RESOURCES_V2: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_BIOMETRIC_INFO => {
                                    let dummy = parse_cbor_ext_biometric_info(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_BIOMETRIC_INFO: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_PRECERT_SIGNING_CERT => {
                                    let dummy = parse_cbor_ext_precert_signing_cert(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_PRECERT_SIGNING_CERT: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_OCSP_NO_CHECK => {
                                    let dummy = parse_cbor_ext_ocsp_no_check(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_OCSP_NO_CHECK: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_QUALIFIED_CERT_STATEMENTS => {
                                    let dummy = parse_cbor_ext_qualified_cert_statements(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_QUALIFIED_CERT_STATEMENTS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_S_MIME_CAPABILITIES => {
                                    let dummy = parse_cbor_ext_s_mime_capabilities(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_S_MIME_CAPABILITIES: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_TLS_FEATURES => {
                                    let dummy = parse_cbor_ext_tls_features(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_TLS_FEATURES: {:02x?}", dummy);
                                    dummy
                                }
                                _ => panic!("Ext type {} out of scope!", ext_type),
                            }
                        }
                        Value::Bytes(raw_ext_type_oid) => {
                            let this_oid = lder_to_generic(raw_ext_type_oid.to_vec(), ASN1_OID);
                            let ext_val = match &extension_array[i + 1] {
                            //assuming the ext.value = next item in the array is also byte encoded
                              Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
                                _ => panic!("Error parsing value: {:?}.", extension_array[i + 1]),
                              };
                            let dummy = lder_to_two_seq(this_oid, ext_val);
                            debug!("parse_cbor_extensions, EXT OF BYTE TYPE {:02x?}", dummy);
                            dummy
                        }
                        _ => panic!("Unknown ext type: {:?}.", extension_array[i]),
                    }
                });
            }
        }
        _ => {
            panic!("Unknown ext value: {:?}.", input);
        }
    }
    lder_to_generic(lder_to_seq(parsed_extensions_arr), ASN1_INDEX_THREE)
    //parsed_extensions
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
pub fn parse_cbor_sig_alg(sig_alg: &Value) -> (Vec<u8>, i32) {

  println!("sig alg input: {:x?}", sig_alg);
  match sig_alg {
  Value::Integer(alg_id) => {
  match alg_id {
    0 => ([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00].to_vec(), (*alg_id as i32)),
    1 => (vec![0;0], (*alg_id as i32)),
    _ => panic!("Unknown pk type: {}", alg_id),
  }
  },
  Value::Array(raw_oid) => {
  panic!("not now")
  },
  _ => panic!("Could not parse sig alg"),
  }
}
*/
//***************************************************************************************************************************************
//***************************************************************************************************************************************
pub fn parse_cbor_sig_info(sig_alg: &Value, sig_val: &Value) -> (Vec<u8>, Vec<u8>) {
    trace!("parse_cbor_sig_info input: {:x?}", sig_alg);
    //let mut result: Vec<Vec<u8>> = Vec::new();
    let mut oid;

    let sig_val_vec: Vec<u8> = match sig_val {
        Value::Bytes(sig_val_bytes) => sig_val_bytes.to_vec(),
        _ => panic!("Could not parse sig val"),
    };
    let parsed_sig_val ;
    let mut param = Vec::new();

    match sig_alg {
        Value::Integer(sign_alg_id) => {
            trace!("parse_cbor_sig_info, working with sign alg_id {}", sign_alg_id);
            match *sign_alg_id as i64 {
                SIG_RSA_V15_SHA1 => {
                    oid = SIG_RSA_V15_SHA1_OID.as_bytes().to_vec(); //TODO check param
                    param = ASN1_NULL.to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                }
                SIG_ECDSA_SHA1 => {
                    oid = SIG_ECDSA_SHA1_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                }
                SIG_ECDSA_SHA256 => {
                    oid = SIG_ECDSA_SHA256_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                    //  panic!("not now");
                }
                SIG_ECDSA_SHA384 => {
                    oid = SIG_ECDSA_SHA384_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_ECDSA_SHA512 => {
                    oid = SIG_ECDSA_SHA512_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_ECDSA_SHAKE128 => {
                    oid = SIG_ECDSA_SHA512_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_ECDSA_SHAKE256 => {
                    oid = SIG_ECDSA_SHAKE256_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_ED25519 => {
                    oid = SIG_ED25519_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_ED448 => {
                    oid = SIG_ED448_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                //MAC based
                SIG_SHA256_HMAC_SHA256 => {
                    oid = SIG_SHA256_HMAC_SHA256_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_mac_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_SHA384_HMAC_SHA384 => {
                    oid = SIG_SHA384_HMAC_SHA384_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_mac_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_SHA512_HMAC_SHA512 => {
                    oid = SIG_SHA512_HMAC_SHA512_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_mac_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                //RSA based
                SIG_RSA_V15_SHA256 => {
                    oid = SIG_RSA_V15_SHA256_OID.as_bytes().to_vec();
                    param = ASN1_NULL.to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_V15_SHA384 => {
                    oid = SIG_RSA_V15_SHA384_OID.as_bytes().to_vec();
                    param = ASN1_NULL.to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_V15_SHA512 => {
                    oid = SIG_RSA_V15_SHA512_OID.as_bytes().to_vec();
                    param = ASN1_NULL.to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_PSS_SHA256 => {
                    oid = SIG_RSA_PSS_SHA256_OID.as_bytes().to_vec();
                    //param = TODO
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_PSS_SHA384 => {
                    oid = SIG_RSA_PSS_SHA384_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_PSS_SHA512 => {
                    oid = SIG_RSA_PSS_SHA512_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_PSS_SHAKE128 => {
                    oid = SIG_RSA_PSS_SHAKE128_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_PSS_SHAKE256 => {
                    oid = SIG_RSA_PSS_SHAKE256_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                //Some odd ones, not yet supported
                SIG_HSS_LMS => {
                    //oid = SIG_HSS_LMS_OID.as_bytes().to_vec();
                    panic!("SIG_HSS_LMS sig alg reconstruction not yet supported");
                }
                SIG_XMSS => {
                    //oid = SIG_XMSS_OID.as_bytes().to_vec();
                    panic!("SIG_XMSS sig alg reconstruction not yet supported");
                }
                SIG_XMSS_MT => {
                    //oid = SIG_XMSS_MT_OID.as_bytes().to_vec();
                    panic!("SIG_XMSS_MT sig alg reconstruction not yet supported");
                }
                _ => panic!("Unknown sign alg type: {}", sign_alg_id),
            }
        }
        Value::Array(_) => {
            panic!("sig alg array not supported")
        }
        _ => panic!("Could not parse sig alg"),
    };
    if param != Vec::new() {
        oid = lder_to_two_seq(lder_to_generic(oid, ASN1_OID), param);
    } else {
        oid = lder_to_generic(lder_to_generic(oid, ASN1_OID), ASN1_SEQ);
    }
    (oid, parsed_sig_val) //lder_to_seq(result))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//use asn1_rs::{BitString, Sequence, Integer, FromBer, ToDer};
//use asn1_rs::{BitString, Sequence, Integer};
pub fn parse_cbor_ecc_sig_value(sig_val_bytes: Vec<u8>) -> Vec<u8> {
    let mut result: Vec<Vec<u8>> = Vec::new();
    //let mut writer = Vec::new();



    let start_r_index = if sig_val_bytes[0] == 0 { 1 } else { 0 };
    let r = sig_val_bytes[start_r_index..sig_val_bytes.len() / 2].to_vec();
    trace!("parse_cbor_ecc_sig_value, restored r: {:02?}", r);

    let midpoint = if sig_val_bytes[sig_val_bytes.len() / 2] == 0 { sig_val_bytes.len() / 2+1 } else { sig_val_bytes.len() / 2 };         
    let s = sig_val_bytes[midpoint..sig_val_bytes.len()].to_vec();
    trace!("parse_cbor_ecc_sig_value, restored s: {:02?}", s);
    
    result.push(lder_to_pos_int(r));
    result.push(lder_to_pos_int(s));

    lder_to_bit_str(lder_to_seq(result))
}
pub fn parse_cbor_rsa_sig_value(sig_val_bytes: Vec<u8>) -> Vec<u8> {
    lder_to_bit_str(sig_val_bytes)
}
pub fn parse_cbor_mac_sig_value(_: Vec<u8>) -> Vec<u8> {
    panic!("Reconstruction of MAC based signatures not yet supported");
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
pub fn cleanup(mut file_contents: Vec<u8>) -> Vec<u8> {
    // Remove the trailing newline if present
    if let Some(last_byte) = file_contents.last() {
        if *last_byte == b'\n' {
            file_contents.remove(file_contents.len() - 1);
            return file_contents;
        //return file_contents[..file_contents.len() - 1]
        } else {
            return file_contents;
        }
    } else {
        return file_contents;
    };
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//            Below are fuctions for parsing and re-encoding cbor encoded extensions back to ASN.1
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_SUBJECT_KEY_ID = 1
fn parse_cbor_ext_subject_key_id(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_KEY_ID_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_KEY_USAGE = 2
fn parse_cbor_ext_key_usage(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_KEY_USAGE_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }

    let mut ext_val_arr = Vec::new();
    match extension_val {
        Value::Integer(key_usage_bitmap) => {
            let key_usage = {
                if 255 < *key_usage_bitmap {
                    ext_val_arr.push(128);
                    ((key_usage_bitmap - 256) as u8).swap_bits()
                } else {
                    (*key_usage_bitmap as u8).swap_bits()
                }
            };
            ext_val_arr.insert(0, key_usage);
            //Calculate number of trailing zeroes
            ext_val_arr.insert(0, key_usage.trailing_zeros() as u8);
            ext_val_arr = lder_to_generic(ext_val_arr, ASN1_BIT_STR);
        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
EXT_SUBJECT_ALT_NAME = 3
CDDL
GeneralName = ( GeneralNameType : int, GeneralNameValue : any )
   GeneralNames = [ + GeneralName ]
   SubjectAltName = GeneralNames / text

*/
fn parse_cbor_ext_subject_alt_name(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_ALT_NAME_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    //  let ext_val_arr = parse_cbor_general_name(extension_val);
    let ext_val_arr = lder_to_generic(parse_cbor_general_name(extension_val), ASN1_OCTET_STR);
    //let ext_val_arr = parse_cbor_general_name(extension_val); //TODO, check if general name always gives the needed octet string wrapping

    lder_to_two_seq(oid, ext_val_arr)
}

fn parse_cbor_general_name(extension_val: &Value) -> Vec<u8> {
    let empty_vec = Vec::new();
    match extension_val {
        Value::Array(general_name) => {
            let mut general_name_arr = Vec::new();
            let mut unwrap = false;
            for i in (0..general_name.len()).step_by(2) {
                general_name_arr.push({
                    match general_name[i] {
                        Value::Integer(gn_field) => {

                            match gn_field {
                                -1 => parse_cbor_general_name_hw_module(&general_name[i + 1]),
                                0 => {
                                    //otherName == [ ~oid, bytes ] //TODO TEST
                                    trace!("parse_cbor_general_name, option 0");
                                    match &general_name[i + 1] {
                                        Value::Array(other_name_array) => {
                                            let oid = {
                                                match &other_name_array[0] {
                                                    Value::Bytes(oid_bytes) => lder_to_generic(oid_bytes.to_vec(), ASN1_OID),
                                                    _ => panic!("Error parsing value: {:?}.", other_name_array[0]),
                                                }
                                            };
                                            let value = {
                                                match &other_name_array[1] {
                                                    Value::Bytes(val_bytes) => val_bytes.to_vec(),
                                                    _ => panic!("Error parsing value: {:?}.", other_name_array[0]),
                                                }
                                            };
                                            lder_to_two_seq(oid, value)
                                        }
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                1 => {
                                    //rfc822Name == text
                                    trace!("parse_cbor_general_name, option 1");
                                    match &general_name[i + 1] {
                                        Value::Text(rfc_822_name) => lder_to_generic(rfc_822_name.as_bytes().to_vec(), ASN1_INDEX_ONE_EXT),
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                2 => {
                                    //dnsName == text
                                    trace!("parse_cbor_general_name, option 2");
                                    match &general_name[i + 1] {
                                        Value::Text(dns_name) => lder_to_generic(dns_name.as_bytes().to_vec(), ASN1_INDEX_TWO_EXT),
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                4 => {
                                    // directoryName == Name
                                    trace!("parse_cbor_general_name, option 4");
                                    unwrap = true;
                                    lder_to_generic(parse_cbor_name(&general_name[i + 1] as &Value, &empty_vec), ASN1_INDEX_FOUR)
                                    //todo test more
                                }
                                6 => {
                                    // uri == text
                                    trace!("parse_cbor_general_name, option 6");
                                    match &general_name[i + 1] {
                                        Value::Text(uri) => lder_to_generic(uri.as_bytes().to_vec(), ASN1_URL),
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                7 => {
                                    //ipAddress == bytes
                                    trace!("parse_cbor_general_name, option 7, ipAddress");
                                    match &general_name[i + 1] {
                                        Value::Bytes(ip) => lder_to_generic(ip.to_vec(), ASN1_IP),
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                8 => {
                                    //registeredID  == ~oid
                                    trace!("parse_cbor_general_name, option 8, oid");
                                    match &general_name[i + 1] {
                                        Value::Bytes(id) => lder_to_generic(id.to_vec(), ASN1_URL),
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                _ => {
                                    panic!("Not implemented: {:?}.", general_name[i])
                                }
                            }
                        }
                        _ => panic!("Error parsing value: {:?}.", general_name[i]),
                    }
                });
            }
            if unwrap == true {
                trace!("parse_cbor_general_name, unwrapping");
                general_name_arr.get(0).unwrap().clone().to_vec()
            } else {
                //implicit else:
                trace!("parse_cbor_general_name, no unwrapping");
                lder_to_seq(general_name_arr)
            }
            //let general_name = lder_to_seq(general_name_arr);  lder_to_generic(general_name, ASN1_OCTET_STR)
        }
        /*
          If subjectAltName contains exactly one dNSName, the array and the int are omitted and
          extensionValue is the dNSName encoded as a CBOR text string.

          The original ASN.1 struct is a an OCT string wrapping a SEQ wrapping a [2] elem
        */
        //Value::Text(raw_val) => lder_to_generic(lder_to_generic(lder_to_generic(raw_val.as_bytes().to_vec(), ASN1_INDEX_TWO_EXT), ASN1_SEQ), ASN1_OCTET_STR),
        Value::Text(raw_val) => lder_to_generic(lder_to_generic(raw_val.as_bytes().to_vec(), ASN1_INDEX_TWO_EXT), ASN1_SEQ),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_BASIC_CONSTRAINTS = 4
fn parse_cbor_ext_basic_constraints(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_BASIC_CONSTRAINTS_OID.to_der_vec().unwrap();
    if critical {
        trace!("parse_cbor_ext_basic_constraints: CRITICAL!");
        oid.extend(ASN1_X509_CRITICAL.to_vec());
        let second = {
            match extension_val {
                Value::Integer(path_len) => {
                    if -2 == *path_len {
                        ASN1_X509_BASIC_CONSTRAINT_FALSE.to_vec()
                    } else if -1 == *path_len {
                        lder_to_generic(lder_to_generic(ASN1_X509_CRITICAL.to_vec(), ASN1_SEQ), ASN1_OCTET_STR)
                    } else {
                        let path_len_vec = vec![*path_len as u8];
                        lder_to_generic(lder_to_two_seq(ASN1_X509_CRITICAL.to_vec(), lder_to_pos_int(path_len_vec)), ASN1_OCTET_STR)
                    }
                }
                _ => panic!("Illegal path len {:?}", extension_val),
            }
        }; //end let second
        lder_to_two_seq(oid, second) //TODO check if this also should be wrapped
    } else {
        trace!("parse_cbor_ext_basic_constraints: NOT CRITICAL!");
        let second = {
            match extension_val {
                Value::Integer(path_len) => {
                    if -2 == *path_len {
                        ASN1_X509_BASIC_CONSTRAINT_FALSE.to_vec()
                    } else if -1 == *path_len {
                        lder_to_generic(lder_to_generic(ASN1_X509_CRITICAL.to_vec(), ASN1_SEQ), ASN1_OCTET_STR)
                    } else {
                        let path_len_vec = vec![*path_len as u8];
                        lder_to_generic(lder_to_two_seq(ASN1_X509_CRITICAL.to_vec(), lder_to_pos_int(path_len_vec)), ASN1_OCTET_STR)
                    }
                }
                _ => panic!("Illegal path len {:?}", extension_val),
            }
        }; //end let second
        lder_to_two_seq(oid, second)
    }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_CRL_DIST_POINTS = 5
fn parse_cbor_ext_crl_dist_points(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut result_vec = Vec::new();
    let mut oid = EXT_CRL_DIST_POINTS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    match extension_val {
        Value::Array(elements) => {
            for element in elements {
                match element {
                    Value::Text(url_string) => {
                        result_vec.push(lder_to_generic(lder_to_generic(lder_to_generic(lder_to_generic(url_string.as_bytes().to_vec(), ASN1_URL), ASN1_INDEX_ZERO), ASN1_INDEX_ZERO), ASN1_SEQ));
                    }
                    Value::Array(inner_elements) => {
                      let mut inner_result_vec = Vec::new();
                      for inner_element in inner_elements {
                        match inner_element {
                            Value::Text(url_string) => {
                                inner_result_vec.append(&mut lder_to_generic(url_string.as_bytes().to_vec(), ASN1_URL));
                            }
                            _ => {
                              panic!("Error parsing value {:?}, quitting", inner_element);
                            }
                        }                      
                      }
                      result_vec.push(lder_to_generic(lder_to_generic(lder_to_generic(inner_result_vec, ASN1_INDEX_ZERO), ASN1_INDEX_ZERO), ASN1_SEQ));
                    } /*
                      unsafe {
                        if GLOBAL_BATCH_MODE {
                          warn!("Can't handle arrays in EXT_CRL_DIST_POINTS - {:?}, skipping", elements);
                        } else {
                          panic!("Can't handle arrays in EXT_CRL_DIST_POINTS - {:?}, quitting", elements);
                        }
                      }
                    } */
                    
                    _ => {
                      unsafe {
                        if GLOBAL_BATCH_MODE {
                          panic!("Error parsing value {:?}, skipping", element);
                        } else {
                          panic!("Error parsing value {:?}, quitting", element);
                        }
                      }
                    }
                }
            }
        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(result_vec), ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_CERT_POLICIES = 6
/*
Qualifier ::= CHOICE {
  cPSuri   CPSuri,
  userNotice   UserNotice }
   CPSuri ::= IA5String
*/
fn parse_cbor_ext_cert_policies(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut result_vec = Vec::new();
    let mut oid = EXT_CERT_POLICIES_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let mut can_specify = false;
    let mut text_type = ASN1_UTC_TIME; //must be overwritten

    match extension_val {
        Value::Array(elements) => {
            let mut wip = Vec::new();
            for element in elements {
                match element {
                    Value::Integer(pol_id) => {
                        if can_specify {
                            //prev oid didn't use any qualifier, and should be stored now
                            result_vec.push(lder_to_seq(wip));
                            wip = Vec::new();
                        }
                        //result_vec.push(lder_to_generic(lder_to_generic(lder_to_generic(lder_to_generic(url_string.as_bytes().to_vec(), ASN1_INDEX_SIX_EXT),ASN1_INDEX_ZERO),ASN1_INDEX_ZERO),ASN1_SEQ));
                        trace!("parse_cbor_ext_cert_policies, FOUND pol id: {:02x?}", map_cert_policy_id_to_oid(*pol_id as i64));
                        wip.push(map_cert_policy_id_to_oid(*pol_id as i64));
                        can_specify = true;
                    }
                    Value::Bytes(raw_oid) => {
                        if can_specify {
                            //prev oid didn't use any qualifier, and should be stored now
                            result_vec.push(lder_to_seq(wip));
                            wip = Vec::new();
                        }
                        wip.push(lder_to_generic(raw_oid.to_vec(), ASN1_OID));
                        trace!("parse_cbor_ext_cert_policies, handling raw bytes");
                        can_specify = true;
                    }
                    Value::Array(specifiers) => {
                        if !can_specify {
                            panic!("Did not expect specifiers here: {:?}", specifiers);
                        }
                        let mut wip_internal = Vec::new();
                        for i in (0..specifiers.len()).step_by(2) { //Specifiers should come in (cps or unotice) / text string pairs, 0 to many
                          let q_oid = {
                              match specifiers.get(i).unwrap() {
                                  Value::Bytes(raw_oid) => lder_to_generic(raw_oid.to_vec(), ASN1_OID),
                                  Value::Integer(pol_id) => {
                                      if PQ_CPS == *pol_id as i64 {
                                          trace!("parse_cbor_ext_cert_policies, handling cps {:02x?}", PQ_CPS_OID.to_der_vec().unwrap());
                                          text_type = ASN1_IA5_SRT;
                                          PQ_CPS_OID.to_der_vec().unwrap()
                                      } else if PQ_UNOTICE == *pol_id as i64 {
                                          trace!("parse_cbor_ext_cert_policies, handling unotice {:02x?}", PQ_UNOTICE_OID.to_der_vec().unwrap());
                                          text_type = ASN1_UTF8_STR;
                                          PQ_UNOTICE_OID.to_der_vec().unwrap()
                                      } else {
                                          panic!("Can't handle policy qualifier: {:?}", pol_id);
                                      }
                                  }
                                  _ => {
                                      panic!("Could not parse {:?}", specifiers.get(0));
                                  }
                              }
                          };
                          let q_text = {
                              match specifiers.get(i+1).unwrap() {
                                  Value::Text(qualifier) => {
                                      trace!("parse_cbor_ext_cert_policies, handling text {:02x?}", qualifier.as_bytes());
                                      //unotice has one extra level of sequence wrapping...!
                                      let t_text = lder_to_generic(qualifier.as_bytes().to_vec(), text_type);
                                      if text_type == ASN1_UTF8_STR {
                                        lder_to_generic(t_text, ASN1_SEQ)
                                      } else {
                                        t_text
                                      }
                                  }
                                  _ => {
                                      panic!("Could not parse {:?}", specifiers.get(1))
                                  }
                              }
                          };
                          //wip.push(lder_to_generic(lder_to_two_seq(q_oid, q_text), ASN1_SEQ));
                          trace!("parse_cbor_ext_cert_policies, storing next two two");
                          wip_internal.push(lder_to_two_seq(q_oid, q_text));

                      } //end of specifiers loop
                      //wip.push(lder_to_generic(lder_to_two_seq(q_oid, q_text), ASN1_SEQ));
                      wip.push(lder_to_seq(wip_internal));
                      trace!("parse_cbor_ext_cert_policies, storing WIP to res {:?}", wip);
                      result_vec.push(lder_to_seq(wip)); //TODO: check empty
                      wip = Vec::new();
                      can_specify = false;

                    }
                    _ => {
                        panic!("Could not parse {:?}", element);
                    }
                } //end of element
            } //end of big for loop
            if can_specify {
                //last oid didn't use any qualifier, and should be stored now
                result_vec.push(lder_to_seq(wip));
            }
        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(result_vec), ASN1_OCTET_STR))
}

fn map_cert_policy_id_to_oid(cert_policy_id: i64) -> Vec<u8> {
    match cert_policy_id {
        CP_ANY_POLICY => CP_ANY_POLICY_OID.to_der_vec().unwrap(),
        CP_DOMAIN_VALIDATION => CP_DOMAIN_VALIDATION_OID.to_der_vec().unwrap(),
        CP_ORGANIZATION_VALIDATION => CP_ORGANIZATION_VALIDATION_OID.to_der_vec().unwrap(),
        CP_INDIVIDUAL_VALIDATION => CP_INDIVIDUAL_VALIDATION_OID.to_der_vec().unwrap(),
        CP_EXTENDED_VALIDATION => CP_EXTENDED_VALIDATION_OID.to_der_vec().unwrap(),
        CP_RESOURCE_PKI => CP_RESOURCE_PKI_OID.to_der_vec().unwrap(),
        CP_RESOURCE_PKI_ALT => CP_RESOURCE_PKI_ALT_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_CI => CP_RSP_ROLE_CI_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_EUICC => CP_RSP_ROLE_EUICC_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_EUM => CP_RSP_ROLE_EUM_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_DP_TLS => CP_RSP_ROLE_DP_TLS_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_DP_AUTH => CP_RSP_ROLE_DP_AUTH_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_DP_PB => CP_RSP_ROLE_DP_PB_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_DS_TLS => CP_RSP_ROLE_DS_TLS_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_DS_AUTH => CP_RSP_ROLE_DS_AUTH_OID.to_der_vec().unwrap(),
        _ => panic!("Found unknown cert policy code: {}", cert_policy_id),
    }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_AUTH_KEY_ID = 7
/*
KeyIdentifierArray = [
   keyIdentifier: KeyIdentifier / null,
   authorityCertIssuer: GeneralNames,
   authorityCertSerialNumber: CertificateSerialNumber
   ]
   AuthorityKeyIdentifier = KeyIdentifierArray / KeyIdentifier
*/
fn parse_cbor_ext_auth_key_id(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_AUTH_KEY_ID_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }

    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(lder_to_generic(raw_val.to_vec(), ASN1_INDEX_ZERO_EXT), ASN1_SEQ),
        Value::Array(array) => {
            let mut int_arr: Vec<Vec<u8>> = Vec::new();
            match array.get(0).unwrap() {
                //expecting key id bytes
                Value::Bytes(key_id) => {
                    trace!("parse_cbor_ext_auth_key_id, handle key_id: {:02x?}", key_id);
                    int_arr.push(lder_to_generic(key_id.to_vec(), ASN1_INDEX_ZERO_EXT));
                }
                _ => panic!("Error parsing value: {:?}.", array.get(0)),
            }
            match array.get(1).unwrap() {
                //expecting general names = array
                Value::Array(gen_names_arr) => {
                    trace!("parse_cbor_ext_auth_key_id, handle gen_names: {:02x?}", gen_names_arr);
                    int_arr.push(lder_to_generic(parse_cbor_general_name(array.get(1).unwrap()), ASN1_INDEX_ONE));
                }
                _ => panic!("Error parsing value: {:?}.", array.get(1)),
            }
            match array.get(2).unwrap() {
                //expecting authorityCertSerialNumber
                Value::Bytes(auth_serial) => {
                    trace!("parse_cbor_ext_auth_key_id, handle authority Cert Serial Number: {:02x?}", auth_serial);
                    int_arr.push(lder_to_generic(auth_serial.to_vec(), ASN1_INDEX_TWO_EXT));
                }
                _ => panic!("Error parsing value: {:?}.", array.get(0)),
            }
            lder_to_seq(int_arr)
        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}

//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_EXT_KEY_USAGE = 8
fn parse_cbor_ext_ext_key_usage(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_EXT_KEY_USAGE_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let mut ext_val_arr = Vec::new();
    match extension_val {
        Value::Integer(key_purpose_id) => {
            ext_val_arr.push(map_key_purpose_id_to_oid(*key_purpose_id as u64));
        }
        Value::Array(elements) => {
            for element in elements {
                match element {
                    Value::Integer(key_purpose_id) => {
                        ext_val_arr.push(map_key_purpose_id_to_oid(*key_purpose_id as u64));
                    }
                    Value::Bytes(raw_val) => {
                        ext_val_arr.push(lder_to_generic(raw_val.to_vec(), ASN1_OID));
                        //todo, check handling of multiple OIDs
                    }
                    _ => panic!("Error parsing value: {:?}.", element),
                }
            }
        }
        Value::Bytes(raw_val) => {
            ext_val_arr.push(lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR));
        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    //lder_to_seq(ext_val_arr);
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(ext_val_arr), ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn map_key_purpose_id_to_oid(key_purpose_id: u64) -> Vec<u8> {
    match key_purpose_id {
        EKU_TLS_SERVER => EKU_TLS_SERVER_OID.to_der_vec().unwrap(),
        EKU_TLS_CLIENT => EKU_TLS_CLIENT_OID.to_der_vec().unwrap(),
        EKU_CODE_SIGNING => EKU_CODE_SIGNING_OID.to_der_vec().unwrap(),
        EKU_EMAIL_PROTECTION => EKU_EMAIL_PROTECTION_OID.to_der_vec().unwrap(),
        EKU_TIME_STAMPING => EKU_TIME_STAMPING_OID.to_der_vec().unwrap(),
        EKU_OCSP_SIGNING => EKU_OCSP_SIGNING_OID.to_der_vec().unwrap(),
        EKU_ANY_EKU => EKU_ANY_EKU_OID.to_der_vec().unwrap(),
        EKU_KERBEROS_PKINIT_CLIENT_AUTH => EKU_KERBEROS_PKINIT_CLIENT_AUTH_OID.to_der_vec().unwrap(),
        EKU_KERBEROS_PKINIT_KDC => EKU_KERBEROS_PKINIT_KDC_OID.to_der_vec().unwrap(),
        EKU_SSH_CLIENT => EKU_SSH_CLIENT_OID.to_der_vec().unwrap(),
        EKU_SSH_SERVER => EKU_SSH_SERVER_OID.to_der_vec().unwrap(),
        EKU_BUNDLE_SECURITY => EKU_BUNDLE_SECURITY_OID.to_der_vec().unwrap(),
        EKU_CMC_CERT_AUTHORITY => EKU_CMC_CERT_AUTHORITY_OID.to_der_vec().unwrap(),
        EKU_CMC_REG_AUTHORITY => EKU_CMC_REG_AUTHORITY_OID.to_der_vec().unwrap(),
        EKU_CMC_ARCHIVE_SERVER => EKU_CMC_ARCHIVE_SERVER_OID.to_der_vec().unwrap(),
        EKU_CMC_KEY_GEN_AUTHORITY => EKU_CMC_KEY_GEN_AUTHORITY_OID.to_der_vec().unwrap(),
        _ => panic!("Found unknown ext key usage code: {}", key_purpose_id),
    }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
EXT_AUTH_INFO = 9
CDDL
AccessDescription = ( accessMethod: int / ~oid , uri: text )
AuthorityInfoAccessSyntax = [ + AccessDescription ]
*/

fn parse_cbor_ext_auth_info(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut result_vec = Vec::new();
    let mut oid = EXT_AUTH_INFO_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    match extension_val {
        Value::Array(elements) => {
            let mut wip = Vec::new();
            trace!("parse_cbor_ext_auth_info, handle {} and {}", elements.len(), elements.len() % 2);
            assert!(0 == (elements.len() % 2), "The AuthorityInfoAccessSyntax array must be of even length");
            for i in (0..elements.len()).step_by(2) {
                match elements.get(i).unwrap() {
                    Value::Integer(access_method) => {
                        //trace!("parse_cbor_ext_auth_info, access_method: {:02x?}", map_auth_info_id_to_oid(*access_method as i64));
                        wip.push(map_auth_info_id_to_oid(*access_method as i64));
                    }
                    Value::Bytes(raw_oid) => {
                        wip.push(lder_to_generic(raw_oid.to_vec(), ASN1_OID));
                        trace!("parse_cbor_ext_auth_info, handle raw bytes");
                    }
                    _ => {
                        panic!("Could not parse {:?}", elements.get(i));
                    }
                };
                match elements.get(i + 1).unwrap() {
                    Value::Text(qualifier) => {
                        trace!("parse_cbor_ext_auth_info, handle text {:02x?}", qualifier.as_bytes());
                        wip.push(lder_to_generic(qualifier.as_bytes().to_vec(), ASN1_URL));
                    }
                    _ => {
                        panic!("Could not parse {:?}", elements.get(i + 1))
                    }
                }
                result_vec.push(lder_to_seq(wip));
                wip = Vec::new();
            }
        }
        _ => {
            panic!("Could not parse {:?}", extension_val);
        }
    }
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(result_vec), ASN1_OCTET_STR))
}
fn map_auth_info_id_to_oid(access_method: i64) -> Vec<u8> {
    match access_method {
        INFO_OCSP => INFO_OCSP_OID.to_der_vec().unwrap(),
        INFO_CA_ISSUERS => INFO_CA_ISSUERS_OID.to_der_vec().unwrap(),
        INFO_TIME_STAMPING => INFO_TIME_STAMPING_OID.to_der_vec().unwrap(),
        INFO_CA_REPOSITORY => INFO_CA_REPOSITORY_OID.to_der_vec().unwrap(),
        INFO_RPKI_MANIFEST => INFO_RPKI_MANIFEST_OID.to_der_vec().unwrap(),
        INFO_SIGNED_OBJECT => INFO_SIGNED_OBJECT_OID.to_der_vec().unwrap(),
        INFO_RPKI_NOTIFY => INFO_RPKI_NOTIFY_OID.to_der_vec().unwrap(),
        _ => panic!("Found unknown access method code: {}", access_method),
    }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
EXT_SCT_LIST = 10
https://letsencrypt.org/2018/04/04/sct-encoding.html
CDDL
SignedCerticateTimestamp = (
   logID: bytes,
   timestamp: int,
   sigAlg: AlgorithmIdentifier,
   sigValue: any,
   )
   SignedCertificateTimestamps = [ + SignedCerticateTimestamp ]

*/
fn parse_cbor_ext_sct_list(extension_val: &Value, critical: bool, ts_offset: i64) -> Vec<u8> {
    let mut ext_val_arr = Vec::new();
    let mut sct_size = 0;
    let mut total_tally = 0;
    let ts_os_ms = 1000 * ts_offset as i64;

    let mut oid = EXT_SCT_LIST_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }

    match extension_val {
        Value::Array(sct_array) => {
            //println!("CBOR array: {:02x?}", sct_array);

            for i in (0..sct_array.len()).step_by(4) {
                if 0 < i {
                    ext_val_arr.insert(total_tally, 0x00);
                    ext_val_arr.insert(total_tally + 1, sct_size as u8);
                    total_tally += sct_size + 2;
                    sct_size = 0;
                    trace!("parse_cbor_ext_sct_list, status after one loop {:02x?}", ext_val_arr);
                }
                match sct_array.get(i).unwrap() {
                    Value::Bytes(log_id) => {
                        trace!("parse_cbor_ext_sct_list, handle logID bytes {:02x?}", log_id);
                        ext_val_arr.push(0x00);
                        ext_val_arr.extend(log_id);
                        sct_size += 32 + 1; //same len assumption as in the encoding part
                    }
                    _ => {
                        panic!("Can't parse {:?}", sct_array.get(i));
                    }
                }
                match sct_array.get(i + 1).unwrap() {
                    Value::Integer(ts) => {
                        trace!("parse_cbor_ext_sct_list, handle ts {} and notBefore {}", ts, ts_os_ms);
                        let o_ts = (*ts as i64) + ts_os_ms;
                        let b = o_ts.to_be_bytes();
                        ext_val_arr.extend(b);
                        sct_size += 8;
                    }
                    _ => {
                        panic!("Can't parse {:?}", sct_array.get(i + 1));
                    }
                }
                match sct_array.get(i + 2).unwrap() {
                    Value::Integer(ai) => {
                        trace!("parse_cbor_ext_sct_list, handle sigAlg {}", ai);
                        if *ai as i64 != SIG_ECDSA_SHA256 {
                            panic!("Can only handle scts using SIG_ECDSA_SHA256");
                        }
                        ext_val_arr.extend(SCT_EXT_AID);
                        sct_size += 4;
                    }
                    _ => {
                        panic!("Can't parse {:?}", sct_array.get(i + 2));
                    }
                }
                match sct_array.get(i + 3).unwrap() {
                    Value::Bytes(sig_val) => {
                        trace!("parse_cbor_ext_sct_list, reconstruct r+s, found sigVal bytes of len {}: {:02x?}", sig_val.len(), sig_val);
                        //let get = ;
                        let start_r_index = if sig_val[0] == 0 { 1 } else { 0 }; //TODO test more
                        let r = lder_to_pos_int(sig_val[start_r_index..sig_val.len() / 2].to_vec());
                        
                        let start_s_index = if sig_val[sig_val.len() / 2] == 0 { sig_val.len() / 2 + 1 } else { sig_val.len() / 2 }; 
                        let s_r = sig_val[start_s_index..sig_val.len()].to_vec();
                        let s = lder_to_pos_int(s_r.clone());

                        let seq = lder_to_two_seq(r, s);
                        trace!("parse_cbor_ext_sct_list, reconstruct r+s, after seq of len {}: {:02x?}", seq.len(), seq);
                        ext_val_arr.push(0x00);
                        ext_val_arr.push(seq.len() as u8); //TODO handle larger lens
                        ext_val_arr.extend(seq.clone());
                        sct_size += seq.len() + 2;
                    }
                    _ => {
                        panic!("Can't parse {:?}", sct_array.get(i + 3));
                    }
                }
            }
            ext_val_arr.insert(total_tally, 0x00); //the size field for the last 4-touple
            ext_val_arr.insert(total_tally + 1, sct_size as u8);

        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    ext_val_arr = lder_to_generic(lder_to_generic(sct_add_len(ext_val_arr), ASN1_OCTET_STR), ASN1_OCTET_STR);
    trace!("parse_cbor_ext_sct_list, reconstructed {:02x?}", ext_val_arr);

    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_subject_directory_attr(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_DIRECTORY_ATTR_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_subject_directory_attr not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
 EXT_ISSUER_ALT_NAME = 25; //0x12
*/

fn parse_cbor_ext_issuer_alt_name(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_ISSUER_ALT_NAME_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    //  let ext_val_arr = parse_cbor_general_name(extension_val);
    let ext_val_arr = lder_to_generic(parse_cbor_general_name(extension_val), ASN1_OCTET_STR);
    //let ext_val_arr = parse_cbor_general_name(extension_val); //TODO, check if general name always gives the needed octet string wrapping
    lder_to_two_seq(oid, ext_val_arr)
}

/*
fn parse_cbor_ext_issuer_alt_name(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_ISSUER_ALT_NAME_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let empty_vec = Vec::new();
    let ext_val_arr = parse_cbor_name(&extension_val, &empty_vec);
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
*/
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_name_constraints(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_NAME_CONSTRAINTS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_name_constraints not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_policy_mappings(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_POLICY_MAPPINGS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_policy_mappings not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_policy_constraints(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_POLICY_CONSTRAINTS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_policy_constraints not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_freshest_crl(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_FRESHEST_CRL_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_freshest_crl not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_inhibit_anypolicy(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_INHIBIT_ANYPOLICY_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_inhibit_anypolicy not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_subject_info_access(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_INFO_ACCESS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_subject_info_access not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_ip_resources(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_IP_RESOURCES_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_ip_resources not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_as_resources(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_AS_RESOURCES_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_as_resources not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_ip_resources_v2(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_IP_RESOURCES_V2_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_ip_resources_v2 not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_as_resources_v2(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_AS_RESOURCES_V2_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_as_resources_v2 not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_biometric_info(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_BIOMETRIC_INFO_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_biometric_info not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_precert_signing_cert(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_PRECERT_SIGNING_CERT_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_precert_signing_cert not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_ocsp_no_check(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_OCSP_NO_CHECK_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_ocsp_no_check not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_qualified_cert_statements(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_QUALIFIED_CERT_STATEMENTS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_qualified_cert_statements not implemented / tested");
    //lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_s_mime_capabilities(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_S_MIME_CAPABILITIES_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_s_mime_capabilities not implemented / tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
 EXT_TLS_FEATURES = 41
 */
fn parse_cbor_ext_tls_features(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_TLS_FEATURES_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        //Value::Bytes(raw_val) => raw_val.to_vec(), //TODO: check if always oct-wrapped
        
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_tls_features not tested");
    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_general_name_hw_module(hw_module: &Value) -> Vec<u8> {
    let mut outer_vec = Vec::new();
    outer_vec.push(OTHER_NAME_WITH_HW_MODULE_NAME_OID.to_der_vec().unwrap());

    let mut inner_vec = Vec::new();

    match hw_module {
        Value::Array(array) => {
            if let Value::Bytes(raw_oid) = &array[0] {
                inner_vec.push(lder_to_generic(raw_oid.to_vec(), ASN1_OID));
                if let Value::Bytes(raw_val) = &array[1] {
                    trace!("parse_cbor_general_name_hw_module, working with raw_val.to_vec() {:02x?}", raw_val.to_vec());
                    inner_vec.push(lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR));
                } else {
                    panic!("Error parsing inner value of: {:?}.", hw_module)
                }
            } else {
                panic!("Error parsing value: {:?}.", hw_module)
            }
            //TODO work is here
        }
        _ => panic!("Error parsing value: {:?}.", hw_module),
    };
    outer_vec.push(lder_to_generic(lder_to_seq(inner_vec), ASN1_INDEX_ZERO));
    lder_to_gen_seq(outer_vec, ASN1_INDEX_ZERO)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
// ======================================================
// General helper functions
// ======================================================
pub mod help {
    use colored::*;
    use oid::prelude::*;
    use serde_cbor::Value;
    use std::io::Write;
    // Convert a byte string to u64 uint
    pub fn be_bytes_to_u64(b: &[u8]) -> u64 {
        let l = b.len();
        assert!(l > 0 && l < 9, "Unexpected length");
        (0..l).into_iter().map(|i| (b[i] as u64) << (8 * (l - i - 1))).sum()
    }
    // Brotli compression
    pub fn brotli(input: &[u8]) -> Vec<u8> {
        let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 11, 22);
        writer.write_all(input).unwrap();
        writer.into_inner()
    }
    // Print a vec to cout
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
    // Print an error to cout (red and white)
    pub fn print_vec(s: &str, v: &[u8]) {
        print_internal(s, v, false);
    }
    
    // Print a compact vec to cout
    pub fn print_vec_compact(v: &[u8]) {
      for (i, byte) in v.iter().enumerate() {
          print!("{:02X}", byte);
      }
    }

    // Print a warning to cout
    pub fn print_str_warning(s: &str) {
        let heading = format!("{}", s);
        println!("{}", heading.red());
    }

    // Print an error to cout (red and white)
    pub fn print_warning(s: &str, v: &[u8], oid: &[u8]) {
        let oid_str: String = ObjectIdentifier::try_from(oid).unwrap().into();
        let text = format!("{} ({})", s, oid_str);
        print_internal(&text, v, true);
    }
    // Print info to cout (green)
    pub fn print_info(rows: &[String]) {
        println!("{}", "--------------------------------------------------------------------".green());
        for row in rows {
            println!("{}", row.green());
        }
        println!("{}", "--------------------------------------------------------------------".green());
        println!();
    }

    pub fn usize_to_u8_vec(x: usize) -> Vec<u8> {
        let mut result = Vec::new();
        for i in 0..std::mem::size_of::<usize>() {
            let byte = ((x >> (i * 8)) & 0xff) as u8;
            result.push(byte);
        }
        while let Some(&0) = result.first() {
            result.remove(0);
        }
        result
    }
    pub fn get_as_bytes(value: &Value) -> Vec<u8> {
        match value {
            Value::Bytes(raw_bytes) => raw_bytes.to_vec(),
            _ => panic!("Expected bytes but got {:?}", value),
        }
    }
}
// =========================================================================================================
// DER parsing & encoding functions
// =========================================================================================================
pub mod lder {
  
    use crate::help::*;
    // Universal ASN1 tags
    pub const ASN1_BOOL: u8 = 0x01;
    pub const ASN1_INT: u8 = 0x02;
    pub const ASN1_BIT_STR: u8 = 0x03;
    pub const ASN1_OCTET_STR: u8 = 0x04;
    pub const ASN1_OID: u8 = 0x06;
    pub const ASN1_UTF8_STR: u8 = 0x0C;
    pub const ASN1_PRINT_STR: u8 = 0x13;
    pub const ASN1_IA5_SRT: u8 = 0x16;
    pub const ASN1_UTC_TIME: u8 = 0x17;
    pub const ASN1_UTC_TIME_MAX: i64 = 2524607999; // Friday 31 December 2049 23:59:59
    pub const ASN1_UTC_TIME_Y2K: i64 = 946684799; // 31 December 1999 23:59:59
                                      
    pub const ASN1_GEN_TIME: u8 = 0x18;
    pub const ASN1_SEQ: u8 = 0x30;
    pub const ASN1_SET: u8 = 0x31;
    pub const ASN1_INDEX_ZERO: u8 = 0xa0;
    pub const ASN1_INDEX_ONE: u8 = 0xa1;
    pub const ASN1_INDEX_TWO: u8 = 0xa2;
    pub const ASN1_INDEX_THREE: u8 = 0xa3;
    pub const ASN1_INDEX_FOUR: u8 = 0xa4;
    pub const ASN1_INDEX_ZERO_EXT: u8 = 0x80; //Clarify
    pub const ASN1_INDEX_ONE_EXT: u8 = 0x81; //Clarify
    pub const ASN1_INDEX_TWO_EXT: u8 = 0x82; //Clarify
    pub const ASN1_URL: u8 = 0x86; //Clarify
    pub const ASN1_IP: u8 = 0x87; //TODO: Clarify
    
    pub const ASN1_ONE_BYTE_SIZE: u8 = 0x81;
    pub const ASN1_TWO_BYTE_SIZE: u8 = 0x82;

    pub const ASN1_GEN_TIME_MAX: &str = "99991231235959Z";
    pub const ASN1_NULL: &[u8] = &[0x05, 0x00];
    pub const ASN1_X509_VERSION_3: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];
    pub const ASN1_X509_CRITICAL: &[u8] = &[0x01, 0x01, 0xff];
    pub const ASN1_X509_BASIC_CONSTRAINT_FALSE: &[u8] = &[0x04, 0x02, 0x30, 0x00];
    //pub const ASN1_X509_BASIC_CONSTRAINT_TRUE: &[u8] = &[0x30, 0x03, 0x01, 0x01, 0xff];

    pub const ASN1_65537: &[u8] = &[0x02, 0x03, 0x01, 0x00, 0x01];

    pub const SCT_EXT_AID: &[u8] = &[0x00, 0x00, 0x04, 0x03];

    // Parse a DER encoded type and returns the value as a byte string
    pub fn lder(b: &[u8], tag: u8) -> &[u8] {
        assert!(b[0] == tag, "Unexpected type! Expected {:x} but got {:x}", tag, b[0]);
        let (value, none) = lder_split(b, true);
        assert!(none.is_empty(), "Expected empty slice!");
        value
    }
    // Parse a DER encoded uint and removes the first zero byte
    pub fn lder_uint(b: &[u8]) -> &[u8] {
        let value = lder(b, ASN1_INT);
        if value.len() > 1 && value[0] == 0 {
            return &value[1..];
        }
        value
    }
    // Parse a DER encoded sequence/set type and returns the elements as a vector
    pub fn lder_vec(b: &[u8], tag: u8) -> Vec<&[u8]> {
        let mut vec = Vec::new();

        let mut rest = lder(b, tag);
        while !rest.is_empty() {
            let (tlv, temp) = lder_split(rest, false);
            vec.push(tlv);
            rest = temp;
        }
        vec
    }
    // Parse a DER encoded sequence/set with a known expected length
    pub fn lder_vec_len(b: &[u8], tag: u8, length: usize) -> Vec<&[u8]> {
        let vec = lder_vec(b, tag);
        assert!(vec.len() == length, "DER encoded sequence/set has invalid length!");
        vec
    }
    // Parse a sequence of DER encoded types and returns a tuple
    // The tuple contains (first type, rest of sequence/set)
    pub fn lder_split(b: &[u8], value_only: bool) -> (&[u8], &[u8]) {
        assert!(b[1] < 0x84, "Did not expected length >= 2^24");
        let (start, end) = match b[1] {
            0x80 => panic!("Indefinite length encoding!"),
            0x81 => (3, 3 + b[2] as usize),
            0x82 => (4, 4 + be_bytes_to_u64(&b[2..4]) as usize),
            0x83 => (5, 5 + be_bytes_to_u64(&b[2..5]) as usize),
            _ => (2, 2 + b[1] as usize),
        };
        (&b[value_only as usize * start..end], &b[end..])
    }
    pub fn lder_to_bit_str(bytes: Vec<u8>) -> Vec<u8> {
        let mut result: Vec<u8> = bytes;
        result.insert(0, 0x00); //TODO: do we care about the short strings here?
        lder_to_generic(result, ASN1_BIT_STR)
    }
    pub fn lder_to_pos_int(bytes: Vec<u8>) -> Vec<u8> {
        //The bits of the first octet and bit 8 of the second octet must not all be ones.
        //The bits of the first octet and bit 8 of the second octet must not all be zero.
        //For positive numbers whose binary representation starts with a 1, a zero byte is added at the front to fulfill the sign constraint.
        let mut result: Vec<u8> = bytes;

        //trace!("Inserting 00: \n0 < 0b1000_0000 & *result.get(0).unwrap()\n{}\n*result.get(0).unwrap() as u8:\n{}", 0 < 0b1000_0000 & *result.get(0).unwrap(), *result.get(0).unwrap() as u8);
        if (0 < 0b1000_0000 & *result.get(0).unwrap() as u8) && (127 < *result.get(0).unwrap() as u8) {
            //TODO test more
            result.insert(0, 0x00);
        }
        lder_to_generic(result, ASN1_INT)
    }
    pub fn lder_to_generic(bytes: Vec<u8>, asn1_type: u8) -> Vec<u8> {
        let len = bytes.len();
        let mut result: Vec<u8> = bytes;
        result.insert(0, len as u8);
        if 127 < len && len <= 255 { //Note, different boundaries cmp with lder_to_gen_seq, since here the incoming items are already wrapped
            result.insert(0, ASN1_ONE_BYTE_SIZE);
        } else if 255 < len {
            result.insert(0, (len >> 8) as u8);
            result.insert(0, ASN1_TWO_BYTE_SIZE);
        }
        result.insert(0, asn1_type);

        result
    }
    /*
    pub fn lder_to_int(bytes: Vec<u8>) -> Vec<u8> {

      let mut result: Vec<u8> = bytes;
      //TODO handle >255
      result.insert(0, (result.len()) as u8);
      result.insert(0, ASN1_INT);

      result
      }
      */

    pub fn lder_to_seq(elements: Vec<Vec<u8>>) -> Vec<u8> {
        lder_to_gen_seq(elements, ASN1_SEQ)
    }
    
    pub fn lder_to_gen_seq(elements: Vec<Vec<u8>>, asn1_type: u8) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        for item in elements.into_iter() {
            result.extend(item);
        }

        result.insert(0, result.len() as u8); //

        if 128 < result.len() && result.len() <= 256 { //corner cases!
            //TODO/CHECK: we don't want the insertion for an original sum of 127, check extensions
            result.insert(0, ASN1_ONE_BYTE_SIZE);
        } else if 256 < result.len() { //256, since this is the resulting len _after_ the insertion above
            result.insert(0, (result.len() - 1 >> 8) as u8);
            result.insert(0, ASN1_TWO_BYTE_SIZE);
        }
        result.insert(0, asn1_type);

        result
    }
    pub fn lder_to_two_seq(first: Vec<u8>, second: Vec<u8>) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(first);
        result.push(second);
        lder_to_seq(result)
    }

    pub fn lder_to_time(input: String, time_type: u8) -> Vec<u8> {
        let mut result: Vec<u8> = input.as_bytes().to_vec();
        result.insert(0, (result.len()) as u8);
        result.insert(0, time_type);

        result
    }

    pub fn sct_add_len(bytes: Vec<u8>) -> Vec<u8> {
        let len = bytes.len();
        let mut result: Vec<u8> = bytes;
        result.insert(0, len as u8);
        if 255 < len {
            result.insert(0, (len >> 8) as u8);
        }
        //result.insert(0, 0x00); //todo test
        if (0 < 0b1000_0000 & *result.get(0).unwrap() as u8) && (127 < *result.get(0).unwrap() as u8) {
            //TODO test
            result.insert(0, 0x00);
        }

        result
    }
}
// ======================================================
// Determinist CBOR encoding (RFC 8949)
// ======================================================
pub mod lcbor {
    // CBOR encodes an unsigned interger
    pub fn lcbor_uint(u: u64) -> Vec<u8> {
        lcbor_type_arg(0, u)
    }
    // CBOR encodes an signed integer
    pub fn lcbor_int(i: i64) -> Vec<u8> {
        if i < 0 {
            lcbor_type_arg(1, -i as u64 - 1)
        } else {
            lcbor_uint(i as u64)
        }
    }
    // CBOR encodes a byte string
    pub fn lcbor_bytes(b: &[u8]) -> Vec<u8> {
        [&lcbor_type_arg(2, b.len() as u64), b].concat()
    }
    // CBOR encodes a text string
    pub fn lcbor_text(b: &[u8]) -> Vec<u8> {
        let s = std::str::from_utf8(b).unwrap(); // check that this is valid utf8
        [&lcbor_type_arg(3, s.len() as u64), s.as_bytes()].concat()
    }
    // CBOR encodes an array
    pub fn lcbor_array(v: &[Vec<u8>]) -> Vec<u8> {
        [lcbor_type_arg(4, v.len() as u64), v.concat()].concat()
    }
    pub const CBOR_FALSE: u8 = 20;
    pub const CBOR_TRUE: u8 = 21;
    pub const CBOR_NULL: u8 = 22;
    // CBOR encodes a simple value
    pub fn lcbor_simple(u: u8) -> Vec<u8> {
        lcbor_type_arg(7, u as u64)
    }
    // Internal CBOR encoding helper funtion
    fn lcbor_type_arg(t: u8, u: u64) -> Vec<u8> {
        let mut vec = vec![t << 5];
        if u < 24 {
            vec[0] |= u as u8;
        } else if u < u8::MAX as u64 {
            vec[0] |= 24;
            vec.extend(&(u as u8).to_be_bytes());
        } else if u < u16::MAX as u64 {
            vec[0] |= 25;
            vec.extend(&(u as u16).to_be_bytes());
        } else if u < u32::MAX as u64 {
            vec[0] |= 26;
            vec.extend(&(u as u32).to_be_bytes());
        } else {
            vec[0] |= 27;
            vec.extend(&u.to_be_bytes());
        }
        vec
    }
}

struct ECCCurve {
    p: BigInt,
    a: BigInt,
    b: BigInt,
    l: usize,
}

/*
impl ECCCurve {
  fn load_curve(&self, ecc_type: i64) {
  self.p = BigInt::parse_bytes(b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16).unwrap();
  self.a = BigInt::parse_bytes(b"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16).unwrap();
  self.b = BigInt::parse_bytes(b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16).unwrap();


  }
}
*/
/*
[package]
name = "c509"
version = "0.3.0"
authors = ["John Preuß Mattsson <john.mattsson@ericsson.com>"]
edition = "2018"


# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html


[dependencies]
asn1 = "0.16"
asn1-rs = "0.6.1"
cbor = "0.4.1"
serde_cbor = "0.11"
brotli = "3.3"
chrono = "0.4"
colored = "2"
hex = "0.4"
num-traits = "0.2"
num-bigint = "0.4"
oid = "0.2"
regex = "1"
rustls = "0.19"
secp256k1 = "0.29.0"
webpki = "0.21"
webpki-roots = "0.21"
bit_reverse = "0.1.8"
#env_logger = "0.11"
*/
