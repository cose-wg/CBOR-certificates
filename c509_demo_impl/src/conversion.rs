//! Top-level X.509 ↔ C509 conversion logic.
//!
//! Entry points:
//! - [`parse_x509_item`] / [`parse_x509_cert`] / [`parse_x509_csr`] — DER → C509 CBOR
//! - [`parse_c509_item`] / [`parse_c509_cert`] / [`parse_c509_csr`] — C509 CBOR → DER
//!
//! The C509 certificate is a flat CBOR sequence of 11 fields (draft §7):
//! `[type, serialNumber, sigAlg, issuer, notBefore, notAfter, subject,
//!   subjectPKAlg, subjectPK, extensions, sigValue]`
//!
//! The C509 CSR is a flat CBOR sequence of 7 fields (draft §8):
//! `[type, sigAlg, subject, subjectPKAlg, subjectPK, attributes, sigValue]`

use crate::lder::*;
use crate::lcbor::*;
use crate::registry::*;
use crate::help::*;
use crate::*;
use crate::extensions::*;
use crate::keys::*;
use asn1_rs::ToDer;
use std::str::from_utf8;
use serde_cbor::Value;
use std::io::Cursor;
use log::{trace, warn};
use chrono::TimeZone;

/// C509 "singleton array" optimisation (draft §7.1): when a Name contains exactly
/// one attribute whose C509 id encodes as a single byte `t`, omit the outer array
/// and return just the value.  Otherwise return a CBOR array of all elements.
pub(crate) fn cbor_opt_array(vec: &[Vec<u8>], t: u8) -> Vec<u8> {
    if vec.len() == 2 && vec[0] == [t] {
        vec[1].clone()
    } else {
        lcbor_array(vec)
    }
}

/// Maps a C509 attribute type ID (draft §9.3) back to a full DER-encoded OID TLV.
///
/// Used during C509→X.509 decoding to reconstruct `AttributeTypeAndValue` SEQUENCEs.
/// IDs without an entry here are unknown and will panic.
pub(crate) fn map_att_id_to_oid(id: i64) -> Vec<u8> {
    match id {
        0 => vec![0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01],
        1 => vec![0x06, 0x03, 0x55, 0x04, 0x03],
        2 => vec![0x06, 0x03, 0x55, 0x04, 0x04],
        3 => vec![0x06, 0x03, 0x55, 0x04, 0x05],
        4 => vec![0x06, 0x03, 0x55, 0x04, 0x06],
        5 => vec![0x06, 0x03, 0x55, 0x04, 0x07],
        6 => vec![0x06, 0x03, 0x55, 0x04, 0x08],
        7 => vec![0x06, 0x03, 0x55, 0x04, 0x09],
        8 => vec![0x06, 0x03, 0x55, 0x04, 0x0A],
        9 => vec![0x06, 0x03, 0x55, 0x04, 0x0B],
        10 => vec![0x06, 0x03, 0x55, 0x04, 0x0C],
        11 => vec![0x06, 0x03, 0x55, 0x04, 0x0F],
        12 => vec![0x06, 0x03, 0x55, 0x04, 0x11],
        13 => vec![0x06, 0x03, 0x55, 0x04, 0x2A],
        14 => vec![0x06, 0x03, 0x55, 0x04, 0x2B],
        15 => vec![0x06, 0x03, 0x55, 0x04, 0x2C],
        16 => vec![0x06, 0x03, 0x55, 0x04, 0x2E],
        17 => vec![0x06, 0x03, 0x55, 0x04, 0x41],
        18 => vec![0x06, 0x03, 0x55, 0x04, 0x61],
        19 => vec![0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x01],
        20 => vec![0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x02],
        21 => vec![0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x03],
        22 => vec![0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19],
        25 => vec![0x06, 0x03, 0x55, 0x04, 0x29],
        26 => vec![0x06, 0x03, 0x55, 0x04, 0x14],
        27 => vec![0x06, 0x03, 0x55, 0x04, 0x36],
        28 => vec![0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01],
        29 => vec![0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02],
        30 => vec![0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x08],
        _ => panic!("Unknown attribute id {}", id),
    }
}

/// Encodes a u64 as a minimal big-endian byte string (no leading zeros, unless value is 0).
pub(crate) fn uint_to_minimal_bytes(v: u64) -> Vec<u8> {
    if v == 0 { return vec![0]; }
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[start..].to_vec()
}

/// Encodes a u64 as a DER context-specific implicit INTEGER with the given tag nibble (0 or 1).
pub(crate) fn uint_to_implicit_der(tag: u8, v: u64) -> Vec<u8> {
    let val_bytes = uint_to_minimal_bytes(v);
    let mut result = vec![0x80 | tag, val_bytes.len() as u8];
    result.extend(val_bytes);
    result
}


/// Decodes a C509 CBOR certificate back into an X.509 DER certificate.
///
/// Panics if the input is not valid C509 CBOR.
pub fn parse_c509_cert(cbor: Vec<u8>) -> Cert {
    let cursor = Cursor::new(cbor);
    let deserializer = serde_cbor::Deserializer::from_reader(cursor);
    let mut elements = Vec::new();
    let mut it = deserializer.into_iter::<Value>();
    while let Some(Ok(v)) = it.next() { elements.push(v); }
    if elements.is_empty() { panic!("Empty CBOR data"); }
    let elements = if elements.len() == 1 {
        if let Value::Array(arr) = &elements[0] { arr.clone() } else { elements }
    } else { elements };

    let mut cbor_components = Vec::new();
    for e in &elements {
        let mut buf = Vec::new();
        serde_cbor::to_writer(&mut buf, e).unwrap();
        cbor_components.push(buf);
    }

    let serial_number_vec = match &elements[1] {
        Value::Bytes(b) => b.to_vec(),
        Value::Integer(i) => {
            let mut b = (*i as u128).to_be_bytes().to_vec();
            while b.len() > 1 && b[0] == 0 { b.remove(0); }
            b
        }
        _ => panic!("Serial missing")
    };
    let (sig_alg, _) = parse_cbor_sig_info(&elements[2], &elements[10]);
    let (not_before, _) = parse_cbor_time(&elements[4]);
    let (not_after, _) = parse_cbor_time(&elements[5]);
    let subject = parse_cbor_name(&elements[6]);
    let issuer = if elements[3] == Value::Null { subject.clone() } else { parse_cbor_name(&elements[3]) };
    let (subject_pka, subject_pka_oid) = map_pk_id_to_oid(&elements[7]);

    let mut tbs_cert_vec = vec![
        ASN1_X509_VERSION_3.to_vec(),
        lder_to_pos_int(serial_number_vec),
        sig_alg.clone(),
        issuer,
        lder_to_two_seq(not_before, not_after),
        subject,
        parse_cbor_pub_key(&elements[8], subject_pka, subject_pka_oid),
    ];
    // 'extensions' (CBOR null) means "no extensions" — per RFC 5280,
    // Extensions ::= SEQUENCE SIZE (1..MAX), so the [3] EXPLICIT field
    // must be omitted entirely rather than encoded as an empty SEQUENCE.
    if elements[9] != Value::Null {
        tbs_cert_vec.push(parse_cbor_extensions(&elements[9]));
    }

    let (_, sig_val) = parse_cbor_sig_info(&elements[2], &elements[10]);
    let certificate_vec = vec![lder_to_seq(tbs_cert_vec), sig_alg, lder_to_bit_str(sig_val)];

    Cert { der: lder_to_seq(certificate_vec), cbor: cbor_components }
}


pub(crate) fn parse_cbor_hex_cn(cn: &[u8]) -> Vec<u8> {
    let mut my_string = String::new();
    for b in cn { my_string.push_str(&format!("{:02x}", b)); }
    my_string.into_bytes()
}

pub(crate) fn parse_cbor_eui64(cn: &[u8]) -> Vec<u8> {
    let mut my_string = String::new();
    for i in 0..cn.len() {
        my_string.push_str(&format!("{:02X}", cn[i]));
        if i == 2 && cn.len() == 6 { my_string.push_str("-FF-FE"); }
        if i < cn.len() - 1 { my_string.push('-'); }
    }
    my_string.into_bytes()
}

pub(crate) fn parse_cbor_name(input: &Value) -> Vec<u8> {
    let mut result_vec = Vec::new();
    match input {
        Value::Null => return Vec::new(),
        Value::Text(name) => {
            let attr_type_and_val = lder_to_two_seq(ATT_COMMON_NAME_OID.to_der_vec().unwrap(), lder_to_generic(name.as_bytes().to_vec(), ASN1_UTF8_STR));
            result_vec.push(lder_to_generic(attr_type_and_val, ASN1_SET));
        }
        Value::Bytes(b) => {
            let cn = parse_cbor_hex_cn(b);
            let attr_type_and_val = lder_to_two_seq(ATT_COMMON_NAME_OID.to_der_vec().unwrap(), lder_to_generic(cn, ASN1_UTF8_STR));
            result_vec.push(lder_to_generic(attr_type_and_val, ASN1_SET));
        }
        Value::Tag(48, inner) => {
            let b = match inner.as_ref() {
                Value::Bytes(b) => b.as_slice(),
                _ => panic!("Expected bytes inside tag(48)"),
            };
            let cn = parse_cbor_eui64(b);
            let attr_type_and_val = lder_to_two_seq(ATT_COMMON_NAME_OID.to_der_vec().unwrap(), lder_to_generic(cn, ASN1_UTF8_STR));
            result_vec.push(lder_to_generic(attr_type_and_val, ASN1_SET));
        }
        Value::Array(name_elements) => {
            for i in (0..name_elements.len()).step_by(2) {
                let attr_type_and_val = match &name_elements[i] {
                    Value::Integer(attribute) => {
                        let (oid, tag) = match attribute.unsigned_abs() as u32 {
                            0 => (ATT_EMAIL_OID, ASN1_IA5_STR),
                            1 => (ATT_COMMON_NAME_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            2 => (ATT_SUR_NAME_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            3 => (ATT_SERIAL_NUMBER_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            4 => (ATT_COUNTRY_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            5 => (ATT_LOCALITY_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            6 => (ATT_STATE_OR_PROVINCE_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            7 => (ATT_STREET_ADDRESS_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            8 => (ATT_ORGANIZATION_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            9 => (ATT_ORGANIZATION_UNIT_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            10 => (ATT_TITLE_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            11 => (ATT_BUSINESS_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            12 => (ATT_POSTAL_CODE_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            13 => (ATT_GIVEN_NAME_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            14 => (ATT_INITIALS_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            15 => (ATT_GENERATION_QUALIFIER_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            16 => (ATT_DN_QUALIFIER_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            17 => (ATT_PSEUDONYM_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            18 => (ATT_ORG_ID_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            19 => (ATT_INC_LOCALITY_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            20 => (ATT_INC_STATE_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            21 => (ATT_INC_COUNTRY_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            22 => (ATT_DOMAIN_COMPONENT_OID, ASN1_IA5_STR),
                            25 => (ATT_NAME_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            26 => (ATT_TELEPHONE_NUMBER_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            27 => (ATT_DIR_MAN_DOMAIN_NAME_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            28 => (ATT_USER_ID_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            29 => (ATT_UNSTRUCTURED_NAME_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            30 => (ATT_UNSTRUCTURED_ADDRESS_OID, if *attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            _ => panic!("Unknown attribute format: {}", attribute),
                        };
                        let value = match &name_elements[i + 1] {
                            Value::Text(text_value) => text_value.as_bytes(),
                            _ => panic!("Unknown attribute value format'"),
                        };
                        lder_to_two_seq(oid.to_der_vec().unwrap(), lder_to_generic(value.to_vec(), tag))
                    }
                    Value::Bytes(raw_oid) => {
                        let value = match &name_elements[i + 1] { Value::Bytes(raw_val) => raw_val, _ => panic!("Value missing") };
                        lder_to_two_seq(lder_to_generic(raw_oid.to_vec(), ASN1_OID), value.to_vec())
                    }
                    _ => panic!("Unknown attribute format'"),
                };
                result_vec.push(lder_to_generic(attr_type_and_val, ASN1_SET));
            }
        }
        _ => panic!("Unknown RDN value."),
    }
    lder_to_seq(result_vec)
}

pub(crate) fn parse_cbor_time(input: &Value) -> (Vec<u8>, i64) {
    let mut type_flag = ASN1_UTC_TIME;
    let (formatted_date, time_val) = match input {
        Value::Integer(val) => {
            let ts = chrono::Utc.timestamp_opt(*val as i64, 0).unwrap();
            if ASN1_UTC_TIME_MAX < *val as i64 {
                type_flag = ASN1_GEN_TIME;
                (ts.format("%Y%m%d%H%M%SZ").to_string(), *val)
            } else {
                (ts.format("%y%m%d%H%M%SZ").to_string(), *val)
            }
        }
        Value::Null => { type_flag = ASN1_GEN_TIME; (ASN1_GEN_TIME_MAX.to_string(), 0) }
        _ => panic!("Unknown time value."),
    };
    (lder_to_time(formatted_date, type_flag), time_val as i64)
}


pub(crate) fn cbor_name(b: &[u8]) -> Vec<u8> {
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
                    vec.push(lcbor_int(att_type));
                    let att_value = lder(der_value, ASN1_IA5_STR);
                    vec.push(lcbor_text(att_value));
                } else if der_value[0] == ASN1_PRINT_STR || der_value[0] == ASN1_UTF8_STR {
                    let sign: i64 = if der_value[0] == ASN1_PRINT_STR { -1 } else { 1 };
                    let att_value = lder(der_value, der_value[0]);
                    vec.push(lcbor_int(sign * att_type));
                    vec.push(lcbor_text(att_value));
                } else {
                    vec.push(lcbor_bytes(oid));
                    vec.push(lcbor_bytes(der_value));
                }
            } else {
                print_warning("No C509 int registered for attribute oid", attribute[0], oid);
                vec.push(lcbor_bytes(oid));
                vec.push(lcbor_bytes(der_value));
            }
        }
    }
    static EUI64_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static HEX_RE:   std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let eui_64 = EUI64_RE.get_or_init(|| regex::Regex::new(r"^([A-F\d]{2}-){7}[A-F\d]{2}$").unwrap());
    let is_hex = HEX_RE.get_or_init(|| regex::Regex::new(r"^(?:[A-Fa-f0-9]{2})*$").unwrap());
    if vec.len() == 2 && vec[0] == [ATT_COMMON_NAME as u8] {
        vec.remove(0);
        // vec[0] is a CBOR text string: [header_byte, text_bytes...]
        // All CN values handled here are < 24 chars so the header is exactly 1 byte.
        let text = &vec[0][1..];
        if eui_64.is_match(from_utf8(text).unwrap()) {
            let hex_str: String = from_utf8(text).unwrap()
                .chars()
                .filter(|&c| c != '-')
                .collect();
            let mut decoded = hex::decode(hex_str.to_uppercase()).unwrap();
            // EUI-64 with FFFE in middle bytes encodes as 6-byte EUI-48
            if decoded.len() == 8 && decoded[3] == 0xFF && decoded[4] == 0xFE {
                decoded.drain(3..5);
            }
            vec[0] = lcbor_tag(48, &lcbor_bytes(&decoded));
        } else if is_hex.is_match(from_utf8(text).unwrap()) {
            vec[0] = lcbor_bytes(&hex::decode(text).unwrap());
        }
        return vec[0].clone();
    }
    lcbor_array(&vec)
}


fn cbor_time(b: &[u8], pre_y2k_flag: u8) -> Vec<u8> {
    let time_string = if pre_y2k_flag == 1 {
        if b[0] == ASN1_UTC_TIME { [b"19", lder(b, ASN1_UTC_TIME)].concat() }
        else { lder(b, ASN1_GEN_TIME).to_vec() }
    } else if b[0] == ASN1_UTC_TIME {
        [b"20", lder(b, ASN1_UTC_TIME)].concat()
    } else {
        lder(b, ASN1_GEN_TIME).to_vec()
    };
    let time_string = from_utf8(&time_string).unwrap();
    match time_string {
        ASN1_GEN_TIME_MAX => lcbor_simple(CBOR_NULL),
        _ => lcbor_uint(chrono::NaiveDateTime::parse_from_str(time_string, "%Y%m%d%H%M%SZ").unwrap().and_utc().timestamp() as u64),
    }
}

/// Returns true if the DER bytes look like a PKCS#10 CSR (first element of TBSCertificate is
/// a plain INTEGER, not [0] EXPLICIT).
fn is_x509_csr(input: &[u8]) -> bool {
    if input.len() < 6 { return false; }
    let outer = lder_vec(input, ASN1_SEQ);
    if outer.is_empty() { return false; }
    let inner = lder_vec(outer[0], ASN1_SEQ);
    if inner.is_empty() { return false; }
    inner[0][0] != 0xa0  // cert version is [0] EXPLICIT; CSR version is plain INTEGER
}

/// Encodes an X.509 DER certificate into C509.
/// If input is a PKCS#10 CSR, encodes it as a C509 CSR instead.
/// When `no_compression` is true, EC public keys are stored uncompressed.
pub fn parse_x509_item(input: Vec<u8>, no_compression: bool) -> Cert {
    if is_x509_csr(&input) {
        parse_x509_csr(input, no_compression)
    } else {
        parse_x509_cert_nc(input, no_compression)
    }
}

/// Encodes a PKCS#10 DER CSR into a C509 type-3 (X.509-encoded) CBOR representation.
///
/// Output CBOR sequence per draft-ietf-cose-cbor-encoded-cert-20 Section 8:
///   [type=3, subjectSignatureAlgorithm, subject, subjectPKAlgorithm,
///    subjectPublicKey, attributes, subjectSignatureValue]
///
/// Attribute encoding (CRAttributes flat array):
///   extensionRequest (OID 1.2.840.113549.1.9.14) → [0, [ext_pairs...]]
///   challengePassword (OID 1.2.840.113549.1.9.7) → [1, text] or [1, tag(121, text)]
///     where tag 121 signals PrintableString; plain text signals UTF8String.
pub fn parse_x509_csr(input: Vec<u8>, no_compression: bool) -> Cert {
    let certificate = lder_vec_len(&input, ASN1_SEQ, 3);
    let cri = lder_vec(certificate[0], ASN1_SEQ);
    assert!(!cri.is_empty() && cri[0][0] == ASN1_INT, "Expected CSR version INTEGER");
    let subject = cri[1];
    let spki = lder_vec_len(cri[2], ASN1_SEQ, 2);
    let spki_alg = spki[0];
    let spki_key = lder(spki[1], ASN1_BIT_STR);
    assert!(spki_key[0] == 0, "Expected 0 unused bits in SubjectPublicKey");
    let spki_key = &spki_key[1..];

    let sig_alg = certificate[1];
    let sig_val = lder(certificate[2], ASN1_BIT_STR);
    assert!(sig_val[0] == 0, "Expected 0 unused bits in signature");
    let sig_val = &sig_val[1..];

    let mut output = Vec::new();
    output.push(lcbor_uint(C509_CSR_TYPE_X509_ENCODED as u64));

    // subjectSignatureAlgorithm (C509 CDDL field 1)
    if let Some(sig_type) = sig_map(sig_alg) {
        output.push(lcbor_int(sig_type));
    } else {
        // RFC 9090 OID fallback (§7.1 draft-ietf-cose-cbor-encoded-cert)
        let sig_seq = lder_vec(sig_alg, ASN1_SEQ);
        let oid_val = lder(sig_seq[0], ASN1_OID);
        if sig_seq.len() > 1 {
            output.push(lcbor_array(&[lcbor_bytes(oid_val), lcbor_bytes(sig_seq[1])]));
        } else {
            output.push(lcbor_array(&[lcbor_bytes(oid_val)]));
        }
    }

    output.push(cbor_name(subject));

    if let Some(pk_type) = pk_map(spki_alg) {
        output.push(lcbor_int(pk_type));
        if pk_type == PK_RSA {
            let rsa_pk = lder_vec_len(spki_key, ASN1_SEQ, 2);
            let n = lcbor_bytes(lder_uint(rsa_pk[0]));
            let e = lcbor_bytes(lder_uint(rsa_pk[1]));
            if e == [0x43, 0x01, 0x00, 0x01] { output.push(n); }
            else { output.push(lcbor_array(&[n, e])); }
        } else if [PK_SECP256R, PK_SECP384R, PK_SECP521R, PK_BRAINPOOL256R1, PK_BRAINPOOL384R1, PK_BRAINPOOL512R1, PK_FRP256V1].contains(&pk_type) {
            let coord_size = (spki_key.len() - 1) / 2;
            let secg_byte = spki_key[0];
            let x = &spki_key[1..1 + coord_size];
            if secg_byte == SECG_UNCOMPRESSED {
                let y = &spki_key[1 + coord_size..];
                if no_compression {
                    output.push(lcbor_bytes(&[&[SECG_UNCOMPRESSED], x, y].concat()));
                } else {
                    let prefix = if y[coord_size - 1] & 1 == 0 { SECG_EVEN_COMPRESSED } else { SECG_ODD_COMPRESSED };
                    output.push(lcbor_bytes(&[&[prefix], x].concat()));
                }
            } else if secg_byte == SECG_EVEN || secg_byte == SECG_ODD {
                output.push(lcbor_bytes(&[&[(-(secg_byte as i8)) as u8], x].concat()));
            } else {
                panic!("Unexpected SECG byte: 0x{:02x}", secg_byte);
            }
        } else {
            output.push(lcbor_bytes(spki_key));
        }
    } else {
        // RFC 9090 OID fallback (§7.1 draft-ietf-cose-cbor-encoded-cert)
        let spki_seq = lder_vec(spki_alg, ASN1_SEQ);
        let oid_val = lder(spki_seq[0], ASN1_OID);
        print_warning("No C509 int registered for public key algorithm", spki_alg, oid_val);
        if spki_seq.len() > 1 {
            output.push(lcbor_array(&[lcbor_bytes(oid_val), lcbor_bytes(spki_seq[1])]));
        } else {
            output.push(lcbor_array(&[lcbor_bytes(oid_val)]));
        }
        output.push(lcbor_bytes(spki_key));
    }

    // Encode attributes as flat CRAttributes array: [attrType, attrValue, ...]
    // extensionRequest OID: 1.2.840.113549.1.9.14
    const EXT_REQ_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E];
    // challengePassword OID: 1.2.840.113549.1.9.7
    const CHAL_PWD_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07];
    // PrivateKeyPossessionStatement OID: 1.3.6.1.4.1.22112.2.1
    const PRIV_KEY_POSS_STMT_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xAC, 0x60, 0x02, 0x01];
    let mut full_attrs_vec: Vec<Vec<u8>> = Vec::new();
    if cri.len() > 3 {
        let attrs_raw = cri[3];  // [0] IMPLICIT SET OF Attribute
        let attrs_content = lder(attrs_raw, 0xa0);
        let mut rest = attrs_content;
        while !rest.is_empty() {
            let (attr_tlv, next) = lder_split(rest, false);
            rest = next;
            let av = lder_vec_len(attr_tlv, ASN1_SEQ, 2);
            let attr_oid = lder(av[0], ASN1_OID);
            let attr_vals = lder_vec(av[1], ASN1_SET);
            if attr_oid == EXT_REQ_OID {
                let mut exts_vec: Vec<Vec<u8>> = Vec::new();
                for ext_seq in &attr_vals {
                    let extensions = lder_vec(ext_seq, ASN1_SEQ);
                    for e in &extensions {
                        let ext = lder_vec(e, ASN1_SEQ);
                        let oid = lder(ext[0], ASN1_OID);
                        let mut crit_sign: i64 = 1;
                        if ext.len() == 3 { crit_sign = -1; }
                        let extn_value = lder(ext[ext.len() - 1], ASN1_OCTET_STR);
                        if let Some(ext_type) = ext_map(oid) {
                            if extensions.len() == 1 && ext_type == EXT_KEY_USAGE {
                                exts_vec.push(lcbor_int(ext_type as i64));
                            } else {
                                exts_vec.push(lcbor_int(crit_sign * ext_type as i64));
                            }
                            exts_vec.push(match ext_type {
                                EXT_SUBJECT_KEY_ID => lcbor_bytes(lder(extn_value, ASN1_OCTET_STR)),
                                EXT_KEY_USAGE => cbor_ext_key_use(extn_value, crit_sign * extensions.len() as i64),
                                EXT_SUBJECT_ALT_NAME => cbor_general_names(extn_value, ASN1_SEQ, 2),
                                EXT_BASIC_CONSTRAINTS => cbor_ext_bas_con(extn_value),
                                EXT_CRL_DIST_POINTS | EXT_FRESHEST_CRL => cbor_ext_crl_dist(extn_value),
                                EXT_CERT_POLICIES => cbor_ext_cert_policies(extn_value),
                                EXT_AUTH_KEY_ID => cbor_ext_auth_key_id(extn_value),
                                EXT_EXT_KEY_USAGE => cbor_ext_eku(extn_value),
                                EXT_AUTH_INFO | EXT_SUBJECT_INFO_ACCESS => cbor_ext_info_access(extn_value),
                                EXT_ISSUER_ALT_NAME => cbor_general_names(extn_value, ASN1_SEQ, 2),
                                EXT_SUBJECT_DIRECTORY_ATTR => cbor_ext_subject_directory_attr(extn_value),
                                EXT_NAME_CONSTRAINTS => cbor_ext_name_constraints(extn_value),
                                EXT_POLICY_MAPPINGS => cbor_ext_policy_mappings(extn_value),
                                EXT_POLICY_CONSTRAINTS => cbor_ext_policy_constraints(extn_value),
                                EXT_INHIBIT_ANYPOLICY => cbor_ext_inhibit_any_policy(extn_value),
                                EXT_IP_ADDR_BLOCKS | EXT_IP_ADDR_BLOCKS_V2 => cbor_ext_ip_addr_blocks(extn_value),
                                EXT_AS_IDENTIFIERS | EXT_AS_IDENTIFIERS_V2 => cbor_ext_as_identifiers(extn_value),
                                _ => cbor_store_only(extn_value, ext[0], oid),
                            });
                        } else {
                            print_warning("No C509 int registered for CSR extension OID", ext[0], oid);
                            exts_vec.push(lcbor_bytes(oid));
                            if crit_sign == -1 { exts_vec.push(lcbor_simple(CBOR_TRUE)); }
                            exts_vec.push(lcbor_bytes(extn_value));
                        }
                    }
                }
                full_attrs_vec.push(lcbor_int(0)); // extensionRequest attr type
                full_attrs_vec.push(lcbor_array(&exts_vec));
            } else if attr_oid == CHAL_PWD_OID {
                // challengePassword: PrintableString → tag 121, UTF8String → plain text
                let cp_raw = attr_vals[0];
                let cp_tag = cp_raw[0];
                let cp_str = lder(cp_raw, cp_tag);
                let text = from_utf8(cp_str).unwrap();
                full_attrs_vec.push(lcbor_int(1)); // challengePassword attr type
                if cp_tag == ASN1_PRINT_STR {
                    full_attrs_vec.push(lcbor_tag(121, &lcbor_text(text.as_bytes())));
                } else {
                    full_attrs_vec.push(lcbor_text(text.as_bytes()));
                }
            } else if attr_oid == PRIV_KEY_POSS_STMT_OID {
                // PrivateKeyPossessionStatement (RFC 9883 / C509 attr ID 2):
                // DER: SEQUENCE { SEQUENCE { Name, INTEGER } [, Certificate] }
                // C509: [issuer: Name, serial: bytes, cert: C509Certificate / null]
                let outer = lder_vec(attr_vals[0], ASN1_SEQ);
                let inner = lder_vec(outer[0], ASN1_SEQ);
                let issuer_der = inner[0];
                let serial_der = inner[1];
                let cert_cbor = if outer.len() > 1 {
                    let embedded = parse_x509_cert_nc(outer[1].to_vec(), false);
                    // draft-ietf-cose-cbor-encoded-cert-20:
                    // PrivateKeyPossessionStatement.cert : C509CertData =
                    // bytes .cbor C509Certificate — byte-string-wrap the cert array
                    // (was the bare array in -19).
                    lcbor_bytes(&lcbor_array(&embedded.cbor))
                } else {
                    lcbor_simple(CBOR_NULL)
                };
                let pks = lcbor_array(&[cbor_name(issuer_der), lcbor_bytes(lder_uint(serial_der)), cert_cbor]);
                full_attrs_vec.push(lcbor_int(2));
                full_attrs_vec.push(pks);
            } else {
                print_warning("No C509 int registered for CSR attribute OID", av[0], attr_oid);
                full_attrs_vec.push(lcbor_bytes(attr_oid));
                full_attrs_vec.push(lcbor_bytes(av[1]));
            }
        }
    }
    output.push(lcbor_array(&full_attrs_vec));

    if let Some(sig_type) = sig_map(sig_alg) {
        if [SIG_ECDSA_SHA1, SIG_ECDSA_SHA256, SIG_ECDSA_SHA384, SIG_ECDSA_SHA512, SIG_ECDSA_SHAKE128, SIG_ECDSA_SHAKE256, SIG_SM2_V15_SM3].contains(&sig_type) {
            output.push(cbor_ecdsa(sig_val));
        } else if [SIG_ECDHPOP_SHA256, SIG_ECDHPOP_SHA384, SIG_ECDHPOP_SHA512].contains(&sig_type) {
            // dhsig sig = SEQUENCE { [keyRef: SEQUENCE { Name, INTEGER }], OCTET STRING { mac } }
            // C509 type-3: no keyRef → bytes(mac); with keyRef → [issuer, serial, mac_bytes]
            let seq_items = lder_vec(sig_val, ASN1_SEQ);
            let mac = lder(seq_items[seq_items.len() - 1], ASN1_OCTET_STR);
            if seq_items.len() > 1 {
                let key_ref = lder_vec(seq_items[0], ASN1_SEQ);
                output.push(lcbor_array(&[
                    cbor_name(key_ref[0]),
                    lcbor_bytes(lder_uint(key_ref[1])),
                    lcbor_bytes(mac),
                ]));
            } else {
                output.push(lcbor_bytes(mac));
            }
        } else {
            output.push(lcbor_bytes(sig_val));
        }
    } else {
        output.push(lcbor_bytes(sig_val));
    }

    Cert { der: input, cbor: output }
}

/// Auto-detect whether a C509 CBOR byte string is a certificate or a CSR,
/// then dispatch to the appropriate decoder.
///
/// Discrimination is by element count in the top-level CBOR sequence:
///   11 elements → C509 Certificate (fields: type, serial, sigAlg, issuer,
///                  notBefore, notAfter, subject, pkAlg, pkKey, exts, sigVal)
///    7 elements → C509 Certification Request (fields: type, sigAlg, subject,
///                  pkAlg, pkKey, attrs, sigVal)
///
/// Any other count indicates malformed input and will propagate to the
/// specific decoder's panic.
pub fn parse_c509_item(cbor: Vec<u8>) -> Cert {
    // Peek at element count without consuming the input.
    let cursor = Cursor::new(&cbor);
    let deserializer = serde_cbor::Deserializer::from_reader(cursor);
    let mut peek: Vec<Value> = Vec::new();
    for v in deserializer.into_iter::<Value>() {
        if let Ok(val) = v { peek.push(val); } else { break; }
    }
    let n = if peek.len() == 1 {
        if let Value::Array(arr) = &peek[0] { arr.len() } else { peek.len() }
    } else {
        peek.len()
    };

    if n == 7 {
        // CRT (C509CertificationRequestTemplate) has templateType = uint(0); a CSR
        // has c509CertificationRequestType = uint(2)/uint(3). Read the first field
        // from the (possibly array-wrapped, draft-20) peeked value rather than the
        // raw first byte — which in draft-20 is the 0x87 array header.
        let first_field = if peek.len() == 1 {
            if let Value::Array(arr) = &peek[0] { arr.first().cloned() } else { peek.first().cloned() }
        } else {
            peek.first().cloned()
        };
        if first_field == Some(Value::Integer(0)) {
            return parse_c509_crt(cbor);
        }
        parse_c509_csr(cbor)
    } else {
        parse_c509_cert(cbor)
    }
}

/// Parse a C509 CertificationRequestTemplate (CRT) — a flat CBOR sequence of
/// 7 items whose first element is uint(0) (templateType).
///
/// CRTs have no X.509 DER equivalent.  This function splits the raw bytes into
/// 7 individual field slices so that `Cert.cbor.concat()` returns the original
/// bytes unchanged — a lossless byte-exact round-trip.
pub fn parse_c509_crt(cbor: Vec<u8>) -> Cert {
    use crate::lcbor::cbor_item_end;
    let mut fields: Vec<Vec<u8>> = Vec::with_capacity(7);
    // draft-20: the CRT is a CBOR array (0x87 header). Skip the array header so
    // the 7 inner fields are stored individually; `print_information` re-wraps them
    // with `lcbor_array`, reproducing the original bytes exactly (a pre-20 bare
    // sequence has no header — first byte 0x00 — and is walked from position 0).
    let mut pos = if !cbor.is_empty() && (cbor[0] >> 5) == 4 { 1 } else { 0 };
    for i in 0..7 {
        assert!(pos < cbor.len(), "parse_c509_crt: ran out of data at field {}", i);
        let end = cbor_item_end(&cbor, pos);
        fields.push(cbor[pos..end].to_vec());
        pos = end;
    }
    Cert { der: vec![], cbor: fields }
}

/// Decodes a C509 type-3 (X.509-encoded) CSR back to PKCS#10 DER (RFC 2986).
///
/// Reconstructs the full CertificationRequest structure:
///   SEQUENCE { CertificationRequestInfo, signatureAlgorithm, signature BIT STRING }
///
/// Supported attribute types:
///   0 (extensionRequest): value is decoded as a C509 extensions array
///   1 (challengePassword): tag(121) → PrintableString; plain text → UTF8String
///   raw OID bytes: stored and restored verbatim as unknown attributes
pub fn parse_c509_csr(cbor: Vec<u8>) -> Cert {
    let bytes = cbor;
    let cursor = Cursor::new(bytes);
    let deserializer = serde_cbor::Deserializer::from_reader(cursor);
    let mut elements: Vec<Value> = Vec::new();
    let mut it = deserializer.into_iter::<Value>();
    while let Some(Ok(v)) = it.next() { elements.push(v); }
    if elements.is_empty() { panic!("Empty CBOR data"); }
    let elements = if elements.len() == 1 {
        if let Value::Array(arr) = &elements[0] { arr.clone() } else { elements }
    } else { elements };

    let mut cbor_components = Vec::new();
    for e in &elements {
        let mut buf = Vec::new();
        serde_cbor::to_writer(&mut buf, e).unwrap();
        cbor_components.push(buf);
    }

    // elements: [type, sigAlg, subject, pkAlg, pkKey, attributes, sigValue]
    let (sig_alg_der, _) = parse_cbor_sig_info(&elements[1], &elements[6]);
    let subject_der = parse_cbor_name(&elements[2]);
    let (pk_type, pk_oid) = map_pk_id_to_oid(&elements[3]);
    let spki_der = parse_cbor_pub_key(&elements[4], pk_type, pk_oid);

    // Reconstruct attributes [0] IMPLICIT
    // extensionRequest OID DER: 06 09 2a 86 48 86 f7 0d 01 09 0e
    const EXT_REQ_OID_DER: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E];
    // challengePassword OID DER: 06 09 2a 86 48 86 f7 0d 01 09 07
    const CHAL_PWD_OID_DER: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07];
    let mut attrs_der: Vec<Vec<u8>> = Vec::new();
    if let Value::Array(attr_array) = &elements[5] {
        let mut i = 0;
        while i < attr_array.len() {
            match &attr_array[i] {
                Value::Integer(attr_type) => {
                    let val = &attr_array[i + 1];
                    i += 2;
                    match *attr_type {
                        0 => {
                            // extensionRequest: value is extensions array
                            let exts_seq = lder_to_seq(parse_cbor_extensions_inner(val));
                            let attr_seq = lder_to_seq(vec![
                                EXT_REQ_OID_DER.to_vec(),
                                lder_to_gen_seq(vec![exts_seq], ASN1_SET),
                            ]);
                            attrs_der.push(attr_seq);
                        }
                        1 => {
                            // challengePassword: text or tag(121, text)
                            let cp_der = match val {
                                Value::Text(s) => lder_to_generic(s.as_bytes().to_vec(), ASN1_UTF8_STR),
                                Value::Tag(121, inner) => {
                                    if let Value::Text(s) = inner.as_ref() {
                                        lder_to_generic(s.as_bytes().to_vec(), ASN1_PRINT_STR)
                                    } else { panic!("Expected text in tag 121") }
                                }
                                _ => panic!("Unexpected challengePassword value"),
                            };
                            let attr_seq = lder_to_seq(vec![
                                CHAL_PWD_OID_DER.to_vec(),
                                lder_to_gen_seq(vec![cp_der], ASN1_SET),
                            ]);
                            attrs_der.push(attr_seq);
                        }
                        2 => {
                            // PrivateKeyPossessionStatement (RFC 9883 / C509 §7.2 attr type 2).
                            // C509 encoding: [issuer_cbor, serial_bytes, cert_cbor_or_null]
                            // Reconstruct DER:
                            //   SEQUENCE { SEQUENCE { Name, INTEGER } [, Certificate] }
                            // wrapped in the attribute SET and OID.
                            const PRIV_KEY_POSS_STMT_OID_DER: &[u8] = &[
                                0x06, 0x0A, // OID tag + length 10
                                0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xAC, 0x60, 0x02, 0x01,
                            ];
                            if let Value::Array(pks) = val {
                                let issuer_der = parse_cbor_name(pks.first().expect("pks: missing issuer"));
                                let serial_bytes = get_as_bytes(pks.get(1).expect("pks: missing serial"));
                                let serial_der = lder_to_pos_int(serial_bytes.to_vec());
                                let inner_seq = lder_to_two_seq(issuer_der, serial_der);
                                let mut outer_items = vec![inner_seq];
                                if let Some(cert_val) = pks.get(2) {
                                    if *cert_val != Value::Null {
                                        // Embedded C509 certificate: decode back to DER
                                        let embedded_cbor = match cert_val {
                                            // draft-20: bytes .cbor C509Certificate —
                                            // the byte string content is the CBOR cert.
                                            Value::Bytes(b) => b.clone(),
                                            // draft-19 and earlier: the cert array placed
                                            // directly (no bytes .cbor wrapper).
                                            Value::Array(arr) => {
                                                let mut buf = Vec::new();
                                                serde_cbor::to_writer(&mut buf, &Value::Array(arr.clone())).unwrap();
                                                buf
                                            }
                                            _ => panic!("pks: embedded cert must be bytes or array"),
                                        };
                                        let embedded_cert = parse_c509_cert(embedded_cbor);
                                        outer_items.push(embedded_cert.der);
                                    }
                                }
                                let outer_seq = lder_to_seq(outer_items);
                                let attr_set = lder_to_gen_seq(vec![outer_seq], ASN1_SET);
                                attrs_der.push(lder_to_seq(vec![PRIV_KEY_POSS_STMT_OID_DER.to_vec(), attr_set]));
                            } else {
                                panic!("pks attr value must be array");
                            }
                        }
                        _ => panic!("Unknown CSR attribute type {}", attr_type),
                    }
                }
                Value::Bytes(raw_oid) => {
                    let oid_der = lder_to_generic(raw_oid.to_vec(), ASN1_OID);
                    let val_bytes = match &attr_array[i + 1] {
                        Value::Bytes(b) => b.to_vec(),
                        _ => panic!("Expected bytes for unknown attribute value"),
                    };
                    attrs_der.push(lder_to_seq(vec![oid_der, val_bytes]));
                    i += 2;
                }
                _ => panic!("Unexpected attribute type element"),
            }
        }
    }
    let attributes_implicit = lder_to_gen_seq(attrs_der, 0xa0);

    // version INTEGER 0
    let version_der = lder_to_generic(vec![0x00], ASN1_INT);

    let cri_der = lder_to_seq(vec![version_der, subject_der, spki_der, attributes_implicit]);

    // subjectSignatureValue
    let (_, sig_val_bytes) = parse_cbor_sig_info(&elements[1], &elements[6]);
    let sig_bit_str = lder_to_bit_str(sig_val_bytes);

    let csr_der = lder_to_seq(vec![cri_der, sig_alg_der, sig_bit_str]);

    Cert { der: csr_der, cbor: cbor_components }
}

/// Encodes an X.509 DER certificate into C509 CBOR (type 3, compressed EC keys).
///
/// This is the standard entry point for DER → C509 encoding. Use [`parse_x509_item`]
/// to auto-detect cert vs. CSR; its `no_compression` argument disables EC key
/// compression (the `-nc` CLI flag).
pub fn parse_x509_cert(der: Vec<u8>) -> Cert {
    parse_x509_cert_nc(der, false)
}

/// Encodes an X.509 DER certificate into C509 CBOR representation.
/// When `no_compression` is true, EC public keys are stored uncompressed (04-prefixed bytes).
pub(crate) fn parse_x509_cert_nc(input: Vec<u8>, no_compression: bool) -> Cert {
    trace!("Parsing X.509: {:02x?}", input);
    let mut output = Vec::new();

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
    let spki_algorithm = subject_public_key_info[0];
    let subject_public_key = lder(subject_public_key_info[1], ASN1_BIT_STR);
    let extensions = lder_vec(lder(tbs_certificate[7], 0xa3), ASN1_SEQ);
    let signature_value = lder(certificate[2], ASN1_BIT_STR);

    assert!(lder(version, ASN1_INT)[0] == 2, "Expected X.509 v3!");
    output.push(lcbor_uint(C509_TYPE_X509_ENCODED as u64));
    output.push(lcbor_bytes(serial_number));

    if let Some(sig_type) = sig_map(signature_algorithm) {
        output.push(lcbor_int(sig_type));
    } else {
        // RFC 9090 OID fallback (§2.2 draft-ietf-cose-cbor-encoded-cert):
        // encode as [~oid] or [~oid, params_der] where ~oid = OID value bytes only.
        let sig_seq = lder_vec(signature_algorithm, ASN1_SEQ);
        let oid_val = lder(sig_seq[0], ASN1_OID);
        print_warning("No C509 int registered for signature algorithm", signature_algorithm, oid_val);
        if sig_seq.len() > 1 {
            output.push(lcbor_array(&[lcbor_bytes(oid_val), lcbor_bytes(sig_seq[1])]));
        } else {
            output.push(lcbor_array(&[lcbor_bytes(oid_val)]));
        }
    }
    assert!(signature_algorithm == signature, "signature_algorithm != signature in TBSCertificate");

    if issuer == subject {
        output.push(lcbor_simple(CBOR_NULL));
    } else {
        output.push(cbor_name(issuer));
    }

    let c_not_before = cbor_time(not_before, 0);
    let c_not_after = cbor_time(not_after, 0);
    if c_not_after < c_not_before {
        warn!("Pre-2000 time detected, adjusting");
        output.push(cbor_time(not_before, 1));
    } else {
        output.push(c_not_before);
    }
    output.push(c_not_after);

    output.push(cbor_name(subject));

    assert!(subject_public_key[0] == 0, "Expected 0 unused bits in SubjectPublicKey");
    let subject_public_key = &subject_public_key[1..];
    if let Some(pk_type) = pk_map(spki_algorithm) {
        output.push(lcbor_int(pk_type));
        if pk_type == PK_RSA {
            let rsa_pk = lder_vec_len(subject_public_key, ASN1_SEQ, 2);
            let n = lcbor_bytes(lder_uint(rsa_pk[0]));
            let e = lcbor_bytes(lder_uint(rsa_pk[1]));
            if e == [0x43, 0x01, 0x00, 0x01] { output.push(n); }
            else { output.push(lcbor_array(&[n, e])); }
        } else if [PK_SECP256R, PK_SECP384R, PK_SECP521R, PK_BRAINPOOL256R1, PK_BRAINPOOL384R1, PK_BRAINPOOL512R1, PK_FRP256V1].contains(&pk_type) {
            assert!(subject_public_key.len() % 2 == 1, "Expected odd public key length");
            let coord_size = (subject_public_key.len() - 1) / 2;
            let secg_byte = subject_public_key[0];
            let x = &subject_public_key[1..1 + coord_size];
            if no_compression {
                output.push(lcbor_bytes(subject_public_key));
            } else if secg_byte == SECG_UNCOMPRESSED {
                let y = &subject_public_key[1 + coord_size..];
                let prefix = if y[coord_size - 1] & 1 == 0 { SECG_EVEN_COMPRESSED } else { SECG_ODD_COMPRESSED };
                output.push(lcbor_bytes(&[&[prefix], x].concat()));
            } else if secg_byte == SECG_EVEN || secg_byte == SECG_ODD {
                output.push(lcbor_bytes(&[&[(-(secg_byte as i8)) as u8], x].concat()));
            } else {
                panic!("Unexpected SECG byte: 0x{:02x}", secg_byte);
            }
        } else {
            output.push(lcbor_bytes(subject_public_key));
        }
    } else {
        // RFC 9090 OID fallback (§2.3.3 draft-ietf-cose-cbor-encoded-cert):
        // encode as [~oid] or [~oid, params_der] where ~oid = OID value bytes only.
        let spki_seq = lder_vec(spki_algorithm, ASN1_SEQ);
        let oid_val = lder(spki_seq[0], ASN1_OID);
        print_warning("No C509 int registered for public key algorithm", spki_algorithm, oid_val);
        if spki_seq.len() > 1 {
            output.push(lcbor_array(&[lcbor_bytes(oid_val), lcbor_bytes(spki_seq[1])]));
        } else {
            output.push(lcbor_array(&[lcbor_bytes(oid_val)]));
        }
        output.push(lcbor_bytes(subject_public_key));
    }

    let mut vec = Vec::new();
    for e in &extensions {
        let extension = lder_vec(e, ASN1_SEQ);
        assert!(extension.len() < 4, "Expected extension length 2 or 3");
        let oid = lder(extension[0], ASN1_OID);
        let mut crit_sign: i64 = 1;
        if extension.len() == 3 {
            assert!(lder(extension[1], ASN1_BOOL) == [0xff], "Expected critical == true");
            crit_sign = -1;
        }
        let extn_value = lder(extension[extension.len() - 1], ASN1_OCTET_STR);

        // For some registered extensions the CBOR encoding is conditional.
        // Detect cases that must fall back to the RFC 9090 OID form even when
        // the OID has a C509 integer registration.
        //
        // AS Identifiers (id-pe-autonomousSysIds, value 33) and v2 (value 35):
        //   Draft §ext-encoding: "If 'rdi' is not present, the extension value
        //   can be CBOR-encoded."  The 'rdi' field is context tag [1] (0xa1) in
        //   the ASIdentifiers SEQUENCE.  When rdi IS present the extension MUST
        //   use the OID fallback (§2.4 draft-ietf-cose-cbor-encoded-cert).
        let force_oid_fallback = if let Some(et) = ext_map(oid) {
            (et == EXT_AS_IDENTIFIERS || et == EXT_AS_IDENTIFIERS_V2) &&
            lder_vec(extn_value, ASN1_SEQ).iter().any(|item| !item.is_empty() && item[0] == 0xa1)
        } else { false };

        if !force_oid_fallback {
            if let Some(ext_type) = ext_map(oid) {
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
                    EXT_CRL_DIST_POINTS | EXT_FRESHEST_CRL => cbor_ext_crl_dist(extn_value),
                    EXT_CERT_POLICIES => cbor_ext_cert_policies(extn_value),
                    EXT_AUTH_KEY_ID => cbor_ext_auth_key_id(extn_value),
                    EXT_EXT_KEY_USAGE => cbor_ext_eku(extn_value),
                    EXT_AUTH_INFO | EXT_SUBJECT_INFO_ACCESS => cbor_ext_info_access(extn_value),
                    EXT_ISSUER_ALT_NAME => cbor_general_names(extn_value, ASN1_SEQ, 2),
                    EXT_SUBJECT_DIRECTORY_ATTR => cbor_ext_subject_directory_attr(extn_value),
                    EXT_NAME_CONSTRAINTS => cbor_ext_name_constraints(extn_value),
                    EXT_POLICY_MAPPINGS => cbor_ext_policy_mappings(extn_value),
                    EXT_POLICY_CONSTRAINTS => cbor_ext_policy_constraints(extn_value),
                    EXT_INHIBIT_ANYPOLICY => cbor_ext_inhibit_any_policy(extn_value),
                    EXT_OCSP_NO_CHECK => lcbor_simple(CBOR_NULL),
                    EXT_TLS_FEATURES => cbor_ext_tls_features(extn_value),
                    EXT_IP_ADDR_BLOCKS | EXT_IP_ADDR_BLOCKS_V2 => cbor_ext_ip_addr_blocks(extn_value),
                    EXT_AS_IDENTIFIERS | EXT_AS_IDENTIFIERS_V2 => cbor_ext_as_identifiers(extn_value),
                    _ => cbor_store_only(extn_value, extension[0], oid),
                });
            } else {
                // RFC 9090 OID fallback (§2.4, §ext-encoding draft-ietf-cose-cbor-encoded-cert):
                // ~oid (OID value bytes without tag) + optional CBOR_TRUE (critical) + extnValue bytes.
                print_warning("No C509 int registered for extension OID", extension[0], oid);
                vec.push(lcbor_bytes(oid));
                if crit_sign == -1 { vec.push(lcbor_simple(CBOR_TRUE)); }
                vec.push(lcbor_bytes(extn_value));
            }
        } else {
            // Forced RFC 9090 OID fallback: registered OID but extension value
            // cannot be CBOR-encoded (e.g. AS Identifiers with rdi present).
            vec.push(lcbor_bytes(oid));
            if crit_sign == -1 { vec.push(lcbor_simple(CBOR_TRUE)); }
            vec.push(lcbor_bytes(extn_value));
        }
    }
    output.push(cbor_opt_array(&vec, EXT_KEY_USAGE as u8));

    assert!(signature_value[0] == 0, "Expected 0 unused bits in signature");
    let signature_value = &signature_value[1..];
    if let Some(sig_type) = sig_map(signature_algorithm) {
        if [SIG_ECDSA_SHA1, SIG_ECDSA_SHA256, SIG_ECDSA_SHA384, SIG_ECDSA_SHA512, SIG_ECDSA_SHAKE128, SIG_ECDSA_SHAKE256, SIG_SM2_V15_SM3].contains(&sig_type) {
            output.push(cbor_ecdsa(signature_value));
        } else {
            output.push(lcbor_bytes(signature_value));
        }
    } else {
        output.push(lcbor_bytes(signature_value));
    }

    Cert { der: input, cbor: output }
}
