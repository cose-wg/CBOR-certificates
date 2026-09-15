//! X.509 extension encoding and decoding for C509.
//!
//! Converts each X.509v3 extension between its DER form and the compact C509 CBOR
//! representation defined in draft-ietf-cose-cbor-encoded-cert-20. Handles all
//! registered extension types (draft §9.4) plus an RFC 9090 OID fallback for
//! unknown extensions.

use serde_cbor::Value;
use asn1_rs::{Oid, ToDer};
use log::{trace, warn};
use crate::lder::*;
use crate::lcbor::*;
use crate::registry::*;
use crate::help::*;
use crate::conversion::{cbor_name, parse_cbor_name, cbor_opt_array, map_att_id_to_oid, uint_to_minimal_bytes, uint_to_implicit_der};

pub(crate) fn cbor_ext_subject_directory_attr(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for attr in lder_vec(b, ASN1_SEQ) {
        let attr_vec = lder_vec(attr, ASN1_SEQ);
        assert!(attr_vec.len() >= 2, "Expected at least 2 elements in Attribute");
        let oid = lder(attr_vec[0], ASN1_OID);
        if let Some(att_id) = att_map(oid) {
            vec.push(lcbor_int(att_id));
        } else {
            vec.push(lcbor_bytes(oid));
        }
        let values = lder_vec(attr_vec[1], ASN1_SET);
        let mut vals_vec = Vec::new();
        for val in values {
            let tag = val[0];
            let content = lder(val, tag);
            if matches!(tag, ASN1_UTF8_STR | ASN1_PRINT_STR | ASN1_IA5_STR | ASN1_VIS_STR | 0x1e) {
                vals_vec.push(lcbor_text(content));
            } else {
                vals_vec.push(lcbor_bytes(val));
            }
        }
        vec.push(lcbor_array(&vals_vec));
    }
    lcbor_array(&vec)
}

fn parse_cbor_ext_subject_directory_attr(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_DIRECTORY_ATTR_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let mut attrs_vec = Vec::new();
    if let Value::Array(elements) = extension_val {
        let mut i = 0;
        while i < elements.len() {
            let mut attr_seq = Vec::new();
            match &elements[i] {
                Value::Integer(id) => attr_seq.push(map_att_id_to_oid(*id as i64)),
                Value::Bytes(b) => attr_seq.push(lder_to_generic(b.to_vec(), ASN1_OID)),
                _ => panic!("Expected attribute id or oid"),
            }
            i += 1;
            if i < elements.len() {
                if let Value::Array(vals) = &elements[i] {
                    let mut vals_der = Vec::new();
                    for v in vals {
                        match v {
                            Value::Text(s) => vals_der.push(lder_to_generic(s.as_bytes().to_vec(), ASN1_UTF8_STR)),
                            Value::Bytes(b) => vals_der.push(b.to_vec()),
                            _ => panic!("Expected text or bytes for SubjectDirectoryAttr value"),
                        }
                    }
                    attr_seq.push(lder_to_gen_seq(vals_der, ASN1_SET));
                    i += 1;
                }
            }
            attrs_vec.push(lder_to_seq(attr_seq));
        }
    }
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(attrs_vec), ASN1_OCTET_STR))
}

pub(crate) fn cbor_ext_policy_mappings(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for mapping in lder_vec(b, ASN1_SEQ) {
        let mapping_vec = lder_vec_len(mapping, ASN1_SEQ, 2);
        for m in mapping_vec {
            let oid = lder(m, ASN1_OID);
            if let Some(cp_id) = cp_map(oid) {
                vec.push(lcbor_int(cp_id));
            } else {
                vec.push(lcbor_bytes(oid));
            }
        }
    }
    lcbor_array(&vec)
}

fn parse_cbor_ext_policy_mappings(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_POLICY_MAPPINGS_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let mut mappings_vec = Vec::new();
    if let Value::Array(elements) = extension_val {
        for i in (0..elements.len()).step_by(2) {
            let mut mapping = Vec::new();
            for j in 0..2 {
                match &elements[i + j] {
                    Value::Integer(id) => mapping.push(map_cert_policy_id_to_oid(*id as i64)),
                    Value::Bytes(b) => mapping.push(lder_to_generic(b.to_vec(), ASN1_OID)),
                    _ => panic!("Expected policy id or oid"),
                }
            }
            mappings_vec.push(lder_to_seq(mapping));
        }
    }
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(mappings_vec), ASN1_OCTET_STR))
}

pub(crate) fn cbor_ext_inhibit_any_policy(b: &[u8]) -> Vec<u8> {
    let val = lder_uint(b);
    lcbor_uint(be_bytes_to_u64(val))
}

fn parse_cbor_ext_inhibit_anypolicy(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_INHIBIT_ANYPOLICY_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let val = match extension_val {
        Value::Integer(i) => *i as u64,
        _ => panic!("Expected integer for Inhibit AnyPolicy"),
    };
    lder_to_two_seq(oid, lder_to_generic(lder_to_pos_int(uint_to_minimal_bytes(val)), ASN1_OCTET_STR))
}

pub(crate) fn cbor_ext_policy_constraints(b: &[u8]) -> Vec<u8> {
    let mut require_explicit: Option<Vec<u8>> = None;
    let mut inhibit_mapping: Option<Vec<u8>> = None;
    for c in lder_vec(b, ASN1_SEQ) {
        let tag = c[0] & 0x1f;
        let (val_bytes, _) = lder_split(c, true);
        let val = lcbor_uint(be_bytes_to_u64(val_bytes));
        match tag {
            0 => require_explicit = Some(val),
            1 => inhibit_mapping = Some(val),
            _ => {}
        }
    }
    let r = require_explicit.unwrap_or_else(|| lcbor_simple(CBOR_NULL));
    let m = inhibit_mapping.unwrap_or_else(|| lcbor_simple(CBOR_NULL));
    lcbor_array(&[r, m])
}

fn parse_cbor_ext_policy_constraints(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_POLICY_CONSTRAINTS_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let mut constraints_vec = Vec::new();
    if let Value::Array(elements) = extension_val {
        // elements[0] = requireExplicitPolicy (null or uint), elements[1] = inhibitPolicyMapping (null or uint)
        for (idx, el) in elements.iter().enumerate() {
            if *el == Value::Null { continue; }
            if let Value::Integer(v) = el {
                constraints_vec.push(uint_to_implicit_der(idx as u8, *v as u64));
            }
        }
    }
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(constraints_vec), ASN1_OCTET_STR))
}

pub(crate) fn cbor_ext_name_constraints(b: &[u8]) -> Vec<u8> {
    let mut permitted: Option<Vec<u8>> = None;
    let mut excluded: Option<Vec<u8>> = None;
    for subtree_container in lder_vec(b, ASN1_SEQ) {
        let tag = subtree_container[0] & 0x1f;
        let gen_subtrees = lder_vec(subtree_container, subtree_container[0]);
        let mut flat: Vec<Vec<u8>> = Vec::new();
        for gen_subtree in gen_subtrees {
            let seq_items = lder_vec(gen_subtree, ASN1_SEQ);
            let base_gn = seq_items[0];
            let gn_val = lder(base_gn, base_gn[0]);
            let context_tag = (base_gn[0] & 0x0f) as u64;
            flat.push(lcbor_uint(context_tag));
            flat.push(match context_tag {
                1 | 2 | 6 => lcbor_text(gn_val),
                4 => cbor_name(gn_val),
                7 | 8 => lcbor_bytes(gn_val),
                _ => lcbor_bytes(gn_val),
            });
        }
        match tag {
            0 => permitted = Some(lcbor_array(&flat)),
            1 => excluded = Some(lcbor_array(&flat)),
            _ => {}
        }
    }
    let p = permitted.unwrap_or_else(|| lcbor_simple(CBOR_NULL));
    let e = excluded.unwrap_or_else(|| lcbor_simple(CBOR_NULL));
    lcbor_array(&[p, e])
}

fn parse_cbor_ext_name_constraints(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_NAME_CONSTRAINTS_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let mut subtrees_vec = Vec::new();
    if let Value::Array(elements) = extension_val {
        // elements[0] = permitted (null or flat [type, val, ...])
        // elements[1] = excluded (null or flat [type, val, ...])
        for (idx, subtree_val) in elements.iter().enumerate() {
            let tag = idx as u8;
            if *subtree_val == Value::Null { continue; }
            if let Value::Array(flat) = subtree_val {
                let mut gen_subtree_list = Vec::new();
                let mut i = 0;
                while i + 1 < flat.len() {
                    let context_tag = match &flat[i] { Value::Integer(t) => *t as u8, _ => panic!("Expected integer tag in NameConstraints") };
                    let gn = match context_tag {
                        1 => match &flat[i+1] { Value::Text(s) => lder_to_generic(s.as_bytes().to_vec(), ASN1_INDEX_ONE_EXT), _ => panic!("Expected text for rfc822Name in NameConstraints") },
                        2 => match &flat[i+1] { Value::Text(s) => lder_to_generic(s.as_bytes().to_vec(), ASN1_INDEX_TWO_EXT), _ => panic!("Expected text for dNSName in NameConstraints") },
                        4 => lder_to_generic(parse_cbor_name(&flat[i+1]), ASN1_INDEX_FOUR),
                        6 => match &flat[i+1] { Value::Text(s) => lder_to_generic(s.as_bytes().to_vec(), ASN1_URL), _ => panic!("Expected text for URI in NameConstraints") },
                        7 => match &flat[i+1] { Value::Bytes(b) => lder_to_generic(b.to_vec(), ASN1_IP), _ => panic!("Expected bytes for IP in NameConstraints") },
                        8 => match &flat[i+1] { Value::Bytes(b) => lder_to_generic(b.to_vec(), ASN1_INDEX_EIGHT_EXT), _ => panic!("Expected bytes for registeredID in NameConstraints") },
                        _ => panic!("Unknown context tag {} in NameConstraints", context_tag),
                    };
                    gen_subtree_list.push(lder_to_seq(vec![gn]));
                    i += 2;
                }
                subtrees_vec.push(lder_to_gen_seq(gen_subtree_list, 0xa0 | tag));
            }
        }
    }
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(subtrees_vec), ASN1_OCTET_STR))
}

/// Converts a BIT STRING content slice (unused_bits || value_bytes) to the integer form
/// used in IntIPAddressChoice: big-endian int of (unused_bits+1) || value_bytes.
/// The +1 on unused_bits guarantees a non-zero leading byte so the integer round-trips cleanly.
fn bitstring_to_i128(bs_content: &[u8]) -> i128 {
    let mut seq = vec![bs_content[0] + 1];
    seq.extend_from_slice(&bs_content[1..]);
    let mut buf = [0u8; 16];
    let len = seq.len().min(16);
    buf[16 - len..].copy_from_slice(&seq[..len]);
    i128::from_be_bytes(buf)
}

/// Encodes a delta value (current_int - prev_int) as CBOR uint (positive) or int (negative).
fn cbor_int_delta(delta: i128) -> Vec<u8> {
    if delta >= 0 { lcbor_uint(delta as u64) } else { lcbor_int(delta as i64) }
}

/// Encodes id-pe-ipAddrBlocks (ID 32) and id-pe-ipAddrBlocks-v2 (ID 34).
///
/// Each IPAddressFamily emits three consecutive values: [AFI, SAFI_or_null, choice].
/// choice is null (inherit), IntIPAddressChoice (delta-encoded ints when all ≤ 8 bytes),
/// or IPAddressChoice (raw BIT STRING bytes when any address exceeds 8 bytes).
/// Delta encoding: first address absolute, each subsequent as (current − previous).
/// For ranges: [min_delta, max−min]. After a range, prev = range max.
pub(crate) fn cbor_ext_ip_addr_blocks(b: &[u8]) -> Vec<u8> {
    let mut result: Vec<Vec<u8>> = Vec::new();
    for family in lder_vec(b, ASN1_SEQ) {
        let items = lder_vec(family, ASN1_SEQ);
        let addr_family = lder(items[0], ASN1_OCTET_STR);
        let afi = u16::from_be_bytes([addr_family[0], addr_family[1]]) as u64;
        let safi = if addr_family.len() >= 3 { Some(addr_family[2] as u64) } else { None };
        result.push(lcbor_uint(afi));
        result.push(safi.map(lcbor_uint).unwrap_or_else(|| lcbor_simple(CBOR_NULL)));

        let choice = items[1];
        if choice[0] == 0x05 {
            // NULL → inherit
            result.push(lcbor_simple(CBOR_NULL));
        } else {
            let ranges = lder_vec(choice, ASN1_SEQ);
            // Use integer form only if every BIT STRING content fits in ≤ 8 bytes
            let all_fit = ranges.iter().all(|item| {
                let check = |bs: &[u8]| lder(bs, ASN1_BIT_STR).len() <= 8;
                if item[0] == ASN1_BIT_STR { check(item) }
                else { lder_vec(item, ASN1_SEQ).iter().all(|si| check(si)) }
            });
            let mut enc: Vec<Vec<u8>> = Vec::new();
            let mut prev: Option<i128> = None;
            for item in &ranges {
                if item[0] == ASN1_BIT_STR {
                    let abs = bitstring_to_i128(lder(item, ASN1_BIT_STR));
                    if all_fit {
                        enc.push(match prev { None => lcbor_uint(abs as u64), Some(p) => cbor_int_delta(abs - p) });
                    } else {
                        // Raw bytes format: unused_bits || value (no +1 transformation)
                        enc.push(lcbor_bytes(lder(item, ASN1_BIT_STR)));
                    }
                    prev = Some(abs);
                } else if item[0] == ASN1_SEQ {
                    let sub = lder_vec(item, ASN1_SEQ);
                    let min_c = lder(sub[0], ASN1_BIT_STR);
                    let max_c = lder(sub[1], ASN1_BIT_STR);
                    let min_abs = bitstring_to_i128(min_c);
                    let max_abs = bitstring_to_i128(max_c);
                    if all_fit {
                        let min_enc = match prev { None => lcbor_uint(min_abs as u64), Some(p) => cbor_int_delta(min_abs - p) };
                        enc.push(lcbor_array(&[min_enc, cbor_int_delta(max_abs - min_abs)]));
                    } else {
                        // Raw bytes format: BIT STRING content as-is for both min and max
                        enc.push(lcbor_array(&[lcbor_bytes(min_c), lcbor_bytes(max_c)]));
                    }
                    prev = Some(max_abs);
                }
            }
            result.push(lcbor_array(&enc));
        }
    }
    lcbor_array(&result)
}

/// Encodes id-pe-autonomousSysIds (ID 33) and id-pe-autonomousSysIds-v2 (ID 35).
///
/// Encodes the [0] asnum choice. If absent or inherit (NULL), encodes as CBOR null.
/// rdi ([1]) is not supported and must be absent for CBOR encoding.
/// Each ASId is delta-encoded from the previous (first item is absolute).
/// Ranges emit [min_delta, max−min]; after a range, prev = range max.
pub(crate) fn cbor_ext_as_identifiers(b: &[u8]) -> Vec<u8> {
    let items = lder_vec(b, ASN1_SEQ);
    let asnum_ctx = items.iter().find(|i| i[0] == 0xa0);
    let asnum = match asnum_ctx {
        None => return lcbor_simple(CBOR_NULL),
        Some(ctx) => lder(ctx, 0xa0),
    };
    if asnum[0] == 0x05 {
        // NULL → inherit
        return lcbor_simple(CBOR_NULL);
    }
    let as_items = lder_vec(asnum, ASN1_SEQ);
    let mut enc: Vec<Vec<u8>> = Vec::new();
    let mut prev: Option<u64> = None;
    for item in as_items {
        if item[0] == 0x02 {
            let val = be_bytes_to_u64(lder_uint(item));
            enc.push(match prev { None => lcbor_uint(val), Some(p) => lcbor_uint(val - p) });
            prev = Some(val);
        } else if item[0] == ASN1_SEQ {
            let sub = lder_vec(item, ASN1_SEQ);
            let min_val = be_bytes_to_u64(lder_uint(sub[0]));
            let max_val = be_bytes_to_u64(lder_uint(sub[1]));
            let min_delta = match prev { None => min_val, Some(p) => min_val - p };
            enc.push(lcbor_array(&[lcbor_uint(min_delta), lcbor_uint(max_val - min_val)]));
            prev = Some(max_val);
        }
    }
    lcbor_array(&enc)
}

pub(crate) fn cbor_store_only(b: &[u8], v: &[u8], oid: &[u8]) -> Vec<u8> {
    print_warning("Warning, currently storing raw data for extension with oid", v, oid);
    lcbor_bytes(b)
}

pub(crate) fn cbor_ext_tls_features(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for feature in lder_vec(b, ASN1_SEQ) {
        vec.push(lcbor_uint(be_bytes_to_u64(lder_uint(feature))));
    }
    lcbor_array(&vec)
}

fn parse_cbor_ext_ocsp_no_check(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_OCSP_NO_CHECK_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let _ = extension_val;
    lder_to_two_seq(oid, lder_to_generic(ASN1_NULL.to_vec(), ASN1_OCTET_STR))
}

fn parse_cbor_ext_tls_features(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_TLS_FEATURES_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let mut features_vec = Vec::new();
    if let Value::Array(elements) = extension_val {
        for el in elements {
            if let Value::Integer(n) = el {
                features_vec.push(lder_to_pos_int(uint_to_minimal_bytes(*n as u64)));
            }
        }
    }
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(features_vec), ASN1_OCTET_STR))
}

pub(crate) fn cbor_general_names(b: &[u8], t: u8, opt: u8) -> Vec<u8> {
    let unwrap = opt;
    let names = lder_vec(b, t);
    let mut vec = Vec::new();
    for name in names {
        trace!("cbor_general_names, handling name: {:02x?}", name);
        let value = lder(name, name[0]);
        let context_tag = name[0] as u64 & 0x0f;
        trace!("cbor_general_names, storing context tag: {}", context_tag);
        if context_tag == 0 {
            let inner_value = &value[12..]; 
            match value {
                [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, ..] => match value[9] {
                    0x0C => {
                        vec.push(lcbor_int(-3));
                        if inner_value.first() == Some(&ASN1_UTF8_STR) {
                            vec.push(lcbor_text(lder(inner_value, ASN1_UTF8_STR)));
                        } else {
                            // Strip the TLV wrapper; encode only the value content
                            vec.push(lcbor_bytes(lder(inner_value, inner_value[0])));
                        }
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
                    } 
                },
                _ => {
                    vec.push(lcbor_int(0));
                    vec.push(cbor_other_name(value))
                } 
            }
        } else {
            vec.push(lcbor_uint(context_tag));
            vec.push(match context_tag {
                1 => lcbor_text(value),  
                2 => lcbor_text(value),  
                4 => cbor_name(value),   
                6 => lcbor_text(value),  
                7 => lcbor_bytes(value), 
                8 => lcbor_bytes(value), 
                _ => panic!("Unknown general name"),
            })
        }
    }
    cbor_opt_array(&vec, unwrap)
}

pub(crate) fn cbor_other_name(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    let (oid_raw, rest) = lder_split(b, false);
    let oid = lder(oid_raw, ASN1_OID);
    let raw_value = lder(rest, ASN1_INDEX_ZERO);
    vec.push(lcbor_bytes(oid));
    vec.push(lcbor_bytes(raw_value));
    lcbor_array(&vec)
}

pub(crate) fn cbor_other_name_mail(b: &[u8]) -> Vec<u8> {
    let value = lder(b, ASN1_UTF8_STR);
    lcbor_text(value)
}

pub(crate) fn cbor_other_name_hw(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    let another_name_vec = lder_vec(b, ASN1_SEQ);
    let type_id = lder(another_name_vec[0], ASN1_OID);
    let value = lder(another_name_vec[1], ASN1_OCTET_STR);
    vec.push(lcbor_bytes(type_id));
    vec.push(lcbor_bytes(value));
    lcbor_array(&vec)
}

pub(crate) fn cbor_ext_auth_key_id(b: &[u8]) -> Vec<u8> {
    let aki = lder_vec(b, ASN1_SEQ);
    match aki.len() {
      1 => lcbor_bytes(lder(aki[0], 0x80)), 
      3 => {
        let ki = lcbor_bytes(lder(aki[0], 0x80));
        lcbor_array(&[ki, cbor_general_names(aki[1], 0xa1, 0xff), lcbor_bytes(lder(aki[2], 0x82))])
      }
      // Unexpected AKI structure (e.g. missing keyIdentifier field, as seen on
      // some hosts). Return empty to skip the extension rather than panicking;
      // the round-trip test will catch the mismatch.
      _ => {
        warn!("Skipping Authority Key Identifier: unexpected structure");
        Vec::new()
      }
    }
}

pub(crate) fn cbor_ext_bas_con(b: &[u8]) -> Vec<u8> {
    let bc = lder_vec(b, ASN1_SEQ);
    match bc.len() {
        0 => lcbor_int(-2),
        1 => {
            let ca = lder(bc[0], ASN1_BOOL);
            if ca == [0xff] { lcbor_int(-1) } else { lcbor_int(-2) }
        }
        2 => {
            let ca = lder(bc[0], ASN1_BOOL);
            let path_len = lder_uint(bc[1]);
            if ca == [0xff] {
                assert!(path_len.len() == 1, "Expected path length < 256");
                lcbor_uint(path_len[0] as u64)
            } else {
                lcbor_simple(CBOR_NULL)
            }
        }
        _ => panic!("Error parsing basic constraints"),
    }
}

pub(crate) fn cbor_ext_cert_policies(b: &[u8]) -> Vec<u8> {
    let policy_infos: Vec<&[u8]> = lder_vec(b, ASN1_SEQ);
    let any_qualifiers = policy_infos.iter().any(|pi| lder_vec(pi, ASN1_SEQ).len() == 2);
    let mut vec = Vec::new();
    for pi_raw in &policy_infos {
        let pi = lder_vec(pi_raw, ASN1_SEQ);
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
                        let text = lder(pqi[1], ASN1_IA5_STR);
                        vec2.push(lcbor_text(text));
                    } else if pq_type == PQ_UNOTICE {
                        let text: Vec<u8> = {
                          let explicit_note = lder(pqi[1], ASN1_SEQ);
                          match explicit_note[0] {
                            ASN1_UTF8_STR => lder(explicit_note, ASN1_UTF8_STR).to_vec(),
                            ASN1_IA5_STR | ASN1_VIS_STR => lder(explicit_note, explicit_note[0]).to_vec(),
                            0x1e => { // BMPString: decode UTF-16 BE to UTF-8 (C509 normalises string types)
                                let raw = lder(explicit_note, 0x1e);
                                let utf16: Vec<u16> = raw.chunks(2)
                                    .map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                                String::from_utf16(&utf16).unwrap_or_default().into_bytes()
                            }
                            tag => {
                              warn!("In Certificate Policies extension: unrecognised explicitText type {:02x}", tag);
                              lder(explicit_note, tag).to_vec()
                            }
                          }
                        };
                        vec2.push(lcbor_text(&text));
                    } else {
                        panic!("unexpected qualifier oid");
                    }
                } else {
                    print_warning("No C509 int registered for Policy Qualifier OID", pqi[0], oid);
                    vec2.push(lcbor_bytes(oid));
                }
            }
            vec.push(lcbor_array(&vec2));
        } else if any_qualifiers {
            // Some other policy has qualifiers; use explicit empty array to keep encoding unambiguous
            vec.push(lcbor_array(&[]));
        }
    }
    lcbor_array(&vec)
}

pub(crate) fn cbor_ext_crl_dist(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for dist_point in lder_vec(b, ASN1_SEQ) {
        // Handles cases where DistributionPoint is a SEQUENCE (as seen in test vector tv_7_2).
        let dist_point_content = lder(dist_point, ASN1_SEQ);
        let mut dp_name_cbor = Value::Null;
        let mut reasons_cbor = Value::Null;
        let mut crl_issuer_cbor = Value::Null;
        let mut rest = dist_point_content;
        while !rest.is_empty() {
            let (tlv, next) = lder_split(rest, false);
            match tlv[0] {
                0xa0 => {
                    // Handles implicit tagging for fullName [0] and distributionPoint [0]
                    // (as seen in Microsoft certificates like support.microsoft.com_170.crt).
                    let dp_name_value = lder(tlv, 0xa0);
                    if !dp_name_value.is_empty() && dp_name_value[0] == 0xa0 {
                        let full_name_value = lder(dp_name_value, 0xa0);
                        let mut gen_names_content = full_name_value;
                        if !gen_names_content.is_empty() && gen_names_content[0] == ASN1_SEQ {
                            gen_names_content = lder(gen_names_content, ASN1_SEQ);
                        }
                        let mut vec2 = Vec::new();
                        let mut gen_names_rest = gen_names_content;
                        while !gen_names_rest.is_empty() {
                            let (gen_name, next_gn) = lder_split(gen_names_rest, false);
                            if !gen_name.is_empty() && gen_name[0] == 0x86 {
                                vec2.push(lcbor_text(lder(gen_name, 0x86)));
                            }
                            gen_names_rest = next_gn;
                        }
                        if vec2.len() == 1 {
                            dp_name_cbor = serde_cbor::from_slice(&vec2[0]).unwrap();
                        } else if vec2.len() > 1 {
                            dp_name_cbor = Value::Array(vec2.into_iter().map(|v| serde_cbor::from_slice(&v).unwrap()).collect());
                        }
                    }
                }
                0x81 => {
                    let bit_str = lder(tlv, 0x81);
                    if bit_str.len() > 1 {
                        let unused_bits = bit_str[0] as usize;
                        let data_bytes = &bit_str[1..];
                        let total_bits = data_bytes.len() * 8 - unused_bits;
                        let mut val: u64 = 0;
                        for (byte_idx, &byte) in data_bytes.iter().enumerate() {
                            for bit_idx in 0..8usize {
                                let reason_bit = byte_idx * 8 + bit_idx;
                                if reason_bit >= total_bits { break; }
                                if (byte >> (7 - bit_idx)) & 1 == 1 {
                                    val |= 1u64 << reason_bit;
                                }
                            }
                        }
                        reasons_cbor = Value::Integer(val as i128);
                    }
                }
                0xa2 => {
                    let issuer_content = lder(tlv, 0xa2);
                    let (gn_tlv, _) = lder_split(issuer_content, false);
                    if !gn_tlv.is_empty() && gn_tlv[0] == ASN1_INDEX_FOUR {
                        let name_der = lder(gn_tlv, ASN1_INDEX_FOUR);
                        let name_cbor = cbor_name(name_der);
                        crl_issuer_cbor = serde_cbor::from_slice(&name_cbor).unwrap();
                    } else {
                        let issuer_bytes = cbor_general_names(tlv, 0xa2, 0);
                        crl_issuer_cbor = serde_cbor::from_slice(&issuer_bytes).unwrap();
                    }
                }
                _ => {}
            }
            rest = next;
        }
        vec.push(Value::Array(vec![dp_name_cbor, reasons_cbor, crl_issuer_cbor]));
    }
    if vec.len() == 1 {
        if let Value::Array(fields) = &vec[0] {
            if fields[1] == Value::Null && fields[2] == Value::Null {
                if let Value::Text(_) = &fields[0] { return lcbor_value(&fields[0]); }
            }
        }
    }
    lcbor_array_v(&vec)
}

pub(crate) fn cbor_ext_eku(b: &[u8]) -> Vec<u8> {
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
    if vec.len() == 1 { vec.remove(0) } else { lcbor_array(&vec) }
}

pub(crate) fn cbor_ext_info_access(b: &[u8]) -> Vec<u8> {
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

pub(crate) fn cbor_ext_key_use(bs: &[u8], signed_nr_ext: i64) -> Vec<u8> {
    // Ensures bit 0 of X.509 byte 0 is handled correctly as MSB (0x80) (as seen in test vector tv_3_2_2).
    assert!(bs[0] == ASN1_BIT_STR, "Expected 0x03");
    let len = bs[1] as usize;
    let mut w: u64 = 0;
    for i in 0..(len - 1) {
        let byte = bs[3 + i];
        w |= (byte.reverse_bits() as u64) << (8 * i);
    }
    if signed_nr_ext == -1 { return lcbor_int(-(w as i64)); }
    lcbor_uint(w)
}

// cbor_ext_sct removed: SCT List (OID 1.3.6.1.4.1.11129.2.4.2) is no longer a registered
// C509 extension in draft-11. Certificates containing this extension are now encoded using
// the raw OID-tagged extension path (lcbor_bytes(oid) + lcbor_bytes(extnValue)).


fn parse_cbor_ext_subject_key_id(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_KEY_ID_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let ext_val = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR), ASN1_OCTET_STR),
        _ => panic!("Error parsing Subject Key ID: {:?}", extension_val),
    };
    lder_to_two_seq(oid, ext_val)
}

fn parse_cbor_ext_key_usage(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_KEY_USAGE_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let ext_val = match extension_val {
        Value::Integer(key_usage_bitmap) => {
            let mut val = key_usage_bitmap.unsigned_abs() as u64;
            let mut bytes = Vec::new();
            if val == 0 { bytes.push(0u8); }
            else { while val > 0 { bytes.push((val & 0xff) as u8); val >>= 8; } }
            for b in bytes.iter_mut() { *b = b.reverse_bits(); }
            let unused = bytes.last().unwrap().trailing_zeros() as u8;
            let mut der_bit_str = vec![unused];
            der_bit_str.extend(bytes);
            lder_to_generic(lder_to_generic(der_bit_str, ASN1_BIT_STR), ASN1_OCTET_STR)
        }
        _ => panic!("Error parsing Key Usage: {:?}", extension_val),
    };
    lder_to_two_seq(oid, ext_val)
}

fn parse_cbor_ext_subject_alt_name(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_ALT_NAME_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    lder_to_two_seq(oid, lder_to_generic(parse_cbor_general_name(extension_val), ASN1_OCTET_STR))
}

pub(crate) fn parse_cbor_general_name(extension_val: &Value) -> Vec<u8> {
    match extension_val {
        Value::Array(general_name) => {
            let mut general_name_arr = Vec::new();
            let mut unwrap = false;
            for i in (0..general_name.len()).step_by(2) {
                general_name_arr.push(match &general_name[i] {
                    Value::Integer(gn_field) => match gn_field {
                        -1 => parse_cbor_general_name_hw_module(&general_name[i + 1]),
                        -2 => parse_cbor_general_name_permanent_id(&general_name[i + 1]),
                        -3 => parse_cbor_general_name_user_notice(&general_name[i + 1]),
                        0 => match &general_name[i + 1] {
                            Value::Array(other_name_array) => {
                                let oid = match &other_name_array[0] {
                                    Value::Bytes(b) => lder_to_generic(b.to_vec(), ASN1_OID),
                                    _ => panic!("Expected OID bytes"),
                                };
                                let value = match &other_name_array[1] {
                                    Value::Bytes(b) => lder_to_generic(b.to_vec(), ASN1_INDEX_ZERO),
                                    _ => panic!("Expected value bytes"),
                                };
                                lder_to_gen_seq(vec![oid, value], ASN1_INDEX_ZERO)
                            }
                            _ => panic!("Expected array for otherName"),
                        },
                        1 => match &general_name[i + 1] {
                            Value::Text(s) => lder_to_generic(s.as_bytes().to_vec(), ASN1_INDEX_ONE_EXT),
                            _ => panic!("Expected text for rfc822Name"),
                        },
                        2 => match &general_name[i + 1] {
                            Value::Text(s) => lder_to_generic(s.as_bytes().to_vec(), ASN1_INDEX_TWO_EXT),
                            _ => panic!("Expected text for dnsName"),
                        },
                        4 => {
                            unwrap = true;
                            lder_to_generic(parse_cbor_name(&general_name[i + 1]), ASN1_INDEX_FOUR)
                        }
                        6 => match &general_name[i + 1] {
                            Value::Text(s) => lder_to_generic(s.as_bytes().to_vec(), ASN1_URL),
                            _ => panic!("Expected text for URI"),
                        },
                        7 => match &general_name[i + 1] {
                            Value::Bytes(b) => lder_to_generic(b.to_vec(), ASN1_IP),
                            _ => panic!("Expected bytes for ipAddress"),
                        },
                        8 => match &general_name[i + 1] {
                            Value::Bytes(b) => lder_to_generic(b.to_vec(), ASN1_INDEX_EIGHT_EXT),
                            _ => panic!("Expected bytes for registeredID"),
                        },
                        _ => panic!("Unknown general name type: {}", gn_field),
                    },
                    _ => panic!("Expected integer for general name type"),
                });
            }
            if unwrap && general_name_arr.len() == 1 {
                general_name_arr.into_iter().next().unwrap()
            } else {
                lder_to_seq(general_name_arr)
            }
        }
        Value::Text(raw_val) => lder_to_generic(lder_to_generic(raw_val.as_bytes().to_vec(), ASN1_INDEX_TWO_EXT), ASN1_SEQ),
        _ => panic!("Error parsing GeneralName: {:?}", extension_val),
    }
}

fn parse_cbor_general_name_hw_module(hw_module: &Value) -> Vec<u8> {
    let mut outer = vec![OTHER_NAME_HW_MODULE_OID.to_der_vec().unwrap()];
    match hw_module {
        Value::Array(array) => {
            let oid = match &array[0] { Value::Bytes(b) => lder_to_generic(b.to_vec(), ASN1_OID), _ => panic!("Expected OID") };
            let val = match &array[1] { Value::Bytes(b) => lder_to_generic(b.to_vec(), ASN1_OCTET_STR), _ => panic!("Expected bytes") };
            outer.push(lder_to_generic(lder_to_seq(vec![oid, val]), ASN1_INDEX_ZERO));
        }
        _ => panic!("Expected array for hwModuleName"),
    }
    lder_to_gen_seq(outer, ASN1_INDEX_ZERO)
}

fn parse_cbor_general_name_permanent_id(val: &Value) -> Vec<u8> {
    let mut outer = vec![OTHER_NAME_PERMANENT_ID_OID.to_der_vec().unwrap()];
    let s = match val { Value::Text(s) => s.as_bytes().to_vec(), _ => panic!("Expected text for permanentIdentifier") };
    outer.push(lder_to_generic(lder_to_generic(s, ASN1_UTF8_STR), ASN1_INDEX_ZERO));
    lder_to_gen_seq(outer, ASN1_INDEX_ZERO)
}

fn parse_cbor_general_name_user_notice(val: &Value) -> Vec<u8> {
    let mut outer = vec![OTHER_NAME_SMTP_UTF8_MAILBOX_OID.to_der_vec().unwrap()];
    match val {
        Value::Text(s) => {
            let utf8_str = lder_to_generic(s.as_bytes().to_vec(), ASN1_UTF8_STR);
            outer.push(lder_to_generic(utf8_str, ASN1_INDEX_ZERO));
        }
        Value::Bytes(b) => {
            let octet_str = lder_to_generic(b.to_vec(), ASN1_OCTET_STR);
            outer.push(lder_to_generic(octet_str, ASN1_INDEX_ZERO));
        }
        _ => panic!("Expected text or bytes for SmtpUTF8Mailbox"),
    }
    lder_to_gen_seq(outer, ASN1_INDEX_ZERO)
}

fn parse_cbor_ext_basic_constraints(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_BASIC_CONSTRAINTS_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let second = match extension_val {
        Value::Integer(path_len) => {
            if -2 == *path_len {
                lder_to_generic(vec![0x30, 0x00], ASN1_OCTET_STR) // cA=FALSE: DER omits default → empty SEQUENCE {}
            } else if -1 == *path_len {
                lder_to_generic(lder_to_generic(vec![0x01, 0x01, 0xff], ASN1_SEQ), ASN1_OCTET_STR)
            } else {
                lder_to_generic(lder_to_two_seq(vec![0x01, 0x01, 0xff], lder_to_pos_int(vec![*path_len as u8])), ASN1_OCTET_STR)
            }
        }
        Value::Null => lder_to_generic(vec![0x30, 0x00], ASN1_OCTET_STR),
        _ => panic!("Illegal path len {:?}", extension_val),
    };
    lder_to_two_seq(oid, second)
}

fn build_reasons(val: u64) -> Vec<u8> {
    if val == 0 {
        return lder_to_generic(vec![0x00], 0x81);
    }
    let highest_bit = 63 - val.leading_zeros() as usize;
    let num_bytes = (highest_bit / 8) + 1;
    let unused_bits = (7 - (highest_bit % 8)) as u8;
    let mut data = vec![0u8; num_bytes];
    for bit in 0..=highest_bit {
        if (val >> bit) & 1 == 1 {
            let byte_idx = bit / 8;
            let bit_in_byte = 7 - (bit % 8);
            data[byte_idx] |= 1u8 << bit_in_byte;
        }
    }
    let mut der = vec![unused_bits];
    der.extend(data);
    lder_to_generic(der, 0x81)
}

fn parse_cbor_crl_distribution_points(extension_val: &Value) -> Vec<u8> {
    let mut result_vec = Vec::new();
    match extension_val {
        Value::Text(url_string) => {
            let gen_name = lder_to_generic(url_string.as_bytes().to_vec(), ASN1_URL);
            let full_name = lder_to_gen_seq(vec![gen_name], ASN1_INDEX_ZERO);
            let dp = lder_to_gen_seq(vec![full_name], ASN1_INDEX_ZERO);
            result_vec.push(lder_to_seq(vec![dp]));
        }
        Value::Array(elements) => {
            for element in elements {
                if let Value::Array(dp_fields) = element {
                    let mut dp_elements = Vec::new();
                    if !dp_fields.is_empty() && dp_fields[0] != Value::Null {
                        match &dp_fields[0] {
                            Value::Text(url) => {
                                let gen_name = lder_to_generic(url.as_bytes().to_vec(), ASN1_URL);
                                let full_name = lder_to_gen_seq(vec![gen_name], ASN1_INDEX_ZERO);
                                dp_elements.push(lder_to_gen_seq(vec![full_name], ASN1_INDEX_ZERO));
                            }
                            Value::Array(uris) => {
                                let mut gen_names = Vec::new();
                                for uri in uris {
                                    if let Value::Text(u) = uri {
                                        gen_names.push(lder_to_generic(u.as_bytes().to_vec(), ASN1_URL));
                                    }
                                }
                                let full_name = lder_to_gen_seq(gen_names, ASN1_INDEX_ZERO);
                                dp_elements.push(lder_to_gen_seq(vec![full_name], ASN1_INDEX_ZERO));
                            }
                            _ => {}
                        }
                    }
                    if dp_fields.len() > 1 && dp_fields[1] != Value::Null {
                        if let Value::Integer(val) = dp_fields[1] {
                            dp_elements.push(build_reasons(val as u64));
                        }
                    }
                    if dp_fields.len() > 2 && dp_fields[2] != Value::Null {
                        let name_der = parse_cbor_name(&dp_fields[2]);
                        let dir_name = lder_to_generic(name_der, ASN1_INDEX_FOUR);
                        dp_elements.push(lder_to_generic(dir_name, 0xa2));
                    }
                    result_vec.push(lder_to_seq(dp_elements));
                } else {
                    panic!("Error parsing CRL DP element: {:?}", element);
                }
            }
        }
        _ => panic!("Error parsing CRL DP: {:?}", extension_val),
    }
    lder_to_generic(lder_to_seq(result_vec), ASN1_OCTET_STR)
}

fn parse_cbor_ext_crl_dist_points(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_CRL_DIST_POINTS_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    lder_to_two_seq(oid, parse_cbor_crl_distribution_points(extension_val))
}

fn parse_cbor_ext_cert_policies(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_CERT_POLICIES_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let mut result_vec = Vec::new();
    let mut text_type = ASN1_UTC_TIME;
    match extension_val {
        Value::Array(elements) => {
            let mut wip = Vec::new();
            let mut can_specify = false;
            for element in elements {
                match element {
                    Value::Integer(pol_id) => {
                        if can_specify { result_vec.push(lder_to_seq(wip)); wip = Vec::new(); }
                        wip.push(map_cert_policy_id_to_oid(*pol_id as i64));
                        can_specify = true;
                    }
                    Value::Bytes(raw_oid) => {
                        if can_specify { result_vec.push(lder_to_seq(wip)); wip = Vec::new(); }
                        wip.push(lder_to_generic(raw_oid.to_vec(), ASN1_OID));
                        can_specify = true;
                    }
                    Value::Array(specifiers) => {
                        if !specifiers.is_empty() {
                            let mut wip_internal = Vec::new();
                            for i in (0..specifiers.len()).step_by(2) {
                                let q_oid = match &specifiers[i] {
                                    Value::Bytes(b) => lder_to_generic(b.to_vec(), ASN1_OID),
                                    Value::Integer(pol_id) => {
                                        if PQ_CPS == *pol_id as i64 { text_type = ASN1_IA5_STR; PQ_CPS_OID.to_der_vec().unwrap() }
                                        else if PQ_UNOTICE == *pol_id as i64 { text_type = ASN1_UTF8_STR; PQ_UNOTICE_OID.to_der_vec().unwrap() }
                                        else { panic!("Unknown policy qualifier: {}", pol_id) }
                                    }
                                    _ => panic!("Expected OID for policy qualifier"),
                                };
                                let q_text = match &specifiers[i + 1] {
                                    Value::Text(s) => {
                                        let t = lder_to_generic(s.as_bytes().to_vec(), text_type);
                                        if text_type == ASN1_UTF8_STR { lder_to_generic(t, ASN1_SEQ) } else { t }
                                    }
                                    _ => panic!("Expected text for policy qualifier"),
                                };
                                wip_internal.push(lder_to_two_seq(q_oid, q_text));
                            }
                            wip.push(lder_to_seq(wip_internal));
                        }
                        // empty [] means no policy qualifiers: reconstruct as SEQUENCE { OID } only
                        result_vec.push(lder_to_seq(wip));
                        wip = Vec::new();
                        can_specify = false;
                    }
                    _ => panic!("Error parsing cert policies: {:?}", element),
                }
            }
            if can_specify { result_vec.push(lder_to_seq(wip)); }
        }
        _ => panic!("Error parsing cert policies: {:?}", extension_val),
    }
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(result_vec), ASN1_OCTET_STR))
}

fn parse_cbor_ext_auth_key_id(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_AUTH_KEY_ID_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let ext_val = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(lder_to_generic(raw_val.to_vec(), ASN1_INDEX_ZERO_EXT), ASN1_SEQ),
        Value::Array(array) => {
            let mut int_arr = Vec::new();
            match &array[0] {
                Value::Bytes(key_id) => int_arr.push(lder_to_generic(key_id.to_vec(), ASN1_INDEX_ZERO_EXT)),
                _ => panic!("Expected key ID bytes"),
            }
            match &array[1] {
                Value::Array(_) => int_arr.push(lder_to_generic(parse_cbor_general_name(&array[1]), ASN1_INDEX_ONE)),
                _ => panic!("Expected general names array"),
            }
            match &array[2] {
                Value::Bytes(serial) => int_arr.push(lder_to_generic(serial.to_vec(), ASN1_INDEX_TWO_EXT)),
                _ => panic!("Expected serial bytes"),
            }
            lder_to_seq(int_arr)
        }
        _ => panic!("Error parsing AKI: {:?}", extension_val),
    };
    lder_to_two_seq(oid, lder_to_generic(ext_val, ASN1_OCTET_STR))
}

fn map_key_purpose_id_to_oid(key_purpose_id: u64) -> Vec<u8> {
    match key_purpose_id {
        EKU_ANY             => EKU_ANY_OID.to_der_vec().unwrap(),
        EKU_TLS_SERVER      => EKU_TLS_SERVER_OID.to_der_vec().unwrap(),
        EKU_TLS_CLIENT      => EKU_TLS_CLIENT_OID.to_der_vec().unwrap(),
        EKU_CODE_SIGNING    => EKU_CODE_SIGNING_OID.to_der_vec().unwrap(),
        EKU_EMAIL_PROTECTION => EKU_EMAIL_PROTECTION_OID.to_der_vec().unwrap(),
        EKU_TIME_STAMPING   => EKU_TIME_STAMPING_OID.to_der_vec().unwrap(),
        EKU_OCSP_SIGNING    => EKU_OCSP_SIGNING_OID.to_der_vec().unwrap(),
        EKU_KERBEROS_CLIENT_AUTH => EKU_KERBEROS_CLIENT_AUTH_OID.to_der_vec().unwrap(),
        EKU_KERBEROS_KDC    => EKU_KERBEROS_KDC_OID.to_der_vec().unwrap(),
        EKU_SSH_CLIENT      => EKU_SSH_CLIENT_OID.to_der_vec().unwrap(),
        EKU_SSH_SERVER      => EKU_SSH_SERVER_OID.to_der_vec().unwrap(),
        EKU_BUNDLE_SECURITY => EKU_BUNDLE_SECURITY_OID.to_der_vec().unwrap(),
        EKU_CMC_CERT_AUTHORITY => EKU_CMC_CERT_AUTHORITY_OID.to_der_vec().unwrap(),
        EKU_CMC_REG_AUTHORITY => EKU_CMC_REG_AUTHORITY_OID.to_der_vec().unwrap(),
        EKU_CMC_ARCHIVE_SERVER => EKU_CMC_ARCHIVE_SERVER_OID.to_der_vec().unwrap(),
        EKU_CMC_KEY_GEN_AUTHORITY => EKU_CMC_KEY_GEN_AUTHORITY_OID.to_der_vec().unwrap(),
        _ => panic!("Unknown EKU ID: {}", key_purpose_id),
    }
}

fn parse_cbor_ext_ext_key_usage(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_EXT_KEY_USAGE_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let mut ext_val = Vec::new();
    match extension_val {
        Value::Integer(id) => ext_val.push(map_key_purpose_id_to_oid(*id as u64)),
        Value::Array(elements) => {
            for e in elements {
                match e {
                    Value::Integer(id) => ext_val.push(map_key_purpose_id_to_oid(*id as u64)),
                    Value::Bytes(b) => ext_val.push(lder_to_generic(b.to_vec(), ASN1_OID)),
                    _ => panic!("Error parsing EKU element: {:?}", e),
                }
            }
        }
        Value::Bytes(b) => ext_val.push(lder_to_generic(b.to_vec(), ASN1_OID)),
        _ => panic!("Error parsing EKU: {:?}", extension_val),
    }
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(ext_val), ASN1_OCTET_STR))
}

fn map_auth_info_id_to_oid(id: i64) -> Vec<u8> {
    match id {
        INFO_OCSP           => INFO_OCSP_OID.to_der_vec().unwrap(),
        INFO_CA_ISSUERS     => INFO_CA_ISSUERS_OID.to_der_vec().unwrap(),
        INFO_TIME_STAMPING  => INFO_TIME_STAMPING_OID.to_der_vec().unwrap(),
        INFO_CA_REPOSITORY  => INFO_CA_REPOSITORY_OID.to_der_vec().unwrap(),
        INFO_RPKI_MANIFEST  => INFO_RPKI_MANIFEST_OID.to_der_vec().unwrap(),
        INFO_SIGNED_OBJECT  => INFO_SIGNED_OBJECT_OID.to_der_vec().unwrap(),
        INFO_RPKI_NOTIFY    => INFO_RPKI_NOTIFY_OID.to_der_vec().unwrap(),
        _ => panic!("Unknown info access ID: {}", id),
    }
}

fn parse_cbor_ext_auth_info(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_AUTH_INFO_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let mut result_vec = Vec::new();
    match extension_val {
        Value::Array(elements) => {
            assert!(elements.len() % 2 == 0, "AuthorityInfoAccess must have even number of elements");
            for i in (0..elements.len()).step_by(2) {
                let access_oid = match &elements[i] {
                    Value::Integer(id) => map_auth_info_id_to_oid(*id as i64),
                    Value::Bytes(b) => lder_to_generic(b.to_vec(), ASN1_OID),
                    _ => panic!("Expected OID for access method"),
                };
                let access_loc = match &elements[i + 1] {
                    Value::Text(s) => lder_to_generic(s.as_bytes().to_vec(), ASN1_URL),
                    _ => panic!("Expected text for access location"),
                };
                result_vec.push(lder_to_seq(vec![access_oid, access_loc]));
            }
        }
        _ => panic!("Error parsing AIA: {:?}", extension_val),
    }
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(result_vec), ASN1_OCTET_STR))
}

fn parse_cbor_ext_issuer_alt_name(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_ISSUER_ALT_NAME_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    lder_to_two_seq(oid, lder_to_generic(parse_cbor_general_name(extension_val), ASN1_OCTET_STR))
}

fn parse_cbor_ext_freshest_crl(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_FRESHEST_CRL_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    lder_to_two_seq(oid, parse_cbor_crl_distribution_points(extension_val))
}

fn parse_cbor_ext_subject_info_access(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_INFO_ACCESS_OID.to_der_vec().unwrap();
    if critical { oid.extend(ASN1_X509_CRITICAL.to_vec()); }
    let mut result_vec = Vec::new();
    match extension_val {
        Value::Bytes(b) => return lder_to_two_seq(oid, lder_to_generic(b.to_vec(), ASN1_OCTET_STR)),
        Value::Array(elements) => {
            assert!(elements.len() % 2 == 0, "SubjectInfoAccess must have even number of elements");
            for i in (0..elements.len()).step_by(2) {
                let access_oid = match &elements[i] {
                    Value::Integer(id) => map_auth_info_id_to_oid(*id as i64),
                    Value::Bytes(b) => lder_to_generic(b.to_vec(), ASN1_OID),
                    _ => panic!("Expected OID for SIA access method"),
                };
                let access_loc = match &elements[i + 1] {
                    Value::Text(s) => lder_to_generic(s.as_bytes().to_vec(), ASN1_URL),
                    _ => panic!("Expected text for SIA access location"),
                };
                result_vec.push(lder_to_seq(vec![access_oid, access_loc]));
            }
        }
        _ => panic!("Error parsing Subject Info Access: {:?}", extension_val),
    }
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(result_vec), ASN1_OCTET_STR))
}

/// Reverses `bitstring_to_i128`: reconstructs a DER BIT STRING from the integer form.
/// The integer encodes [unused_bits+1, value_bytes...] in big-endian.
fn i128_to_bitstring_der(v: i128) -> Vec<u8> {
    let be = v.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(15);
    let trimmed = &be[start..]; // [unused_bits+1, val_bytes...]
    let mut bs_content = vec![trimmed[0] - 1]; // unused_bits
    bs_content.extend_from_slice(&trimmed[1..]);
    lder_to_generic(bs_content, ASN1_BIT_STR)
}

/// Decodes C509 ipAddrBlocks (IDs 32, 34) back to DER.
/// CBOR: flat array [AFI, SAFI_or_null, choice, ...] in groups of 3.
fn reconstruct_ip_addr_blocks(oid: &Oid<'static>, val: &Value, critical: bool) -> Vec<u8> {
    let mut oid_der = oid.to_der_vec().unwrap();
    if critical { oid_der.extend(ASN1_X509_CRITICAL.to_vec()); }
    let items = match val {
        Value::Array(a) => a,
        _ => panic!("Expected array for ipAddrBlocks, got {:?}", val),
    };
    let mut families = Vec::new();
    let mut j = 0;
    while j + 2 < items.len() {
        let afi = match &items[j] { Value::Integer(v) => *v as u16, _ => panic!("Expected AFI integer") };
        let safi = match &items[j + 1] {
            Value::Null => None,
            Value::Integer(v) => Some(*v as u8),
            _ => panic!("Expected SAFI integer or null"),
        };
        let mut addr_family_bytes = afi.to_be_bytes().to_vec();
        if let Some(s) = safi { addr_family_bytes.push(s); }
        let addr_family_der = lder_to_generic(addr_family_bytes, ASN1_OCTET_STR);
        let choice_der = match &items[j + 2] {
            Value::Null => ASN1_NULL.to_vec(),
            Value::Array(addr_items) => {
                let mut addr_or_ranges = Vec::new();
                let mut prev: i128 = 0;
                for item in addr_items {
                    match item {
                        Value::Integer(delta) => {
                            let curr = prev + *delta;
                            prev = curr;
                            addr_or_ranges.push(i128_to_bitstring_der(curr));
                        }
                        Value::Bytes(bs_content) => {
                            addr_or_ranges.push(lder_to_generic(bs_content.to_vec(), ASN1_BIT_STR));
                        }
                        Value::Array(inner) => match &inner[0] {
                            Value::Integer(min_d) => {
                                let max_d = match &inner[1] { Value::Integer(v) => *v, _ => panic!("Expected integer for range max") };
                                let curr_min = prev + *min_d;
                                let curr_max = curr_min + max_d;
                                prev = curr_max;
                                addr_or_ranges.push(lder_to_seq(vec![
                                    i128_to_bitstring_der(curr_min),
                                    i128_to_bitstring_der(curr_max),
                                ]));
                            }
                            Value::Bytes(min_bs) => {
                                let max_bs = match &inner[1] { Value::Bytes(b) => b, _ => panic!("Expected bytes for range max") };
                                addr_or_ranges.push(lder_to_seq(vec![
                                    lder_to_generic(min_bs.to_vec(), ASN1_BIT_STR),
                                    lder_to_generic(max_bs.to_vec(), ASN1_BIT_STR),
                                ]));
                            }
                            _ => panic!("Unexpected range format in ipAddrBlocks"),
                        },
                        _ => panic!("Unexpected item in ipAddrBlocks choice: {:?}", item),
                    }
                }
                lder_to_seq(addr_or_ranges)
            }
            _ => panic!("Unexpected choice value in ipAddrBlocks"),
        };
        families.push(lder_to_seq(vec![addr_family_der, choice_der]));
        j += 3;
    }
    lder_to_two_seq(oid_der, lder_to_generic(lder_to_seq(families), ASN1_OCTET_STR))
}

/// Decodes C509 autonomousSysIds (IDs 33, 35) back to DER.
/// CBOR: null (inherit/absent) or array of delta-encoded AS numbers/ranges.
fn reconstruct_as_identifiers(oid: &Oid<'static>, val: &Value, critical: bool) -> Vec<u8> {
    let mut oid_der = oid.to_der_vec().unwrap();
    if critical { oid_der.extend(ASN1_X509_CRITICAL.to_vec()); }
    let asnum_der = match val {
        Value::Null => ASN1_NULL.to_vec(),
        Value::Array(items) => {
            let mut as_list = Vec::new();
            let mut prev: u64 = 0;
            for item in items {
                match item {
                    Value::Integer(delta) => {
                        let curr = prev + *delta as u64;
                        prev = curr;
                        as_list.push(lder_to_pos_int(uint_to_minimal_bytes(curr)));
                    }
                    Value::Array(inner) => {
                        let min_d = match &inner[0] { Value::Integer(v) => *v as u64, _ => panic!("Expected integer for AS range min") };
                        let max_d = match &inner[1] { Value::Integer(v) => *v as u64, _ => panic!("Expected integer for AS range max") };
                        let curr_min = prev + min_d;
                        let curr_max = curr_min + max_d;
                        prev = curr_max;
                        as_list.push(lder_to_seq(vec![
                            lder_to_pos_int(uint_to_minimal_bytes(curr_min)),
                            lder_to_pos_int(uint_to_minimal_bytes(curr_max)),
                        ]));
                    }
                    _ => panic!("Unexpected item in autonomousSysIds: {:?}", item),
                }
            }
            lder_to_seq(as_list)
        }
        _ => panic!("Expected null or array for autonomousSysIds, got {:?}", val),
    };
    // Wrap asnum choice in [0] context tag, then in outer SEQUENCE
    let asnum_ctx = lder_to_gen_seq(vec![asnum_der], 0xa0);
    let ext_content = lder_to_seq(vec![asnum_ctx]);
    lder_to_two_seq(oid_der, lder_to_generic(ext_content, ASN1_OCTET_STR))
}

/// Decodes a C509 extensions array into a Vec of individual DER-encoded extension SEQUENCEs.
/// Shared by `parse_cbor_extensions` (cert path, adds [3] wrapper) and
/// `parse_c509_csr` (CSR extensionRequest path, wraps in plain SEQUENCE).
pub(crate) fn parse_cbor_extensions_inner(input: &Value) -> Vec<Vec<u8>> {
    let mut parsed_extensions_arr = Vec::new();
    match input {
        Value::Null => { /* no extensions */ }
        Value::Integer(val) => { parsed_extensions_arr.push(parse_cbor_ext_key_usage(input, *val < 0)); }
        Value::Array(extension_array) => {
            let mut i = 0;
            while i < extension_array.len() {
                parsed_extensions_arr.push({
                    match &extension_array[i] {
                        Value::Integer(ext_type) => {
                            let dummy = match ext_type.unsigned_abs() as u16 {
                                1 => parse_cbor_ext_subject_key_id(&extension_array[i + 1], *ext_type < 0),
                                2 => parse_cbor_ext_key_usage(&extension_array[i + 1], *ext_type < 0),
                                3 => parse_cbor_ext_subject_alt_name(&extension_array[i + 1], *ext_type < 0),
                                4 => parse_cbor_ext_basic_constraints(&extension_array[i + 1], *ext_type < 0),
                                5 => parse_cbor_ext_crl_dist_points(&extension_array[i + 1], *ext_type < 0),
                                6 => parse_cbor_ext_cert_policies(&extension_array[i + 1], *ext_type < 0),
                                7 => parse_cbor_ext_auth_key_id(&extension_array[i + 1], *ext_type < 0),
                                8 => parse_cbor_ext_ext_key_usage(&extension_array[i + 1], *ext_type < 0),
                                9 => parse_cbor_ext_auth_info(&extension_array[i + 1], *ext_type < 0),
                                // ext ID 10 (SCT List) removed in draft-11; falls through to raw-OID path
                                24 => parse_cbor_ext_subject_directory_attr(&extension_array[i + 1], *ext_type < 0),
                                25 => parse_cbor_ext_issuer_alt_name(&extension_array[i + 1], *ext_type < 0),
                                26 => parse_cbor_ext_name_constraints(&extension_array[i + 1], *ext_type < 0),
                                27 => parse_cbor_ext_policy_mappings(&extension_array[i + 1], *ext_type < 0),
                                28 => parse_cbor_ext_policy_constraints(&extension_array[i + 1], *ext_type < 0),
                                29 => parse_cbor_ext_freshest_crl(&extension_array[i + 1], *ext_type < 0),
                                30 => parse_cbor_ext_inhibit_anypolicy(&extension_array[i + 1], *ext_type < 0),
                                31 => parse_cbor_ext_subject_info_access(&extension_array[i + 1], *ext_type < 0),
                                32 => reconstruct_ip_addr_blocks(&EXT_IP_ADDR_BLOCKS_OID, &extension_array[i + 1], *ext_type < 0),
                                33 => reconstruct_as_identifiers(&EXT_AS_IDENTIFIERS_OID, &extension_array[i + 1], *ext_type < 0),
                                34 => reconstruct_ip_addr_blocks(&EXT_IP_ADDR_BLOCKS_V2_OID, &extension_array[i + 1], *ext_type < 0),
                                35 => reconstruct_as_identifiers(&EXT_AS_IDENTIFIERS_V2_OID, &extension_array[i + 1], *ext_type < 0),
                                36 => parse_cbor_ext_ocsp_no_check(&extension_array[i + 1], *ext_type < 0),
                                38 => parse_cbor_ext_tls_features(&extension_array[i + 1], *ext_type < 0),
                                _ => panic!("Ext type {} out of scope!", ext_type),
                            };
                            i += 2;
                            dummy
                        }
                        Value::Bytes(raw_ext_type_oid) => {
                            let this_oid = lder_to_generic(raw_ext_type_oid.to_vec(), ASN1_OID);
                            let mut current_idx = i + 1;
                            let mut critical_flag = Vec::new();
                            if let Some(Value::Bool(true)) = extension_array.get(current_idx) {
                                critical_flag = ASN1_X509_CRITICAL.to_vec();
                                current_idx += 1;
                            }
                            let ext_val = match extension_array.get(current_idx) {
                                Some(Value::Bytes(raw_val)) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
                                _ => panic!("Error parsing unknown extension value"),
                            };
                            i = current_idx + 1;
                            lder_to_two_seq(this_oid, [critical_flag, ext_val].concat())
                        }
                        _ => panic!("Unknown ext type"),
                    }
                });
            }
        }
        _ => panic!("Unknown ext value"),
    }
    parsed_extensions_arr
}

/// Decodes a C509 extensions array and wraps the result in the X.509 [3] EXPLICIT container
/// used in TBSCertificate. For CSR extensionRequest use `parse_cbor_extensions_inner` directly.
pub(crate) fn parse_cbor_extensions(input: &Value) -> Vec<u8> {
    lder_to_generic(lder_to_seq(parse_cbor_extensions_inner(input)), ASN1_INDEX_THREE)
}
