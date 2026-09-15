//! Public key and signature encoding/decoding for C509.
//!
//! Converts between C509 CBOR key/signature representations and standard DER
//! SubjectPublicKeyInfo and AlgorithmIdentifier structures. Includes EC point
//! decompression (Tonelli-Shanks) for all supported Weierstrass curves.

use serde_cbor::Value;
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use asn1_rs::ToDer;
use crate::lder::*;
use crate::lcbor::*;
use crate::registry::*;
use crate::help::get_as_bytes;
use crate::*;

/// Parameters for an elliptic curve field, used during EC public key decompression.
#[derive(Clone)]
pub(crate) struct ECCCurve {
    pub p: BigInt, // field prime
    pub a: BigInt, // curve coefficient a
    pub b: BigInt, // curve coefficient b
    pub l: usize,  // field byte length
}

/// Maps a C509 public-key algorithm ID (or fallback OID bytes) to a DER-encoded OID.
///
/// Returns `(Some(id), oid_der)` for registered IDs (draft §9.2), or
/// `(None, oid_der)` for raw OID byte arrays (RFC 9090 fallback).
pub(crate) fn map_pk_id_to_oid(input: &Value) -> (Option<i64>, Vec<u8>) {
    match input {
        Value::Integer(alg_id) => {
            let id = *alg_id as i64;
            // Helper to encode a single OID (no params) as AlgorithmIdentifier.
            let oid_only = |oid: &asn1_rs::Oid| lder_to_generic(oid.as_bytes().to_vec(), ASN1_OID);
            // Helper to encode OID + curve-param OID as AlgorithmIdentifier SEQUENCE.
            let oid_with_param = |oid: &asn1_rs::Oid, param: &asn1_rs::Oid|
                lder_to_two_seq(lder_to_generic(oid.as_bytes().to_vec(), ASN1_OID),
                                lder_to_generic(param.as_bytes().to_vec(), ASN1_OID));
            match id {
                x if x == PK_RSA          => (Some(id), oid_only(&PK_RSA_OID)),
                x if x == PK_SECP256R     => (Some(id), oid_only(&PK_SECP256R_OID)),
                x if x == PK_SECP384R     => (Some(id), oid_only(&PK_SECP384R_OID)),
                x if x == PK_SECP521R     => (Some(id), oid_only(&PK_SECP521R_OID)),
                x if x == PK_X25519       => (Some(id), oid_only(&PK_X25519_OID)),
                x if x == PK_X448         => (Some(id), oid_only(&PK_X448_OID)),
                x if x == PK_ED25519      => (Some(id), oid_only(&PK_ED25519_OID)),
                x if x == PK_ED448        => (Some(id), oid_only(&PK_ED448_OID)),
                x if x == PK_BRAINPOOL256R1 => (Some(id), oid_with_param(&PK_EC_OID, &PK_BRAINPOOL256R1_PARAM_OID)),
                x if x == PK_BRAINPOOL384R1 => (Some(id), oid_with_param(&PK_EC_OID, &PK_BRAINPOOL384R1_PARAM_OID)),
                x if x == PK_BRAINPOOL512R1 => (Some(id), oid_with_param(&PK_EC_OID, &PK_BRAINPOOL512R1_PARAM_OID)),
                x if x == PK_FRP256V1     => (Some(id), oid_with_param(&PK_EC_OID, &PK_FRP256V1_PARAM_OID)),
                x if x == PK_SM2P256V1    => (Some(id), oid_with_param(&PK_EC_OID, &PK_SM2P256V1_PARAM_OID)),
                _ => panic!("Unknown pk type: {}", id),
            }
        },
        Value::Bytes(raw_alg_id) => (None, raw_alg_id.to_vec()),
        Value::Array(arr) => {
            // RFC 9090 OID fallback (draft-ietf-cose-cbor-encoded-cert §2.3.3):
            // [~oid_value_bytes] or [~oid_value_bytes, params_der_bytes]
            // ~oid = OID value bytes only, WITHOUT the 06+length DER tag.
            // The parameters byte string (if present) is full DER (including its own tag).
            let oid_val = match &arr[0] {
                Value::Bytes(b) => b.to_vec(),
                _ => panic!("Could not parse pkAlg: expected bytes for ~oid"),
            };
            let oid_der = lder_to_generic(oid_val, ASN1_OID);
            let alg_id_der = if arr.len() > 1 {
                match &arr[1] {
                    Value::Bytes(params) => lder_to_two_seq(oid_der, params.to_vec()),
                    _ => panic!("Could not parse pkAlg: expected bytes for parameters"),
                }
            } else {
                lder_to_seq(vec![oid_der])
            };
            (None, alg_id_der)
        }
        _ => panic!("Could not parse pk type"),
    }
}

/// Reconstructs an X.509 SubjectPublicKeyInfo DER structure from C509 fields.
///
/// `key_type` is the algorithm ID returned by [`map_pk_id_to_oid`].
/// `oid_bytes` is the DER-encoded algorithm OID.
/// Handles RSA, EC (secp256r1/384r1/521r1, SM2, FRP256v1), X25519/X448, Ed25519/Ed448,
/// and DH keys; falls back to raw storage for unknown types.
pub(crate) fn parse_cbor_pub_key(pub_key: &Value, key_type: Option<i64>, oid_bytes: Vec<u8>) -> Vec<u8> {
    let mut pub_key_vec = Vec::new();
    let mut result = Vec::new();
    if let Value::Bytes(pub_key_array) = pub_key { pub_key_vec = pub_key_array.to_vec(); }

    match key_type {
        Some(id) => {
            let oid_b = |oid: &asn1_rs::Oid| lder_to_generic(oid.as_bytes().to_vec(), ASN1_OID);
            let ec_alg_id = |param_oid: &asn1_rs::Oid|
                lder_to_two_seq(oid_b(&PK_EC_OID), oid_b(param_oid));
            let oid_only_seq = |oid: &asn1_rs::Oid|
                lder_to_generic(oid_b(oid), ASN1_SEQ);
            match id {
            x if x == PK_RSA => {
                result.push(lder_to_two_seq(oid_b(&PK_RSA_OID), ASN1_NULL.to_vec()));
                result.push(check_and_reconstruct_pub_key_rsa(pub_key));
            }
            x if x == PK_SECP256R => {
                result.push(ec_alg_id(&PK_SECP256R_PARAM_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            x if x == PK_SECP384R => {
                result.push(ec_alg_id(&PK_SECP384R_PARAM_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            x if x == PK_SECP521R => {
                result.push(ec_alg_id(&PK_SECP521R_PARAM_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            x if x == PK_X25519 => {
                result.push(oid_only_seq(&PK_X25519_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            x if x == PK_X448 => {
                result.push(oid_only_seq(&PK_X448_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            x if x == PK_ED25519 => {
                result.push(oid_only_seq(&PK_ED25519_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            x if x == PK_ED448 => {
                result.push(oid_only_seq(&PK_ED448_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            x if x == PK_BRAINPOOL256R1 => {
                result.push(ec_alg_id(&PK_BRAINPOOL256R1_PARAM_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            x if x == PK_BRAINPOOL384R1 => {
                result.push(ec_alg_id(&PK_BRAINPOOL384R1_PARAM_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            x if x == PK_BRAINPOOL512R1 => {
                result.push(ec_alg_id(&PK_BRAINPOOL512R1_PARAM_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            x if x == PK_FRP256V1 => {
                result.push(ec_alg_id(&PK_FRP256V1_PARAM_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            x if x == PK_SM2P256V1 => {
                result.push(ec_alg_id(&PK_SM2P256V1_PARAM_OID));
                result.push(check_and_reconstruct_pub_key_ecc(pub_key_vec, id));
            }
            _ => panic!("Could not parse public key type {}", id),
        }}
        None => {
            result.push(oid_bytes);
            result.push(lder_to_bit_str(pub_key_vec));
        }
    }
    lder_to_seq(result)
}

/// Reconstructs a full uncompressed (04-prefixed) EC public key from C509 form.
///
/// C509 uses 0xFE (even y) and 0xFD (odd y) as compressed-point prefixes instead
/// of the standard SECG 0x02/0x03, to distinguish C509-compressed from already-
/// compressed keys that may appear in type-3 (X.509-encoded) certificates.
/// Decompression recovers y by solving y² = x³ + ax + b mod p via Tonelli-Shanks.
pub(crate) fn check_and_reconstruct_pub_key_ecc(pub_key: Vec<u8>, ecc_type_id: i64) -> Vec<u8> {
    let mut result = Vec::new();
    if [PK_X25519, PK_X448, PK_ED25519, PK_ED448, 12, 13].contains(&ecc_type_id) {
        result = pub_key;
    } else {
        match pub_key[0] {
            SECG_EVEN_COMPRESSED => {
                result.push(SECG_UNCOMPRESSED);
                result.extend_from_slice(&pub_key[1..]);
                result.extend(decompress_ecc_key(pub_key[1..].to_vec(), true, ecc_type_id));
            }
            SECG_ODD_COMPRESSED => {
                result.push(SECG_UNCOMPRESSED);
                result.extend_from_slice(&pub_key[1..]);
                result.extend(decompress_ecc_key(pub_key[1..].to_vec(), false, ecc_type_id));
            }
            // Handles cases where the public key is already in uncompressed (0x04) or native compressed (0x02, 0x03) format
            // (as seen in test vector tv_3_10_2).
            SECG_EVEN | SECG_ODD | SECG_UNCOMPRESSED => result = pub_key,
            _ => panic!("Expected compression indicator"),
        }
    }
    lder_to_bit_str(result)
}

/// Returns the Legendre symbol (a/p): 1 if a is a QR mod p, -1 if not, 0 if a≡0.
pub(crate) fn legendre_symbol(a: &BigInt, p: &BigInt) -> BigInt {
    let ls = a.modpow(&((p - BigInt::one()) / BigInt::from(2)), p);
    if ls == p - BigInt::one() { BigInt::from(-1) } else { ls }
}

/// Modular square root via Tonelli-Shanks. Used to recover the y-coordinate
/// of an EC point from its x-coordinate during C509 public key decompression
/// (draft §7.2). Panics if n is not a quadratic residue mod p.
pub(crate) fn tonelli_shanks(n: &BigInt, p: &BigInt) -> BigInt {
    if legendre_symbol(n, p) != BigInt::one() { panic!("n is not a quadratic residue modulo p"); }
    let mut q = p - BigInt::one();
    let mut s = 0u32;
    while q.clone() % 2 == BigInt::zero() { q /= 2; s += 1; }
    if s == 1 { return n.modpow(&((p + BigInt::one()) / BigInt::from(4)), p); }
    let mut z = BigInt::from(2);
    while legendre_symbol(&z, p) != BigInt::from(-1) { z += 1; }
    let mut m = s;
    let mut c = z.modpow(&q, p);
    let mut t = n.modpow(&q, p);
    let mut r = n.modpow(&((q + BigInt::one()) / BigInt::from(2)), p);
    loop {
        if t == BigInt::zero() { return BigInt::zero(); }
        if t == BigInt::one() { return r; }
        let mut i = 0u32;
        let mut temp = t.clone();
        while temp != BigInt::one() && i < m { temp = temp.modpow(&BigInt::from(2), p); i += 1; }
        if i == m { panic!("Tonelli-Shanks failed"); }
        let b = c.modpow(&BigInt::from(2u32).pow(m - i - 1), p);
        m = i;
        c = (&b * &b) % p;
        t = (&t * &c) % p;
        r = (&r * &b) % p;
    }
}


pub(crate) fn decompress_ecc_key(pub_key_x: Vec<u8>, is_even: bool, ecc_type_id: i64) -> Vec<u8> {
    // Supports Brainpool curves (P256R1, P384R1, P512R1) and others (as seen in tv_3_6_2, tv_3_7_2).
    let x = BigInt::from_bytes_be(Sign::Plus, &pub_key_x);
    let mc = match ecc_type_id {
        PK_SECP256R => ECCCurve {
            p: BigInt::parse_bytes(b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16).unwrap(),
            a: BigInt::parse_bytes(b"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16).unwrap(),
            b: BigInt::parse_bytes(b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16).unwrap(),
            l: 32,
        },
        PK_SECP384R => ECCCurve {
            p: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16).unwrap(),
            a: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16).unwrap(),
            b: BigInt::parse_bytes(b"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16).unwrap(),
            l: 48,
        },
        PK_SECP521R => ECCCurve {
            p: BigInt::parse_bytes(b"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
            a: BigInt::parse_bytes(b"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", 16).unwrap(),
            b: BigInt::parse_bytes(b"0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16).unwrap(),
            l: 66,
        },
        PK_BRAINPOOL256R1 => ECCCurve {
            p: BigInt::parse_bytes(b"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16).unwrap(),
            a: BigInt::parse_bytes(b"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16).unwrap(),
            b: BigInt::parse_bytes(b"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16).unwrap(),
            l: 32,
        },
        PK_BRAINPOOL384R1 => ECCCurve {
            p: BigInt::parse_bytes(b"8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53", 16).unwrap(),
            a: BigInt::parse_bytes(b"7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826", 16).unwrap(),
            b: BigInt::parse_bytes(b"04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11", 16).unwrap(),
            l: 48,
        },
        PK_BRAINPOOL512R1 => ECCCurve {
            p: BigInt::parse_bytes(b"aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3", 16).unwrap(),
            a: BigInt::parse_bytes(b"7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca", 16).unwrap(),
            b: BigInt::parse_bytes(b"3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723", 16).unwrap(),
            l: 64,
        },
        PK_FRP256V1 => ECCCurve {
            p: BigInt::parse_bytes(b"f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03", 16).unwrap(),
            a: BigInt::parse_bytes(b"f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00", 16).unwrap(),
            b: BigInt::parse_bytes(b"ee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f", 16).unwrap(),
            l: 32,
        },
        // SM2P256V1 (GB/T 32918.1-2016, OID 1.2.156.10197.1.301)
        PK_SM2P256V1 => ECCCurve {
            p: BigInt::parse_bytes(b"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16).unwrap(),
            a: BigInt::parse_bytes(b"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16).unwrap(),
            b: BigInt::parse_bytes(b"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16).unwrap(),
            l: 32,
        },
        _ => panic!("Cannot handle ECC curve of type {}", ecc_type_id),
    };
    let x3 = (&x * &x * &x) % &mc.p;
    let ax = (&mc.a * &x) % &mc.p;
    let mut y2 = (x3 + ax + &mc.b) % &mc.p;
    if y2 < BigInt::zero() { y2 += &mc.p; }
    if y2 == BigInt::zero() { return vec![0; mc.l]; }
    let mut y = tonelli_shanks(&y2, &mc.p);
    if (y.clone() % 2 == BigInt::zero()) != is_even { y = &mc.p - &y; }
    let (_, mut yb) = y.to_bytes_be();
    while yb.len() < mc.l { yb.insert(0, 0); } 
    yb
}

/// Reconstructs an RSA public key DER BIT STRING from C509 encoding.
///
/// C509 stores RSA keys as `[modulus, exponent]` (both as bytes) if the exponent
/// is non-standard, or as bare `modulus` bytes when exponent is 65537 (default).
pub(crate) fn check_and_reconstruct_pub_key_rsa(pub_key: &Value) -> Vec<u8> {
    let modulus;
    let exponent;
    match pub_key {
        Value::Array(pub_key_arr) => {
            assert!(pub_key_arr.len() == 2);
            modulus = lder_to_pos_int(get_as_bytes(pub_key_arr.first().unwrap()));
            exponent = lder_to_pos_int(get_as_bytes(pub_key_arr.get(1).unwrap()));
        }
        Value::Bytes(pub_key_mod_only) => {
            modulus = lder_to_pos_int(pub_key_mod_only.to_vec());
            exponent = ASN1_65537.to_vec();
        }
        _ => panic!("Could not decode rsa pub key"),
    }
    lder_to_bit_str(lder_to_two_seq(modulus, exponent))
}

/// Reconstructs DER-encoded algorithm identifier and signature value from C509 fields.
///
/// Returns `(alg_id_der, sig_value_der)` where:
/// - `alg_id_der` is the full AlgorithmIdentifier SEQUENCE (OID + optional params).
/// - `sig_value_der` is the DER BIT STRING containing the signature bytes.
///
/// Handles ECDSA (RFC 5480), RSA PKCS#1 v1.5 and PSS, EdDSA, SM2, and DH-PoP
/// (RFC 6955 `sa-ecdhPop-sha*-hmac-sha*` — stored as HMAC bytes or `[issuer, serial, mac]`).
pub(crate) fn parse_cbor_sig_info(sig_alg: &Value, sig_val: &Value) -> (Vec<u8>, Vec<u8>) {
    let oid;
    // sig_val is Bytes for most algorithms, but may be Array for DH-PoP (keyRef present).
    // Defer extraction to avoid panicking before the alg match dispatches correctly.
    let sig_val_vec = match sig_val { Value::Bytes(b) => b.to_vec(), _ => Vec::new() };
    let parsed_sig_val;
    let mut param = Vec::new();
    match sig_alg {
        Value::Integer(sign_alg_id) => {
            let id = *sign_alg_id as i64;
            match id {
                x if x == SIG_RSA_V15_SHA1    => { oid = SIG_RSA_V15_SHA1_OID.as_bytes().to_vec();    param = ASN1_NULL.to_vec(); parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_ECDSA_SHA1      => { oid = SIG_ECDSA_SHA1_OID.as_bytes().to_vec();      parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone()); }
                x if x == SIG_ECDSA_SHA256    => { oid = SIG_ECDSA_SHA256_OID.as_bytes().to_vec();    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone()); }
                x if x == SIG_ECDSA_SHA384    => { oid = SIG_ECDSA_SHA384_OID.as_bytes().to_vec();    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone()); }
                x if x == SIG_ECDSA_SHA512    => { oid = SIG_ECDSA_SHA512_OID.as_bytes().to_vec();    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone()); }
                x if x == SIG_ECDSA_SHAKE128  => { oid = SIG_ECDSA_SHAKE128_OID.as_bytes().to_vec();  parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone()); }
                x if x == SIG_ECDSA_SHAKE256  => { oid = SIG_ECDSA_SHAKE256_OID.as_bytes().to_vec();  parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone()); }
                x if x == SIG_ALG_UNSIGNED    => { oid = SIG_ALG_UNSIGNED_OID.as_bytes().to_vec();    parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_ED25519         => { oid = SIG_ED25519_OID.as_bytes().to_vec();         parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_ED448           => { oid = SIG_ED448_OID.as_bytes().to_vec();           parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_RSA_V15_SHA256  => { oid = SIG_RSA_V15_SHA256_OID.as_bytes().to_vec(); param = ASN1_NULL.to_vec(); parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_RSA_V15_SHA384  => { oid = SIG_RSA_V15_SHA384_OID.as_bytes().to_vec(); param = ASN1_NULL.to_vec(); parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_RSA_V15_SHA512  => { oid = SIG_RSA_V15_SHA512_OID.as_bytes().to_vec(); param = ASN1_NULL.to_vec(); parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_RSA_PSS_SHA256  => { oid = SIG_RSA_PSS_SHA256_OID.as_bytes().to_vec(); param = build_pss_params(&HASH_SHA256_OID.to_der_vec().unwrap(), 32); parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_RSA_PSS_SHA384  => { oid = SIG_RSA_PSS_SHA384_OID.as_bytes().to_vec(); param = build_pss_params(&HASH_SHA384_OID.to_der_vec().unwrap(), 48); parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_RSA_PSS_SHA512  => { oid = SIG_RSA_PSS_SHA512_OID.as_bytes().to_vec(); param = build_pss_params(&HASH_SHA512_OID.to_der_vec().unwrap(), 64); parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_RSA_PSS_SHAKE128 => { oid = SIG_RSA_PSS_SHAKE128_OID.as_bytes().to_vec(); parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_RSA_PSS_SHAKE256 => { oid = SIG_RSA_PSS_SHAKE256_OID.as_bytes().to_vec(); parsed_sig_val = sig_val_vec.clone(); }
                x if x == SIG_SM2_V15_SM3     => { oid = SIG_SM2_V15_SM3_OID.as_bytes().to_vec();    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone()); }
                // DH proof-of-possession (RFC 6955 / C509 §9.1 Table 3 values 14–16).
                // C509 encoding (from parse_x509_csr):
                //   no keyRef  → bytes(mac)
                //   with keyRef → [issuer_cbor, serial_bytes, mac_bytes]
                // Decode reconstructs DhSigStatic DER:
                //   SEQUENCE { [SEQUENCE { Name, INTEGER }], OCTET STRING(mac) }
                x if x == SIG_ECDHPOP_SHA256 || x == SIG_ECDHPOP_SHA384 || x == SIG_ECDHPOP_SHA512 => {
                    oid = match id {
                        x if x == SIG_ECDHPOP_SHA256 => SIG_ECDHPOP_SHA256_OID.as_bytes().to_vec(),
                        x if x == SIG_ECDHPOP_SHA384 => SIG_ECDHPOP_SHA384_OID.as_bytes().to_vec(),
                        _                             => SIG_ECDHPOP_SHA512_OID.as_bytes().to_vec(),
                    };
                    parsed_sig_val = match sig_val {
                        Value::Bytes(mac) => {
                            // No keyRef: SEQUENCE { OCTET STRING(mac) }
                            lder_to_seq(vec![lder_to_generic(mac.clone(), ASN1_OCTET_STR)])
                        }
                        Value::Array(parts) => {
                            // With keyRef: SEQUENCE { SEQUENCE { Name, INTEGER }, OCTET STRING(mac) }
                            let issuer_der = crate::conversion::parse_cbor_name(parts.first().expect("missing issuer"));
                            let serial_bytes = get_as_bytes(parts.get(1).expect("missing serial"));
                            let mac = get_as_bytes(parts.get(2).expect("missing mac"));
                            let key_ref = lder_to_two_seq(issuer_der, lder_to_pos_int(serial_bytes.to_vec()));
                            lder_to_seq(vec![key_ref, lder_to_generic(mac.to_vec(), ASN1_OCTET_STR)])
                        }
                        _ => panic!("DH-PoP sig val must be bytes or array"),
                    };
                }
                _ => panic!("Unknown sign alg type: {}", id),
            }
            if !param.is_empty() { (lder_to_two_seq(lder_to_generic(oid, ASN1_OID), param), parsed_sig_val) }
            else { (lder_to_generic(lder_to_generic(oid, ASN1_OID), ASN1_SEQ), parsed_sig_val) }
        }
        Value::Bytes(raw_alg_id) => { (raw_alg_id.to_vec(), sig_val_vec) }
        Value::Array(arr) => {
            // RFC 9090 OID fallback (draft-ietf-cose-cbor-encoded-cert §2.2):
            // [~oid_value_bytes] or [~oid_value_bytes, params_der_bytes]
            // ~oid = OID value bytes only (no 06+length tag); params = full DER.
            let oid_val = match &arr[0] {
                Value::Bytes(b) => b.to_vec(),
                _ => panic!("Expected bytes for ~oid in sigAlg array"),
            };
            let oid_der = lder_to_generic(oid_val, ASN1_OID);
            let alg_id_der = if arr.len() > 1 {
                match &arr[1] {
                    Value::Bytes(params) => lder_to_two_seq(oid_der, params.to_vec()),
                    _ => panic!("Expected bytes for params in sigAlg array"),
                }
            } else {
                lder_to_seq(vec![oid_der])
            };
            (alg_id_der, sig_val_vec)
        }
        _ => panic!("Could not parse sig alg"),
    }
}

/// Converts a raw C509 ECDSA signature (fixed-length r‖s) into DER SEQUENCE { r, s }.
///
/// C509 stores ECDSA signatures as `r ‖ s` with each component zero-padded to the
/// curve byte length. DER INTEGERs use minimal encoding, so leading zeros are stripped.
pub(crate) fn parse_cbor_ecc_sig_value(sig_val_bytes: Vec<u8>) -> Vec<u8> {
    let key_size = sig_val_bytes.len() / 2;
    // C509 pads r and s to key_size; DER INTEGERs require minimal encoding (no leading zeros)
    let r = strip_leading_zeros(sig_val_bytes[..key_size].to_vec());
    let s = strip_leading_zeros(sig_val_bytes[key_size..].to_vec());
    lder_to_seq(vec![lder_to_pos_int(r), lder_to_pos_int(s)])
}

fn strip_leading_zeros(mut v: Vec<u8>) -> Vec<u8> {
    let first_nonzero = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    v.drain(..first_nonzero);
    v
}

/// Builds a DER-encoded RSASSA-PSS AlgorithmIdentifier parameter block.
///
/// Encodes `RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0], maskGenAlgorithm [1], saltLength [2] }`
/// using `hash_oid` for both hash and MGF1 algorithm, with the given `salt_len`.
pub(crate) fn build_pss_params(hash_oid: &[u8], salt_len: u8) -> Vec<u8> {
    let elements = vec![
        lder_to_generic(lder_to_two_seq(hash_oid.to_vec(), ASN1_NULL.to_vec()), ASN1_INDEX_ZERO),
        lder_to_generic(lder_to_two_seq(MGF1_OID.to_der_vec().unwrap(), lder_to_two_seq(hash_oid.to_vec(), ASN1_NULL.to_vec())), ASN1_INDEX_ONE),
        lder_to_generic(lder_to_generic(vec![salt_len], ASN1_INT), ASN1_INDEX_TWO),
    ];
    lder_to_seq(elements)
}

/// Converts a DER ECDSA signature SEQUENCE { INTEGER r, INTEGER s } into C509 form.
///
/// C509 stores ECDSA as `r ‖ s` with both components zero-padded to the same length
/// (the longer of the two), so the decoder can split the buffer at the midpoint.
pub(crate) fn cbor_ecdsa(b: &[u8]) -> Vec<u8> {
    let seq = lder_vec(b, ASN1_SEQ);
    let r = lder_uint(seq[0]).to_vec();
    let s = lder_uint(seq[1]).to_vec();
    let max = std::cmp::max(r.len(), s.len());
    lcbor_bytes(&[vec![0u8; max - r.len()], r, vec![0u8; max - s.len()], s].concat())
}
