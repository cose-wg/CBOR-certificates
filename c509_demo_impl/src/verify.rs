//! Cryptographic verification of natively-signed C509 Type-2 certificates.
//!
//! Complements `type2.rs` (which *produces* Type-2 objects): given a Type-2
//! C509, reconstruct the CBOR TBS (concatenation of fields 0–9), take the signer
//! public key (the subject public key for a self-signed cert, or an explicitly
//! supplied issuer point), and cryptographically verify field 10
//! (issuerSignatureValue) over the TBS.
//!
//! This upgrades the harness's Type-2 story from *structural* (the TBS bytes are
//! reproduced) to *cryptographic* (the draft's published signature is valid) —
//! the check that matters for the non-deterministic ECDSA vectors, whose
//! signatures cannot be reproduced by re-encoding.
//!
//! Supported signer keys and signature algorithms:
//! - ECDSA over secp256r1/secp384r1/secp521r1 (RustCrypto);
//! - ECDSA with SHA-1/SHA-2 or SHAKE (RFC 8692) over brainpoolP256r1/P384r1/
//!   P512r1 and frp256v1 (OpenSSL; frp256v1 from explicit curve parameters, as
//!   OpenSSL has no named curve for it);
//! - SM2 with SM3 and the default distinguishing ID (`sm2.rs`);
//! - Ed25519 (ed25519-dalek) and Ed448 (OpenSSL);
//! - RSA PKCS#1 v1.5 with SHA-1/256/384/512 and RSASSA-PSS with SHA-256/384/512
//!   (`rsa` crate), and RSASSA-PSS with SHAKE128/SHAKE256 (RFC 8702).
//!
//! SECURITY NOTICE: test-vector tooling only. Never use in production.

use std::convert::TryInto;

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroupRef, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;

use crate::lcbor::cbor_item_end;
use crate::registry::{
    PK_BRAINPOOL256R1, PK_BRAINPOOL384R1, PK_BRAINPOOL512R1, PK_ED25519, PK_ED448,
    PK_FRP256V1, PK_RSA, PK_SECP256R, PK_SECP384R, PK_SECP521R, PK_SM2P256V1,
    SIG_ECDSA_SHA256, SIG_ECDSA_SHA384, SIG_ECDSA_SHA512, SIG_ED448,
    SIG_RSA_PSS_SHA256, SIG_RSA_PSS_SHA384, SIG_RSA_PSS_SHA512, SIG_RSA_PSS_SHAKE128,
    SIG_RSA_PSS_SHAKE256, SIG_RSA_V15_SHA1, SIG_RSA_V15_SHA256, SIG_RSA_V15_SHA384,
    SIG_RSA_V15_SHA512, SIG_SM2_V15_SM3,
};
use crate::sm2::{sm2_group, sm2_verify};
use crate::type2::{cbor_int_value, ecdsa_digest, frp256v1_group, pss_shake_params, shake};

const SUPPORTED_KEYS: &str = "P-256, P-384, P-521, brainpoolP256r1, brainpoolP384r1, \
                              brainpoolP512r1, frp256v1, SM2, Ed25519, Ed448, RSA";

/// Split a C509 certificate CBOR (bare 11-item sequence, or a draft-20 `0x8B`
/// array(11)) into its 11 field byte-slices.
fn split_c509_fields(cbor: &[u8]) -> Result<Vec<&[u8]>, String> {
    let mut pos = 0;
    if cbor.first() == Some(&0x8b) {
        pos = 1; // skip the draft-20 array(11) header
    }
    let mut fields = Vec::with_capacity(11);
    for _ in 0..11 {
        if pos >= cbor.len() {
            return Err("truncated C509: fewer than 11 CBOR fields".into());
        }
        let end = cbor_item_end(cbor, pos);
        fields.push(&cbor[pos..end]);
        pos = end;
    }
    Ok(fields)
}

/// Return the payload of a CBOR byte string (major type 2), stripping the header.
fn bstr_payload(cbor: &[u8]) -> Result<&[u8], String> {
    if cbor.is_empty() || (cbor[0] >> 5) != 2 {
        return Err("expected a CBOR byte string".into());
    }
    let ai = cbor[0] & 0x1f;
    let (len, hdr) = match ai {
        0..=23 => (ai as usize, 1usize),
        24 => (cbor[1] as usize, 2),
        25 => (u16::from_be_bytes([cbor[1], cbor[2]]) as usize, 3),
        26 => (u32::from_be_bytes([cbor[1], cbor[2], cbor[3], cbor[4]]) as usize, 5),
        _ => return Err("unsupported byte-string length encoding".into()),
    };
    if hdr + len > cbor.len() {
        return Err("byte string longer than field".into());
    }
    Ok(&cbor[hdr..hdr + len])
}

/// Convert a C509 EC point (`0xFE`/`0xFD` compressed prefix, or `0x04`
/// uncompressed) to a standard SEC1 point (`0x02`/`0x03`/`0x04`) that RustCrypto
/// can decode. Non-EC keys (Ed25519 raw 32-byte) must NOT pass through here.
fn c509_point_to_sec1(point: &[u8]) -> Vec<u8> {
    let mut p = point.to_vec();
    match p.first() {
        Some(0xfe) => p[0] = 0x02, // even-y compressed
        Some(0xfd) => p[0] = 0x03, // odd-y compressed
        _ => {}                    // 0x04 uncompressed / already SEC1
    }
    p
}

/// Verify a self-signed (or issuer-key-supplied) Type-2 C509 certificate's
/// signature. `issuer_point`: raw C509 signer EC point for a CA-signed cert;
/// `None` means self-signed (signer key = the subject key, field 8).
///
/// Returns `Ok(description)` on a valid signature, `Err(reason)` otherwise.
pub fn verify_type2(cbor: &[u8], issuer_point: Option<&[u8]>) -> Result<String, String> {
    let fields = split_c509_fields(cbor)?;

    if cbor_int_value(fields[0]) != 2 {
        return Err(format!(
            "not a Type-2 (natively signed) certificate: field 0 = {}",
            cbor_int_value(fields[0])
        ));
    }

    // TBS = concatenation of the raw CBOR of fields 0..=9 (matches type2.rs).
    let tbs: Vec<u8> = fields[..10].iter().flat_map(|f| f.iter().copied()).collect();

    let sig_alg = cbor_int_value(fields[2]);
    let pk_alg = cbor_int_value(fields[7]);

    // Bail out with the "unsupported" message (which the harness maps to SKIP)
    // BEFORE parsing the key/signature.
    let supported = [
        PK_SECP256R, PK_SECP384R, PK_SECP521R, PK_BRAINPOOL256R1, PK_BRAINPOOL384R1,
        PK_BRAINPOOL512R1, PK_FRP256V1, PK_SM2P256V1, PK_ED25519, PK_ED448, PK_RSA,
    ];
    if !supported.contains(&pk_alg) {
        return Err(format!(
            "verify: unsupported public-key algorithm id {} (supported: {})",
            pk_alg, SUPPORTED_KEYS
        ));
    }

    let sig = bstr_payload(fields[10])?;

    // An RSA key is a CBOR byte string (modulus, exponent 65537) or an array
    // [modulus, exponent]; it is handled before the byte-string parsing below.
    if pk_alg == PK_RSA {
        if issuer_point.is_some() {
            return Err("verify: an explicit issuer key is supported for EC keys only".into());
        }
        let (n, e) = rsa_key_components(fields[8])?;
        return verify_rsa(&tbs, &n, &e, sig, sig_alg);
    }

    // Raw signer key material: subject key (self-signed) unless an issuer key
    // is supplied. Left un-normalised here; each EC path applies the SEC1 fixup.
    let signer_key: &[u8] = match issuer_point {
        Some(k) => k,
        None => bstr_payload(fields[8])?,
    };

    match pk_alg {
        x if x == PK_SECP256R => verify_ecdsa_p256(&tbs, signer_key, sig, sig_alg),
        x if x == PK_SECP384R => verify_ecdsa_p384(&tbs, signer_key, sig, sig_alg),
        x if x == PK_SECP521R => verify_ecdsa_p521(&tbs, signer_key, sig, sig_alg),
        x if x == PK_BRAINPOOL256R1 => verify_ecdsa_named(
            &tbs, openssl::nid::Nid::BRAINPOOL_P256R1, "brainpoolP256r1", signer_key, sig, sig_alg),
        x if x == PK_BRAINPOOL384R1 => verify_ecdsa_named(
            &tbs, openssl::nid::Nid::BRAINPOOL_P384R1, "brainpoolP384r1", signer_key, sig, sig_alg),
        x if x == PK_BRAINPOOL512R1 => verify_ecdsa_named(
            &tbs, openssl::nid::Nid::BRAINPOOL_P512R1, "brainpoolP512r1", signer_key, sig, sig_alg),
        x if x == PK_FRP256V1 => {
            let group = frp256v1_group().map_err(|e| format!("frp256v1 curve setup failed: {e}"))?;
            verify_ecdsa_openssl(&tbs, &group, "frp256v1", signer_key, sig, sig_alg)
        }
        x if x == PK_SM2P256V1 => verify_sm2(&tbs, signer_key, sig, sig_alg),
        x if x == PK_ED25519 => verify_ed25519(&tbs, signer_key, sig),
        x if x == PK_ED448 => verify_ed448(&tbs, signer_key, sig, sig_alg),
        other => Err(format!(
            "verify: unsupported public-key algorithm id {} (supported: {})",
            other, SUPPORTED_KEYS
        )),
    }
}

/// Split a raw r||s signature into an OpenSSL ECDSA signature.
fn raw_to_ecdsa_sig(sig: &[u8], coord_size: usize, curve: &str) -> Result<EcdsaSig, String> {
    if sig.len() != 2 * coord_size {
        return Err(format!(
            "{curve} signature must be {} bytes (r||s), got {}",
            2 * coord_size,
            sig.len()
        ));
    }
    let r = BigNum::from_slice(&sig[..coord_size]).map_err(|e| e.to_string())?;
    let s = BigNum::from_slice(&sig[coord_size..]).map_err(|e| e.to_string())?;
    EcdsaSig::from_private_components(r, s).map_err(|e| e.to_string())
}

/// Public key for `point` (C509 or SEC1 encoding) on `group`.
fn ec_public_key(
    group: &EcGroupRef,
    point: &[u8],
    curve: &str,
) -> Result<EcKey<openssl::pkey::Public>, String> {
    let mut ctx = BigNumContext::new().map_err(|e| e.to_string())?;
    let pt = EcPoint::from_bytes(group, &c509_point_to_sec1(point), &mut ctx)
        .map_err(|e| format!("{curve} public key invalid: {e}"))?;
    EcKey::from_public_key(group, &pt).map_err(|e| format!("{curve} public key invalid: {e}"))
}

/// ECDSA over a curve that OpenSSL knows by name.
fn verify_ecdsa_named(
    tbs: &[u8],
    nid: openssl::nid::Nid,
    curve: &str,
    point: &[u8],
    sig: &[u8],
    sig_alg: i64,
) -> Result<String, String> {
    let group = openssl::ec::EcGroup::from_curve_name(nid)
        .map_err(|e| format!("{curve} curve unavailable in OpenSSL: {e}"))?;
    verify_ecdsa_openssl(tbs, &group, curve, point, sig, sig_alg)
}

/// ECDSA over an OpenSSL `EcGroup` (named or built from explicit parameters).
fn verify_ecdsa_openssl(
    tbs: &[u8],
    group: &EcGroupRef,
    curve: &str,
    point: &[u8],
    sig: &[u8],
    sig_alg: i64,
) -> Result<String, String> {
    // The hash is set by the signature algorithm, not by the curve.
    let (digest, alg) = ecdsa_digest(sig_alg, tbs).map_err(|e| format!("{curve}: {e}"))?;
    let coord_size = ((group.degree() + 7) / 8) as usize;
    let key = ec_public_key(group, point, curve)?;
    let esig = raw_to_ecdsa_sig(sig, coord_size, curve)?;
    match esig.verify(&digest, &key) {
        Ok(true) => Ok(format!("{curve} {alg}: signature VALID")),
        Ok(false) => Err(format!("{curve} {alg} verification FAILED: signature does not match")),
        Err(e) => Err(format!("{curve} {alg} verification FAILED: {e}")),
    }
}

/// SM2 signature with SM3 and the default distinguishing ID (see `sm2.rs`).
fn verify_sm2(tbs: &[u8], point: &[u8], sig: &[u8], sig_alg: i64) -> Result<String, String> {
    if sig_alg != SIG_SM2_V15_SM3 {
        return Err(format!("SM2 with sig alg {} unsupported (expected SM2-with-SM3=8)", sig_alg));
    }
    if sig.len() != 64 {
        return Err(format!("SM2 signature must be 64 bytes (r||s), got {}", sig.len()));
    }
    let group = sm2_group().map_err(|e| format!("SM2 curve unavailable in OpenSSL: {e}"))?;
    let key = ec_public_key(&group, point, "SM2")?;
    let r = BigNum::from_slice(&sig[..32]).map_err(|e| e.to_string())?;
    let s = BigNum::from_slice(&sig[32..]).map_err(|e| e.to_string())?;
    match sm2_verify(&group, key.public_key(), tbs, &r, &s) {
        Ok(true) => Ok("SM2-with-SM3: signature VALID".to_string()),
        Ok(false) => Err("SM2-with-SM3 verification FAILED: signature does not match".into()),
        Err(e) => Err(format!("SM2-with-SM3 verification FAILED: {e}")),
    }
}

fn verify_ed448(tbs: &[u8], key: &[u8], sig: &[u8], sig_alg: i64) -> Result<String, String> {
    use openssl::pkey::{Id, PKey};
    use openssl::sign::Verifier;
    if sig_alg != SIG_ED448 {
        return Err(format!("Ed448 with sig alg {} unsupported (expected Ed448=13)", sig_alg));
    }
    if key.len() != 57 {
        return Err("Ed448 public key must be 57 bytes".into());
    }
    if sig.len() != 114 {
        return Err("Ed448 signature must be 114 bytes".into());
    }
    let pkey = PKey::public_key_from_raw_bytes(key, Id::ED448)
        .map_err(|e| format!("Ed448 public key invalid: {e}"))?;
    let mut verifier = Verifier::new_without_digest(&pkey).map_err(|e| e.to_string())?;
    match verifier.verify_oneshot(sig, tbs) {
        Ok(true) => Ok("Ed448: signature VALID".to_string()),
        Ok(false) => Err("Ed448 verification FAILED: signature does not match".into()),
        Err(e) => Err(format!("Ed448 verification FAILED: {e}")),
    }
}

/// Modulus and public exponent of a C509 RSA key (field 8): a byte string
/// holding the modulus (exponent 65537), or an array [modulus, exponent].
fn rsa_key_components(field8: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    use serde_cbor::Value;
    let value: Value = serde_cbor::from_slice(field8)
        .map_err(|e| format!("RSA public key is not valid CBOR: {e}"))?;
    match value {
        Value::Bytes(n) => Ok((n, vec![0x01, 0x00, 0x01])),
        Value::Array(items) => match items.as_slice() {
            [Value::Bytes(n), Value::Bytes(e)] => Ok((n.clone(), e.clone())),
            _ => Err("RSA public key array must be [modulus, exponent] byte strings".into()),
        },
        _ => Err("RSA public key must be a byte string or an array".into()),
    }
}

fn verify_rsa(tbs: &[u8], n: &[u8], e: &[u8], sig: &[u8], sig_alg: i64) -> Result<String, String> {
    use rsa::{BigUint, Pkcs1v15Sign, Pss, RsaPublicKey};
    use sha1::Sha1;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    if sig_alg == SIG_RSA_PSS_SHAKE128 || sig_alg == SIG_RSA_PSS_SHAKE256 {
        return verify_rsa_pss_shake(tbs, n, e, sig, sig_alg);
    }
    let key = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
        .map_err(|e| format!("RSA public key invalid: {e}"))?;
    let (alg, result) = match sig_alg {
        x if x == SIG_RSA_V15_SHA1 =>
            ("RSA PKCS#1 v1.5 SHA-1", key.verify(Pkcs1v15Sign::new::<Sha1>(), &Sha1::digest(tbs), sig)),
        x if x == SIG_RSA_V15_SHA256 =>
            ("RSA PKCS#1 v1.5 SHA-256", key.verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(tbs), sig)),
        x if x == SIG_RSA_V15_SHA384 =>
            ("RSA PKCS#1 v1.5 SHA-384", key.verify(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(tbs), sig)),
        x if x == SIG_RSA_V15_SHA512 =>
            ("RSA PKCS#1 v1.5 SHA-512", key.verify(Pkcs1v15Sign::new::<Sha512>(), &Sha512::digest(tbs), sig)),
        x if x == SIG_RSA_PSS_SHA256 =>
            ("RSASSA-PSS SHA-256", key.verify(Pss::new::<Sha256>(), &Sha256::digest(tbs), sig)),
        x if x == SIG_RSA_PSS_SHA384 =>
            ("RSASSA-PSS SHA-384", key.verify(Pss::new::<Sha384>(), &Sha384::digest(tbs), sig)),
        x if x == SIG_RSA_PSS_SHA512 =>
            ("RSASSA-PSS SHA-512", key.verify(Pss::new::<Sha512>(), &Sha512::digest(tbs), sig)),
        other => return Err(format!("RSA with sig alg {} unsupported", other)),
    };
    result
        .map(|_| format!("{alg}: signature VALID"))
        .map_err(|e| format!("{alg} verification FAILED: {e}"))
}

/// RSASSA-PSS with SHAKE128 / SHAKE256 (RFC 8702 §3.2): the hash is SHAKE with
/// 32 / 64 bytes of output, the mask generation function is the same SHAKE
/// (not MGF1), the salt is 32 / 64 bytes and the trailer field is 0xBC.
/// EMSA-PSS-VERIFY as in RFC 8017 §9.1.2.
fn verify_rsa_pss_shake(tbs: &[u8], n: &[u8], e: &[u8], sig: &[u8], sig_alg: i64) -> Result<String, String> {
    use num_bigint::BigUint;
    let (md, h_len, alg) = pss_shake_params(sig_alg)
        .ok_or_else(|| format!("sig alg {} is not RSASSA-PSS-SHAKE", sig_alg))?;
    let s_len = h_len;
    let fail = |why: &str| Err(format!("{alg} verification FAILED: {why}"));

    let n_int = BigUint::from_bytes_be(n);
    let e_int = BigUint::from_bytes_be(e);
    let k = (n_int.bits() as usize + 7) / 8;
    if sig.len() != k {
        return fail("signature length differs from the modulus length");
    }
    let s_int = BigUint::from_bytes_be(sig);
    if s_int >= n_int {
        return fail("signature representative out of range");
    }
    let m = s_int.modpow(&e_int, &n_int).to_bytes_be();

    let em_bits = n_int.bits() as usize - 1;
    let em_len = (em_bits + 7) / 8;
    if m.len() > em_len {
        return fail("encoded message too long");
    }
    let mut em = vec![0u8; em_len - m.len()];
    em.extend_from_slice(&m);
    if em_len < h_len + s_len + 2 {
        return fail("modulus too short for the encoding");
    }
    if em[em_len - 1] != 0xbc {
        return fail("trailer field is not 0xBC");
    }
    let db_len = em_len - h_len - 1;
    let (masked_db, h) = em[..em_len - 1].split_at(db_len);
    let top_bits = 8 * em_len - em_bits;
    let top_mask: u8 = 0xffu8.checked_shr(top_bits as u32).unwrap_or(0);
    if masked_db[0] & !top_mask != 0 {
        return fail("leftmost bits of the masked DB are not zero");
    }
    let db_mask = shake(md, &[h], db_len)?;
    let mut db: Vec<u8> = masked_db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    db[0] &= top_mask;
    let ps_len = em_len - h_len - s_len - 2;
    if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
        return fail("DB padding is malformed");
    }
    let salt = &db[db_len - s_len..];
    let m_hash = shake(md, &[tbs], h_len)?;
    let h_prime = shake(md, &[&[0u8; 8], &m_hash, salt], h_len)?;
    if h_prime.as_slice() != h {
        return fail("signature does not match");
    }
    Ok(format!("{alg}: signature VALID"))
}

fn verify_ecdsa_p256(tbs: &[u8], point: &[u8], sig: &[u8], sig_alg: i64) -> Result<String, String> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    if sig_alg != SIG_ECDSA_SHA256 {
        return Err(format!("P-256 with sig alg {} unsupported (expected ECDSA-SHA256=0)", sig_alg));
    }
    let vk = VerifyingKey::from_sec1_bytes(&c509_point_to_sec1(point))
        .map_err(|e| format!("P-256 public key invalid: {e}"))?;
    let signature = Signature::from_slice(sig).map_err(|e| format!("P-256 signature invalid: {e}"))?;
    vk.verify(tbs, &signature)
        .map(|_| "P-256 ECDSA-SHA256: signature VALID".to_string())
        .map_err(|e| format!("P-256 ECDSA verification FAILED: {e}"))
}

fn verify_ecdsa_p384(tbs: &[u8], point: &[u8], sig: &[u8], sig_alg: i64) -> Result<String, String> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    if sig_alg != SIG_ECDSA_SHA384 {
        return Err(format!("P-384 with sig alg {} unsupported (expected ECDSA-SHA384=1)", sig_alg));
    }
    let vk = VerifyingKey::from_sec1_bytes(&c509_point_to_sec1(point))
        .map_err(|e| format!("P-384 public key invalid: {e}"))?;
    let signature = Signature::from_slice(sig).map_err(|e| format!("P-384 signature invalid: {e}"))?;
    vk.verify(tbs, &signature)
        .map(|_| "P-384 ECDSA-SHA384: signature VALID".to_string())
        .map_err(|e| format!("P-384 ECDSA verification FAILED: {e}"))
}

fn verify_ecdsa_p521(tbs: &[u8], point: &[u8], sig: &[u8], sig_alg: i64) -> Result<String, String> {
    use p521::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    if sig_alg != SIG_ECDSA_SHA512 {
        return Err(format!("P-521 with sig alg {} unsupported (expected ECDSA-SHA512=2)", sig_alg));
    }
    let vk = VerifyingKey::from_sec1_bytes(&c509_point_to_sec1(point))
        .map_err(|e| format!("P-521 public key invalid: {e}"))?;
    let signature = Signature::from_slice(sig).map_err(|e| format!("P-521 signature invalid: {e}"))?;
    vk.verify(tbs, &signature)
        .map(|_| "P-521 ECDSA-SHA512: signature VALID".to_string())
        .map_err(|e| format!("P-521 ECDSA verification FAILED: {e}"))
}

fn verify_ed25519(tbs: &[u8], key: &[u8], sig: &[u8]) -> Result<String, String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key_arr: [u8; 32] = key.try_into().map_err(|_| "Ed25519 public key must be 32 bytes".to_string())?;
    let vk = VerifyingKey::from_bytes(&key_arr).map_err(|e| format!("Ed25519 public key invalid: {e}"))?;
    let sig_arr: [u8; 64] = sig.try_into().map_err(|_| "Ed25519 signature must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify(tbs, &signature)
        .map(|_| "Ed25519: signature VALID".to_string())
        .map_err(|e| format!("Ed25519 verification FAILED: {e}"))
}
