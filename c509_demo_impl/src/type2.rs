//! Type-2 (natively signed) C509 certificate encoding.
//!
//! Converts an X.509 DER certificate + PKCS#8 PEM private key into a
//! natively-signed C509 Type-2 certificate per
//! draft-ietf-cose-cbor-encoded-cert (§2.1, §2.3.5).
//!
//! Supported signing keys: secp256r1 (P-256), secp384r1 (P-384),
//! secp521r1 (P-521), Ed25519, RSA (PKCS#1v1.5 SHA-1/256/384/512,
//! RSASSA-PSS SHA-256/384/512 and SHAKE128/256), brainpoolP256r1/P384r1/P512r1
//! and frp256v1 (ECDSA with SHA-1, SHA-2 or SHAKE), Ed448 and SM2. The
//! brainpool, frp256v1, Ed448 and SM2 keys and SHAKE use the system OpenSSL
//! library.
//!
//! Certs with id-alg-unsigned (C509 sig alg id = 5) produce an empty
//! bstr for field 10 without invoking any signing operation.
//!
//! The signature is computed over the CBOR TBS = concatenation of fields 0–9.
//!
//! Subject Key Identifier for native certs:
//!   SHA-256(CBOR(field7) || CBOR(field8)) truncated to 20 bytes.

use sha2::{Digest, Sha256};
use crate::conversion::parse_x509_cert_nc;
use crate::lcbor::{lcbor_bytes, lcbor_uint};
use crate::registry::{
    SIG_ALG_UNSIGNED, SIG_ECDSA_SHA1, SIG_ECDSA_SHA256, SIG_ECDSA_SHA384, SIG_ECDSA_SHA512,
    SIG_ECDSA_SHAKE128, SIG_ECDSA_SHAKE256, SIG_RSA_V15_SHA1, SIG_RSA_V15_SHA256, SIG_RSA_V15_SHA384,
    SIG_RSA_V15_SHA512, SIG_RSA_PSS_SHA256, SIG_RSA_PSS_SHA384, SIG_RSA_PSS_SHA512,
    SIG_RSA_PSS_SHAKE128, SIG_RSA_PSS_SHAKE256,
};
use crate::Cert;

/// Encode an X.509 DER certificate as a natively-signed C509 Type-2 certificate.
///
/// `privkey_pem`: PKCS#8 PEM private key (or the subject key for unsigned certs).
/// `no_compression`: when true, store EC public keys uncompressed (04|x|y).
/// `ca_der`: optional DER of the issuing CA's X.509 cert, required to recompute
///   the Authority Key Identifier for CA-signed certs (Cat C AKI update).
///
/// Special cases:
/// - id-alg-unsigned (sig alg = 5): field 10 = empty bstr; no signing key used.
/// - RSASSA-PSS-SHAKE128/256: custom MGF not implemented; field 10 = empty bstr;
///   fields 0–9 (TBS) are still correctly encoded.
pub fn encode_x509_as_type2(
    der: Vec<u8>,
    privkey_pem: &str,
    no_compression: bool,
    ca_der: Option<Vec<u8>>,
) -> Cert {
    let type3 = parse_x509_cert_nc(der, no_compression);
    assert!(type3.cbor.len() == 11, "expected 11 CBOR fields from parse_x509_cert_nc");

    let mut fields = type3.cbor;

    // Field 0: type = 2 (natively signed).
    fields[0] = lcbor_uint(2);

    // Recompute SKI = SHA-256(field7 || field8)[:20] and patch extensions.
    let new_ski = compute_type2_ski(&fields[7], &fields[8]);
    fields[9] = replace_ski_in_extensions(&fields[9], &new_ski);

    // If a CA cert is provided, recompute the CA's type-2 SKI and patch AKI.
    if let Some(ca_der_bytes) = ca_der {
        let ca_type3 = parse_x509_cert_nc(ca_der_bytes, no_compression);
        assert!(ca_type3.cbor.len() == 11, "expected 11 CBOR fields from CA cert");
        let ca_ski = compute_type2_ski(&ca_type3.cbor[7], &ca_type3.cbor[8]);
        fields[9] = replace_aki_in_extensions(&fields[9], &ca_ski);
    }

    // TBS = concatenation of fields 0–9.
    let tbs: Vec<u8> = fields[..10].iter().flat_map(|f| f.iter().copied()).collect();

    // Decode the C509 sig alg id from field 2 to handle special cases.
    let sig_alg = cbor_int_value(&fields[2]);

    // id-alg-unsigned: no signature over TBS; field 10 = empty bstr.
    if sig_alg == SIG_ALG_UNSIGNED {
        fields[10] = lcbor_bytes(&[]);
        return Cert { der: vec![], cbor: fields };
    }

    fields[10] = sign_tbs(&tbs, privkey_pem, sig_alg);
    Cert { der: vec![], cbor: fields }
}

/// Sign `tbs` with the key in `privkey_pem`, returning a CBOR bstr of the raw signature.
///
/// `sig_alg`: C509 signature algorithm id (from the cert's field 2). Used to
/// select the RSA and frp256v1 hash algorithm; ignored for the other keys
/// (determined by the key).
///
/// Tries P-256, P-384, P-521, Ed25519, RSA, the OpenSSL-loaded keys
/// (brainpool, SM2, Ed448) and frp256v1 in order. Panics if none succeed.
pub fn sign_tbs(tbs: &[u8], privkey_pem: &str, sig_alg: i64) -> Vec<u8> {
    use p256::pkcs8::DecodePrivateKey;
    use p256::ecdsa::signature::Signer;

    // P-256 — r||s 64 bytes
    if let Ok(sk) = p256::ecdsa::SigningKey::from_pkcs8_pem(privkey_pem) {
        let sig: p256::ecdsa::Signature = sk.sign(tbs);
        return lcbor_bytes(&sig.to_bytes());
    }
    // P-384 — r||s 96 bytes
    if let Ok(sk) = p384::ecdsa::SigningKey::from_pkcs8_pem(privkey_pem) {
        let sig: p384::ecdsa::Signature = sk.sign(tbs);
        return lcbor_bytes(&sig.to_bytes());
    }
    // P-521 — r||s 132 bytes; ecdsa::SigningKey has no DecodePrivateKey impl,
    // so load via SecretKey then convert through scalar bytes.
    if let Ok(secret) = p521::SecretKey::from_pkcs8_pem(privkey_pem) {
        let sk = p521::ecdsa::SigningKey::from_slice(&secret.to_bytes()[..])
            .expect("p521: ecdsa signing key from secret key bytes is always valid");
        let sig: p521::ecdsa::Signature = sk.sign(tbs);
        return lcbor_bytes(&sig.to_bytes());
    }
    // Ed25519 — 64 bytes
    if let Ok(sk) = ed25519_dalek::SigningKey::from_pkcs8_pem(privkey_pem) {
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(tbs);
        return lcbor_bytes(&sig.to_bytes());
    }
    // RSA — PKCS#1 v1.5 (deterministic) or PSS (randomised)
    if let Ok(rsa_key) = rsa::RsaPrivateKey::from_pkcs8_pem(privkey_pem) {
        return sign_tbs_rsa(tbs, rsa_key, sig_alg);
    }
    // OpenSSL fallback: brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, SM2, Ed448.
    if let Some(sig) = sign_tbs_openssl(tbs, privkey_pem, sig_alg) {
        return sig;
    }
    // frp256v1: not a named curve in OpenSSL, so the key is parsed here.
    if let Some(sig) = sign_tbs_frp256v1(tbs, privkey_pem, sig_alg) {
        return sig;
    }

    panic!("f2: unsupported key type — supported: secp256r1, secp384r1, secp521r1, Ed25519, \
            RSA (PKCS#1v1.5/PSS), brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, SM2, \
            Ed448, frp256v1");
}

/// OID 1.2.250.1.223.101.256.1 (frp256v1), DER content bytes.
const FRP256V1_OID_DER: [u8; 10] = [0x2a, 0x81, 0x7a, 0x01, 0x81, 0x5f, 0x65, 0x82, 0x00, 0x01];

/// The ANSSI frp256v1 curve (JORF n°0241, 16 October 2011) as an OpenSSL group
/// built from its explicit parameters.
pub(crate) fn frp256v1_group() -> Result<openssl::ec::EcGroup, openssl::error::ErrorStack> {
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcPoint};
    let mut ctx = BigNumContext::new()?;
    let p = BigNum::from_hex_str("F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03")?;
    let a = BigNum::from_hex_str("F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00")?;
    let b = BigNum::from_hex_str("EE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F")?;
    let n = BigNum::from_hex_str("F1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1")?;
    let g = hex::decode(
        "04B6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF\
         6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB",
    )
    .expect("frp256v1 generator constant is valid hex");
    let mut group = EcGroup::from_components(p, a, b, &mut ctx)?;
    let generator = EcPoint::from_bytes(&group, &g, &mut ctx)?;
    group.set_generator(generator, n, BigNum::from_u32(1)?)?;
    Ok(group)
}

/// Read one DER TLV at `pos`; returns (tag, content range end, content start).
fn der_tlv(der: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    let tag = *der.get(pos)?;
    let first = *der.get(pos + 1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 2 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *der.get(pos + 2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let start = pos + hdr;
    let end = start.checked_add(len)?;
    if end > der.len() {
        return None;
    }
    Some((tag, end, start))
}

/// Private scalar of a PKCS#8 frp256v1 key (RFC 5915 ECPrivateKey inside a
/// PKCS#8 PrivateKeyInfo with the frp256v1 named-curve OID), or None.
fn frp256v1_private_scalar(privkey_pem: &str) -> Option<Vec<u8>> {
    let b64: String = privkey_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = openssl::base64::decode_block(b64.trim()).ok()?;
    // PrivateKeyInfo ::= SEQUENCE { version, AlgorithmIdentifier, OCTET STRING }
    let (tag, _, pos) = der_tlv(&der, 0)?;
    if tag != 0x30 {
        return None;
    }
    let (_, pos, _) = der_tlv(&der, pos)?; // version
    let (tag, alg_end, alg_start) = der_tlv(&der, pos)?;
    if tag != 0x30 {
        return None;
    }
    let (_, curve_pos, _) = der_tlv(&der, alg_start)?; // id-ecPublicKey
    let (tag, curve_end, curve_start) = der_tlv(&der, curve_pos)?;
    if tag != 0x06 || der[curve_start..curve_end] != FRP256V1_OID_DER {
        return None;
    }
    let (tag, _, ec_start) = der_tlv(&der, alg_end)?;
    if tag != 0x04 {
        return None;
    }
    // ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING, ... }
    let (tag, _, pos) = der_tlv(&der, ec_start)?;
    if tag != 0x30 {
        return None;
    }
    let (_, pos, _) = der_tlv(&der, pos)?; // version
    let (tag, d_end, d_start) = der_tlv(&der, pos)?;
    if tag != 0x04 {
        return None;
    }
    Some(der[d_start..d_end].to_vec())
}

/// ECDSA over frp256v1; the digest follows `sig_alg`.
fn sign_tbs_frp256v1(tbs: &[u8], privkey_pem: &str, sig_alg: i64) -> Option<Vec<u8>> {
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcKey, EcPoint};

    let d_bytes = frp256v1_private_scalar(privkey_pem)?;
    let (digest, _) = ecdsa_digest(sig_alg, tbs)
        .unwrap_or_else(|e| panic!("f2: frp256v1 key found but {}", e));
    let group = frp256v1_group().ok()?;
    let mut ctx = BigNumContext::new().ok()?;
    let d = BigNum::from_slice(&d_bytes).ok()?;
    let mut q = EcPoint::new(&group).ok()?;
    q.mul_generator2(&group, &d, &mut ctx).ok()?;
    let key = EcKey::from_private_components(&group, &d, &q).ok()?;
    Some(lcbor_bytes(&ecdsa_sign_raw(&key, &digest)?))
}

/// RSA signing dispatch by C509 sig alg id.
fn sign_tbs_rsa(tbs: &[u8], key: rsa::RsaPrivateKey, sig_alg: i64) -> Vec<u8> {
    use rsa::signature::{Signer as _, RandomizedSigner as _, SignatureEncoding as _};
    use sha1::Sha1;
    use sha2::{Sha256, Sha384, Sha512};

    match sig_alg {
        // PKCS#1 v1.5 — deterministic
        x if x == SIG_RSA_V15_SHA1 => {
            let sk = rsa::pkcs1v15::SigningKey::<Sha1>::new(key);
            let sig: rsa::pkcs1v15::Signature = sk.sign(tbs);
            lcbor_bytes(&sig.to_vec())
        }
        x if x == SIG_RSA_V15_SHA256 => {
            let sk = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
            let sig: rsa::pkcs1v15::Signature = sk.sign(tbs);
            lcbor_bytes(&sig.to_vec())
        }
        x if x == SIG_RSA_V15_SHA384 => {
            let sk = rsa::pkcs1v15::SigningKey::<Sha384>::new(key);
            let sig: rsa::pkcs1v15::Signature = sk.sign(tbs);
            lcbor_bytes(&sig.to_vec())
        }
        x if x == SIG_RSA_V15_SHA512 => {
            let sk = rsa::pkcs1v15::SigningKey::<Sha512>::new(key);
            let sig: rsa::pkcs1v15::Signature = sk.sign(tbs);
            lcbor_bytes(&sig.to_vec())
        }
        // RSASSA-PSS — randomised (salt len = digest len by default)
        x if x == SIG_RSA_PSS_SHA256 => {
            let sk = rsa::pss::SigningKey::<Sha256>::new(key);
            let sig: rsa::pss::Signature = sk.sign_with_rng(&mut rand::rngs::OsRng, tbs);
            lcbor_bytes(&sig.to_vec())
        }
        x if x == SIG_RSA_PSS_SHA384 => {
            let sk = rsa::pss::SigningKey::<Sha384>::new(key);
            let sig: rsa::pss::Signature = sk.sign_with_rng(&mut rand::rngs::OsRng, tbs);
            lcbor_bytes(&sig.to_vec())
        }
        x if x == SIG_RSA_PSS_SHA512 => {
            let sk = rsa::pss::SigningKey::<Sha512>::new(key);
            let sig: rsa::pss::Signature = sk.sign_with_rng(&mut rand::rngs::OsRng, tbs);
            lcbor_bytes(&sig.to_vec())
        }
        x if x == SIG_RSA_PSS_SHAKE128 || x == SIG_RSA_PSS_SHAKE256 => {
            let sig = sign_rsa_pss_shake(tbs, &key, sig_alg)
                .unwrap_or_else(|e| panic!("f2: RSASSA-PSS-SHAKE signing failed: {}", e));
            lcbor_bytes(&sig)
        }
        other => panic!("f2: RSA key found but sig alg {} not supported", other),
    }
}

/// Parameters of RSASSA-PSS with SHAKE (RFC 8702 §3.2): the SHAKE function,
/// its output length (also the salt length) and the algorithm name.
pub(crate) fn pss_shake_params(sig_alg: i64) -> Option<(openssl::hash::MessageDigest, usize, &'static str)> {
    use openssl::hash::MessageDigest;
    match sig_alg {
        x if x == SIG_RSA_PSS_SHAKE128 => Some((MessageDigest::shake_128(), 32, "RSASSA-PSS SHAKE128")),
        x if x == SIG_RSA_PSS_SHAKE256 => Some((MessageDigest::shake_256(), 64, "RSASSA-PSS SHAKE256")),
        _ => None,
    }
}

/// RSASSA-PSS with SHAKE128 / SHAKE256 (RFC 8702 §3.2): EMSA-PSS-ENCODE
/// (RFC 8017 §9.1.1) with SHAKE as both hash and mask generation function,
/// then the RSA private-key operation. Returns the k-byte signature.
fn sign_rsa_pss_shake(tbs: &[u8], key: &rsa::RsaPrivateKey, sig_alg: i64) -> Result<Vec<u8>, String> {
    use num_bigint::BigUint;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};

    let (md, h_len, _) = pss_shake_params(sig_alg).ok_or("not an RSASSA-PSS-SHAKE algorithm")?;
    let s_len = h_len;
    let n = BigUint::from_bytes_be(&key.n().to_bytes_be());
    let d = BigUint::from_bytes_be(&key.d().to_bytes_be());
    let mod_bits = n.bits() as usize;
    let k = (mod_bits + 7) / 8;
    let em_bits = mod_bits - 1;
    let em_len = (em_bits + 7) / 8;
    if em_len < h_len + s_len + 2 {
        return Err("modulus too short for the encoding".into());
    }

    let m_hash = shake(md, &[tbs], h_len)?;
    let mut salt = vec![0u8; s_len];
    openssl::rand::rand_bytes(&mut salt).map_err(|e| e.to_string())?;
    let h = shake(md, &[&[0u8; 8], &m_hash, &salt], h_len)?;

    let db_len = em_len - h_len - 1;
    let mut db = vec![0u8; db_len - s_len - 1];
    db.push(0x01);
    db.extend_from_slice(&salt);
    let db_mask = shake(md, &[&h], db_len)?;
    let mut em: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    em[0] &= 0xffu8.checked_shr((8 * em_len - em_bits) as u32).unwrap_or(0);
    em.extend_from_slice(&h);
    em.push(0xbc);

    let s = BigUint::from_bytes_be(&em).modpow(&d, &n).to_bytes_be();
    let mut sig = vec![0u8; k - s.len()];
    sig.extend_from_slice(&s);
    Ok(sig)
}

/// Decode a CBOR-encoded integer (positive or negative) from the first bytes.
pub fn cbor_int_value(cbor: &[u8]) -> i64 {
    let b = cbor[0];
    let major = (b >> 5) & 7;
    let additional = b & 0x1f;
    let n: u64 = match additional {
        0..=23 => additional as u64,
        24 => cbor[1] as u64,
        25 => u16::from_be_bytes([cbor[1], cbor[2]]) as u64,
        26 => u32::from_be_bytes([cbor[1], cbor[2], cbor[3], cbor[4]]) as u64,
        _ => panic!("cbor_int_value: unsupported additional info {}", additional),
    };
    if major == 1 { -(n as i64) - 1 } else { n as i64 }
}

/// SHA-256(CBOR(subjectPKAlg) || CBOR(subjectPublicKey)) truncated to 20 bytes.
fn compute_type2_ski(field7: &[u8], field8: &[u8]) -> [u8; 20] {
    let mut h = Sha256::new();
    h.update(field7);
    h.update(field8);
    let digest = h.finalize();
    let mut ski = [0u8; 20];
    ski.copy_from_slice(&digest[..20]);
    ski
}

/// SHAKE128 / SHAKE256 output of `len` bytes over the concatenation of `parts`.
pub(crate) fn shake(
    md: openssl::hash::MessageDigest,
    parts: &[&[u8]],
    len: usize,
) -> Result<Vec<u8>, String> {
    let mut hasher = openssl::hash::Hasher::new(md).map_err(|e| e.to_string())?;
    for p in parts {
        hasher.update(p).map_err(|e| e.to_string())?;
    }
    let mut out = vec![0u8; len];
    hasher.finish_xof(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Message digest for a C509 ECDSA signature algorithm: SHA-1/256/384/512, or
/// SHAKE128 / SHAKE256 with 32 / 64 bytes of output (RFC 8692). Returns the
/// digest and the algorithm name.
pub(crate) fn ecdsa_digest(sig_alg: i64, data: &[u8]) -> Result<(Vec<u8>, &'static str), String> {
    use openssl::hash::{hash, MessageDigest};
    let sha = |md: MessageDigest| hash(md, data).map(|d| d.to_vec()).map_err(|e| e.to_string());
    match sig_alg {
        x if x == SIG_ECDSA_SHA1 => Ok((sha(MessageDigest::sha1())?, "ECDSA-SHA1")),
        x if x == SIG_ECDSA_SHA256 => Ok((sha(MessageDigest::sha256())?, "ECDSA-SHA256")),
        x if x == SIG_ECDSA_SHA384 => Ok((sha(MessageDigest::sha384())?, "ECDSA-SHA384")),
        x if x == SIG_ECDSA_SHA512 => Ok((sha(MessageDigest::sha512())?, "ECDSA-SHA512")),
        x if x == SIG_ECDSA_SHAKE128 => {
            Ok((shake(MessageDigest::shake_128(), &[data], 32)?, "ECDSA-SHAKE128"))
        }
        x if x == SIG_ECDSA_SHAKE256 => {
            Ok((shake(MessageDigest::shake_256(), &[data], 64)?, "ECDSA-SHAKE256"))
        }
        other => Err(format!("sig alg {} is not an ECDSA algorithm", other)),
    }
}

/// ECDSA signature over `digest` as raw r||s, each padded to the field size.
fn ecdsa_sign_raw(
    key: &openssl::ec::EcKeyRef<openssl::pkey::Private>,
    digest: &[u8],
) -> Option<Vec<u8>> {
    let coord_size = ((key.group().degree() + 7) / 8) as i32;
    let sig = openssl::ecdsa::EcdsaSig::sign(digest, key).ok()?;
    let mut raw = sig.r().to_vec_padded(coord_size).ok()?;
    raw.extend(sig.s().to_vec_padded(coord_size).ok()?);
    Some(raw)
}

/// OpenSSL-based signing for curves not handled by RustCrypto:
/// brainpoolP256r1/P384r1/P512r1 (ECDSA; digest from `sig_alg`), SM2 and
/// Ed448 (pure EdDSA). Returns None for any key OpenSSL cannot load or that is
/// not listed (e.g. frp256v1, whose curve OID OpenSSL does not know).
fn sign_tbs_openssl(tbs: &[u8], privkey_pem: &str, sig_alg: i64) -> Option<Vec<u8>> {
    use openssl::pkey::{Id, PKey};
    use openssl::sign::Signer;

    let pkey = PKey::private_key_from_pem(privkey_pem.as_bytes()).ok()?;

    match pkey.id() {
        Id::EC => {
            let ec_key = pkey.ec_key().ok()?;
            let curve_nid = ec_key.group().curve_name()?;
            match curve_nid.short_name().ok()? {
                "brainpoolP256r1" | "brainpoolP384r1" | "brainpoolP512r1" => {}
                _ => return None,
            }
            let (digest, _) = ecdsa_digest(sig_alg, tbs)
                .unwrap_or_else(|e| panic!("f2: brainpool key found but {}", e));
            Some(lcbor_bytes(&ecdsa_sign_raw(&ec_key, &digest)?))
        }
        // SM2 with SM3 and the default distinguishing ID (see sm2.rs; the
        // OpenSSL EVP signer would use an empty ID).
        Id::SM2 => {
            let ec_key = pkey.ec_key().ok()?;
            let raw = crate::sm2::sm2_sign(ec_key.group(), ec_key.private_key(), tbs).ok()?;
            Some(lcbor_bytes(&raw))
        }
        Id::ED448 => {
            let mut signer = Signer::new_without_digest(&pkey).ok()?;
            let raw_sig = signer.sign_oneshot_to_vec(tbs).ok()?;
            Some(lcbor_bytes(&raw_sig))
        }
        _ => None,
    }
}

/// Replace the SKI value inside the CBOR-encoded extensions field.
///
/// Looks for the byte pattern `01 54 <20 bytes>` (uint(1) = SKI ext id,
/// bstr(20) = SHA-1 key identifier) and overwrites the 20 bytes with `new_ski`.
/// If no SKI extension is found the field is returned unchanged.
fn replace_ski_in_extensions(ext_cbor: &[u8], new_ski: &[u8; 20]) -> Vec<u8> {
    let mut result = ext_cbor.to_vec();
    if result.len() < 22 {
        return result;
    }
    let limit = result.len().saturating_sub(22);
    for i in 0..=limit {
        if result[i] == 0x01 && result[i + 1] == 0x54 {
            result[i + 2..i + 22].copy_from_slice(new_ski);
            return result;
        }
    }
    result
}

/// Replace the AKI key identifier inside the CBOR-encoded extensions field.
///
/// Looks for the byte pattern `07 54 <20 bytes>` (uint(7) = AKI ext id,
/// bstr(20) = key identifier from CA cert) and overwrites the 20 bytes with
/// the CA's type-2 SKI. If no AKI with a plain key identifier is found the
/// field is returned unchanged.
fn replace_aki_in_extensions(ext_cbor: &[u8], ca_ski: &[u8; 20]) -> Vec<u8> {
    let mut result = ext_cbor.to_vec();
    // Two AKI encoding patterns (C509 §7.3 extension id = 7):
    //   keyid-only:            07 54 <20 bytes>        (keyid bstr directly)
    //   keyid+issuer+serial:   07 83 54 <20 bytes> ... (array[3], keyid first)
    if result.len() < 22 {
        return result;
    }
    let limit = result.len().saturating_sub(23);
    for i in 0..=limit {
        if result[i] == 0x07 {
            if result[i + 1] == 0x54 && result.len() >= i + 22 {
                result[i + 2..i + 22].copy_from_slice(ca_ski);
                return result;
            }
            if result[i + 1] == 0x83 && result[i + 2] == 0x54 && result.len() >= i + 23 {
                result[i + 3..i + 23].copy_from_slice(ca_ski);
                return result;
            }
        }
    }
    result
}
