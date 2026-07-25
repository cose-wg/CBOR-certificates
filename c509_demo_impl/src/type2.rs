//! Type-2 (natively signed) C509 certificate encoding.
//!
//! Converts an X.509 DER certificate + PKCS#8 PEM private key into a
//! natively-signed C509 Type-2 certificate per
//! draft-ietf-cose-cbor-encoded-cert (§2.1, §2.3.5).
//!
//! Supported signing keys: secp256r1 (P-256), secp384r1 (P-384),
//! secp521r1 (P-521), Ed25519, RSA (PKCS#1v1.5 SHA-1/256/384/512,
//! RSASSA-PSS SHA-256/384/512), brainpoolP256r1/P384r1/P512r1, Ed448,
//! SM2 (the latter three via the system OpenSSL library).
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
    SIG_ALG_UNSIGNED, SIG_RSA_V15_SHA1, SIG_RSA_V15_SHA256, SIG_RSA_V15_SHA384,
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

    // RSASSA-PSS-SHAKE: custom MGF1(SHAKE) not implemented per RFC 8702.
    // Fields 0–9 are correctly encoded; field 10 = empty bstr placeholder.
    if sig_alg == SIG_RSA_PSS_SHAKE128 || sig_alg == SIG_RSA_PSS_SHAKE256 {
        let bits = if sig_alg == SIG_RSA_PSS_SHAKE128 { 128 } else { 256 };
        eprintln!("f2: RSASSA-PSS-SHAKE{} not implemented (RFC 8702 custom MGF); field 10 = empty", bits);
        fields[10] = lcbor_bytes(&[]);
        return Cert { der: vec![], cbor: fields };
    }

    fields[10] = sign_tbs(&tbs, privkey_pem, sig_alg);
    Cert { der: vec![], cbor: fields }
}

/// Sign `tbs` with the key in `privkey_pem`, returning a CBOR bstr of the raw signature.
///
/// `sig_alg`: C509 signature algorithm id (from the cert's field 2). Used to
/// select the RSA hash algorithm; ignored for EC/Ed25519 (determined by the key).
///
/// Tries P-256, P-384, P-521, Ed25519, RSA in order. Panics if none succeed.
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
    // OpenSSL fallback: brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, Ed448.
    if let Some(sig) = sign_tbs_openssl(tbs, privkey_pem) {
        return sig;
    }

    panic!("f2: unsupported key type — supported: secp256r1, secp384r1, secp521r1, Ed25519, \
            RSA (PKCS#1v1.5/PSS), brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, Ed448");
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
        other => panic!("f2: RSA key found but sig alg {} not supported", other),
    }
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

/// OpenSSL-based signing for curves not handled by RustCrypto:
/// brainpoolP256r1/P384r1/P512r1 (ECDSA+SHA) and Ed448 (pure EdDSA).
/// Returns None for any unrecognised key type (SM2, FRP256v1, …).
fn sign_tbs_openssl(tbs: &[u8], privkey_pem: &str) -> Option<Vec<u8>> {
    use openssl::hash::MessageDigest;
    use openssl::pkey::{Id, PKey};
    use openssl::sign::Signer;

    let pkey = PKey::private_key_from_pem(privkey_pem.as_bytes()).ok()?;

    match pkey.id() {
        Id::EC => {
            let ec_key = pkey.ec_key().ok()?;
            let curve_nid = ec_key.group().curve_name()?;
            let curve = curve_nid.short_name().ok()?;
            let (coord_size, digest) = match curve {
                "brainpoolP256r1" => (32usize, MessageDigest::sha256()),
                "brainpoolP384r1" => (48usize, MessageDigest::sha384()),
                "brainpoolP512r1" => (64usize, MessageDigest::sha512()),
                _ => return None,
            };
            let mut signer = Signer::new(digest, &pkey).ok()?;
            signer.update(tbs).ok()?;
            let der_sig = signer.sign_to_vec().ok()?;
            Some(lcbor_bytes(&der_ecdsa_to_raw(&der_sig, coord_size)))
        }
        // SM2DSA over SM2 256-bit curve; OpenSSL automatically prepends the ZA
        // hash (SM3 of curve params + default user ID "1234567812345678").
        Id::SM2 => {
            let mut signer = Signer::new(MessageDigest::sm3(), &pkey).ok()?;
            signer.update(tbs).ok()?;
            let der_sig = signer.sign_to_vec().ok()?;
            Some(lcbor_bytes(&der_ecdsa_to_raw(&der_sig, 32)))
        }
        Id::ED448 => {
            let mut signer = Signer::new_without_digest(&pkey).ok()?;
            let raw_sig = signer.sign_oneshot_to_vec(tbs).ok()?;
            Some(lcbor_bytes(&raw_sig))
        }
        _ => None,
    }
}

/// Convert DER-encoded ECDSA signature to raw r||s (IEEE P1363 / C509 format).
///
/// `coord_size`: field-element byte length for the curve (32/48/64 for brainpool).
/// DER wraps each integer with a possible leading 0x00 sign byte; we strip it and
/// zero-pad to `coord_size` on the left.
pub(crate) fn der_ecdsa_to_raw(der: &[u8], coord_size: usize) -> Vec<u8> {
    // Layout: 30 <seq_len_bytes> 02 <r_len> <r…> 02 <s_len> <s…>
    // Sequence length encoding:
    //   short form: 1 byte if length < 0x80
    //   long form:  0x81 <1-byte> for length 128–255 (used for brainpoolP512r1 ~133 bytes)
    let header_len = if der[1] < 0x80 { 2 } else { 2 + (der[1] & 0x7f) as usize };
    let r_len = der[header_len + 1] as usize;
    let r = &der[header_len + 2..header_len + 2 + r_len];
    let s_tag = header_len + 2 + r_len;
    let s_len = der[s_tag + 1] as usize;
    let s = &der[s_tag + 2..s_tag + 2 + s_len];

    // If DER added a leading 0x00 (sign extension), take the rightmost coord_size bytes.
    let r = if r.len() > coord_size { &r[r.len() - coord_size..] } else { r };
    let s = if s.len() > coord_size { &s[s.len() - coord_size..] } else { s };
    let mut raw = vec![0u8; coord_size * 2];
    raw[coord_size - r.len()..coord_size].copy_from_slice(r);
    raw[coord_size * 2 - s.len()..].copy_from_slice(s);
    raw
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
