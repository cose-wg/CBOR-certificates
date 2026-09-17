//! Type-2 (natively signed) C509 certification request encoding.
//!
//! Converts a PKCS#10 DER CSR + private key(s) into a natively-signed
//! C509 Type-2 certification request per draft-ietf-cose-cbor-encoded-cert.
//!
//! Signature algorithms supported:
//!   - ECDSA (secp256r1/384r1/521r1, Ed25519) — subject key signs TBS
//!   - DhSigStatic SHA-256/384/512 (RFC 6955) — ECDH-derived key via RFC 6955
//!     KDF, HMAC over CBOR TBS
//!   - Unsigned (algorithm id 5) — field 6 is empty bstr, unchanged from type-3
//!
//! For DhSigStatic, both the subject private key, the peer private key, and the
//! peer's C509 type-2 certificate (for the KDF subject/issuer fields) are
//! required.  The IETF test vectors use the peer's secp256r1/384r1/521r1 self-
//! signed cert key (sections 3.3.1 / 3.5.1 / 3.6.1) as the peer key and
//! sections 3.3.4 / 3.5.4 / 3.6.4 as the peer C509 cert.
//!
//! RFC 6955 KDF (for C509 type-2): K = Hash(subject_CBOR || ZZ || issuer_CBOR)
//!   where subject_CBOR / issuer_CBOR are the raw CBOR bytes of the subject and
//!   issuer fields from the peer's C509 cert, and issuer = F6 (null) is resolved
//!   to the same value as subject (self-signed cert).
//!
//! TBS = concatenation of CBOR-encoded fields 0–5 (fields 0–5 of the 7-field
//! C509 CSR sequence).  Field 6 is the signature / MAC value.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::conversion::parse_x509_csr;
use crate::lcbor::{lcbor_uint, lcbor_bytes, cbor_item_end};
use crate::registry::{SIG_ALG_UNSIGNED, SIG_ECDHPOP_SHA256, SIG_ECDHPOP_SHA384, SIG_ECDHPOP_SHA512};
use crate::type2::sign_tbs;
use crate::Cert;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

/// Encode a PKCS#10 DER CSR as a natively-signed C509 Type-2 certification request.
///
/// `subject_pem`: PKCS#8 PEM private key of the CSR subject.
/// `peer_pem`: PKCS#8 PEM private key of the DhSig peer (required for DhSigStatic).
/// `peer_cert_cbor`: Raw CBOR bytes of the peer's C509 type-2 certificate (required
///   for DhSigStatic; used to extract subject/issuer fields for the RFC 6955 KDF).
/// `embedded_cert_key`: PKCS#8 PEM private key used to re-sign any type-3 C509 certs
///   embedded in CSR attributes (e.g. PrivateKeyPossessionStatement); converts them
///   to type-2.
/// `no_compression`: when true, store EC public keys uncompressed (04|x|y).
pub fn encode_csr_as_type2(
    csr_der: Vec<u8>,
    subject_pem: &str,
    peer_pem: Option<&str>,
    peer_cert_cbor: Option<&[u8]>,
    embedded_cert_key: Option<&str>,
    no_compression: bool,
) -> Cert {
    let type3 = parse_x509_csr(csr_der, no_compression);
    assert!(type3.cbor.len() == 7, "expected 7 CBOR fields from parse_x509_csr");

    let mut fields = type3.cbor;

    // Convert any type-3 C509 certs embedded in the attributes to type-2.
    if let Some(key) = embedded_cert_key {
        fields[5] = convert_embedded_certs_to_type2(&fields[5], key);
    }

    // Field 0: type = 2 (natively signed).
    fields[0] = lcbor_uint(2);

    // TBS = concatenation of fields 0–5.
    let tbs: Vec<u8> = fields[..6].iter().flat_map(|f| f.iter().copied()).collect();

    // Field 1 encodes the signature algorithm as a CBOR uint (small values fit
    // in a single byte with no length prefix).
    let sig_alg = cbor_uint_value(&fields[1]);

    let new_field6 = match sig_alg {
        x if x == SIG_ALG_UNSIGNED as u64 => {
            // Unsigned: keep the type-3 field 6 verbatim (empty bstr 0x40).
            fields[6].clone()
        }
        x if x == SIG_ECDHPOP_SHA256 as u64 => {
            let peer = peer_pem.expect("DhSig SHA-256 requires a peer private key (--peer)");
            let cert = peer_cert_cbor.expect("DhSig SHA-256 requires peer C509 cert (--peer-cert)");
            let mac = dhsig_p256(&tbs, subject_pem, peer, cert);
            replace_dhsig_hash(&fields[6], &mac)
        }
        x if x == SIG_ECDHPOP_SHA384 as u64 => {
            let peer = peer_pem.expect("DhSig SHA-384 requires a peer private key (--peer)");
            let cert = peer_cert_cbor.expect("DhSig SHA-384 requires peer C509 cert (--peer-cert)");
            let mac = dhsig_p384(&tbs, subject_pem, peer, cert);
            replace_dhsig_hash(&fields[6], &mac)
        }
        x if x == SIG_ECDHPOP_SHA512 as u64 => {
            let peer = peer_pem.expect("DhSig SHA-512 requires a peer private key (--peer)");
            let cert = peer_cert_cbor.expect("DhSig SHA-512 requires peer C509 cert (--peer-cert)");
            let mac = dhsig_p521(&tbs, subject_pem, peer, cert);
            replace_dhsig_hash(&fields[6], &mac)
        }
        _ => {
            // ECDSA or any other signing algorithm: sign TBS with the subject key.
            sign_tbs(&tbs, subject_pem, sig_alg as i64)
        }
    };
    fields[6] = new_field6;

    Cert { der: vec![], cbor: fields }
}

// ---------------------------------------------------------------------------
// DhSigStatic HMAC helpers (RFC 6955 KDF)
// ---------------------------------------------------------------------------
//
// RFC 6955 Section 6(3): K = Hash(subject_cbor || ZZ || issuer_cbor)
// where subject_cbor / issuer_cbor are the raw CBOR bytes of the subject (field[6])
// and issuer (field[3]) from the peer's C509 cert.  If issuer = F6 (null), it is
// resolved to the same value as subject (self-signed cert convention).
// hashValue = HMAC-Hash(K, TBS)

/// ECDH(subj_P256, peer_P256) → RFC 6955 KDF → HMAC-SHA256(K, tbs).
fn dhsig_p256(tbs: &[u8], subject_pem: &str, peer_pem: &str, peer_cert: &[u8]) -> Vec<u8> {
    use p256::pkcs8::DecodePrivateKey;
    let subj = p256::SecretKey::from_pkcs8_pem(subject_pem)
        .expect("dhsig-sha256: subject key must be secp256r1");
    let peer = p256::SecretKey::from_pkcs8_pem(peer_pem)
        .expect("dhsig-sha256: peer key must be secp256r1");
    let shared = p256::elliptic_curve::ecdh::diffie_hellman(
        subj.to_nonzero_scalar(), peer.public_key().as_affine());
    let (subj_cbor, iss_cbor) = c509_subject_issuer(peer_cert);
    let k = Sha256::new()
        .chain_update(subj_cbor)
        .chain_update(shared.raw_secret_bytes())
        .chain_update(iss_cbor)
        .finalize();
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key always valid");
    mac.update(tbs);
    mac.finalize().into_bytes().to_vec()
}

/// ECDH(subj_P384, peer_P384) → RFC 6955 KDF → HMAC-SHA384(K, tbs).
fn dhsig_p384(tbs: &[u8], subject_pem: &str, peer_pem: &str, peer_cert: &[u8]) -> Vec<u8> {
    use p384::pkcs8::DecodePrivateKey;
    let subj = p384::SecretKey::from_pkcs8_pem(subject_pem)
        .expect("dhsig-sha384: subject key must be secp384r1");
    let peer = p384::SecretKey::from_pkcs8_pem(peer_pem)
        .expect("dhsig-sha384: peer key must be secp384r1");
    let shared = p384::elliptic_curve::ecdh::diffie_hellman(
        subj.to_nonzero_scalar(), peer.public_key().as_affine());
    let (subj_cbor, iss_cbor) = c509_subject_issuer(peer_cert);
    let k = Sha384::new()
        .chain_update(subj_cbor)
        .chain_update(shared.raw_secret_bytes())
        .chain_update(iss_cbor)
        .finalize();
    let mut mac = HmacSha384::new_from_slice(&k).expect("HMAC key always valid");
    mac.update(tbs);
    mac.finalize().into_bytes().to_vec()
}

/// ECDH(subj_P521, peer_P521) → RFC 6955 KDF → HMAC-SHA512(K, tbs).
fn dhsig_p521(tbs: &[u8], subject_pem: &str, peer_pem: &str, peer_cert: &[u8]) -> Vec<u8> {
    use p521::pkcs8::DecodePrivateKey;
    let subj = p521::SecretKey::from_pkcs8_pem(subject_pem)
        .expect("dhsig-sha512: subject key must be secp521r1");
    let peer = p521::SecretKey::from_pkcs8_pem(peer_pem)
        .expect("dhsig-sha512: peer key must be secp521r1");
    let shared = p521::elliptic_curve::ecdh::diffie_hellman(
        subj.to_nonzero_scalar(), peer.public_key().as_affine());
    let (subj_cbor, iss_cbor) = c509_subject_issuer(peer_cert);
    let k = Sha512::new()
        .chain_update(subj_cbor)
        .chain_update(shared.raw_secret_bytes())
        .chain_update(iss_cbor)
        .finalize();
    let mut mac = HmacSha512::new_from_slice(&k).expect("HMAC key always valid");
    mac.update(tbs);
    mac.finalize().into_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// C509 certificate field extraction
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Embedded cert conversion (Cat D fix)
// ---------------------------------------------------------------------------

/// Convert type-3 C509 certs embedded in CSR attributes to type-2.
///
/// Walks the CBOR structure of `attrs` (the CSR's attributes field).  Any
/// CBOR array(11) whose first element is uint 3 is treated as a type-3 C509
/// certificate and re-signed as type-2 using `key_pem`.
fn convert_embedded_certs_to_type2(attrs: &[u8], key_pem: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(attrs.len() + 16);
    let mut pos = 0;
    while pos < attrs.len() {
        pos = cbor_copy_convert(attrs, pos, key_pem, &mut out);
    }
    out
}

/// Copy one CBOR item from `data[pos..]` to `out`, replacing embedded type-3
/// C509 certs (array(11) with first element == 0x03) with type-2 versions.
/// Returns the position just past the copied item.
fn cbor_copy_convert(data: &[u8], pos: usize, key_pem: &str, out: &mut Vec<u8>) -> usize {
    let b = data[pos];
    let major = b >> 5;
    let addl = b & 0x1f;
    let (length, hdr_end) = match addl {
        0..=23 => (addl as usize, pos + 1),
        24 => (data[pos + 1] as usize, pos + 2),
        25 => (u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize, pos + 3),
        26 => (u32::from_be_bytes([data[pos+1], data[pos+2], data[pos+3], data[pos+4]]) as usize, pos + 5),
        _ => panic!("cbor_copy_convert: unsupported additional info {}", addl),
    };
    match major {
        // uint / negint / simple — header encodes everything
        0 | 1 | 7 => { out.extend_from_slice(&data[pos..hdr_end]); hdr_end }
        // bstr — may be a draft-20 `bytes .cbor C509Certificate` wrapping an
        // embedded type-3 cert (content starts 0x8B 0x03). Re-sign the inner cert
        // as type-2 and re-wrap it as bytes .cbor; otherwise copy verbatim.
        2 => {
            let content = &data[hdr_end..hdr_end + length];
            if length >= 2 && content[0] == 0x8b && content[1] == 0x03 {
                let new_cert = recode_embedded_cert_as_type2(content, key_pem);
                out.extend_from_slice(&lcbor_bytes(&new_cert));
            } else {
                out.extend_from_slice(&data[pos..hdr_end + length]);
            }
            hdr_end + length
        }
        // tstr — header + payload bytes, verbatim
        3 => { out.extend_from_slice(&data[pos..hdr_end + length]); hdr_end + length }
        // array — check for embedded C509 cert (11 elements, first == 0x03)
        4 => {
            if length == 11 && hdr_end < data.len() && data[hdr_end] == 0x03 {
                let cert_end = cbor_item_end(data, pos);
                let new_cert = recode_embedded_cert_as_type2(&data[pos..cert_end], key_pem);
                out.extend_from_slice(&new_cert);
                return cert_end;
            }
            out.extend_from_slice(&data[pos..hdr_end]);
            let mut p = hdr_end;
            for _ in 0..length { p = cbor_copy_convert(data, p, key_pem, out); }
            p
        }
        // map
        5 => {
            out.extend_from_slice(&data[pos..hdr_end]);
            let mut p = hdr_end;
            for _ in 0..2 * length { p = cbor_copy_convert(data, p, key_pem, out); }
            p
        }
        // tag
        6 => { out.extend_from_slice(&data[pos..hdr_end]); cbor_copy_convert(data, hdr_end, key_pem, out) }
        _ => unreachable!(),
    }
}

/// Re-sign a type-3 C509 certificate (as raw CBOR bytes, starting with `8b 03 …`)
/// as a type-2 certificate.  Returns new CBOR bytes for the re-signed cert.
fn recode_embedded_cert_as_type2(cert: &[u8], key_pem: &str) -> Vec<u8> {
    // cert[0] must be 0x8b (array(11)); cert[1] must be 0x03 (type-3).
    let mut pos = 1; // skip array(11) header
    let mut starts = [0usize; 11];
    let mut ends = [0usize; 11];
    for i in 0..11 {
        starts[i] = pos;
        pos = cbor_item_end(cert, pos);
        ends[i] = pos;
    }
    // TBS = 0x02 (type-2) || fields 1–9 verbatim
    let mut tbs: Vec<u8> = vec![0x02];
    for i in 1..10 { tbs.extend_from_slice(&cert[starts[i]..ends[i]]); }
    let sig_alg = crate::type2::cbor_int_value(&cert[starts[2]..ends[2]]);
    let new_sig = sign_tbs(&tbs, key_pem, sig_alg);
    // Reassemble: array(11) header + 0x02 + fields 1–9 + new signature
    let mut result = vec![0x8bu8, 0x02u8];
    for i in 1..10 { result.extend_from_slice(&cert[starts[i]..ends[i]]); }
    result.extend_from_slice(&new_sig);
    result
}

/// Extract (subject_cbor, issuer_cbor) from a C509 cert CBOR sequence.
///
/// C509 cert fields: [0]=type [1]=serial [2]=sigAlg [3]=issuer [4]=notBefore
///   [5]=notAfter [6]=subject [7]=subPubKeyAlg [8]=subPubKey [9]=extensions [10]=sig
///
/// If issuer == 0xf6 (CBOR null, meaning self-signed "same as subject"), the
/// returned issuer slice equals the subject slice.
fn c509_subject_issuer(cert: &[u8]) -> (&[u8], &[u8]) {
    // draft-20: the peer C509 certificate is a CBOR array (0x8B header). Skip the
    // array header so the field walk below sees the 11 fields at the top level.
    // The RFC 6955 KDF uses the subject/issuer *field* bytes, which are identical
    // with or without the outer array header, so the derived MAC is unchanged.
    let mut pos = if !cert.is_empty() && (cert[0] >> 5) == 4 { 1 } else { 0 };
    let mut field_ranges: [(usize, usize); 7] = [(0, 0); 7];
    for i in 0..7 {
        let start = pos;
        pos = cbor_item_end(cert, pos);
        field_ranges[i] = (start, pos);
    }
    let (iss_start, iss_end) = field_ranges[3];
    let (sub_start, sub_end) = field_ranges[6];
    let issuer_raw = &cert[iss_start..iss_end];
    let subject = &cert[sub_start..sub_end];
    // CBOR null (0xf6) means issuer = same as subject.
    let issuer = if issuer_raw == [0xf6] { subject } else { issuer_raw };
    (subject, issuer)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Replace the trailing `new_hash.len()` bytes of `field6` with `new_hash`.
///
/// The C509 DhSigStatic field 6 ends with the MAC bytes (hashValue).  The
/// preceding bytes encode either nothing (just a bstr header) or a keyRef
/// (array header + issuer + serial + bstr header).  Replacing the tail is
/// safe regardless of which variant is present.
fn replace_dhsig_hash(field6: &[u8], new_hash: &[u8]) -> Vec<u8> {
    let mut result = field6.to_vec();
    let n = new_hash.len();
    assert!(result.len() >= n, "field6 is shorter than the new hash — malformed type-3 CSR?");
    let tail = result.len() - n;
    result[tail..].copy_from_slice(new_hash);
    result
}

/// Decode a CBOR-encoded non-negative integer from the first 1–3 bytes.
fn cbor_uint_value(cbor: &[u8]) -> u64 {
    let b = cbor[0];
    let addl = b & 0x1f;
    match addl {
        0..=23 => addl as u64,
        24 => cbor[1] as u64,
        25 => u16::from_be_bytes([cbor[1], cbor[2]]) as u64,
        _ => panic!("unexpected CBOR additional info {} in sig-alg field", addl),
    }
}
