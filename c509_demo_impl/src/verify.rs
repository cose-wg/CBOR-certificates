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
//! Scope: ECDSA over secp256r1/secp384r1/secp521r1 and Ed25519 — the pure-Rust
//! algorithms, covering the self-signed ECDSA Type-2 vectors. brainpool / Ed448 /
//! SM2 / RSA verification is not yet wired here (their signing goes through
//! OpenSSL / the `rsa` crate in `type2.rs`); add later if the shepherd needs it.
//!
//! SECURITY NOTICE: test-vector tooling only. Never use in production.

use std::convert::TryInto;

use crate::lcbor::cbor_item_end;
use crate::registry::{
    PK_ED25519, PK_SECP256R, PK_SECP384R, PK_SECP521R,
    SIG_ECDSA_SHA256, SIG_ECDSA_SHA384, SIG_ECDSA_SHA512,
};
use crate::type2::cbor_int_value;

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
    // BEFORE parsing the key/signature — RSA keys are CBOR arrays, not byte
    // strings, so bstr parsing would otherwise error with a misleading message.
    if pk_alg != PK_SECP256R && pk_alg != PK_SECP384R
        && pk_alg != PK_SECP521R && pk_alg != PK_ED25519 {
        return Err(format!(
            "verify: unsupported public-key algorithm id {} \
             (supported: P-256, P-384, P-521, Ed25519)",
            pk_alg
        ));
    }

    let sig = bstr_payload(fields[10])?;

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
        x if x == PK_ED25519 => verify_ed25519(&tbs, signer_key, sig),
        other => Err(format!(
            "verify: unsupported public-key algorithm id {} \
             (supported: P-256, P-384, P-521, Ed25519)",
            other
        )),
    }
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
