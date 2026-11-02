//! SM2 digital signatures with SM3 (GB/T 32918.2-2016, RFC 8998 §3.2.1), using
//! the default distinguishing identifier "1234567812345678".
//!
//! Implemented on OpenSSL's big-number and EC-point primitives because the
//! OpenSSL EVP interface does not apply the default identifier unless it is set
//! explicitly, and the `openssl` crate offers no way to set it.
//!
//! SECURITY NOTICE: test-vector tooling only. Never use in production.

use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef};
use openssl::error::ErrorStack;
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;

/// Default distinguishing identifier (GB/T 32918.2, RFC 8998 §3.2.1).
const DEFAULT_ID: &[u8] = b"1234567812345678";

pub(crate) fn sm2_group() -> Result<EcGroup, ErrorStack> {
    EcGroup::from_curve_name(Nid::SM2)
}

/// e = SM3(ZA || M) as an integer, where
/// ZA = SM3(ENTL || ID || a || b || xG || yG || xA || yA).
fn message_digest(
    group: &EcGroupRef,
    q: &EcPointRef,
    msg: &[u8],
    ctx: &mut BigNumContext,
) -> Result<BigNum, ErrorStack> {
    let mut p = BigNum::new()?;
    let mut a = BigNum::new()?;
    let mut b = BigNum::new()?;
    group.components_gfp(&mut p, &mut a, &mut b, ctx)?;
    let mut xg = BigNum::new()?;
    let mut yg = BigNum::new()?;
    let generator = group.generator_opt().ok_or_else(ErrorStack::get)?;
    generator.affine_coordinates(group, &mut xg, &mut yg, ctx)?;
    let mut xa = BigNum::new()?;
    let mut ya = BigNum::new()?;
    q.affine_coordinates(group, &mut xa, &mut ya, ctx)?;

    let entl = ((DEFAULT_ID.len() * 8) as u16).to_be_bytes();
    let mut za = Hasher::new(MessageDigest::sm3())?;
    za.update(&entl)?;
    za.update(DEFAULT_ID)?;
    for v in [&a, &b, &xg, &yg, &xa, &ya] {
        za.update(&v.to_vec_padded(32)?)?;
    }
    let za = za.finish()?;

    let mut e = Hasher::new(MessageDigest::sm3())?;
    e.update(&za)?;
    e.update(msg)?;
    BigNum::from_slice(&e.finish()?)
}

fn order(group: &EcGroupRef, ctx: &mut BigNumContext) -> Result<BigNum, ErrorStack> {
    let mut n = BigNum::new()?;
    group.order(&mut n, ctx)?;
    Ok(n)
}

/// Verify the SM2 signature (r, s) over `msg` with public key `q`.
pub(crate) fn sm2_verify(
    group: &EcGroupRef,
    q: &EcPointRef,
    msg: &[u8],
    r: &BigNumRef,
    s: &BigNumRef,
) -> Result<bool, ErrorStack> {
    let mut ctx = BigNumContext::new()?;
    let n = order(group, &mut ctx)?;
    let one = BigNum::from_u32(1)?;
    let in_range = |v: &BigNumRef| v >= &*one && v < &*n;
    if !in_range(r) || !in_range(s) {
        return Ok(false);
    }
    let e = message_digest(group, q, msg, &mut ctx)?;
    // t = (r + s) mod n; (x1, y1) = s·G + t·Q; valid iff (e + x1) mod n = r.
    let mut t = BigNum::new()?;
    t.mod_add(r, s, &n, &mut ctx)?;
    if t.num_bits() == 0 {
        return Ok(false);
    }
    let mut pt = EcPoint::new(group)?;
    pt.mul_full(group, s, q, &t, &mut ctx)?;
    let mut x1 = BigNum::new()?;
    let mut y1 = BigNum::new()?;
    pt.affine_coordinates(group, &mut x1, &mut y1, &mut ctx)?;
    let mut rr = BigNum::new()?;
    rr.mod_add(&e, &x1, &n, &mut ctx)?;
    Ok(&*rr == r)
}

/// Sign `msg` with private key `d`; returns raw r || s (32 bytes each).
pub(crate) fn sm2_sign(group: &EcGroupRef, d: &BigNumRef, msg: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut ctx = BigNumContext::new()?;
    let n = order(group, &mut ctx)?;
    let mut q = EcPoint::new(group)?;
    q.mul_generator2(group, d, &mut ctx)?;
    let e = message_digest(group, &q, msg, &mut ctx)?;

    // (1 + d)^-1 mod n
    let one = BigNum::from_u32(1)?;
    let mut d1 = BigNum::new()?;
    d1.mod_add(d, &one, &n, &mut ctx)?;
    let mut d1_inv = BigNum::new()?;
    d1_inv.mod_inverse(&d1, &n, &mut ctx)?;

    loop {
        // k in [1, n-1]; (x1, y1) = k·G; r = (e + x1) mod n.
        let mut k = BigNum::new()?;
        n.rand_range(&mut k)?;
        if k.num_bits() == 0 {
            continue;
        }
        let mut kg = EcPoint::new(group)?;
        kg.mul_generator2(group, &k, &mut ctx)?;
        let mut x1 = BigNum::new()?;
        let mut y1 = BigNum::new()?;
        kg.affine_coordinates(group, &mut x1, &mut y1, &mut ctx)?;
        let mut r = BigNum::new()?;
        r.mod_add(&e, &x1, &n, &mut ctx)?;
        let mut rk = BigNum::new()?;
        rk.checked_add(&r, &k)?;
        if r.num_bits() == 0 || rk == n {
            continue;
        }
        // s = (1 + d)^-1 · (k - r·d) mod n
        let mut rd = BigNum::new()?;
        rd.mod_mul(&r, d, &n, &mut ctx)?;
        let mut k_rd = BigNum::new()?;
        k_rd.mod_sub(&k, &rd, &n, &mut ctx)?;
        let mut s = BigNum::new()?;
        s.mod_mul(&d1_inv, &k_rd, &n, &mut ctx)?;
        if s.num_bits() == 0 {
            continue;
        }
        let mut raw = r.to_vec_padded(32)?;
        raw.extend(s.to_vec_padded(32)?);
        return Ok(raw);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signature made by `sm2_sign` verifies, and fails for another message.
    #[test]
    fn sign_verify_round_trip() {
        let group = sm2_group().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let n = order(&group, &mut ctx).unwrap();
        let mut d = BigNum::new().unwrap();
        n.rand_range(&mut d).unwrap();
        let mut q = EcPoint::new(&group).unwrap();
        q.mul_generator2(&group, &d, &mut ctx).unwrap();

        let sig = sm2_sign(&group, &d, b"message").unwrap();
        let r = BigNum::from_slice(&sig[..32]).unwrap();
        let s = BigNum::from_slice(&sig[32..]).unwrap();
        assert!(sm2_verify(&group, &q, b"message", &r, &s).unwrap());
        assert!(!sm2_verify(&group, &q, b"messagf", &r, &s).unwrap());
    }
}
