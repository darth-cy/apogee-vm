//! `constants::mod_mul::MODULI` against two independent readings.
//!
//! Four 256-bit numbers entered this crate as literals at S26b, and
//! `crates/constants/CLAUDE.md`'s standing rule is that a table copied from a
//! reference is exactly the kind of constant a test must re-derive. There are
//! two readings here and each covers a different failure:
//!
//! - **The committed vector**, `tests/vectors/moduli.txt`, written by
//!   `cargo run -p kat-gen -- moduli` out of `ark-secp256k1` and `ark-bn254`
//!   and regenerated-and-diffed in CI. This is the only pin secp256k1's group
//!   order `n` can have: it has no closed form and appears nowhere else in
//!   `crates/`.
//! - **A derivation inside this repository** for the other three:
//!   secp256k1's `p` is `2^256 − 2^32 − 977`, and BN254's two are already here
//!   as [`constants::FQ_MODULUS`] and [`constants::FR_MODULUS`], four 64-bit
//!   limbs where `MODULI` holds eight 32-bit ones.
//!
//! A single transcription error fails both; a wrong *oracle* — the generator
//! reading another curve's field — fails only the second, which is why the
//! second exists.

use constants::mod_mul as f;

/// The committed vector, as `(name, limbs)` in file order.
fn vector() -> Vec<(String, [u32; f::LIMBS])> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/moduli.txt"
    ))
    .expect("cargo run -p kat-gen -- moduli writes this file");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next().expect("a name").to_string();
            let limbs: Vec<u32> = parts
                .map(|w| u32::from_str_radix(w, 16).expect("a hex limb"))
                .collect();
            let limbs: [u32; f::LIMBS] = limbs.try_into().expect("eight limbs");
            (name, limbs)
        })
        .collect()
}

/// Every modulus is arkworks', limb for limb, in `CODES` order.
#[test]
fn the_moduli_are_arkworks() {
    let vector = vector();
    let names = ["SECP256K1_P", "SECP256K1_N", "BN254_P", "BN254_R"];
    assert_eq!(vector.len(), f::MODULI.len(), "one line per modulus");
    assert_eq!(f::MODULI.len(), f::CODES.len(), "one modulus per code");
    for (i, (name, limbs)) in vector.iter().enumerate() {
        assert_eq!(name, names[i], "line {i}");
        assert_eq!(*limbs, f::MODULI[i], "{name}");
    }
    // The names are the codes' own, so a reordering of either list fails here
    // rather than silently renaming a field.
    assert_eq!(
        [f::SECP256K1_P, f::SECP256K1_N, f::BN254_P, f::BN254_R],
        f::CODES
    );
}

/// The three this repository can derive, derived — without reading the vector.
#[test]
fn the_three_derivable_moduli_are_derived() {
    // `2^256 − 2^32 − 977`, as eight limbs: every limb is `0xffff_ffff`
    // except the bottom two, which carry the subtraction.
    let mut secp_p = [0xffff_ffffu32; f::LIMBS];
    secp_p[0] = 0xffff_ffffu32.wrapping_sub(977 - 1); // −(2^32) borrows into limb 1
    secp_p[1] = 0xffff_fffe;
    assert_eq!(
        f::MODULI[f::SECP256K1_P as usize - 1],
        secp_p,
        "secp256k1 p is 2^256 - 2^32 - 977"
    );

    // BN254's two, split out of the 64-bit limbs this crate already holds.
    let split = |m: [u64; 4]| -> [u32; f::LIMBS] {
        core::array::from_fn(|k| (m[k / 2] >> (32 * (k % 2))) as u32)
    };
    assert_eq!(
        f::MODULI[f::BN254_P as usize - 1],
        split(constants::FQ_MODULUS),
        "BN254 q is FQ_MODULUS"
    );
    assert_eq!(
        f::MODULI[f::BN254_R as usize - 1],
        split(constants::FR_MODULUS),
        "BN254 r is FR_MODULUS"
    );
}

/// The two Montgomery corrections are inverses of `2^256` modulo their own
/// field, checked by multiplying them back out over 32-bit limbs.
///
/// `guests/vendor/ark-ff` multiplies by these to turn a plain product of two
/// Montgomery representatives into a Montgomery product, so a wrong one is an
/// arkworks field that computes the wrong answer in a guest and nowhere else.
#[test]
fn the_montgomery_corrections_invert_the_radix() {
    for (code, r_inv) in [
        (f::BN254_P, f::BN254_P_R_INV),
        (f::BN254_R, f::BN254_R_R_INV),
    ] {
        let m = f::MODULI[code as usize - 1];
        // `2^256 mod m`, by doubling from 1 — 256 doublings of an eight-limb
        // value, which needs no multiply and no reference.
        let mut r = [0u32; f::LIMBS];
        r[0] = 1;
        for _ in 0..256 {
            r = add_mod(&r, &r, &m);
        }
        assert_eq!(mul_mod(&r, &r_inv, &m), one(), "R * R^-1 = 1 mod {code}");
    }
}

/// `1` over eight limbs.
fn one() -> [u32; f::LIMBS] {
    let mut v = [0u32; f::LIMBS];
    v[0] = 1;
    v
}

/// `x + y mod m`, for `x, y < m < 2^256`.
fn add_mod(x: &[u32; f::LIMBS], y: &[u32; f::LIMBS], m: &[u32; f::LIMBS]) -> [u32; f::LIMBS] {
    let mut sum = [0u64; f::LIMBS + 1];
    let mut carry = 0u64;
    for k in 0..f::LIMBS {
        let total = x[k] as u64 + y[k] as u64 + carry;
        sum[k] = total & 0xffff_ffff;
        carry = total >> 32;
    }
    sum[f::LIMBS] = carry;
    if sum[f::LIMBS] != 0 || !below(&sum, m) {
        let mut borrow = 0i64;
        for k in 0..f::LIMBS {
            let d = sum[k] as i64 - m[k] as i64 - borrow;
            borrow = i64::from(d < 0);
            sum[k] = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u64;
        }
    }
    core::array::from_fn(|k| sum[k] as u32)
}

/// `x · y mod m`, by double-and-add over `y`'s bits: no 512-bit product and no
/// long division, so this shares nothing with the circuit, the executor or the
/// prover's fill.
fn mul_mod(x: &[u32; f::LIMBS], y: &[u32; f::LIMBS], m: &[u32; f::LIMBS]) -> [u32; f::LIMBS] {
    let mut acc = [0u32; f::LIMBS];
    for bit in (0..32 * f::LIMBS).rev() {
        acc = add_mod(&acc, &acc, m);
        if (y[bit / 32] >> (bit % 32)) & 1 == 1 {
            acc = add_mod(&acc, x, m);
        }
    }
    acc
}

/// Whether the nine-lane `x` is below the eight-limb `m`.
fn below(x: &[u64; f::LIMBS + 1], m: &[u32; f::LIMBS]) -> bool {
    if x[f::LIMBS] != 0 {
        return false;
    }
    for k in (0..f::LIMBS).rev() {
        if x[k] != m[k] as u64 {
            return x[k] < m[k] as u64;
        }
    }
    false
}
