//! The `moduli` group: `constants::mod_mul::MODULI` against arkworks.
//!
//! S26b fixed the `MOD_MUL` delegation's modulus to one of four, which put
//! four 256-bit numbers into `crates/constants` as literals — and
//! `crates/constants/CLAUDE.md`'s standing rule is that a table of numbers
//! copied from a reference is exactly the kind of constant a test must
//! re-derive. Three of the four can be derived inside this repository:
//! secp256k1's `p` is `2^256 − 2^32 − 977`, and BN254's two are already here
//! as `constants::FQ_MODULUS` and `constants::FR_MODULUS`. **secp256k1's `n`
//! cannot** — the group order has no closed form and appears nowhere in
//! `crates/`, so an outside oracle is the only honest pin, and master rule 2
//! names arkworks as exactly that.
//!
//! So this file writes all four out of `ark-secp256k1` and `ark-bn254`, which
//! never reach the prover, the verifier or a guest, and
//! `crates/constants/tests/moduli.rs` diffs the constants against the file.
//! The two derivable ones are written here as well and re-derived there, so
//! the fixture and the constants have two independent sources apiece rather
//! than one shared one.

use ark_ff::{BigInteger, PrimeField};

use crate::write_vectors;

/// One field's modulus as sixteen little-endian 32-bit limbs in hex — the
/// frame's own encoding, which is what `constants::mod_mul::MODULI` holds.
fn line(name: &str, modulus: &[u8]) -> String {
    assert_eq!(modulus.len(), 32, "{name} is not 256 bits wide");
    let limbs: Vec<String> = modulus
        .chunks(4)
        .map(|w| format!("{:08x}", u32::from_le_bytes([w[0], w[1], w[2], w[3]])))
        .collect();
    format!("{name} {}\n", limbs.join(" "))
}

/// A field's modulus, little-endian bytes, through `ark-ff`'s own accessor.
fn modulus_of<F: PrimeField>() -> Vec<u8> {
    let mut bytes = F::MODULUS.to_bytes_le();
    bytes.resize(32, 0);
    bytes
}

pub fn generate() {
    let mut out = String::new();
    out.push_str("# the four moduli `constants::mod_mul::MODULI` holds, from arkworks\n");
    out.push_str("# docs/spec/delegation.md \u{00a7}14 is normative; the order is `mod_mul::CODES`\n");
    out.push_str("# name, then eight little-endian 32-bit limbs in hex, low limb first\n");
    out.push_str(&line(
        "SECP256K1_P",
        &modulus_of::<ark_secp256k1::Fq>(),
    ));
    out.push_str(&line(
        "SECP256K1_N",
        &modulus_of::<ark_secp256k1::Fr>(),
    ));
    out.push_str(&line("BN254_P", &modulus_of::<ark_bn254::Fq>()));
    out.push_str(&line("BN254_R", &modulus_of::<ark_bn254::Fr>()));
    write_vectors("crates/constants/tests/vectors/moduli.txt", &out);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The oracle is an oracle: arkworks' secp256k1 base field is
    /// `2^256 − 2^32 − 977`, which is the one of the four this repository can
    /// derive without it. If this fails, the generator is reading the wrong
    /// curve's field and the other three lines are worth nothing either.
    #[test]
    fn the_secp256k1_base_field_is_the_number_it_should_be() {
        let bytes = modulus_of::<ark_secp256k1::Fq>();
        let mut want = [0xffu8; 32];
        // `2^256 − 2^32 − 977` = `0xffff...fffffffefffffc2f`.
        want[0..4].copy_from_slice(&0xffff_fc2fu32.to_le_bytes());
        want[4..8].copy_from_slice(&0xffff_fffeu32.to_le_bytes());
        assert_eq!(bytes, want);
    }

    /// The four lines are distinct and 256 bits wide, which is what the frame
    /// and the selector both assume.
    #[test]
    fn the_four_moduli_are_distinct() {
        let all = [
            modulus_of::<ark_secp256k1::Fq>(),
            modulus_of::<ark_secp256k1::Fr>(),
            modulus_of::<ark_bn254::Fq>(),
            modulus_of::<ark_bn254::Fr>(),
        ];
        for (i, m) in all.iter().enumerate() {
            assert_eq!(m.len(), 32);
            for (j, n) in all.iter().enumerate().skip(i + 1) {
                assert_ne!(m, n, "moduli {i} and {j}");
            }
        }
    }
}
