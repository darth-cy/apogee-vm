//! The `MOD_MUL` family's circuit: one 256-bit modular multiplication a row,
//! invoked by the `ecall::PRECOMPILE_MOD_MUL` ecall and never decoded.
//!
//! `docs/spec/delegation.md` §14 is normative. One invocation is one row and
//! one row is one operation — `ops/row = 1`, as every delegation family has it
//! — so the family needs no batch, no populated count and no no-op selector: a
//! row is live or it is padding.
//!
//! ```text
//! frame     M[0..132]: cycle live base anchor_value, then 4 per word
//! words 0..8, 8..16, 16..24   the modulus m and the operands a and b
//! words 24..32                the result, the only words the invocation computes
//! W[0..1276]      the frame's own: 38 gap bits a word, then the base's bounds
//! W[1276..2300]   256 word bits each for m, a, b, out
//! W[2300..2308]   q's eight limbs, the quotient the prover supplies
//! W[2308..2564]   q's 256 word bits
//! W[2564..2828]   the `out < m` borrow chain: 8 difference limbs, 8 borrows
//! W[2828..3346]   14 signed carries of 37 bits
//! ```
//!
//! # Why the modulus is in the frame
//!
//! `FR_ARITH` (§13) multiplies modulo **the circuit's own field**, so its
//! multiply is one degree-2 gate: `prod = a·b` over `Fr` *is* the reduction. A
//! 256-bit modulus cannot work that way — a 256-bit value does not fit an `Fr`
//! at all, `p` being 254 bits — so this circuit carries the values as eight
//! 32-bit limbs and proves the schoolbook identity
//!
//! ```text
//! a·b = q·m + out,   out < m,   every limb below 2^32
//! ```
//!
//! over the integers, limb by limb, with a signed carry chain. Every term of a
//! limb equation is far below `p` — the largest is `8·(2^32−1)^2 < 2^67` — so
//! the `Fr` equation **is** the integer equation, which is the same argument
//! §13.3's borrow chain rests on.
//!
//! Carrying `m` costs eight frame words, 256 witness bits and a degree-2
//! product where a constant modulus would give a degree-1 term. What it buys is
//! that **one family serves every 256-bit modulus**: secp256k1's base field,
//! which a mainnet block spends 44% of its cycles in, its scalar field, BN254's
//! base field, and the EVM's `MULMOD`. Two constant-modulus families would be
//! two family ids, two ecalls, two circuits and two request selectors on
//! `ADD_SUB_LUI_AUIPC` — more surface, not less.
//!
//! # Soundness, in one paragraph
//!
//! Every limb of `m`, `a`, `b`, `out` and `q` is decomposed into 32 boolean
//! bits, so each is a non-negative integer below `2^32` and each value is below
//! `2^256`. The fifteen limb equations telescope to `a·b − q·m − out = 0` over
//! ℤ exactly when the last carry is zero, which the last equation forces by
//! having no outgoing carry. The borrow chain puts `out < m`, and `m > 0`
//! follows from it (no value is below zero). Integer division being unique,
//! `out` is `a·b mod m` and nothing else. Two notes: `q` is bounded to
//! `2^256` by its bits, which is enough for the honest prover because the guest
//! passes `a, b < m` and then `q = (a·b − out)/m < m`; and a prover who passed
//! unreduced operands would simply be unable to fit `q`, which costs the
//! *prover* and never the verifier.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::address_space;
use constants::mod_mul as f;

use crate::delegation as d;
use crate::{CircuitArtifact, Coeff, GateDef, PolyAddress};

/// The frame's words: four values of eight limbs.
const WORDS: usize = f::FRAME_WORDS;

/// `M` columns: the frame's four head columns and four per word.
pub const MEMORY_COLUMNS: usize = d::HEAD_COLUMNS + 4 * WORDS;

/// The four frame values, in frame order, with the field each is read from.
/// `out` is the only one the invocation writes.
const VALUES: [(&str, usize, u32); 4] = [
    ("m", f::M_WORD, d::WORD_READ_VALUE),
    ("a", f::A_WORD, d::WORD_READ_VALUE),
    ("b", f::B_WORD, d::WORD_READ_VALUE),
    ("out", f::OUT_WORD, d::WORD_WRITE_VALUE),
];

const fn w(i: usize) -> PolyAddress {
    PolyAddress::Witness(i as u32)
}

// The frame's committed addresses, re-exported so a fill, a checker or a
// tamper twin names a column rather than a number.

/// `M[0]`: the requesting cycle.
pub const CYCLE: PolyAddress = d::CYCLE;
/// `M[1]`: the row's one mask.
pub const LIVE: PolyAddress = d::LIVE;
/// `M[2]`: the frame base pointer.
pub const BASE: PolyAddress = d::BASE;
/// `M[3]`: the anchor teardown's value, free on both sides.
pub const ANCHOR_VALUE: PolyAddress = d::ANCHOR_VALUE;
/// A frame word's address field.
pub const WORD_ADDR: u32 = d::WORD_ADDR;
/// A frame word's read-timestamp field.
pub const WORD_READ_TS: u32 = d::WORD_READ_TS;
/// A frame word's read-value field.
pub const WORD_READ_VALUE: u32 = d::WORD_READ_VALUE;
/// A frame word's write-value field.
pub const WORD_WRITE_VALUE: u32 = d::WORD_WRITE_VALUE;

/// `M` column `4 + 4j + field` of frame word `j`.
pub fn word(j: usize, field: u32) -> PolyAddress {
    d::word(j, field)
}

/// `W[38j + i]`: bit `i` of frame word `j`'s timestamp gap.
pub fn gap_bit(j: usize, bit: usize) -> PolyAddress {
    d::gap_bit(j, bit)
}

/// `W[…]`: bit `i` of the frame pointer's low decomposition.
pub fn base_low_bit(bit: usize) -> PolyAddress {
    d::base_low_bit(WORDS, bit)
}

/// `W[…]`: bit `i` of the frame pointer's headroom decomposition.
pub fn base_room_bit(bit: usize) -> PolyAddress {
    d::base_room_bit(WORDS, bit)
}

/// The `W` index of value `v`'s 256 word bits, `v` indexing [`VALUES`].
fn value_bits(v: usize) -> usize {
    d::frame_witness(WORDS) + v * d::VALUE_BITS
}

/// The `W` index of `q`'s eight limb columns.
fn q_limbs() -> usize {
    value_bits(VALUES.len())
}

/// The `W` index of `q`'s 256 word bits.
fn q_bits() -> usize {
    q_limbs() + f::LIMBS
}

/// The `W` index of the `out < m` borrow chain: eight 32-bit difference limbs
/// then eight borrow bits.
fn chain() -> usize {
    q_bits() + d::VALUE_BITS
}

/// The `W` index of the fourteen signed carries' bits.
fn carries() -> usize {
    chain() + 32 * f::LIMBS + f::LIMBS
}

/// `W[…]`: limb `i` of the quotient the prover supplies.
pub fn q_limb(i: usize) -> PolyAddress {
    w(q_limbs() + i)
}

/// `W[…]`: bit `t` of limb `k` of value `v` ([`VALUES`]' order).
pub fn value_bit(v: usize, k: usize, t: usize) -> PolyAddress {
    w(value_bits(v) + 32 * k + t)
}

/// `W[…]`: bit `t` of limb `k` of `q`.
pub fn q_bit(k: usize, t: usize) -> PolyAddress {
    w(q_bits() + 32 * k + t)
}

/// `W[…]`: bit `t` of difference limb `i` of the `out < m` chain.
pub fn diff_bit(i: usize, t: usize) -> PolyAddress {
    w(chain() + 32 * i + t)
}

/// `W[…]`: borrow `i` of the `out < m` chain. Borrow 7 is `live`.
pub fn borrow_bit(i: usize) -> PolyAddress {
    w(chain() + 32 * f::LIMBS + i)
}

/// `W[…]`: bit `t` of carry `k`. The carry is `Σ 2^t·bit − 2^36·live`.
pub fn carry_bit(k: usize, t: usize) -> PolyAddress {
    w(carries() + f::CARRY_BITS * k + t)
}

/// The family's `W` columns: the frame's, four values' bits, `q`'s limbs and
/// bits, the borrow chain, and the carries.
pub const WITNESS_COLUMNS: usize = d::GAP_BITS * WORDS
    + d::BASE_LOW_BITS
    + d::BASE_ROOM_BITS
    + 4 * d::VALUE_BITS
    + f::LIMBS
    + d::VALUE_BITS
    + 32 * f::LIMBS
    + f::LIMBS
    + f::CARRY_BITS * f::CARRIES;

/// The family's circuit over `2^trace_vars` rows.
///
/// Validated, held to `crate::memory::check_memory` and to [`check_shape`];
/// panics if any of the three refuses it, so an artifact this returns is a
/// circuit that obeys every rule the engine assumes.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let mut enforcing = d::frame_gates(WORDS, f::FRAME_BYTES as u64);

    // Every word but the result's eight is read-only: the invocation writes
    // back what it read, so the guest's modulus and operands survive the call.
    for j in 0..f::OUT_WORD {
        enforcing.push((
            format!("writes_back_w{j}"),
            d::linear(vec![
                (d::lit(1), word(j, d::WORD_WRITE_VALUE)),
                (d::neg(1), word(j, d::WORD_READ_VALUE)),
            ]),
        ));
    }

    // Each of the four frame values' limbs: 32 boolean bits and the decode that
    // is also the 32-bit bound.
    for (v, (name, first, field)) in VALUES.into_iter().enumerate() {
        enforcing.extend(d::word_gates(name, first, field, value_bits(v)));
    }

    // `q`'s limbs are witnesses rather than frame words — the guest does not
    // compute the quotient — so each needs its own bits and its own decode.
    for k in 0..f::LIMBS {
        for t in 0..32 {
            enforcing.push((format!("q_bit{k}_{t}_boolean"), d::booleanity(q_bit(k, t))));
        }
    }
    for k in 0..f::LIMBS {
        let mut terms = vec![(d::lit(1), q_limb(k))];
        for t in 0..32 {
            terms.push((d::neg(1u64 << t), q_bit(k, t)));
        }
        enforcing.push((format!("q_word{k}"), d::linear(terms)));
    }

    // The carries' bits.
    for k in 0..f::CARRIES {
        for t in 0..f::CARRY_BITS {
            enforcing.push((
                format!("carry{k}_{t}_boolean"),
                d::booleanity(carry_bit(k, t)),
            ));
        }
    }

    enforcing.extend(product_gates());
    enforcing.extend(below_modulus_gates());

    let artifact = crate::memory::assemble(
        trace_vars,
        [d::memory_names(WORDS), witness_names(), Vec::new()],
        Vec::new(),
        d::leaves(address_space::DELEGATION_MOD_MUL, WORDS),
        enforcing,
        Vec::new(),
        &[],
    );
    check_shape(&artifact);
    artifact
}

/// Carry `k` as a linear form: `Σ 2^t·bit − 2^36·live`, or the empty form for
/// the position past the last carry, whose carry the identity forces to zero.
///
/// The `live` factor on the offset is what makes a padding row's carry **0**
/// rather than `−2^36`: every bit is zero there and so is `live`.
fn carry_terms(k: usize) -> Vec<(Coeff, PolyAddress)> {
    if k >= f::CARRIES {
        return Vec::new();
    }
    let mut terms: Vec<(Coeff, PolyAddress)> = (0..f::CARRY_BITS)
        .map(|t| (Coeff::Literal(d::pow2(t as u32)), carry_bit(k, t)))
        .collect();
    terms.push((Coeff::Literal(-d::pow2(f::CARRY_BITS as u32 - 1)), LIVE));
    terms
}

/// The fifteen limb equations of `a·b = q·m + out`.
///
/// At position `k`, with `P_k = Σ_{i+j=k} a_i·b_j` and `S_k = Σ_{i+j=k} q_i·m_j`:
///
/// ```text
/// P_k − S_k − out_k + c_{k−1} − 2^32·c_k = 0
/// ```
///
/// `out_k` is zero past limb 7, `c_{−1}` is zero, and `c_{POSITIONS−1}` is zero
/// — which is the closing condition: summing the fifteen equations weighted by
/// `2^{32k}` gives `a·b − q·m − out = c_{14}·2^{480}`, so a last carry of zero
/// *is* the identity.
///
/// Every term is a product of two committed columns or a column times a
/// literal, so every gate is degree 2.
fn product_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for k in 0..f::POSITIONS {
        let mut products: Vec<(Coeff, PolyAddress, PolyAddress)> = Vec::new();
        for i in 0..f::LIMBS {
            let Some(j) = k.checked_sub(i) else {
                continue;
            };
            if j >= f::LIMBS {
                continue;
            }
            products.push((
                d::lit(1),
                word(f::A_WORD + i, d::WORD_READ_VALUE),
                word(f::B_WORD + j, d::WORD_READ_VALUE),
            ));
            products.push((
                d::neg(1),
                q_limb(i),
                word(f::M_WORD + j, d::WORD_READ_VALUE),
            ));
        }
        let mut terms: Vec<(Coeff, PolyAddress)> = Vec::new();
        if k < f::LIMBS {
            terms.push((d::neg(1), word(f::OUT_WORD + k, d::WORD_WRITE_VALUE)));
        }
        if let Some(prev) = k.checked_sub(1) {
            terms.extend(carry_terms(prev));
        }
        let scale = d::pow2(32);
        for (c, x) in carry_terms(k) {
            let Coeff::Literal(c) = c else {
                panic!("mod_mul: a carry coefficient is a literal");
            };
            terms.push((Coeff::Literal(-(c * scale)), x));
        }
        out.push((format!("limb{k}"), d::quadratic(terms, products)));
    }
    out
}

/// `out < m`, as a borrow chain over eight 32-bit limbs.
///
/// ```text
/// out_i − m_i − b_{i−1} + 2^32·b_i = d_i,   d_i < 2^32,   b_i boolean
/// ```
///
/// telescopes to `out − m + 2^256·b_7 = D` with `D` below `2^256`, and
/// `b_7 = live` says the subtraction borrowed out, so `out < m` on a live row.
/// It is §13.3's chain with `m`'s **columns** where that one has `p`'s literals,
/// which is the one place carrying the modulus costs a degree: a literal times
/// `live` becomes a column, and the gate is ungated instead — a padding row's
/// words are all zero, so it holds there with every borrow zero.
///
/// `m > 0` follows and needs no gate of its own: `out` is a non-negative
/// integer and `out < m`.
fn below_modulus_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for i in 0..f::LIMBS {
        for t in 0..32 {
            out.push((
                format!("diff{i}_{t}_boolean"),
                d::booleanity(diff_bit(i, t)),
            ));
        }
    }
    for i in 0..f::LIMBS {
        out.push((format!("borrow{i}_boolean"), d::booleanity(borrow_bit(i))));
    }
    for i in 0..f::LIMBS {
        let mut terms = vec![
            (d::lit(1), word(f::OUT_WORD + i, d::WORD_WRITE_VALUE)),
            (d::neg(1), word(f::M_WORD + i, d::WORD_READ_VALUE)),
            (d::lit(1u64 << 32), borrow_bit(i)),
        ];
        if let Some(prev) = i.checked_sub(1) {
            terms.push((d::neg(1), borrow_bit(prev)));
        }
        for t in 0..32 {
            terms.push((d::neg(1u64 << t), diff_bit(i, t)));
        }
        out.push((format!("chain{i}"), d::linear(terms)));
    }
    out.push((
        "out_below_modulus".to_string(),
        d::linear(vec![
            (d::lit(1), LIVE),
            (d::neg(1), borrow_bit(f::LIMBS - 1)),
        ]),
    ));
    out
}

/// The family's lookup channels: **none**.
///
/// A delegation family carries no channel and that is load-bearing: its height
/// is `2^8`, where no range channel's table fits, so every bound it makes is a
/// bit decomposition with a booleanity gate (`docs/spec/delegation.md` §9). That
/// is also why its registry arm sits below `family_circuit`'s minimum-height
/// guard — a family with no channel reaches no `BITS <= trace_vars` assertion.
pub fn channels() -> Vec<crate::lookup::ChannelSpec> {
    Vec::new()
}

/// The `W` column names, in layout order.
fn witness_names() -> Vec<String> {
    let mut out = d::witness_names(WORDS);
    for (name, ..) in VALUES {
        for k in 0..f::LIMBS {
            for t in 0..32 {
                out.push(format!("{name}_bit{k}_{t}"));
            }
        }
    }
    for k in 0..f::LIMBS {
        out.push(format!("q_limb{k}"));
    }
    for k in 0..f::LIMBS {
        for t in 0..32 {
            out.push(format!("q_bit{k}_{t}"));
        }
    }
    for i in 0..f::LIMBS {
        for t in 0..32 {
            out.push(format!("diff{i}_{t}"));
        }
    }
    for i in 0..f::LIMBS {
        out.push(format!("borrow{i}"));
    }
    for k in 0..f::CARRIES {
        for t in 0..f::CARRY_BITS {
            out.push(format!("carry{k}_{t}"));
        }
    }
    out
}

/// The shape this family's artifact must have, checked where it is built.
///
/// The counts are what a fill writes and what `crates/checker` reads, so a
/// layout change that moved one silently would be a fill writing into the wrong
/// column. `docs/spec/constraint-manifest.md` §15 is the same account by name.
fn check_shape(artifact: &CircuitArtifact) {
    assert_eq!(
        artifact.memory.len(),
        MEMORY_COLUMNS,
        "mod_mul: the frame's M width"
    );
    assert_eq!(
        artifact.witness.len(),
        WITNESS_COLUMNS,
        "mod_mul: the family's W width"
    );
    assert_eq!(
        witness_names().len(),
        WITNESS_COLUMNS,
        "mod_mul: one W name per W column"
    );
    // The carries are last, so the family's own columns end exactly where the
    // witness does: a fill that wrote past them would be writing into nothing.
    assert_eq!(
        carries() + f::CARRY_BITS * f::CARRIES,
        d::frame_witness(WORDS) + WITNESS_COLUMNS
            - d::GAP_BITS * WORDS
            - d::BASE_LOW_BITS
            - d::BASE_ROOM_BITS,
        "mod_mul: the carries close the witness"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The circuit exists, validates and keeps the memory argument's provenance
    /// rule at the height it is used at. `artifact` asserts all three itself,
    /// so this is the test that it is *called*.
    #[test]
    fn the_circuit_validates() {
        let a = artifact(8);
        assert_eq!(a.memory.len(), MEMORY_COLUMNS);
        assert_eq!(a.witness.len(), WITNESS_COLUMNS);
        assert!(
            a.setup.is_empty(),
            "a delegation family has no setup column"
        );
        assert!(channels().is_empty(), "a delegation family has no channel");
        assert_eq!(a.validate(), Ok(()));
        assert_eq!(crate::memory::check_memory(&a), Ok(()));
    }

    /// The fifteen limb gates are present by name, and the fourteen carries
    /// close the identity: position `POSITIONS - 1` has **no** outgoing carry,
    /// which is what makes the telescoped sum `a·b − q·m − out = 0` rather than
    /// a multiple of `2^480`.
    #[test]
    fn the_limb_identity_closes() {
        let a = artifact(8);
        let names: Vec<&str> = a.relations.iter().map(|r| r.name.as_str()).collect();
        for k in 0..f::POSITIONS {
            assert!(names.contains(&&*format!("limb{k}")), "limb{k}");
        }
        assert_eq!(f::CARRIES, f::POSITIONS - 1);
        assert!(carry_terms(f::CARRIES).is_empty(), "the last carry is zero");
        assert!(!carry_terms(f::CARRIES - 1).is_empty());
    }

    /// The carry bound the offset rests on, checked by arithmetic rather than
    /// asserted in prose: with every limb below `2^32`, the largest a position's
    /// left-hand side can be is `8·(2^32 − 1)^2`, and dividing by `2^32` with
    /// the incoming carry folded in settles below the offset.
    #[test]
    fn the_carry_offset_covers_the_bound() {
        let limb = (1u128 << 32) - 1;
        let max_products = f::LIMBS as u128 * limb * limb;
        let mut bound = 0u128;
        for _ in 0..8 {
            bound = (max_products + limb + bound) / (1u128 << 32) + 1;
        }
        assert!(
            bound < f::CARRY_OFFSET as u128,
            "a carry reaches {bound} and the offset is {}",
            f::CARRY_OFFSET
        );
        // And one bit of room, which is what makes the constant a choice rather
        // than a coincidence.
        assert!(2 * bound < f::CARRY_OFFSET as u128);
    }

    /// Every column the layout names is inside the witness, and the five
    /// regions do not overlap: a fill that wrote `q`'s bits over the chain's
    /// would produce a circuit that still validates.
    #[test]
    fn the_witness_regions_do_not_overlap() {
        let mut seen = alloc::vec![0usize; WITNESS_COLUMNS];
        let mut mark = |a: PolyAddress| {
            let PolyAddress::Witness(i) = a else {
                panic!("not a witness column: {a}");
            };
            seen[i as usize] += 1;
        };
        for v in 0..VALUES.len() {
            for k in 0..f::LIMBS {
                for t in 0..32 {
                    mark(value_bit(v, k, t));
                }
            }
        }
        for k in 0..f::LIMBS {
            mark(q_limb(k));
            for t in 0..32 {
                mark(q_bit(k, t));
            }
        }
        for i in 0..f::LIMBS {
            mark(borrow_bit(i));
            for t in 0..32 {
                mark(diff_bit(i, t));
            }
        }
        for k in 0..f::CARRIES {
            for t in 0..f::CARRY_BITS {
                mark(carry_bit(k, t));
            }
        }
        assert!(seen.iter().all(|n| *n <= 1), "two names share a column");
        let claimed: usize = seen.iter().sum();
        assert_eq!(
            claimed + d::frame_witness(WORDS),
            WITNESS_COLUMNS,
            "the family's own columns and the frame's fill the witness exactly"
        );
    }
}
