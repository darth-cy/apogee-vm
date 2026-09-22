//! The `FR_ARITH` family's circuit: one `Fr` add, multiply or inverse a row,
//! invoked by the `ecall::PRECOMPILE_FR_ARITH` ecall and never decoded.
//!
//! `docs/spec/delegation.md` §13 is normative. One invocation is one row and
//! one row is one operation — `ops/row = 1`, which is the cost model the
//! recursion guest's contraction is sized against — so the family needs no
//! batch, no populated count and no no-op selector: a row is live or it is
//! padding.
//!
//! ```text
//! frame     M[0..104]: cycle live base anchor_value, then 4 per word
//! word 0    the operation code, 1 add, 2 mul, 3 inverse
//! words 1..9, 9..17   the operands a and b, read and written back unchanged
//! words 17..25        the result, the only words the invocation computes
//! W[0..1010]     the frame's own: 38 gap bits a word, then the base's bounds
//! W[1010..2570]  per value, 256 word bits then 264 canonicity bits: a, b, out
//! W[2570..2573]  f_add, f_mul, f_inv
//! W[2573..2576]  prod, inv, z
//! ```
//!
//! # What the three operations are
//!
//! The frame carries `field::Fr`'s **in-memory** representation (`§13.2`), so
//! the element a frame value encodes is `x·R` where `x` is the mathematical
//! value and `R = 2^256 mod p`. The delegation computes exactly what `Fr`'s
//! own `Add`, `Mul` and `inverse` compute on those representatives:
//!
//! ```text
//! add   out = a + b                 R is linear, so nothing is carried
//! mul   out = a·b·R^-1              which is what a Montgomery multiply is
//! inv   out = R^2·a^-1, and 0 at a = 0
//! ```
//!
//! That is not a second definition of field arithmetic: it is the same one,
//! read on the representation the guest already holds. A mathematically
//! canonical frame would be a second definition *and* would cost a Montgomery
//! conversion per operand — about twice the software multiply the delegation
//! replaces — which is the whole reason this encoding was chosen.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::address_space;
use constants::fr_arith as f;
use field::Fr;

use crate::delegation as d;
use crate::lookup::ChannelSpec;
use crate::{CircuitArtifact, Coeff, PolyAddress};

/// The frame's words: the opcode, then three values of eight.
const WORDS: usize = f::FRAME_WORDS;

/// `M` columns: the frame's four head columns and four per word.
pub const MEMORY_COLUMNS: usize = d::HEAD_COLUMNS + 4 * WORDS;

/// The `W` index of value `v`'s 256 word bits, `v` being 0 for `a`, 1 for `b`
/// and 2 for `out`. Each value's canonicity bits follow its word bits.
fn value_bits(v: usize) -> usize {
    d::frame_witness(WORDS) + v * (d::VALUE_BITS + d::CANONICITY_BITS)
}

/// The `W` index of value `v`'s 264 canonicity bits.
fn value_canon(v: usize) -> usize {
    value_bits(v) + d::VALUE_BITS
}

/// The `W` index the family's own scalar columns start at.
const SCALARS: usize = 3 * (d::VALUE_BITS + d::CANONICITY_BITS);

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

/// `M[4 + 4j + field]`: one field of frame word `j`.
pub fn word(j: usize, field: u32) -> PolyAddress {
    d::word(j, field)
}

/// Bit `bit` of frame word `j`'s timestamp gap.
pub fn gap_bit(j: usize, bit: usize) -> PolyAddress {
    d::gap_bit(j, bit)
}

/// Bit `bit` of `(base − RAM_ORIGIN) / 4`.
pub fn base_low_bit(bit: usize) -> PolyAddress {
    d::base_low_bit(WORDS, bit)
}

/// Bit `bit` of `2^31 − frame bytes − base`.
pub fn base_room_bit(bit: usize) -> PolyAddress {
    d::base_room_bit(WORDS, bit)
}

/// Bit `t` of word `k` of value `v` — 0 for `a`, 1 for `b`, 2 for the result.
pub fn value_bit(v: usize, k: usize, t: usize) -> PolyAddress {
    w(value_bits(v) + 32 * k + t)
}

/// Bit `t` of limb `k` of value `v`'s canonicity difference, `X − p`.
pub fn diff_bit(v: usize, k: usize, t: usize) -> PolyAddress {
    w(value_canon(v) + 32 * k + t)
}

/// Borrow `k` of value `v`'s canonicity chain. The last is 1 exactly when the
/// value is below the modulus.
pub fn borrow_bit(v: usize, k: usize) -> PolyAddress {
    w(value_canon(v) + 32 * d::WORDS_PER_VALUE + k)
}

/// `W[2570..2573]`: the operation selectors, in `constants::fr_arith::OPS`
/// order. Booleans summing to `live`, so a live row claims exactly one
/// operation and a row claiming two is unprovable.
pub fn selector(i: usize) -> PolyAddress {
    w(d::frame_witness(WORDS) + SCALARS + i)
}

/// `W[2573]`: `a·b`, the one committed helper. A selector times a product is
/// degree 3, so the product is pinned by an ungated gate of its own and the
/// selected relation reads it.
pub fn prod() -> PolyAddress {
    w(d::frame_witness(WORDS) + SCALARS + 3)
}

/// `W[2574]`: the witnessed inverse of `a`, and 0 wherever `a` is 0.
pub fn inv() -> PolyAddress {
    w(d::frame_witness(WORDS) + SCALARS + 4)
}

/// `W[2575]`: the is-zero gadget's flag, 1 exactly on an inverse row whose
/// operand is 0. Boolean with no gate of its own: the two gadget gates force
/// it (`crates/constraints/src/gadgets.rs`).
pub fn is_zero() -> PolyAddress {
    w(d::frame_witness(WORDS) + SCALARS + 5)
}

/// `W` columns: the frame's own, three values' bits, and six scalars.
pub const WITNESS_COLUMNS: usize =
    d::GAP_BITS * WORDS + d::BASE_LOW_BITS + d::BASE_ROOM_BITS + SCALARS + 6;

/// `ρ = 2^256 mod p`, as a field element.
///
/// Re-derived from `constants::FR_R` — the Montgomery radix, which is also the
/// limb pattern `Fr::ONE` holds — rather than restated as a second literal.
/// This is the factor `Fr`'s in-memory representation carries: the element
/// `Fr`'s limbs spell for the value `x` is `x·ρ`.
fn rho() -> Fr {
    let mut bytes = [0u8; 32];
    for (i, limb) in constants::FR_R.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
    }
    Fr::from_bytes(&bytes).expect("the Montgomery radix is reduced mod p")
}

/// The family's circuit over `2^trace_vars` rows.
///
/// Validated, held to `crate::memory::check_memory` and to [`check_shape`];
/// panics if any of the three refuses it, so an artifact this returns is a
/// circuit that obeys every rule the engine assumes.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let mut enforcing = d::frame_gates(WORDS, f::FRAME_BYTES as u64);

    // Every word but the result's eight is read-only: the invocation writes
    // back what it read, so the guest's operands survive the call.
    for j in 0..f::OUT_WORD {
        enforcing.push((
            format!("writes_back_w{j}"),
            d::linear(vec![
                (d::lit(1), d::word(j, d::WORD_WRITE_VALUE)),
                (d::neg(1), d::word(j, d::WORD_READ_VALUE)),
            ]),
        ));
    }

    // The opcode word is the selectors, written out. That is also its bound:
    // it is `f::OPS`-valued on a live row and 0 on a padding one, and needs no
    // 32-bit decomposition of its own.
    for (i, op) in f::OPS.iter().enumerate() {
        enforcing.push((format!("selector{op}_boolean"), d::booleanity(selector(i))));
    }
    {
        let mut terms = vec![(d::lit(1), d::word(f::OPCODE_WORD, d::WORD_READ_VALUE))];
        for (i, op) in f::OPS.iter().enumerate() {
            terms.push((d::neg(*op as u64), selector(i)));
        }
        enforcing.push(("opcode_rule".to_string(), d::linear(terms)));
    }
    // Exactly one operation a live row, none on a padding row. Two selectors
    // at once would make the sum 2, which no value of `live` is: that is
    // acceptance 7's "a row claiming two ops simultaneously is unprovable".
    {
        let mut terms: Vec<(Coeff, PolyAddress)> = (0..f::OPS.len())
            .map(|i| (d::lit(1), selector(i)))
            .collect();
        terms.push((d::neg(1), d::LIVE));
        enforcing.push(("one_op_a_live_row".to_string(), d::linear(terms)));
    }

    // The three frame values: each word below `2^32`, each value below `p`.
    for (v, (name, first, field)) in [
        ("a", f::A_WORD, d::WORD_READ_VALUE),
        ("b", f::B_WORD, d::WORD_READ_VALUE),
        ("out", f::OUT_WORD, d::WORD_WRITE_VALUE),
    ]
    .into_iter()
    .enumerate()
    {
        enforcing.extend(d::canonical_gates(
            name,
            first,
            field,
            value_bits(v),
            value_canon(v),
        ));
    }

    let a_terms = d::value_terms(f::A_WORD, d::WORD_READ_VALUE);
    let b_terms = d::value_terms(f::B_WORD, d::WORD_READ_VALUE);
    let out_terms = d::value_terms(f::OUT_WORD, d::WORD_WRITE_VALUE);

    // `prod = a·b`, ungated and degree 2 in the frame's own columns. A padding
    // row's operands are 0, so it holds there with `prod = 0`.
    {
        let mut products = Vec::with_capacity(1 + a_terms.len() * b_terms.len());
        for (ca, xa) in &a_terms {
            for (cb, xb) in &b_terms {
                let (Coeff::Literal(ca), Coeff::Literal(cb)) = (ca, cb) else {
                    panic!("fr_arith: a word weight is a literal");
                };
                products.push((Coeff::Literal(-(*ca * *cb)), *xa, *xb));
            }
        }
        enforcing.push((
            "prod_rule".to_string(),
            d::quadratic(vec![(d::lit(1), prod())], products),
        ));
    }

    // The is-zero gadget on `a`, enabled by the inverse selector
    // (`crates/constraints/src/gadgets.rs` is the same two gates over a linear
    // form), and the third gate the gadget does not owe but this family does.
    {
        let mut products: Vec<(Coeff, PolyAddress, PolyAddress)> =
            a_terms.iter().map(|(c, x)| (*c, *x, inv())).collect();
        enforcing.push((
            "inv_is_an_inverse".to_string(),
            d::quadratic(
                vec![(d::lit(1), is_zero()), (d::neg(1), selector(2))],
                products.split_off(0),
            ),
        ));
    }
    enforcing.push((
        "is_zero_at_nonzero".to_string(),
        d::quadratic(
            vec![],
            a_terms.iter().map(|(c, x)| (*c, *x, is_zero())).collect(),
        ),
    ));
    // `z·inv = 0`. Without it `inv` is free at `a = 0` and "inv(0) = 0" would
    // be asserted by the prose and enforced by nothing.
    enforcing.push((
        "inverse_of_zero_is_zero".to_string(),
        d::quadratic(vec![], vec![(d::lit(1), is_zero(), inv())]),
    ));

    // `out = f_add·(a + b) + R^-1·f_mul·prod + R^2·f_inv·inv`, the one gate
    // that selects the operation. Every term is a selector times a degree-1
    // form, so the whole gate is degree 2.
    {
        let rho = rho();
        let rho_inv = rho.inverse().expect("the Montgomery radix is invertible");
        let rho_sq = rho.square();
        let mut products: Vec<(Coeff, PolyAddress, PolyAddress)> = Vec::new();
        for (c, x) in a_terms.iter().chain(b_terms.iter()) {
            let Coeff::Literal(c) = c else {
                panic!("fr_arith: a word weight is a literal");
            };
            products.push((Coeff::Literal(-*c), selector(0), *x));
        }
        products.push((Coeff::Literal(-rho_inv), selector(1), prod()));
        products.push((Coeff::Literal(-rho_sq), selector(2), inv()));
        enforcing.push(("out_rule".to_string(), d::quadratic(out_terms, products)));
    }

    let artifact = crate::memory::assemble(
        trace_vars,
        [d::memory_names(WORDS), witness_names(), Vec::new()],
        Vec::new(),
        d::leaves(address_space::DELEGATION_FR_ARITH, WORDS),
        enforcing,
        Vec::new(),
        &[],
    );
    check_shape(&artifact);
    artifact
}

/// The `W` column names, in layout order.
fn witness_names() -> Vec<String> {
    let mut out = d::witness_names(WORDS);
    for name in ["a", "b", "out"] {
        for k in 0..d::WORDS_PER_VALUE {
            for t in 0..32 {
                out.push(format!("{name}_bit{k}_{t}"));
            }
        }
        for k in 0..d::WORDS_PER_VALUE {
            for t in 0..32 {
                out.push(format!("{name}_diff{k}_{t}"));
            }
        }
        for k in 0..d::WORDS_PER_VALUE {
            out.push(format!("{name}_borrow{k}"));
        }
    }
    for op in f::OPS {
        out.push(format!("selector{op}"));
    }
    out.push("prod".to_string());
    out.push("inv".to_string());
    out.push("is_zero".to_string());
    out
}

/// The family carries **no lookup channel**: at a delegation height no range
/// channel's table fits, and every bound it makes is a bit decomposition with
/// a booleanity gate (`docs/spec/delegation.md` §9).
pub fn channels() -> Vec<ChannelSpec> {
    Vec::new()
}

/// What the emitted artifact must be, counted on the artifact rather than on
/// the vectors handed in (S21 must-be-exact 4): a gate built and then dropped
/// on the way reaches no circuit and no test that reads the source would see
/// it.
fn check_shape(a: &CircuitArtifact) {
    assert_eq!(a.memory.len(), MEMORY_COLUMNS, "fr_arith: M columns");
    assert_eq!(a.witness.len(), WITNESS_COLUMNS, "fr_arith: W columns");
    assert!(a.setup.is_empty(), "fr_arith: no setup column");
    assert!(a.lookups.is_empty(), "fr_arith: no lookup obligation");
    assert!(a.virtuals.is_empty(), "fr_arith: no virtual table");
    for name in [
        "base_aligned",
        "base_in_window",
        "prod_rule",
        "out_rule",
        "opcode_rule",
        "one_op_a_live_row",
        "inv_is_an_inverse",
        "is_zero_at_nonzero",
        "inverse_of_zero_is_zero",
    ] {
        assert!(
            a.relations.iter().any(|r| r.name == name),
            "fr_arith: the emitted artifact has no relation `{name}`"
        );
    }
    for (prefix, want) in [
        ("addr_w", WORDS),
        ("gap_w", WORDS),
        ("writes_back_w", f::OUT_WORD),
        ("a_canonical", d::WORDS_PER_VALUE),
        ("b_canonical", d::WORDS_PER_VALUE),
        ("out_canonical", d::WORDS_PER_VALUE),
        ("a_word", d::WORDS_PER_VALUE),
        ("b_word", d::WORDS_PER_VALUE),
        ("out_word", d::WORDS_PER_VALUE),
    ] {
        let got = a
            .relations
            .iter()
            .filter(|r| r.name.starts_with(prefix) && !r.name.ends_with("_boolean"))
            .count();
        assert_eq!(
            got, want,
            "fr_arith: {got} `{prefix}*` relations, not {want}"
        );
    }
    assert!(
        !a.relations.iter().any(|r| r.name.contains("assume")),
        "fr_arith: no relation may be an unchecked hypothesis"
    );
}
