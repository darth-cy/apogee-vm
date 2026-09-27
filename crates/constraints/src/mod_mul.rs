//! The `MOD_MUL` family's circuit: one Ethereum field multiplication a row,
//! invoked by the `ecall::PRECOMPILE_MOD_MUL` ecall and never decoded.
//!
//! `docs/spec/delegation.md` §14 is normative. One invocation is one row and
//! one row is one operation — `ops/row = 1`, as every delegation family has it
//! — so the family needs no batch, no populated count and no no-op selector: a
//! row is live or it is padding.
//!
//! ```text
//! frame     M[0..104]: cycle live base anchor_value, then 4 per word
//! word 0                      the modulus selector, one of `mod_mul::CODES`
//! words 1..9, 9..17           the operands a and b, both below the modulus
//! words 17..25                the result, the only words the invocation computes
//! W[0..1010]      the frame's own: 38 gap bits a word, then the base's bounds
//! W[1010..1014]   the four modulus selectors, one-hot on a live row
//! W[1014..1022]   the eight limbs of the selected modulus
//! W[1022..2582]   per value, 256 word bits then 264 `< m` chain bits: a, b, out
//! W[2582..2590]   q's eight limbs, the quotient the prover supplies
//! W[2590..2846]   q's 256 word bits
//! W[2846..3364]   14 signed carries of 37 bits
//! ```
//!
//! # Why the modulus is a selector
//!
//! `FR_ARITH` (§13) multiplies modulo **the circuit's own field**, so its
//! multiply is one degree-2 gate: `prod = a·b` over `Fr` *is* the reduction. A
//! 256-bit modulus cannot work that way — a 256-bit value does not fit an `Fr`
//! at all, `p` being 254 bits — so this circuit carries the values as eight
//! 32-bit limbs and proves the schoolbook identity
//!
//! ```text
//! a·b = q·m + out,   a < m,   b < m,   out < m,   every limb below 2^32
//! ```
//!
//! over the integers, limb by limb, with a signed carry chain. Every term of a
//! limb equation is far below `p` — the largest is `8·(2^32−1)^2 < 2^67` — so
//! the `Fr` equation **is** the integer equation, which is the same argument
//! §13.3's borrow chain rests on.
//!
//! `m` is not a frame operand. Frame word 0 names one of **four** moduli —
//! secp256k1's `p` and `n`, BN254's `q` and `r`, which between them are every
//! 256-bit field Ethereum block execution multiplies in — and eight witness
//! limbs are pinned to that selector's literals by a degree-1 gate each. S26
//! carried the modulus as a witnessed operand and S26b removed it: no caller
//! ever passed one outside this table, and carrying it cost eight frame words,
//! 256 witness bits, and the ability to say `a < m` at all.
//!
//! # Soundness, in one paragraph
//!
//! The four selectors are boolean and sum to `live`, so a live row claims
//! exactly one modulus; `selector_rule` ties that claim to the frame word the
//! guest wrote, so the field the circuit reduces in is the field the guest
//! asked for and a code outside the table has no witness. `m_limb{k}_rule`
//! then fixes every limb of `m` to that modulus' literal — which is also its
//! `2^32` bound, so `m` needs no bits. Every limb of `a`, `b`, `out` and `q`
//! is decomposed into 32 boolean bits, so each is a non-negative integer below
//! `2^32` and each value below `2^256`. The fifteen limb equations telescope
//! to `a·b − q·m − out = 0` over ℤ exactly when the last carry is zero, which
//! the last equation forces by having no outgoing carry. Three borrow chains
//! put `a`, `b` and `out` below `m`. Integer division being unique, `out` is
//! `a·b mod m` and nothing else.
//!
//! **The operand bounds are what make the statement total.** With `a, b < m`
//! the honest quotient is `q = (a·b − out)/m < m ≤ 2^256`, so it always fits
//! the eight limbs its bits bound it to: every frame this circuit accepts has
//! a witness, and every witness it has is accepted. S26, which bounded neither
//! operand, had one half of that — an unreduced operand was a quotient the
//! prover could not fit, a cost to the prover and never a hole for the
//! verifier — and this is the other half.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::address_space;
use constants::mod_mul as f;

use crate::delegation as d;
use crate::{CircuitArtifact, Coeff, GateDef, PolyAddress};

/// The frame's words: the selector, then two operands and a result.
const WORDS: usize = f::FRAME_WORDS;

/// `M` columns: the frame's four head columns and four per word.
pub const MEMORY_COLUMNS: usize = d::HEAD_COLUMNS + 4 * WORDS;

/// The value index of operand `a` — [`value_bit`]'s and [`diff_bit`]'s first
/// argument. Named rather than spelled, because the fill, the checker and the
/// tamper twins all index the same list and a bare `0` there is a renumbering
/// waiting to happen.
pub const A: usize = 0;
/// The value index of operand `b`.
pub const B: usize = 1;
/// The value index of the result.
pub const OUT: usize = 2;

/// The three frame values, in frame order, with the field each is read from.
/// `out` is the only one the invocation writes.
const VALUES: [(&str, usize, u32); 3] = [
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

/// The `W` index of the four modulus selectors.
fn selectors() -> usize {
    d::frame_witness(WORDS)
}

/// The `W` index of the selected modulus' eight limbs.
fn moduli_limbs() -> usize {
    selectors() + f::CODES.len()
}

/// The `W` index of value `v`'s block: 256 word bits then 264 chain bits.
fn value_block(v: usize) -> usize {
    moduli_limbs() + f::LIMBS + v * (d::VALUE_BITS + d::CANONICITY_BITS)
}

/// The `W` index of value `v`'s 256 word bits.
fn value_bits(v: usize) -> usize {
    value_block(v)
}

/// The `W` index of value `v`'s 264 `< m` chain bits.
fn value_chain(v: usize) -> usize {
    value_block(v) + d::VALUE_BITS
}

/// The `W` index of `q`'s eight limb columns.
fn q_limbs() -> usize {
    value_block(VALUES.len())
}

/// The `W` index of `q`'s 256 word bits.
fn q_bits() -> usize {
    q_limbs() + f::LIMBS
}

/// The `W` index of the fourteen signed carries' bits.
fn carries() -> usize {
    q_bits() + d::VALUE_BITS
}

/// `W[…]`: modulus selector `i`, indexing [`constants::mod_mul::CODES`].
/// Boolean, and the four sum to `live`.
pub fn selector(i: usize) -> PolyAddress {
    w(selectors() + i)
}

/// `W[…]`: limb `k` of the selected modulus, pinned to the selector's literal.
pub fn m_limb(k: usize) -> PolyAddress {
    w(moduli_limbs() + k)
}

/// `W[…]`: limb `i` of the quotient the prover supplies.
pub fn q_limb(i: usize) -> PolyAddress {
    w(q_limbs() + i)
}

/// `W[…]`: bit `t` of limb `k` of value `v` — [`A`], [`B`] or [`OUT`].
pub fn value_bit(v: usize, k: usize, t: usize) -> PolyAddress {
    w(value_bits(v) + 32 * k + t)
}

/// `W[…]`: bit `t` of limb `k` of `q`.
pub fn q_bit(k: usize, t: usize) -> PolyAddress {
    w(q_bits() + 32 * k + t)
}

/// `W[…]`: bit `t` of difference limb `i` of value `v`'s `< m` chain.
pub fn diff_bit(v: usize, i: usize, t: usize) -> PolyAddress {
    w(value_chain(v) + 32 * i + t)
}

/// `W[…]`: borrow `i` of value `v`'s `< m` chain. Borrow 7 is `live`.
pub fn borrow_bit(v: usize, i: usize) -> PolyAddress {
    w(value_chain(v) + 32 * f::LIMBS + i)
}

/// `W[…]`: bit `t` of carry `k`. The carry is `Σ 2^t·bit − 2^36·live`.
pub fn carry_bit(k: usize, t: usize) -> PolyAddress {
    w(carries() + f::CARRY_BITS * k + t)
}

/// The family's `W` columns: the frame's, the selector and its modulus, three
/// values' bits and chains, `q`'s limbs and bits, and the carries.
pub const WITNESS_COLUMNS: usize = d::GAP_BITS * WORDS
    + d::BASE_LOW_BITS
    + d::BASE_ROOM_BITS
    + f::CODES.len()
    + f::LIMBS
    + 3 * (d::VALUE_BITS + d::CANONICITY_BITS)
    + f::LIMBS
    + d::VALUE_BITS
    + f::CARRY_BITS * f::CARRIES;

/// The family's circuit over `2^trace_vars` rows.
///
/// Validated, held to `crate::memory::check_memory` and to [`check_shape`];
/// panics if any of the three refuses it, so an artifact this returns is a
/// circuit that obeys every rule the engine assumes.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let mut enforcing = d::frame_gates(WORDS, f::FRAME_BYTES as u64);

    // Every word but the result's eight is read-only: the invocation writes
    // back what it read, so the guest's selector and operands survive the
    // call. The selector word is inside that set and must stay there — an
    // invocation that could rewrite it would report a field it was not asked
    // for.
    for j in 0..f::OUT_WORD {
        enforcing.push((
            format!("writes_back_w{j}"),
            d::linear(vec![
                (d::lit(1), word(j, d::WORD_WRITE_VALUE)),
                (d::neg(1), word(j, d::WORD_READ_VALUE)),
            ]),
        ));
    }

    enforcing.extend(selector_gates());

    // Each of the three frame values: 32-bit limbs, and below the modulus.
    for (v, (name, first, field)) in VALUES.into_iter().enumerate() {
        enforcing.extend(d::word_gates(name, first, field, value_bits(v)));
        enforcing.extend(below_modulus_gates(name, first, field, v));
    }

    // `q`'s limbs are witnesses rather than frame words — the guest does not
    // compute the quotient — so each needs its own bits and its own decode.
    // It needs no `q < m` chain: `a, b < m` already bounds it below `m`, and
    // what the identity needs of it is the 32-bit limb bound these give.
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

/// The modulus selector: four booleans, one-hot on a live row, naming the
/// field this row multiplies in.
///
/// ```text
/// selector{c}_boolean        s_i² = s_i
/// selector_rule              word 0 = Σ code_i·s_i
/// one_modulus_a_live_row     Σ s_i = live
/// m_limb{k}_rule             m_k = Σ MODULI[i][k]·s_i
/// ```
///
/// **`one_modulus_a_live_row` is load-bearing twice, and the second time is
/// not about the selector at all.** The first is §13.3's lesson from
/// `fr_arith`'s three opcodes: `1 + 3 = 4`, so a row claiming secp256k1's `p`
/// *and* BN254's `q` spells the same selector word as one claiming BN254's
/// `r`, and only `Σ s_i = live` refuses it. The `const` assertion below says
/// that forgery is constructible, so nobody deletes the gate believing the
/// codes are separated.
///
/// The second is the **carry bound**. `m` has no bit decomposition; its limbs
/// are bounded only by being one table entry each, and that holds only while
/// at most one selector is set. Two selectors at once would give
/// `m_0 = 0xffff_fc2f + 0xd036_4141 > 2^32`, `S_k = Σ q_i·m_j` would reach
/// `2^68`, and the module header's "every term is far below `p`, so the `Fr`
/// equation **is** the integer equation" would stop being true — the identity
/// would no longer be about integers at all. **So this gate is not
/// redundant at any code spacing**: separating the codes to 1, 2, 4, 8 would
/// make the selector word distinguish the combinations and would still leave
/// `Σ s_i = live` as the only thing bounding `m`.
///
/// **`m` needs no bits.** Each limb is pinned to one literal of a four-entry
/// table, all of whose entries are below `2^32`, so the pinning gate is its
/// bound as well as its value — and it is degree 1, a literal times a
/// committed column, which is what keeps `Σ q_i·m_j` at degree 2.
///
/// A padding row satisfies all four: `live` is 0, so every selector is 0 by
/// the sum gate, so every `m_k` is 0 and the frame word is 0 on both sides of
/// `selector_rule`.
fn selector_gates() -> Vec<(String, GateDef)> {
    // Two codes summing to a third is what makes `one_modulus_a_live_row`
    // necessary rather than decorative. If a later table were separated —
    // 1, 2, 4, 8 — this assertion would fire and the comment above would need
    // rewriting, which is the point of asserting it.
    const _: () = assert!(f::SECP256K1_P + f::BN254_P == f::BN254_R);

    let mut out: Vec<(String, GateDef)> = Vec::new();
    for (i, code) in f::CODES.iter().enumerate() {
        out.push((
            format!("selector{code}_boolean"),
            d::booleanity(selector(i)),
        ));
    }
    {
        let mut terms = vec![(d::lit(1), word(f::SELECTOR_WORD, d::WORD_READ_VALUE))];
        for (i, code) in f::CODES.iter().enumerate() {
            terms.push((d::neg(*code as u64), selector(i)));
        }
        out.push(("selector_rule".to_string(), d::linear(terms)));
    }
    {
        let mut terms: Vec<(Coeff, PolyAddress)> = (0..f::CODES.len())
            .map(|i| (d::lit(1), selector(i)))
            .collect();
        terms.push((d::neg(1), LIVE));
        out.push(("one_modulus_a_live_row".to_string(), d::linear(terms)));
    }
    for k in 0..f::LIMBS {
        let mut terms = vec![(d::lit(1), m_limb(k))];
        for (i, modulus) in f::MODULI.iter().enumerate() {
            terms.push((d::neg(modulus[k] as u64), selector(i)));
        }
        out.push((format!("m_limb{k}_rule"), d::linear(terms)));
    }
    out
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
/// literal, so every gate is degree 2. `m`'s limbs are witness columns pinned
/// to the selector rather than frame words, which changes which column each
/// `S_k` product reads and nothing else about the shape.
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
            products.push((d::neg(1), q_limb(i), m_limb(j)));
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

/// `x < m`, as a borrow chain over eight 32-bit limbs, for one of the three
/// frame values.
///
/// ```text
/// x_i − m_i − b_{i−1} + 2^32·b_i = d_i,   d_i < 2^32,   b_i boolean
/// ```
///
/// telescopes to `x − m + 2^256·b_7 = D` with `D` below `2^256`, and
/// `b_7 = live` says the subtraction borrowed out, so `x < m` on a live row.
/// It is §13.3's canonicity chain with `m`'s **columns** where that one has
/// `p`'s literals, which is the one place the selector costs anything: a
/// literal times `live` becomes a column, so the gate is **ungated** instead
/// of `live`-gated. That is free rather than expensive — `m_i` is 0 on a
/// padding row, by the selector's sum gate, and so is every other term.
///
/// **Which of the three is soundness and which is totality.** `out < m` is the
/// reduction: without it a prover answers `r + m` with the quotient one lower,
/// and the identity holds over the integers just as well. `a < m` and `b < m`
/// are not soundness — S26 was sound without them — they are what bounds the
/// honest quotient below `2^256`, so that every frame the circuit accepts is
/// one an honest prover can fill. They are also what makes the frame's meaning
/// exactly "two canonical elements of the selected field".
fn below_modulus_gates(
    name: &str,
    first: usize,
    field: u32,
    v: usize,
) -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for i in 0..f::LIMBS {
        for t in 0..32 {
            out.push((
                format!("{name}_diff{i}_{t}_boolean"),
                d::booleanity(diff_bit(v, i, t)),
            ));
        }
    }
    for i in 0..f::LIMBS {
        out.push((
            format!("{name}_borrow{i}_boolean"),
            d::booleanity(borrow_bit(v, i)),
        ));
    }
    for i in 0..f::LIMBS {
        let mut terms = vec![
            (d::lit(1), word(first + i, field)),
            (d::neg(1), m_limb(i)),
            (d::lit(1u64 << 32), borrow_bit(v, i)),
        ];
        if let Some(prev) = i.checked_sub(1) {
            terms.push((d::neg(1), borrow_bit(v, prev)));
        }
        for t in 0..32 {
            terms.push((d::neg(1u64 << t), diff_bit(v, i, t)));
        }
        out.push((format!("{name}_canonical{i}"), d::linear(terms)));
    }
    out.push((
        format!("{name}_below_modulus"),
        d::linear(vec![
            (d::lit(1), LIVE),
            (d::neg(1), borrow_bit(v, f::LIMBS - 1)),
        ]),
    ));
    out
}

/// The family's lookup channels: **none**.
///
/// A delegation family carries no channel and that is load-bearing: its rows
/// are invocations rather than halfwords, so every bound it makes is a bit
/// decomposition with a booleanity gate (`docs/spec/delegation.md` §9). That
/// is also why its registry arm sits below `family_circuit`'s minimum-height
/// guard — a family with no channel reaches no `BITS <= trace_vars` assertion.
pub fn channels() -> Vec<crate::lookup::ChannelSpec> {
    Vec::new()
}

/// The `W` column names, in layout order.
fn witness_names() -> Vec<String> {
    let mut out = d::witness_names(WORDS);
    for code in f::CODES {
        out.push(format!("selector{code}"));
    }
    for k in 0..f::LIMBS {
        out.push(format!("m_limb{k}"));
    }
    for (name, ..) in VALUES {
        for k in 0..f::LIMBS {
            for t in 0..32 {
                out.push(format!("{name}_bit{k}_{t}"));
            }
        }
        for i in 0..f::LIMBS {
            for t in 0..32 {
                out.push(format!("{name}_diff{i}_{t}"));
            }
        }
        for i in 0..f::LIMBS {
            out.push(format!("{name}_borrow{i}"));
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
/// layout change that moved one silently would be a fill writing into the
/// wrong column. `docs/spec/constraint-manifest.md` §18 is the same account by
/// name.
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
    // The three value indices name the three values, in frame order. Every
    // caller outside this module indexes by these constants, so a reordering
    // of `VALUES` that left them behind would silently route `a`'s bits into
    // `b`'s columns.
    assert_eq!(
        [VALUES[A].1, VALUES[B].1, VALUES[OUT].1],
        [f::A_WORD, f::B_WORD, f::OUT_WORD],
        "mod_mul: A, B and OUT index their own values"
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

    /// The selector's four gates and the three values' chains are all present
    /// by name. The mutation this catches is a dropped `one_modulus_a_live_row`
    /// or a dropped operand chain — each of which leaves a circuit that still
    /// validates, still has the right column count, and proves something
    /// weaker than the module's soundness paragraph claims.
    #[test]
    fn the_selector_and_the_three_chains_are_all_enforced() {
        let a = artifact(8);
        let names: Vec<&str> = a.relations.iter().map(|r| r.name.as_str()).collect();
        for code in f::CODES {
            assert!(names.contains(&&*format!("selector{code}_boolean")));
        }
        assert!(names.contains(&"selector_rule"));
        assert!(names.contains(&"one_modulus_a_live_row"));
        for k in 0..f::LIMBS {
            assert!(names.contains(&&*format!("m_limb{k}_rule")), "m_limb{k}_rule");
        }
        for value in ["a", "b", "out"] {
            assert!(
                names.contains(&&*format!("{value}_below_modulus")),
                "{value}_below_modulus"
            );
            for i in 0..f::LIMBS {
                assert!(names.contains(&&*format!("{value}_canonical{i}")));
            }
        }
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

    /// Every column the layout names is inside the witness, and the regions do
    /// not overlap: a fill that wrote `q`'s bits over a chain's would produce a
    /// circuit that still validates.
    #[test]
    fn the_witness_regions_do_not_overlap() {
        let mut seen = alloc::vec![0usize; WITNESS_COLUMNS];
        let mut mark = |a: PolyAddress| {
            let PolyAddress::Witness(i) = a else {
                panic!("not a witness column: {a}");
            };
            seen[i as usize] += 1;
        };
        for i in 0..f::CODES.len() {
            mark(selector(i));
        }
        for k in 0..f::LIMBS {
            mark(m_limb(k));
        }
        for v in 0..VALUES.len() {
            for k in 0..f::LIMBS {
                for t in 0..32 {
                    mark(value_bit(v, k, t));
                    mark(diff_bit(v, k, t));
                }
            }
            for i in 0..f::LIMBS {
                mark(borrow_bit(v, i));
            }
        }
        for k in 0..f::LIMBS {
            mark(q_limb(k));
            for t in 0..32 {
                mark(q_bit(k, t));
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

    /// Every modulus the selector can name is a 256-bit odd value above
    /// `2^253`, which is what the module's soundness paragraph assumes when it
    /// says the honest quotient fits eight limbs: `q < m ≤ 2^256`. A fifth
    /// entry that broke either half would break the identity's bound and not
    /// this circuit's shape, so the assertion belongs here.
    #[test]
    fn every_modulus_is_a_256_bit_odd_value() {
        assert_eq!(f::MODULI.len(), f::CODES.len());
        for (i, m) in f::MODULI.iter().enumerate() {
            assert_eq!(m[0] & 1, 1, "modulus {i} is even");
            assert!(m[7] >= 1 << 29, "modulus {i} is below 2^253");
        }
        // Distinct, or two codes would name one field and the selector would
        // be carrying a distinction that is not one.
        for i in 0..f::MODULI.len() {
            for j in i + 1..f::MODULI.len() {
                assert_ne!(f::MODULI[i], f::MODULI[j], "moduli {i} and {j}");
            }
        }
    }
}
