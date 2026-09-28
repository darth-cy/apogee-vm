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
//! W[0..50]        two RANGE16 gap chunks a word
//! W[50..54]       base_low and its halfword, base_room and its halfword
//! W[54..58]       the four modulus selectors, one-hot on a live row
//! W[58..66]       the eight limbs of the selected modulus
//! W[66..162]      per value, eight halfwords then a 24-column `< m` chain
//! W[162..178]     q's eight limbs and their halfwords
//! W[178..220]     14 signed carries, each a value and two chunks
//! W[220]          the RANGE16 channel's multiplicity
//! ```
//!
//! # Why this family carries a lookup channel
//!
//! It did not until S26c. `docs/spec/delegation.md` §9 forbade a delegation
//! family any channel; §10.3 amends that, and this family is the measured
//! reason. Every bound it makes was a bit decomposition — 950 gap bits, 768
//! value bits, 768 chain bits, 256 quotient bits, 518 carry bits — and at
//! `2^16`, where its table fits, `RANGE16` makes each of them one committed
//! column and two obligations instead. **3,468 committed columns become 325**:
//! 9.9x the prover work, 3.4x the proof bytes and 1.9x the peak memory, for one
//! channel on one existing family.
//!
//! `TIMESTAMP` would be the natural channel for the frame's gap and it does not
//! fit — its table needs 19 variables — so the gap takes `RANGE16` in two
//! chunks with a scaled obligation on the top one, exact at `2^38`
//! (`delegation::bound_chunked`).
//!
//! Nothing else about the family moved: the frame is the same 25 words, the
//! ecall number is the same `0x0504`, the four moduli are the same, and every
//! gate states the same thing. What changed is how a bound is spelled.
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
use crate::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};

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

/// `W[…]`: chunk `c` of frame word `j`'s timestamp gap, weight `2^{16(c+1)}`.
pub fn gap_chunk(j: usize, c: usize) -> PolyAddress {
    w(GAP_CHUNKS_AT + d::GAP_CHUNKS * j + c)
}

/// `W[…]`: `(base − RAM_ORIGIN) / 4`.
pub fn base_low() -> PolyAddress {
    w(BASE_AT)
}
/// `W[…]`: [`base_low`]'s high halfword.
pub fn base_low_hi() -> PolyAddress {
    w(BASE_AT + 1)
}
/// `W[…]`: `2^31 − frame bytes − base`.
pub fn base_room() -> PolyAddress {
    w(BASE_AT + 2)
}
/// `W[…]`: [`base_room`]'s high halfword.
pub fn base_room_hi() -> PolyAddress {
    w(BASE_AT + 3)
}

/// The `W` index of the gap chunks, which open the witness.
const GAP_CHUNKS_AT: usize = 0;
/// The `W` index of the frame pointer's two decompositions.
const BASE_AT: usize = GAP_CHUNKS_AT + d::GAP_CHUNKS * WORDS;

/// The `W` index of the four modulus selectors.
fn selectors() -> usize {
    BASE_AT + 4
}

/// The `W` index of the selected modulus' eight limbs.
fn moduli_limbs() -> usize {
    selectors() + f::CODES.len()
}

/// Columns one value takes: eight halfwords bounding its limbs, then the
/// `< m` chain's eight differences, their halfwords and eight borrows.
const VALUE_COLUMNS: usize = 4 * f::LIMBS;

/// The `W` index of value `v`'s block.
fn value_block(v: usize) -> usize {
    moduli_limbs() + f::LIMBS + v * VALUE_COLUMNS
}

/// The `W` index of `q`'s eight limbs.
fn q_limbs() -> usize {
    value_block(VALUES.len())
}

/// The `W` index of the fourteen carries.
fn carries() -> usize {
    q_limbs() + 2 * f::LIMBS
}

/// Columns one signed carry takes: its unsigned value and two chunks.
const CARRY_COLUMNS: usize = 1 + d::GAP_CHUNKS;

/// The `W` index of the channel's multiplicity, last in the subtree.
fn multiplicity() -> usize {
    carries() + CARRY_COLUMNS * f::CARRIES
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

/// `W[…]`: the high halfword of limb `k` of value `v` — [`A`], [`B`] or
/// [`OUT`]. With the derived low half it is that limb's `2^32` bound.
pub fn value_hi(v: usize, k: usize) -> PolyAddress {
    w(value_block(v) + k)
}

/// `W[…]`: difference limb `i` of value `v`'s `< m` chain.
pub fn diff(v: usize, i: usize) -> PolyAddress {
    w(value_block(v) + f::LIMBS + i)
}

/// `W[…]`: [`diff`]'s high halfword.
pub fn diff_hi(v: usize, i: usize) -> PolyAddress {
    w(value_block(v) + 2 * f::LIMBS + i)
}

/// `W[…]`: borrow `i` of value `v`'s `< m` chain. Borrow 7 is `live`.
pub fn borrow_bit(v: usize, i: usize) -> PolyAddress {
    w(value_block(v) + 3 * f::LIMBS + i)
}

/// `W[…]`: limb `i` of the quotient the prover supplies.
pub fn q_limb(i: usize) -> PolyAddress {
    w(q_limbs() + i)
}

/// `W[…]`: [`q_limb`]'s high halfword.
pub fn q_hi(i: usize) -> PolyAddress {
    w(q_limbs() + f::LIMBS + i)
}

/// `W[…]`: carry `k`, as the **unsigned** value `carry + 2^36`.
pub fn carry(k: usize) -> PolyAddress {
    w(carries() + CARRY_COLUMNS * k)
}

/// `W[…]`: chunk `j` of carry `k`'s range decomposition, weight
/// `2^{16(j+1)}`.
pub fn carry_chunk(k: usize, j: usize) -> PolyAddress {
    w(carries() + CARRY_COLUMNS * k + 1 + j)
}

/// `W[…]`: the `RANGE16` channel's multiplicity.
pub fn multiplicity_column() -> PolyAddress {
    w(multiplicity())
}

/// The family's `W` columns.
pub const WITNESS_COLUMNS: usize = d::GAP_CHUNKS * WORDS
    + 4
    + f::CODES.len()
    + f::LIMBS
    + 3 * VALUE_COLUMNS
    + 2 * f::LIMBS
    + CARRY_COLUMNS * f::CARRIES
    + 1;

/// The family's circuit over `2^trace_vars` rows.
///
/// Validated, held to `crate::memory::check_memory` and to [`check_shape`];
/// panics if any of the three refuses it, so an artifact this returns is a
/// circuit that obeys every rule the engine assumes.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let mut enforcing =
        d::frame_gates_range16(WORDS, f::FRAME_BYTES as u64, base_low(), base_room());

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

    // Each of the three frame values is below the modulus. Their **limbs** are
    // frame `M` columns, so there is nothing to decode: the 32-bit bound is two
    // `RANGE16` obligations and no gate at all, which is where 768 of the
    // family's old witness columns went.
    for (v, (name, first, field)) in VALUES.into_iter().enumerate() {
        enforcing.extend(below_modulus_gates(name, first, field, v));
    }

    // `q`'s limbs are witnesses rather than frame words — the guest does not
    // compute the quotient — but they need no decode either, only the same
    // 32-bit bound. It needs no `q < m` chain: `a, b < m` already bounds it
    // below `m`.

    enforcing.extend(product_gates());

    let artifact = crate::memory::assemble(
        trace_vars,
        [d::memory_names(WORDS), witness_names(), Vec::new()],
        vec![(VirtualKind::Range16, "range16".to_string())],
        d::leaves(address_space::DELEGATION_MOD_MUL, WORDS),
        enforcing,
        lookups(),
        &channels(),
    );
    if let Err(e) = crate::lookup::check_copowers(&artifact, &scaled_columns()) {
        panic!("mod_mul: {e}");
    }
    check_shape(&artifact);
    artifact
}

/// Every obligation the circuit carries: the frame's gaps and base, each
/// value's eight limbs and its chain's eight differences, the quotient's eight
/// limbs, and the fourteen carries.
fn lookups() -> Vec<crate::LookupExpr> {
    let mut out = d::gap_lookups_range16(WORDS, &|j, c| gap_chunk(j, c));
    out.extend(d::bound_chunked(
        "base_low",
        vec![(d::lit(1), base_low())],
        &[base_low_hi()],
        d::BASE_LOW_BITS as u32,
        LIVE,
        d::lit(0),
    ));
    out.extend(d::bound_chunked(
        "base_room",
        vec![(d::lit(1), base_room())],
        &[base_room_hi()],
        d::BASE_ROOM_BITS as u32,
        LIVE,
        d::lit(0),
    ));
    for (v, (name, first, field)) in VALUES.into_iter().enumerate() {
        for k in 0..f::LIMBS {
            out.extend(d::bound32(
                &format!("{name}{k}"),
                word(first + k, field),
                value_hi(v, k),
                LIVE,
            ));
            out.extend(d::bound32(
                &format!("{name}_diff{k}"),
                diff(v, k),
                diff_hi(v, k),
                LIVE,
            ));
        }
    }
    for k in 0..f::LIMBS {
        out.extend(d::bound32(&format!("q{k}"), q_limb(k), q_hi(k), LIVE));
    }
    for k in 0..f::CARRIES {
        let chunks: Vec<PolyAddress> = (0..d::GAP_CHUNKS).map(|j| carry_chunk(k, j)).collect();
        out.extend(d::bound_chunked(
            &format!("carry{k}"),
            vec![(d::lit(1), carry(k))],
            &chunks,
            f::CARRY_BITS as u32,
            LIVE,
            d::lit(0),
        ));
    }
    out
}

/// Every scaled obligation's column with the selector it carries, for
/// `lookup::check_copowers`.
fn scaled_columns() -> Vec<(PolyAddress, PolyAddress)> {
    let mut out: Vec<(PolyAddress, PolyAddress)> = Vec::new();
    for j in 0..WORDS {
        out.push((gap_chunk(j, d::GAP_CHUNKS - 1), LIVE));
    }
    out.push((base_low_hi(), LIVE));
    out.push((base_room_hi(), LIVE));
    for k in 0..f::CARRIES {
        out.push((carry_chunk(k, d::GAP_CHUNKS - 1), LIVE));
    }
    out
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
    vec![
        (d::lit(1), carry(k)),
        (Coeff::Literal(-d::pow2(f::CARRY_BITS as u32 - 1)), LIVE),
    ]
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
fn below_modulus_gates(name: &str, first: usize, field: u32, v: usize) -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
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
        terms.push((d::neg(1), diff(v, i)));
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

/// The family's lookup channels: `RANGE16`.
///
/// S26c's amendment to `docs/spec/delegation.md` §9. The channel's table needs
/// sixteen variables, which makes `2^16` this family's floor — and `2^16` is
/// already its `DEFAULT_HEIGHTS` entry, chosen at S26 for an unrelated reason.
/// `family_circuit` derives the floor from this list, so the two cannot drift.
pub fn channels() -> Vec<crate::lookup::ChannelSpec> {
    vec![crate::lookup::ChannelSpec {
        channel: constants::lookup_channel::RANGE16,
        table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
        multiplicity: multiplicity_column(),
    }]
}

/// The `W` column names, in layout order.
fn witness_names() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for j in 0..WORDS {
        for c in 0..d::GAP_CHUNKS {
            out.push(format!("gap{j}_c{c}"));
        }
    }
    out.push("base_low".to_string());
    out.push("base_low_hi".to_string());
    out.push("base_room".to_string());
    out.push("base_room_hi".to_string());
    for code in f::CODES {
        out.push(format!("selector{code}"));
    }
    for k in 0..f::LIMBS {
        out.push(format!("m_limb{k}"));
    }
    for (name, ..) in VALUES {
        for k in 0..f::LIMBS {
            out.push(format!("{name}{k}_hi"));
        }
        for i in 0..f::LIMBS {
            out.push(format!("{name}_diff{i}"));
        }
        for i in 0..f::LIMBS {
            out.push(format!("{name}_diff{i}_hi"));
        }
        for i in 0..f::LIMBS {
            out.push(format!("{name}_borrow{i}"));
        }
    }
    for k in 0..f::LIMBS {
        out.push(format!("q_limb{k}"));
    }
    for k in 0..f::LIMBS {
        out.push(format!("q_limb{k}_hi"));
    }
    for k in 0..f::CARRIES {
        out.push(format!("carry{k}"));
        for j in 0..d::GAP_CHUNKS {
            out.push(format!("carry{k}_c{j}"));
        }
    }
    out.push("range16_multiplicity".to_string());
    out
}

/// The shape this family's artifact must have, checked where it is built.
///
/// The counts are what a fill writes and what `crates/checker` reads, so a
/// layout change that moved one silently would be a fill writing into the wrong
/// column. `docs/spec/constraint-manifest.md` §18 is the same account by name.
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
    // The multiplicity is last, which `lookup`'s own rule requires and which
    // also means the family's columns end exactly where the witness does.
    assert_eq!(
        multiplicity() + 1,
        WITNESS_COLUMNS,
        "mod_mul: the multiplicity closes the witness"
    );
    assert_eq!(
        artifact.lookups.len(),
        lookups().len(),
        "mod_mul: every obligation reached the artifact"
    );
    // The three value indices name the three values, in frame order. Every
    // caller outside this module indexes by these constants, so a reordering
    // of `VALUES` that left them behind would silently route `a`'s bounds into
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
        let a = artifact(16);
        assert_eq!(a.memory.len(), MEMORY_COLUMNS);
        assert_eq!(a.witness.len(), WITNESS_COLUMNS);
        assert!(
            a.setup.is_empty(),
            "a delegation family has no setup column"
        );
        assert_eq!(channels().len(), 1, "one channel, RANGE16, since S26c");
        assert_eq!(a.validate(), Ok(()));
        assert_eq!(crate::memory::check_memory(&a), Ok(()));
    }

    /// The fifteen limb gates are present by name, and the fourteen carries
    /// close the identity: position `POSITIONS - 1` has **no** outgoing carry,
    /// which is what makes the telescoped sum `a·b − q·m − out = 0` rather than
    /// a multiple of `2^480`.
    #[test]
    fn the_limb_identity_closes() {
        let a = artifact(16);
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
        let a = artifact(16);
        let names: Vec<&str> = a.relations.iter().map(|r| r.name.as_str()).collect();
        for code in f::CODES {
            assert!(names.contains(&&*format!("selector{code}_boolean")));
        }
        assert!(names.contains(&"selector_rule"));
        assert!(names.contains(&"one_modulus_a_live_row"));
        for k in 0..f::LIMBS {
            assert!(
                names.contains(&&*format!("m_limb{k}_rule")),
                "m_limb{k}_rule"
            );
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
                mark(value_hi(v, k));
                mark(diff(v, k));
                mark(diff_hi(v, k));
                mark(borrow_bit(v, k));
            }
        }
        for k in 0..f::LIMBS {
            mark(q_limb(k));
            mark(q_hi(k));
        }
        for k in 0..f::CARRIES {
            mark(carry(k));
            for j in 0..d::GAP_CHUNKS {
                mark(carry_chunk(k, j));
            }
        }
        mark(multiplicity_column());
        for j in 0..WORDS {
            for c in 0..d::GAP_CHUNKS {
                mark(gap_chunk(j, c));
            }
        }
        mark(base_low());
        mark(base_low_hi());
        mark(base_room());
        mark(base_room_hi());
        assert!(seen.iter().all(|n| *n <= 1), "two names share a column");
        let claimed: usize = seen.iter().sum();
        assert_eq!(
            claimed, WITNESS_COLUMNS,
            "every name the layout gives is a column, and they fill the witness"
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
