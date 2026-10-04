//! The `FQ_OP` family's circuit: one operation a row over elements of BN254's
//! base field — each four field cells of 64-bit limbs, lazily reduced —
//! invoked by `ecall::PRECOMPILE_FQ_OP` and never decoded.
//!
//! `docs/spec/recursion.md` §6 is normative.
//!
//! ```text
//! frame     M[0..20]   cycle live base anchor_value, then 4 per word of [op, d, a, b]
//! M[20..23]            g_addr g_read_ts digit           the digit cell, read at Δ0
//! M[23..32]            a_addr a_read_ts0..3 a0..a3      read at Δ1, a timestamp a cell
//! M[32..38]            b_addr b_read_ts b0..b3          read at Δ2
//! M[38..48]            d_addr d_read_ts d0..d3 n0..n3   read and written at Δ3
//! W[0..12]             the frame's gap chunks and base bounds
//! W[12..19]            each gap's high TIMESTAMP chunk: g, a's four, b, d
//! W[19..24]            one selector per op, `fq_op::OPS` order
//! W[24..27]            ind_d ind_a ind_b
//! W[27..31]            y0..y3: b's limbs on MUL and MULEQ, 1 on ADD and SUB
//! W[31..43]            d′'s limbs' upper three 16-bit chunks each
//! W[43..59]            the quotient K: K0..K2 four 16-bit chunks each, K3 four 19-bit
//! W[59..71]            the three carries, four 19-bit chunks each, offset by 2^75
//! W[71..73]            the TIMESTAMP and RANGE16 multiplicities
//! ```
//!
//! **One identity serves every op.** `a·y + z = q·K + d′` over the integers,
//! checked as four equations over 128-bit groups of limbs with three signed
//! carries, every term below `2^208`, so no equation wraps mod p. `y` is `b`
//! on `MUL` and `MULEQ` and 1 on `ADD` and `SUB`; `z` is `b` on `ADD`,
//! `6q − b` on `SUB` and `d′` on `FROM128`, where `y = 0` and the identity
//! says `K = 0`. `MULEQ` writes `d` back, so there it asserts `a·b ≡ d`.
//!
//! **`b` and `d` are elements, and `a` may not be.** `b`'s and `d`'s four
//! cells are only ever written together, by this family, so each shares one
//! read timestamp and one gap. `a` is `FROM128`'s pair of transcript limbs,
//! written apart, so each of its cells carries its own.
//!
//! **An indirect operand** names a bucket base: its element is
//! `word + 8·digit`, the digit the value of the cell the op word names, which
//! is what makes the MSM's per-point template a static tape
//! (`docs/spec/recursion.md` §8.3).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::{address_space, fq_op as f, lookup_channel, memory as mem};
use field::Fr;

use crate::delegation::{self as d, booleanity, linear, lit, neg, quadratic, Access, CYCLE, LIVE};
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

/// The frame's words: `[op, d, a, b]`.
const WORDS: usize = f::FRAME_WORDS;

const FRAME_M: u32 = (d::HEAD_COLUMNS + 4 * WORDS) as u32;
const FRAME_W: u32 = d::frame_witness_range16(WORDS);

const fn m(i: u32) -> PolyAddress {
    PolyAddress::Memory(FRAME_M + i)
}
const fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(FRAME_W + i)
}

/// The four accesses, in slot order: the digit cell, then `a`, `b`, `d`.
const G: usize = 0;
const A: usize = 1;
const B: usize = 2;
const D: usize = 3;

/// `M[20]`: the digit cell, the op word shifted down.
pub const G_ADDR: PolyAddress = m(0);
/// `M[21]`: when it was last written.
pub const G_READ_TS: PolyAddress = m(1);
/// `M[22]`: its value, the digit an indirect operand's address scales.
pub const DIGIT: PolyAddress = m(2);
/// Access `q`'s address column: the cell of its element's first limb.
pub const fn addr(q: usize) -> PolyAddress {
    match q {
        G => G_ADDR,
        A => m(3),
        B => m(12),
        _ => m(18),
    }
}
/// `a`'s cell `i`'s read timestamp: each its own.
pub const fn a_read_ts(i: usize) -> PolyAddress {
    m(4 + i as u32)
}
/// `b`'s or `d`'s read timestamp, shared by the element's four cells, which
/// only this family writes and only together.
pub const fn read_ts(q: usize) -> PolyAddress {
    match q {
        G => G_READ_TS,
        B => m(13),
        _ => m(19),
    }
}
/// Limb `i` of `a`, as read.
pub const fn a(i: usize) -> PolyAddress {
    m(8 + i as u32)
}
/// Limb `i` of `b`, as read.
pub const fn b(i: usize) -> PolyAddress {
    m(14 + i as u32)
}
/// Limb `i` of `d` before the row.
pub const fn d_old(i: usize) -> PolyAddress {
    m(20 + i as u32)
}
/// Limb `i` of `d′`, `d` after the row.
pub const fn d_new(i: usize) -> PolyAddress {
    m(24 + i as u32)
}
pub const MEMORY_COLUMNS: usize = FRAME_M as usize + 28;

/// The seven timestamp gaps, in `W` order: the digit cell, `a`'s four
/// cells, `b`, `d`.
pub const GAPS: usize = 7;
/// `W[12 + k]`: gap `k`'s high 19 bits.
pub const fn gap_hi(k: usize) -> PolyAddress {
    w(k as u32)
}
/// `W[19 + i]`: the selector of `fq_op::OPS[i]`, op code `i + 1`.
pub const fn selector(i: usize) -> PolyAddress {
    w(7 + i as u32)
}
/// `W[24..27]`: the indirection flags of `d`, `a` and `b`.
pub const IND_D: PolyAddress = w(12);
pub const IND_A: PolyAddress = w(13);
pub const IND_B: PolyAddress = w(14);
/// `W[27 + j]`: limb `j` of `y`.
pub const fn y(j: usize) -> PolyAddress {
    w(15 + j as u32)
}
/// `W[31 + 3i + c − 1]`: bits `16c..16c + 16` of `d′`'s limb `i`, `c` in
/// `1..4`; bits `0..16` are the limb less the three.
pub const fn d_chunk(i: usize, c: usize) -> PolyAddress {
    w(19 + 3 * i as u32 + c as u32 - 1)
}
/// `W[43 + 4j + c]`: chunk `c` of the quotient's limb `j` — 16 bits for
/// `j < 3`, 19 for `K3`, which can pass `2^64` on a product.
pub const fn k_chunk(j: usize, c: usize) -> PolyAddress {
    w(31 + 4 * j as u32 + c as u32)
}
/// `W[59 + 4g + c]`: chunk `c` of carry `g` plus `2^75`, 19 bits.
pub const fn carry_chunk(g: usize, c: usize) -> PolyAddress {
    w(47 + 4 * g as u32 + c as u32)
}
/// `W[71]`, `W[72]`: the two channels' multiplicities, last in the witness.
pub const MULT_TIMESTAMP: PolyAddress = w(59);
pub const MULT_RANGE16: PolyAddress = w(60);
pub const WITNESS_COLUMNS: usize = FRAME_W as usize + 61;

/// A carry's offset: `2^75` past any honest carry's magnitude, which stays
/// below `2^71`, so `carry + 2^75` lies in four 19-bit chunks.
pub const CARRY_OFFSET_BITS: u32 = 75;

// A selector's index is its code less one.
const _: () = {
    let mut i = 0;
    while i < f::OPS.len() {
        assert!(f::OPS[i] == i as u32 + 1);
        i += 1;
    }
    assert!(f::OPS.len() < 1 << f::CODE_BITS);
};

const fn sel(code: u32) -> PolyAddress {
    selector(code as usize - 1)
}

/// Frame word `j`'s value.
fn frame(j: usize) -> PolyAddress {
    d::word(j, d::WORD_READ_VALUE)
}

fn pow2(n: u32) -> Fr {
    d::pow2(n)
}

/// `Σ k·x + Σ k·y·z`, with each column's linear coefficients merged.
#[derive(Default)]
struct Sum {
    lin: Vec<(Fr, PolyAddress)>,
    prod: Vec<(Fr, PolyAddress, PolyAddress)>,
}

impl Sum {
    fn lin(&mut self, k: Fr, x: PolyAddress) {
        match self.lin.iter_mut().find(|(_, at)| *at == x) {
            Some(t) => t.0 += k,
            None => self.lin.push((k, x)),
        }
    }
    fn prod(&mut self, k: Fr, x: PolyAddress, y: PolyAddress) {
        self.prod.push((k, x, y));
    }
    fn gate(self) -> GateDef {
        GateDef::Quadratic {
            constant: lit(0),
            linear: self
                .lin
                .into_iter()
                .filter(|(k, _)| *k != Fr::ZERO)
                .map(|(k, x)| (Coeff::Literal(k), x))
                .collect(),
            products: self
                .prod
                .into_iter()
                .map(|(k, x, y)| (Coeff::Literal(k), x, y))
                .collect(),
        }
    }
}

/// The quotient limb `j` as its chunks: weight of chunk `c`.
fn k_weight(j: usize, c: usize) -> Fr {
    if j < 3 {
        pow2(16 * c as u32)
    } else {
        pow2(19 * c as u32)
    }
}

/// `carry g = Σ_c 2^{19c}·chunk_c − 2^75·live`, scaled by `k`, into `s`.
fn carry(s: &mut Sum, g: usize, k: Fr) {
    for c in 0..4 {
        s.lin(k * pow2(19 * c as u32), carry_chunk(g, c));
    }
    s.lin(-k * pow2(CARRY_OFFSET_BITS), LIVE);
}

/// Group equation `g`: limb positions `2g` and `2g + 1` of
/// `a·y + z − q·K − d′`, plus the carry in and less `2^128` times the carry
/// out — the last group has no carry out.
fn group(g: usize) -> GateDef {
    let mut s = Sum::default();
    for (shift, k) in [(0u32, 2 * g), (64, 2 * g + 1)] {
        let scale = pow2(shift);
        for i in 0..4 {
            if let Some(j) = k.checked_sub(i).filter(|j| *j < 4) {
                // a·y
                s.prod(scale, a(i), y(j));
                // −q·K
                for c in 0..4 {
                    s.lin(
                        -scale * Fr::from_u64(f::Q[i]) * k_weight(j, c),
                        k_chunk(j, c),
                    );
                }
            }
        }
        if k < 4 {
            // z, by op: b, 6q − b, or d′ — and −d′.
            s.prod(scale, sel(f::ADD), b(k));
            s.prod(-scale, sel(f::SUB), b(k));
            s.lin(
                scale * Fr::from_u64(f::SUB_MULTIPLE) * Fr::from_u64(f::Q[k]),
                sel(f::SUB),
            );
            s.prod(scale, sel(f::FROM128), d_new(k));
            s.lin(-scale, d_new(k));
        }
    }
    if g > 0 {
        carry(&mut s, g - 1, Fr::ONE);
    }
    if g < 3 {
        carry(&mut s, g, -pow2(128));
    }
    s.gate()
}

/// Gap `k`'s name, read timestamp and slot: the digit cell, `a`'s four
/// cells, `b`, `d`.
fn gap(k: usize) -> (String, PolyAddress, u64) {
    match k {
        0 => ("g".to_string(), G_READ_TS, f::DELTA_G),
        1..=4 => (format!("a{}", k - 1), a_read_ts(k - 1), f::DELTA_A),
        5 => ("b".to_string(), read_ts(B), f::DELTA_B),
        _ => ("d".to_string(), read_ts(D), f::DELTA_D),
    }
}

/// The thirteen cells' accesses: the digit's, then one `Access` a cell of
/// `a`, `b` and `d`, an element's cells sharing its address.
fn accesses() -> Vec<Access> {
    let access = |name: String, q: usize, offset: u64, k: usize, read, write| Access {
        name,
        space: address_space::FIELD,
        mask: LIVE,
        addr: addr(q),
        offset,
        delta: gap(k).2,
        read_ts: gap(k).1,
        read,
        write,
        // Bounded once per gap, below.
        gap: [gap_hi(k), gap_hi(k)],
    };
    let mut out = vec![access("g".to_string(), G, 0, 0, DIGIT, DIGIT)];
    for i in 0..f::ELEMENT_CELLS {
        out.push(access(format!("a{i}"), A, i as u64, 1 + i, a(i), a(i)));
    }
    for i in 0..f::ELEMENT_CELLS {
        out.push(access(format!("b{i}"), B, i as u64, 5, b(i), b(i)));
    }
    for i in 0..f::ELEMENT_CELLS {
        out.push(access(format!("d{i}"), D, i as u64, 6, d_old(i), d_new(i)));
    }
    out
}

/// A `TIMESTAMP` obligation under `live`.
fn ts19(name: String, terms: Vec<(Coeff, PolyAddress)>, constant: Coeff) -> LookupExpr {
    LookupExpr {
        name,
        channel: lookup_channel::TIMESTAMP,
        selector: LIVE,
        tuple: vec![GateDef::Linear { terms, constant }],
    }
}

/// A `RANGE16` obligation under `live`.
fn r16(name: String, terms: Vec<(Coeff, PolyAddress)>) -> LookupExpr {
    d::range16(name, LIVE, linear(terms))
}

/// Every obligation the family adds beside its frame's.
fn lookups() -> Vec<LookupExpr> {
    let mut out = Vec::new();
    let ts_chunk = Coeff::Literal(-pow2(
        lookup_channel::BITS[lookup_channel::TIMESTAMP as usize],
    ));
    for k in 0..GAPS {
        let (name, read_ts, delta) = gap(k);
        out.push(ts19(
            format!("gap_{name}_hi_range"),
            vec![(lit(1), gap_hi(k))],
            lit(0),
        ));
        out.push(ts19(
            format!("gap_{name}_lo_range"),
            vec![
                (lit(mem::TS_STEP), CYCLE),
                (neg(1), read_ts),
                (ts_chunk, gap_hi(k)),
            ],
            Coeff::Literal(Fr::from_u64(delta) - Fr::ONE),
        ));
    }
    for i in 0..f::ELEMENT_CELLS {
        let mut low = vec![(lit(1), d_new(i))];
        for c in 1..4 {
            out.push(r16(
                format!("n{i}_c{c}_range"),
                vec![(lit(1), d_chunk(i, c))],
            ));
            low.push((Coeff::Literal(-pow2(16 * c as u32)), d_chunk(i, c)));
        }
        out.push(r16(format!("n{i}_c0_range"), low));
    }
    for j in 0..4 {
        for c in 0..4 {
            let name = format!("k{j}_c{c}_range");
            out.push(match j {
                3 => ts19(name, vec![(lit(1), k_chunk(j, c))], lit(0)),
                _ => r16(name, vec![(lit(1), k_chunk(j, c))]),
            });
        }
    }
    for g in 0..3 {
        for c in 0..4 {
            out.push(ts19(
                format!("carry{g}_c{c}_range"),
                vec![(lit(1), carry_chunk(g, c))],
                lit(0),
            ));
        }
    }
    out
}

/// Everything the family adds beside its frame.
fn gates() -> Vec<(String, GateDef)> {
    let op = frame(f::OP_WORD);
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for code in f::OPS {
        out.push((format!("op{code}_boolean"), booleanity(sel(code))));
    }
    for (name, flag) in [("ind_d", IND_D), ("ind_a", IND_A), ("ind_b", IND_B)] {
        out.push((format!("{name}_boolean"), booleanity(flag)));
    }
    // One op a live row, and the word the guest wrote: the code, the flags
    // and the digit cell.
    let mut one = vec![(neg(1), LIVE)];
    let mut word = vec![(neg(1), op)];
    for code in f::OPS {
        one.push((lit(1), sel(code)));
        word.push((lit(code as u64), sel(code)));
    }
    word.push((lit(f::IND_D as u64), IND_D));
    word.push((lit(f::IND_A as u64), IND_A));
    word.push((lit(f::IND_B as u64), IND_B));
    word.push((lit(1 << f::DIGIT_SHIFT), G_ADDR));
    out.push(("one_op_a_live_row".to_string(), linear(one)));
    out.push(("op_word".to_string(), linear(word)));
    // Each element's address: its word, plus 8·digit where it is indirect.
    for (name, q, word, flag) in [
        ("d", D, f::D_WORD, IND_D),
        ("a", A, f::A_WORD, IND_A),
        ("b", B, f::B_WORD, IND_B),
    ] {
        out.push((
            format!("{name}_addr_rule"),
            quadratic(
                vec![(lit(1), addr(q)), (neg(1), frame(word))],
                vec![(neg(f::BUCKET_CELLS as u64), flag, DIGIT)],
            ),
        ));
    }
    // `y`: `b` on the two products, 1 in limb 0 on the two sums.
    for j in 0..4 {
        let mut lin = vec![(lit(1), y(j))];
        if j == 0 {
            lin.push((neg(1), sel(f::ADD)));
            lin.push((neg(1), sel(f::SUB)));
        }
        out.push((
            format!("y{j}_rule"),
            quadratic(
                lin,
                vec![(neg(1), sel(f::MUL), b(j)), (neg(1), sel(f::MULEQ), b(j))],
            ),
        ));
    }
    // `MULEQ` writes `d` back, so the identity reads its value.
    for i in 0..f::ELEMENT_CELLS {
        out.push((
            format!("muleq_keeps_d{i}"),
            quadratic(
                vec![],
                vec![
                    (lit(1), sel(f::MULEQ), d_new(i)),
                    (neg(1), sel(f::MULEQ), d_old(i)),
                ],
            ),
        ));
    }
    // `FROM128`: two cells below `2^128`, as four limbs.
    for (half, lo, hi) in [(0, 0, 1), (1, 2, 3)] {
        out.push((
            format!("from128_half{half}"),
            quadratic(
                vec![],
                vec![
                    (lit(1), sel(f::FROM128), d_new(lo)),
                    (Coeff::Literal(pow2(64)), sel(f::FROM128), d_new(hi)),
                    (neg(1), sel(f::FROM128), a(half)),
                ],
            ),
        ));
    }
    for g in 0..4 {
        out.push((format!("group{g}"), group(g)));
    }
    out
}

/// The circuit at `2^trace_vars` rows.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let (mut enforcing, mut obligations) = d::read_only_frame_range16(WORDS, f::FRAME_BYTES as u64);
    enforcing.extend(gates());
    obligations.extend(lookups());
    let accesses = accesses();
    let artifact = crate::memory::assemble(
        trace_vars,
        [memory_names(), witness_names(), Vec::new()],
        vec![
            (VirtualKind::Range19, "range19".to_string()),
            (VirtualKind::Range16, "range16".to_string()),
        ],
        d::leaves_with(
            address_space::DELEGATION_FQ_OP,
            WORDS,
            accesses.iter().map(Access::leaves).collect(),
        ),
        enforcing,
        obligations,
        &channels(),
    );
    if let Err(e) = crate::lookup::check_copowers(&artifact, &d::frame_scaled_range16(WORDS)) {
        panic!("fq_op: {e}");
    }
    assert_eq!(artifact.memory.len(), MEMORY_COLUMNS, "fq_op: M width");
    assert_eq!(artifact.witness.len(), WITNESS_COLUMNS, "fq_op: W width");
    // Each channel's fraction tree is its obligations plus the table's one
    // fraction, rounded up to a power of two: TIMESTAMP's 30 fill 31 of 32
    // leaves and RANGE16's 50 fill 51 of 64. Two more TIMESTAMP obligations
    // double that tree.
    let count = |ch| artifact.lookups.iter().filter(|l| l.channel == ch).count();
    assert_eq!(
        count(lookup_channel::TIMESTAMP),
        30,
        "fq_op: TIMESTAMP obligations"
    );
    assert_eq!(
        count(lookup_channel::RANGE16),
        50,
        "fq_op: RANGE16 obligations"
    );
    artifact
}

/// The `M` column names, in layout order.
fn memory_names() -> Vec<String> {
    let mut out = d::memory_names(WORDS);
    for name in ["g_addr", "g_read_ts", "digit"] {
        out.push(name.to_string());
    }
    out.push("a_addr".to_string());
    for i in 0..f::ELEMENT_CELLS {
        out.push(format!("a_read_ts{i}"));
    }
    for i in 0..f::ELEMENT_CELLS {
        out.push(format!("a{i}"));
    }
    out.push("b_addr".to_string());
    out.push("b_read_ts".to_string());
    for i in 0..f::ELEMENT_CELLS {
        out.push(format!("b{i}"));
    }
    out.push("d_addr".to_string());
    out.push("d_read_ts".to_string());
    for i in 0..f::ELEMENT_CELLS {
        out.push(format!("d{i}"));
    }
    for i in 0..f::ELEMENT_CELLS {
        out.push(format!("n{i}"));
    }
    out
}

/// The `W` column names, in layout order.
fn witness_names() -> Vec<String> {
    let mut out = d::frame_names_range16(WORDS);
    for k in 0..GAPS {
        out.push(format!("gap_{}_hi", gap(k).0));
    }
    for code in f::OPS {
        out.push(format!("op{code}"));
    }
    for name in ["ind_d", "ind_a", "ind_b"] {
        out.push(name.to_string());
    }
    for j in 0..4 {
        out.push(format!("y{j}"));
    }
    for i in 0..f::ELEMENT_CELLS {
        for c in 1..4 {
            out.push(format!("n{i}_c{c}"));
        }
    }
    for j in 0..4 {
        for c in 0..4 {
            out.push(format!("k{j}_c{c}"));
        }
    }
    for g in 0..3 {
        for c in 0..4 {
            out.push(format!("carry{g}_c{c}"));
        }
    }
    out.push("mult_timestamp".to_string());
    out.push("mult_range16".to_string());
    out
}

/// Two channels: `TIMESTAMP` for the gaps, `K3` and the carries, `RANGE16`
/// for the frame, `d′`'s limbs and the low quotient limbs.
pub fn channels() -> Vec<crate::lookup::ChannelSpec> {
    vec![
        crate::lookup::ChannelSpec {
            channel: lookup_channel::TIMESTAMP,
            table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
            multiplicity: MULT_TIMESTAMP,
        },
        crate::lookup::ChannelSpec {
            channel: lookup_channel::RANGE16,
            table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
            multiplicity: MULT_RANGE16,
        },
    ]
}

// ---------------------------------------------------------------------------
// The witness
// ---------------------------------------------------------------------------

/// One row's arithmetic witness, which no event carries: `y`, `d′`'s upper
/// chunks, the quotient's chunks and the carries' offset chunks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Witness {
    pub y: [u64; 4],
    pub d_chunks: [[u32; 3]; 4],
    pub k_chunks: [[u32; 4]; 4],
    pub carry_chunks: [[u32; 4]; 3],
}

/// `x`'s little-endian 64-bit limbs, wide enough for `a·y + z`.
type Wide = [u64; 9];

fn wide(x: &[u64]) -> Wide {
    let mut out = [0u64; 9];
    out[..x.len()].copy_from_slice(x);
    out
}

fn add(x: &Wide, y: &Wide) -> Wide {
    let mut out = [0u64; 9];
    let mut carry = 0u128;
    for k in 0..9 {
        let t = x[k] as u128 + y[k] as u128 + carry;
        out[k] = t as u64;
        carry = t >> 64;
    }
    assert_eq!(carry, 0, "fq_op: a sum leaves 576 bits");
    out
}

fn sub(x: &Wide, y: &Wide) -> Wide {
    let mut out = [0u64; 9];
    let mut borrow = 0i128;
    for k in 0..9 {
        let t = x[k] as i128 - y[k] as i128 - borrow;
        out[k] = t as u64;
        borrow = (t < 0) as i128;
    }
    assert_eq!(borrow, 0, "fq_op: a difference goes negative");
    out
}

/// `x·y` truncated to 576 bits, where the callers' products fit.
fn mul(x: &Wide, y: &Wide) -> Wide {
    let mut out = [0u64; 9];
    for i in 0..9 {
        let mut carry = 0u128;
        for j in 0..9 - i {
            let t = out[i + j] as u128 + x[i] as u128 * y[j] as u128 + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
    }
    out
}

/// `x − y` mod `2^576`.
fn sub_wrapping(x: &Wide, y: &Wide) -> Wide {
    let mut out = [0u64; 9];
    let mut borrow = 0u64;
    for k in 0..9 {
        let (t, b1) = x[k].overflowing_sub(y[k]);
        let (t, b2) = t.overflowing_sub(borrow);
        out[k] = t;
        borrow = (b1 | b2) as u64;
    }
    out
}

/// `q⁻¹ mod 2^576`, by Newton's iteration `x ← x·(2 − q·x)` from 1, which
/// is `q⁻¹ mod 2`: each step doubles the bits that agree, and ten reach
/// 1,024.
fn q_inverse() -> Wide {
    let q = wide(&f::Q);
    let mut x = wide(&[1]);
    for _ in 0..10 {
        x = mul(&x, &sub_wrapping(&wide(&[2]), &mul(&q, &x)));
    }
    x
}

/// A field element's integer, when it is below `2^64`.
pub fn limb(v: Fr) -> Option<u64> {
    let b = v.to_bytes();
    b[8..]
        .iter()
        .all(|x| *x == 0)
        .then(|| u64::from_le_bytes(b[..8].try_into().expect("eight bytes")))
}

/// Row `code`'s witness over `a`, `b` and `d′`, every limb below `2^64` —
/// `a` unread by `FROM128`. Panics where `a·y + z − d′` is not a multiple of
/// `q`, which an honest trace cannot produce.
pub fn witness(code: u32, a: [u64; 4], b: [u64; 4], d_new: [u64; 4]) -> Witness {
    let (y, z): ([u64; 4], Wide) = match code {
        f::MUL | f::MULEQ => (b, [0; 9]),
        f::ADD => ([1, 0, 0, 0], wide(&b)),
        f::SUB => {
            let six_q = mul(&wide(&f::Q), &wide(&[f::SUB_MULTIPLE]));
            ([1, 0, 0, 0], sub(&six_q, &wide(&b)))
        }
        f::FROM128 => ([0; 4], wide(&d_new)),
        other => panic!("fq_op: no op {other}"),
    };
    let x = add(&mul(&wide(&a), &wide(&y)), &z);
    let rem = sub(&x, &wide(&d_new));
    // `rem = q·K` exactly, so `K = rem·q⁻¹` mod `2^576`.
    let k = mul(&rem, &q_inverse());
    assert_eq!(
        mul(&k, &wide(&f::Q)),
        rem,
        "fq_op: a·y + z − d′ is not a multiple of q"
    );
    // The circuit's `K3` is limbs 3 and 4 together, at most 76 bits.
    assert!(
        k[5..].iter().all(|v| *v == 0) && k[4] >> 12 == 0,
        "fq_op: the quotient passes 2^268"
    );
    let k3 = k[3] as u128 | (k[4] as u128) << 64;
    let mut out = Witness {
        y,
        ..Witness::default()
    };
    for (chunks, limb) in out.d_chunks.iter_mut().zip(d_new) {
        for (c, chunk) in chunks.iter_mut().enumerate() {
            *chunk = ((limb >> (16 * (c + 1))) & 0xffff) as u32;
        }
    }
    for (j, chunks) in out.k_chunks.iter_mut().enumerate() {
        let (value, bits) = if j < 3 { (k[j] as u128, 16) } else { (k3, 19) };
        for (c, chunk) in chunks.iter_mut().enumerate() {
            *chunk = ((value >> (bits * c)) & ((1 << bits) - 1)) as u32;
        }
    }
    // The carries, over the field and over the circuit's own limb terms —
    // `z`'s limb `k` is `b_k`, `6q_k − b_k` or `d′_k`, not the normalized
    // integer's — every group's terms being exact integers well below p, so
    // each carry is its group's sum over `2^128`.
    let fr = Fr::from_u64;
    let quotient = [fr(k[0]), fr(k[1]), fr(k[2]), fr(k[3]) + pow2(64) * fr(k[4])];
    let z_limb = |k: usize| -> Fr {
        match code {
            f::ADD => fr(b[k]),
            f::SUB => fr(f::SUB_MULTIPLE) * fr(f::Q[k]) - fr(b[k]),
            f::FROM128 => fr(d_new[k]),
            _ => Fr::ZERO,
        }
    };
    let t = |pos: usize| -> Fr {
        let mut v = Fr::ZERO;
        for (i, (ai, qi)) in a.iter().zip(f::Q).enumerate() {
            if let Some(j) = pos.checked_sub(i).filter(|j| *j < 4) {
                v += fr(*ai) * fr(y[j]) - fr(qi) * quotient[j];
            }
        }
        if pos < 4 {
            v += z_limb(pos) - fr(d_new[pos]);
        }
        v
    };
    let unit = pow2(128).inverse().expect("a power of two is invertible");
    let mut carry_in = Fr::ZERO;
    for g in 0..3 {
        let sum = t(2 * g) + pow2(64) * t(2 * g + 1) + carry_in;
        let c = sum * unit;
        let shifted = limbs(c + pow2(CARRY_OFFSET_BITS));
        assert!(
            shifted[1] >> 12 == 0 && shifted[2..].iter().all(|v| *v == 0),
            "fq_op: carry {g} passes 2^75"
        );
        let v = shifted[0] as u128 | (shifted[1] as u128) << 64;
        for (ch, chunk) in out.carry_chunks[g].iter_mut().enumerate() {
            *chunk = ((v >> (19 * ch)) & ((1 << 19) - 1)) as u32;
        }
        carry_in = c;
    }
    assert_eq!(
        t(6) + carry_in,
        Fr::ZERO,
        "fq_op: the top group does not close"
    );
    out
}

/// A field element's four little-endian 64-bit limbs.
fn limbs(v: Fr) -> [u64; 4] {
    let b = v.to_bytes();
    core::array::from_fn(|i| {
        u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().expect("eight bytes"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `q·q⁻¹ = 1` mod `2^576`.
    #[test]
    fn the_inverse_inverts() {
        assert_eq!(mul(&wide(&f::Q), &q_inverse()), wide(&[1]));
    }
}
