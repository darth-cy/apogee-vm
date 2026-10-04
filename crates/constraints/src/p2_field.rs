//! The `P2_FIELD` family's circuit: one step of the transcript's duplex a row
//! over cells of the field memory, invoked by `ecall::PRECOMPILE_P2_FIELD` and
//! never decoded.
//!
//! `docs/spec/recursion.md` §4 is normative.
//!
//! ```text
//! frame     M[0..24]   cycle live base anchor_value, then 4 per word of [n, s, x, y, d]
//! M[24..30]            the state s..s+3: read_ts, value each      at Δ0
//! M[30..36]            x_live x_read_ts x, y_live y_read_ts y     at Δ1, Δ2
//! M[36..45]            the next state d..d+3: read_ts, old, new   at Δ3
//! W[0..14]             the frame's gap chunks and base bounds
//! W[14..30]            two gap chunks per access: state, x, y, next
//! W[30..32]            lane0, lane1: the rate after absorbing
//! W[32..381]           the permutation, in round order: each S-box's u², u⁴,
//!                      then each round's output lanes but the last round's,
//!                      which are the next state's M columns
//! W[381]               the RANGE16 channel's multiplicity
//! ```
//!
//! **Flat.** Every gate is degree 2 on one list, so a parent verifies the row
//! in about 350 sumcheck rounds where S23's layered `POSEIDON2` costs about
//! 3,600. **Homogeneous.** Each round constant enters as `rc·live`, so on a
//! padding row the whole permutation is zero and the all-zero row is valid.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::{address_space, p2_field as f};
use field::Fr;

use crate::delegation::{self as d, booleanity, linear, lit, neg, quadratic, Access, LIVE};
use crate::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};

/// The frame's words: `[n, s, x, y, d]`.
const WORDS: usize = f::FRAME_WORDS;

const FRAME_M: u32 = (d::HEAD_COLUMNS + 4 * WORDS) as u32;
const FRAME_W: u32 = d::frame_witness_range16(WORDS);

const fn m(i: u32) -> PolyAddress {
    PolyAddress::Memory(FRAME_M + i)
}
const fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(FRAME_W + i)
}

/// `M[24 + 2i]`: when state lane `i` was last written.
pub const fn state_read_ts(i: usize) -> PolyAddress {
    m(2 * i as u32)
}
/// `M[25 + 2i]`: state lane `i`.
pub const fn state(i: usize) -> PolyAddress {
    m(2 * i as u32 + 1)
}
/// `M[30]`: whether `x` is absorbed, `n >= 1`.
pub const X_LIVE: PolyAddress = m(6);
pub const X_READ_TS: PolyAddress = m(7);
pub const X: PolyAddress = m(8);
/// `M[33]`: whether `y` is absorbed, `n = 2`.
pub const Y_LIVE: PolyAddress = m(9);
pub const Y_READ_TS: PolyAddress = m(10);
pub const Y: PolyAddress = m(11);
/// `M[36 + 3i]`: when next-state lane `i` was last written.
pub const fn next_read_ts(i: usize) -> PolyAddress {
    m(12 + 3 * i as u32)
}
/// `M[37 + 3i]`: what next-state lane `i`'s cell held.
pub const fn next_old(i: usize) -> PolyAddress {
    m(13 + 3 * i as u32)
}
/// `M[38 + 3i]`: next-state lane `i`, the permutation's output.
pub const fn next(i: usize) -> PolyAddress {
    m(14 + 3 * i as u32)
}
pub const MEMORY_COLUMNS: usize = FRAME_M as usize + 21;

/// Accesses in order: the state's three lanes, `x`, `y`, the next state's.
const ACCESSES: usize = 8;
/// `W[14 + 2q + c]`: chunk `c` of access `q`'s gap.
pub const fn gap_chunk(q: usize, c: usize) -> PolyAddress {
    w((d::GAP_CHUNKS * q + c) as u32)
}
/// `W[30]`: lane 0 after absorbing, `n >= 1 ? x : s₀`.
pub const LANE0: PolyAddress = w(2 * ACCESSES as u32);
/// `W[31]`: lane 1 after absorbing, `n = 2 ? y : (n = 1 ? 0 : s₁)`.
pub const LANE1: PolyAddress = w(2 * ACCESSES as u32 + 1);
/// The permutation's first column.
const PERMUTATION: u32 = 2 * ACCESSES as u32 + 2;
/// The permutation's `i`-th column, in [`permutation_witness`]' order.
pub const fn permutation_column(i: usize) -> PolyAddress {
    w(PERMUTATION + i as u32)
}
/// The permutation's columns: two an S-box, three a round but the last.
pub const PERMUTATION_COLUMNS: usize =
    2 * constants::poseidon2::SBOXES + 3 * (constants::poseidon2::ROUNDS - 1);
/// `W[381]`: the `RANGE16` channel's multiplicity, last in the witness.
pub const MULTIPLICITY: PolyAddress = w(PERMUTATION + PERMUTATION_COLUMNS as u32);
pub const WITNESS_COLUMNS: usize =
    FRAME_W as usize + PERMUTATION as usize + PERMUTATION_COLUMNS + 1;

/// Frame word `j`'s value.
fn frame(j: usize) -> PolyAddress {
    d::word(j, d::WORD_READ_VALUE)
}

/// A degree-2 expression with no constant: what a lane is between commits.
#[derive(Clone, Default)]
struct Expr {
    lin: Vec<(Fr, PolyAddress)>,
    prod: Vec<(Fr, PolyAddress, PolyAddress)>,
}

impl Expr {
    fn col(x: PolyAddress) -> Expr {
        Expr {
            lin: vec![(Fr::ONE, x)],
            prod: Vec::new(),
        }
    }
    fn add(&self, o: &Expr) -> Expr {
        let mut out = self.clone();
        out.lin.extend_from_slice(&o.lin);
        out.prod.extend_from_slice(&o.prod);
        out
    }
    fn scale(&self, c: u64) -> Expr {
        let c = Fr::from_u64(c);
        Expr {
            lin: self.lin.iter().map(|(k, x)| (*k * c, *x)).collect(),
            prod: self.prod.iter().map(|(k, x, y)| (*k * c, *x, *y)).collect(),
        }
    }
    /// `self²`, for a degree-1 `self`.
    fn square(&self) -> Expr {
        assert!(self.prod.is_empty(), "p2_field: squares a degree-1 lane");
        let mut prod = Vec::new();
        for (i, (a, x)) in self.lin.iter().enumerate() {
            prod.push((*a * *a, *x, *x));
            for (b, y) in &self.lin[i + 1..] {
                prod.push((Fr::from_u64(2) * *a * *b, *x, *y));
            }
        }
        Expr {
            lin: Vec::new(),
            prod,
        }
    }
    /// `x·self`, for a degree-1 `self`.
    fn times(&self, x: PolyAddress) -> Expr {
        assert!(self.prod.is_empty(), "p2_field: multiplies a degree-1 lane");
        Expr {
            lin: Vec::new(),
            prod: self.lin.iter().map(|(c, y)| (*c, x, *y)).collect(),
        }
    }
    /// The gate `col − self = 0`.
    fn defines(&self, col: PolyAddress) -> GateDef {
        let mut linear = vec![(lit(1), col)];
        linear.extend(self.lin.iter().map(|(c, x)| (Coeff::Literal(-*c), *x)));
        quadratic(
            linear,
            self.prod
                .iter()
                .map(|(c, x, y)| (Coeff::Literal(-*c), *x, *y))
                .collect(),
        )
    }
}

/// `[[2,1,1],[1,2,1],[1,1,a]]`: the external layer at `a = 2`, the internal at 3.
fn matrix(s: &[Expr; 3], a: u64) -> [Expr; 3] {
    let sum = s[0].add(&s[1]).add(&s[2]);
    [sum.add(&s[0]), sum.add(&s[1]), sum.add(&s[2].scale(a - 1))]
}

/// The permutation's rounds in order: three constants a full round, one a
/// partial round.
fn rounds() -> Vec<Vec<Fr>> {
    let hex = |h: &str| Fr::from_hex(h).expect("a frozen round constant is canonical");
    let mut out: Vec<Vec<Fr>> = Vec::new();
    out.extend(
        constants::POSEIDON2_RC3_INITIAL
            .iter()
            .map(|row| row.iter().map(|h| hex(h)).collect()),
    );
    out.extend(
        constants::POSEIDON2_RC3_INTERNAL
            .iter()
            .map(|h| vec![hex(h)]),
    );
    out.extend(
        constants::POSEIDON2_RC3_TERMINAL
            .iter()
            .map(|row| row.iter().map(|h| hex(h)).collect()),
    );
    out
}

/// The permutation's gates over `lanes`, its last round landing on `out`.
fn permutation_gates(lanes: [Expr; 3], out: [PolyAddress; 3]) -> Vec<(String, GateDef)> {
    let mut gates: Vec<(String, GateDef)> = Vec::new();
    let mut next = PERMUTATION;
    let mut alloc = || {
        let c = w(next);
        next += 1;
        c
    };
    let mut s = matrix(&lanes, 2);
    let rounds = rounds();
    let last = rounds.len() - 1;
    for (r, rc) in rounds.iter().enumerate() {
        let mut v = s.clone();
        for (i, c) in rc.iter().enumerate() {
            // `u = lane + rc·live`, so a padding row's permutation is zero.
            let u = s[i].add(&Expr {
                lin: vec![(*c, LIVE)],
                prod: Vec::new(),
            });
            let (q, p) = (alloc(), alloc());
            gates.push((format!("r{r}_l{i}_square"), u.square().defines(q)));
            gates.push((
                format!("r{r}_l{i}_fourth"),
                Expr::col(q).square().defines(p),
            ));
            v[i] = u.times(p);
        }
        s = matrix(&v, if rc.len() == 3 { 2 } else { 3 });
        for i in 0..3 {
            let col = if r == last { out[i] } else { alloc() };
            gates.push((format!("r{r}_out{i}"), s[i].defines(col)));
            s[i] = Expr::col(col);
        }
    }
    assert_eq!(
        next,
        PERMUTATION + PERMUTATION_COLUMNS as u32,
        "p2_field: permutation columns"
    );
    gates
}

/// One row's permutation columns, in [`permutation_gates`]' order, and its
/// output: what the prover fills from the absorbed lanes.
pub fn permutation_witness(lanes: [Fr; 3]) -> (Vec<Fr>, [Fr; 3]) {
    let matrix = |s: [Fr; 3], a: u64| {
        let sum = s[0] + s[1] + s[2];
        [
            sum + s[0],
            sum + s[1],
            sum + (Fr::from_u64(a) - Fr::ONE) * s[2],
        ]
    };
    let mut cols: Vec<Fr> = Vec::with_capacity(PERMUTATION_COLUMNS);
    let mut s = matrix(lanes, 2);
    let rounds = rounds();
    let last = rounds.len() - 1;
    for (r, rc) in rounds.iter().enumerate() {
        let mut v = s;
        for (i, c) in rc.iter().enumerate() {
            let u = s[i] + *c;
            let q = u.square();
            let p = q.square();
            cols.extend([q, p]);
            v[i] = p * u;
        }
        s = matrix(v, if rc.len() == 3 { 2 } else { 3 });
        if r != last {
            cols.extend(s);
        }
    }
    (cols, s)
}

/// The eight accesses: the state, `x`, `y`, the next state.
fn accesses() -> Vec<Access> {
    let access = |q: usize, name: String, mask, word, offset, delta, read_ts, read, write| Access {
        name,
        space: address_space::FIELD,
        mask,
        addr: frame(word),
        offset,
        delta,
        read_ts,
        read,
        write,
        gap: [gap_chunk(q, 0), gap_chunk(q, 1)],
    };
    let mut out = Vec::new();
    for i in 0..3 {
        out.push(access(
            i,
            format!("state{i}"),
            LIVE,
            f::S_WORD,
            i as u64,
            f::DELTA_STATE,
            state_read_ts(i),
            state(i),
            state(i),
        ));
    }
    out.push(access(
        3,
        "x".to_string(),
        X_LIVE,
        f::X_WORD,
        0,
        f::DELTA_X,
        X_READ_TS,
        X,
        X,
    ));
    out.push(access(
        4,
        "y".to_string(),
        Y_LIVE,
        f::Y_WORD,
        0,
        f::DELTA_Y,
        Y_READ_TS,
        Y,
        Y,
    ));
    for i in 0..3 {
        out.push(access(
            5 + i,
            format!("next{i}"),
            LIVE,
            f::D_WORD,
            i as u64,
            f::DELTA_NEXT,
            next_read_ts(i),
            next_old(i),
            next(i),
        ));
    }
    out
}

/// The circuit at `2^trace_vars` rows.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let (mut enforcing, mut lookups) = d::read_only_frame_range16(WORDS, f::FRAME_BYTES as u64);
    let n = frame(f::N_WORD);
    enforcing.extend([
        ("x_live_boolean".to_string(), booleanity(X_LIVE)),
        ("y_live_boolean".to_string(), booleanity(Y_LIVE)),
        // `y` absorbed only with `x`, and either only on a live row.
        (
            "y_needs_x".to_string(),
            quadratic(vec![(lit(1), Y_LIVE)], vec![(neg(1), X_LIVE, Y_LIVE)]),
        ),
        (
            "x_needs_live".to_string(),
            quadratic(vec![(lit(1), X_LIVE)], vec![(neg(1), X_LIVE, LIVE)]),
        ),
        (
            "n_word".to_string(),
            linear(vec![(lit(1), n), (neg(1), X_LIVE), (neg(1), Y_LIVE)]),
        ),
        // The rate, overwritten and zero-filled (`transcript::Transcript::duplex`).
        (
            "lane0_rule".to_string(),
            quadratic(
                vec![(lit(1), LANE0), (neg(1), state(0))],
                vec![(neg(1), X_LIVE, X), (lit(1), X_LIVE, state(0))],
            ),
        ),
        (
            "lane1_rule".to_string(),
            quadratic(
                vec![(lit(1), LANE1), (neg(1), state(1))],
                vec![(lit(1), X_LIVE, state(1)), (neg(1), Y_LIVE, Y)],
            ),
        ),
    ]);
    // The capacity takes the count: `s₂ + n`.
    let lane2 = Expr::col(state(2)).add(&Expr::col(n));
    enforcing.extend(permutation_gates(
        [Expr::col(LANE0), Expr::col(LANE1), lane2],
        [next(0), next(1), next(2)],
    ));
    let accesses = accesses();
    for a in &accesses {
        lookups.extend(a.gap_lookups());
    }
    let mut scaled = d::frame_scaled_range16(WORDS);
    scaled.extend(accesses.iter().map(Access::scaled));
    let artifact = crate::memory::assemble(
        trace_vars,
        [memory_names(), witness_names(), Vec::new()],
        vec![(VirtualKind::Range16, "range16".to_string())],
        d::leaves_with(
            address_space::DELEGATION_P2_FIELD,
            WORDS,
            accesses.iter().map(Access::leaves).collect(),
        ),
        enforcing,
        lookups,
        &channels(),
    );
    if let Err(e) = crate::lookup::check_copowers(&artifact, &scaled) {
        panic!("p2_field: {e}");
    }
    assert_eq!(artifact.memory.len(), MEMORY_COLUMNS, "p2_field: M width");
    assert_eq!(artifact.witness.len(), WITNESS_COLUMNS, "p2_field: W width");
    assert!(
        artifact.padding.zero_row_valid,
        "p2_field: the all-zero row is a padding row"
    );
    artifact
}

/// The `M` column names, in layout order.
fn memory_names() -> Vec<String> {
    let mut out = d::memory_names(WORDS);
    for i in 0..3 {
        out.push(format!("state{i}_read_ts"));
        out.push(format!("state{i}"));
    }
    for name in ["x_live", "x_read_ts", "x", "y_live", "y_read_ts", "y"] {
        out.push(name.to_string());
    }
    for i in 0..3 {
        out.push(format!("next{i}_read_ts"));
        out.push(format!("next{i}_old"));
        out.push(format!("next{i}"));
    }
    out
}

/// The `W` column names, in layout order.
fn witness_names() -> Vec<String> {
    let mut out = d::frame_names_range16(WORDS);
    for name in accesses().iter().map(|a| a.name.clone()) {
        for c in 0..d::GAP_CHUNKS {
            out.push(format!("gap_{name}_c{c}"));
        }
    }
    out.push("lane0".to_string());
    out.push("lane1".to_string());
    let rounds = rounds();
    for (r, rc) in rounds.iter().enumerate() {
        for i in 0..rc.len() {
            out.push(format!("r{r}_l{i}_u2"));
            out.push(format!("r{r}_l{i}_u4"));
        }
        if r != rounds.len() - 1 {
            for i in 0..3 {
                out.push(format!("r{r}_s{i}"));
            }
        }
    }
    out.push("mult_range16".to_string());
    out
}

/// One channel, `RANGE16`.
pub fn channels() -> Vec<crate::lookup::ChannelSpec> {
    vec![crate::lookup::ChannelSpec {
        channel: constants::lookup_channel::RANGE16,
        table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
        multiplicity: MULTIPLICITY,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The witness's output is the permutation, and its columns are the ones
    /// the gates name.
    #[test]
    fn the_witness_is_the_permutation() {
        let lanes = [Fr::from_u64(7), Fr::from_u64(11), Fr::from_u64(13)];
        let (cols, out) = permutation_witness(lanes);
        assert_eq!(cols.len(), PERMUTATION_COLUMNS);
        assert_eq!(witness_names().len(), WITNESS_COLUMNS);
        // Every permutation gate vanishes on the row: evaluate it directly.
        let lane2 = Expr::col(state(2)).add(&Expr::col(frame(f::N_WORD)));
        let gates = permutation_gates(
            [Expr::col(LANE0), Expr::col(LANE1), lane2],
            [next(0), next(1), next(2)],
        );
        let value = |x: PolyAddress| -> Fr {
            match x {
                LIVE => Fr::ONE,
                LANE0 => lanes[0],
                LANE1 => lanes[1],
                x if x == state(2) => lanes[2],
                x if x == frame(f::N_WORD) => Fr::ZERO,
                x if x == next(0) => out[0],
                x if x == next(1) => out[1],
                x if x == next(2) => out[2],
                PolyAddress::Witness(i) => cols[(i - FRAME_W - PERMUTATION) as usize],
                other => panic!("unexpected operand {other:?}"),
            }
        };
        let coeff = |c: &Coeff| match c {
            Coeff::Literal(x) => *x,
            Coeff::Challenge(_) => panic!("a permutation gate names no challenge"),
        };
        for (name, gate) in gates {
            let GateDef::Quadratic {
                constant,
                linear,
                products,
            } = gate
            else {
                panic!("{name} is not Quadratic");
            };
            let mut acc = coeff(&constant);
            for (c, x) in &linear {
                acc += coeff(c) * value(*x);
            }
            for (c, x, y) in &products {
                acc += coeff(c) * value(*x) * value(*y);
            }
            assert_eq!(acc, Fr::ZERO, "{name} does not vanish");
        }
    }
}
