//! The Poseidon2-A64-C5 precompile, `docs/spec/precompiles.md` §3, as two
//! circuits on `crate::delegation`'s builder. The permutation is
//! `transcript::poseidon2_permute`: the external layer `M_E`, six full rounds,
//! 42 partial rounds and six full rounds.
//!
//! - `POSEIDON2`, one row a call: the frame's 32 words read and written in
//!   place, lane `i` being words `2i` and `2i + 1`; the input after `M_E` sent
//!   as boundary 0 and the output received as boundary 15, through
//!   `address_space::POSEIDON2`; each output lane written canonical.
//! - `POSEIDON2_ROUNDS`, sixteen rows a call, row `k` taking boundary `k` to
//!   `k + 1`: rows 0–5 and 9–14 one full round each, rows 6–8 fourteen partial
//!   rounds each, row 15 idle. One layout of sixteen S-boxes serves both kinds,
//!   in parallel for a full round and in sequence for partial ones, so a gate
//!   is the kind's form under `ext` or `int` and no row mixes them.
//!
//! Lane pair `j` of the call at `cycle` at boundary `b` is the tuple
//! `(POSEIDON2, 8·cycle + j, b, lane 2j, lane 2j + 1)`.

use alloc::format;
use alloc::vec::Vec;

use constants::{address_space, delegation, ecall, family};
use field::Fp;
use transcript::{INTERNAL_DIAG, M4, RC_INITIAL, RC_PARTIAL, RC_TERMINAL, WIDTH};

use crate::delegation::{frame, Builder, Part};
use crate::family::{sum, Expr, T16, T32};
use crate::lookup::ChannelSpec;
use crate::{gadgets, CircuitArtifact, Coeff, PolyAddress};

/// Rows a call takes in `POSEIDON2_ROUNDS`, the last one idle.
pub const ROWS: usize = 16;
/// Partial rounds an internal row takes: three rows cover the 42.
pub const PARTIAL: usize = 14;
/// The boundary the frame row receives the output at, the last live row's.
pub const LAST: u64 = ROWS as u64 - 1;
/// The state's lane pairs: tuple `j` carries lanes `2j` and `2j + 1`.
const PAIRS: usize = WIDTH / 2;

const _: () = {
    assert!(3 * PARTIAL == RC_PARTIAL.len());
    assert!(RC_INITIAL.len() + 3 + RC_TERMINAL.len() == ROWS - 1);
    // The registry's rows a call, for the frame family and the rounds.
    assert!(delegation::TYPES[0].0 == family::POSEIDON2 && delegation::TYPES[0].3 == 1);
    assert!(delegation::TYPES[1].0 == family::POSEIDON2_ROUNDS);
    assert!(delegation::TYPES[1].3 as usize == ROWS);
    assert!(delegation::TYPES[0].2 == 2 * WIDTH);
};

/// Whether row `k` of a call is internal: the three after the initial rounds.
pub fn internal(k: usize) -> bool {
    (6..9).contains(&k)
}

/// `M_E = circ(2·M4, M4, M4, M4)` at `(i, k)`.
pub fn external_entry(i: usize, k: usize) -> Fp {
    let m = M4[i % 4][k % 4] as u64;
    Fp::from_u64(if i / 4 == k / 4 { 2 * m } else { m })
}

/// Row `k`'s round constant at S-box slot `j`: a full round's lane `j`, or the
/// `j`-th of an internal row's partial rounds; 0 at an internal row's two idle
/// slots.
pub fn round_constant(k: usize, j: usize) -> Fp {
    match k {
        0..6 => RC_INITIAL[k][j],
        6..9 if j < PARTIAL => RC_PARTIAL[PARTIAL * (k - 6) + j],
        6..9 => Fp::ZERO,
        _ => RC_TERMINAL[k - 9][j],
    }
}

/// Coefficients over an internal row's inputs: its lanes `s_0..s_15`, then its
/// S-box outputs `z_0..z_13`.
type Form = [Fp; WIDTH + PARTIAL];

/// An internal row as linear forms: each S-box input less its constant, and
/// each output lane. Partial round `m` S-boxes lane 0 and applies
/// `M_I = J + diag(μ − 1)`, so every lane after it is linear in the lanes
/// before and the S-box outputs so far.
pub fn internal_forms() -> ([Form; PARTIAL], [Form; WIDTH]) {
    let mut state: [Form; WIDTH] = core::array::from_fn(|i| {
        let mut f = [Fp::ZERO; WIDTH + PARTIAL];
        f[i] = Fp::ONE;
        f
    });
    let mut inputs = [[Fp::ZERO; WIDTH + PARTIAL]; PARTIAL];
    for m in 0..PARTIAL {
        inputs[m] = state[0];
        state[0] = [Fp::ZERO; WIDTH + PARTIAL];
        state[0][WIDTH + m] = Fp::ONE;
        let total: Form =
            core::array::from_fn(|v| state.iter().fold(Fp::ZERO, |acc, lane| acc + lane[v]));
        for (lane, d) in state.iter_mut().zip(INTERNAL_DIAG) {
            *lane = core::array::from_fn(|v| d * lane[v] + total[v]);
        }
    }
    (inputs, state)
}

/// `POSEIDON2_ROUNDS`: a row reads lane pair `j` at boundary `round`, applies
/// row `round`'s rounds, and writes it at `round + 1`.
///
/// ```text
/// one_kind      Σ_k row_k − live                 the kind bits, one-hot on a live row
/// round_rule    round − Σ_k k·row_k
/// ext_rule      ext − Σ_{k external} row_k        int_rule   int − live + ext
/// y{j}_rule     y_j − ext·s_j − int·L_j(s, z) − Σ_k row_k·c_k[j]
/// y{j}_sq_rule  y2_j − y_j²                       y{j}_cube_rule   z_j − y2_j·y_j
/// o{l}_rule     o_l − ext·Σ_k M_E[l][k]·z_k − int·K_l(s, z)
/// ```
///
/// `L_j` and `K_l` are [`internal_forms`], `c_k` [`round_constant`]. Every
/// gate is degree 2, the kind riding a linear factor.
fn rounds() -> Builder {
    let mut b = Builder::new(family::POSEIDON2_ROUNDS);
    let live = b.live;
    let key = b.mcol("key");
    let round = b.mcol("round");
    let s: Vec<PolyAddress> = (0..WIDTH).map(|i| b.mcol(&format!("s{i}"))).collect();
    let o: Vec<PolyAddress> = (0..WIDTH).map(|i| b.mcol(&format!("o{i}"))).collect();
    let kinds: Vec<PolyAddress> = (0..ROWS - 1).map(|k| b.bit(&format!("row{k}"))).collect();
    b.gate("one_kind", sum(&kinds) - live);
    let mut at = Expr::from(round);
    for (k, x) in kinds.iter().enumerate() {
        at = at - *x * k as u64;
    }
    b.gate("round_rule", at);
    let ext = b.col("ext");
    let int = b.col("int");
    let external: Vec<PolyAddress> = (0..ROWS - 1)
        .filter(|k| !internal(*k))
        .map(|k| kinds[k])
        .collect();
    b.gate("ext_rule", ext - sum(&external));
    b.gate("int_rule", int - live + ext);
    let y: Vec<PolyAddress> = (0..WIDTH).map(|j| b.col(&format!("y{j}"))).collect();
    let y2: Vec<PolyAddress> = (0..WIDTH).map(|j| b.col(&format!("y{j}_sq"))).collect();
    let z: Vec<PolyAddress> = (0..WIDTH).map(|j| b.col(&format!("y{j}_cube"))).collect();
    let linear = |f: &Form| {
        let mut e = Expr::default();
        for (v, c) in f.iter().enumerate() {
            let x = if v < WIDTH { s[v] } else { z[v - WIDTH] };
            e = e + Expr::from(x) * *c;
        }
        e
    };
    let (inputs, outputs) = internal_forms();
    for j in 0..WIDTH {
        let mut e = y[j] - ext * s[j];
        if j < PARTIAL {
            e = e - int * linear(&inputs[j]);
        }
        for (k, x) in kinds.iter().enumerate() {
            e = e - Expr::from(*x) * round_constant(k, j);
        }
        b.gate(&format!("y{j}_rule"), e);
        b.gate(&format!("y{j}_sq_rule"), y2[j] - y[j] * y[j]);
        b.gate(&format!("y{j}_cube_rule"), z[j] - y2[j] * y[j]);
    }
    for l in 0..WIDTH {
        let mut full = Expr::default();
        for (k, x) in z.iter().enumerate() {
            full = full + Expr::from(*x) * external_entry(l, k);
        }
        let e = o[l] - ext * full - int * linear(&outputs[l]);
        b.gate(&format!("o{l}_rule"), e);
    }
    for j in 0..PAIRS {
        let space = address_space::POSEIDON2;
        b.leaf(
            false,
            &format!("read_s{j}"),
            space,
            [
                Part::plus(key, j as u64),
                Part::of(round),
                Part::of(s[2 * j]),
                Part::of(s[2 * j + 1]),
            ],
        );
        b.leaf(
            true,
            &format!("write_o{j}"),
            space,
            [
                Part::plus(key, j as u64),
                Part::plus(round, 1),
                Part::of(o[2 * j]),
                Part::of(o[2 * j + 1]),
            ],
        );
    }
    b
}

/// `POSEIDON2`: the frame, the input lanes after `M_E` sent as boundary 0, the
/// output lanes received as boundary 15 and written canonical.
///
/// ```text
/// key_rule      key − 8·cycle
/// u{j}_rule     u_j − Σ_k M_E[j][k]·(read_{2k} + 2^32·read_{2k+1})
/// o{l}_rule     o_l − write_{2l} − 2^32·write_{2l+1}
/// o{l}_top      is_zero(3·0xFFFF − h1 − h0 − l1, inv, top): both words' halfwords
///               but the lowest all ones
/// o{l}_canonical   0xFFFF − 59·top − l0 < 2^16
/// ```
///
/// `l0 l1` and `h0 h1` are the output words' halfwords, each bounded, so a
/// lane is canonical exactly when `top = 0` or `l0 ≤ 0xFFC4`: below
/// `p = 2^64 − 59`. A read lane is read mod `p`.
fn frame_row() -> Builder {
    let mut b = Builder::new(family::POSEIDON2);
    let live = b.live;
    let f = frame(&mut b, ecall::POSEIDON2, 2 * WIDTH, |_| true);
    let key = b.mcol("key");
    b.gate("key_rule", key - f.cycle * 8);
    let u: Vec<PolyAddress> = (0..WIDTH).map(|j| b.mcol(&format!("u{j}"))).collect();
    let o: Vec<PolyAddress> = (0..WIDTH).map(|l| b.mcol(&format!("o{l}"))).collect();
    for (j, uj) in u.iter().enumerate() {
        let mut e = Expr::from(*uj);
        for k in 0..WIDTH {
            let lane = f.words[2 * k].read + f.words[2 * k + 1].read * T32;
            e = e - lane * external_entry(j, k);
        }
        b.gate(&format!("u{j}_rule"), e);
    }
    let lit = |v: Fp| Coeff::Literal(v);
    for (l, ol) in o.iter().enumerate() {
        let (lo, hi) = (f.words[2 * l].write, f.words[2 * l + 1].write);
        b.gate(&format!("o{l}_rule"), *ol - lo - hi * T32);
        let l1 = b.word(&format!("o{l}_lo"), lo.into());
        let h1 = b.word(&format!("o{l}_hi"), hi.into());
        let inv = b.col(&format!("o{l}_inv"));
        let top = b.col(&format!("o{l}_top"));
        let all_ones = [
            (lit(Fp::from_u64(3 * 0xffff)), live),
            (lit(Fp::MINUS_ONE), hi),
            (lit(Fp::from_u64(0xffff)), h1),
            (lit(Fp::MINUS_ONE), l1),
        ];
        let [inverse, at_nonzero] = gadgets::is_zero(&all_ones, inv, top, live);
        b.push_gate(&format!("o{l}_top_inverse"), inverse);
        b.push_gate(&format!("o{l}_top_at_nonzero"), at_nonzero);
        b.range16(
            &format!("o{l}_canonical"),
            live * 0xffff - top * 59 - (lo - l1 * T16),
        );
    }
    for j in 0..PAIRS {
        let space = address_space::POSEIDON2;
        b.leaf(
            true,
            &format!("send_u{j}"),
            space,
            [
                Part::plus(key, j as u64),
                Part::default(),
                Part::of(u[2 * j]),
                Part::of(u[2 * j + 1]),
            ],
        );
        b.leaf(
            false,
            &format!("receive_o{j}"),
            space,
            [
                Part::plus(key, j as u64),
                Part::constant(LAST),
                Part::of(o[2 * j]),
                Part::of(o[2 * j + 1]),
            ],
        );
    }
    b
}

/// `POSEIDON2`'s circuit over `2^trace_vars` rows; at least `2^16`, its
/// `RANGE16` table's, which the registry refuses below.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    frame_row().artifact(trace_vars)
}

/// `POSEIDON2`'s one channel, `RANGE16`.
pub fn channels() -> Vec<ChannelSpec> {
    frame_row().channels()
}

/// `POSEIDON2_ROUNDS`' circuit over `2^trace_vars` rows; it reads no lookup.
pub fn rounds_artifact(trace_vars: u32) -> CircuitArtifact {
    rounds().artifact(trace_vars)
}

/// `POSEIDON2_ROUNDS` has no channel.
pub fn rounds_channels() -> Vec<ChannelSpec> {
    Vec::new()
}
