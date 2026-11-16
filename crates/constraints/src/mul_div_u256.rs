//! The `MUL_DIV_U256` precompile's circuit, `docs/spec/precompiles.md` §4: one
//! row a call, on `crate::delegation`'s builder. The frame is 24 words, `a`,
//! `b` and `d` eight little-endian words each; the call writes
//! `q = floor(a·b/d)` over `a` and `r = a·b mod d` over `b`, and `d` back.
//!
//! ```text
//! limbs        every word of a, b, d, q, r its two RANGE16 halfwords: 16-bit limbs
//! chunk{k}     S_k(a·b) − S_k(q·d) − [k < 8]·r_k + carry_{k−1} − 2^32·carry_k = 0
//!              k = 0..16, S_k the limb products at limb positions 2k and 2k + 1,
//!              the second weighted 2^16; carry_{−1} = carry_15 = 0
//! carry{k}     carry_k + 2^21 ∈ [0, 2^22)
//! bound{k}     d_k − r_k − [k = 0] + 2^32·borrow_k − borrow_{k−1}, a word;
//!              borrow_{−1} = borrow_7 = 0: d − r − 1 ≥ 0
//! ```
//!
//! A chunk's limb products total below `2^53`, so each gate is an identity
//! over ℤ; summed with weights `2^32k` they say `a·b = q·d + r`, and the bound
//! `r < d`. A quotient past `2^256` or `d = 0` has no witness: the caller
//! owes both (`constants::ecall::MUL_DIV_U256`).

use alloc::format;
use alloc::vec::Vec;

use constants::{ecall, family};

use crate::delegation::{frame, Builder};
use crate::family::{Expr, T16, T32};
use crate::lookup::ChannelSpec;
use crate::{CircuitArtifact, PolyAddress};

/// Words in each operand.
pub const WORDS: usize = 8;
/// The carries' offset: every carry is above `−2^21` and below `2^21`.
pub const CARRY_OFFSET: u64 = 1 << 21;
/// The offset carries' width.
pub const CARRY_BITS: u32 = 22;

fn spec() -> Builder {
    let mut b = Builder::new(family::MUL_DIV_U256);
    let live = b.live;
    let f = frame(&mut b, ecall::MUL_DIV_U256, 3 * WORDS, |j| j < 2 * WORDS);
    let words = |at: usize, write: bool| -> Vec<PolyAddress> {
        f.words[at..at + WORDS]
            .iter()
            .map(|w| if write { w.write } else { w.read })
            .collect()
    };
    let (a, bw, d, q, r) = (
        words(0, false),
        words(WORDS, false),
        words(2 * WORDS, false),
        words(0, true),
        words(WORDS, true),
    );
    // Each word as its two 16-bit limbs, low first.
    let mut limbs = |name: &str, ws: &[PolyAddress]| -> Vec<Expr> {
        let mut out = Vec::with_capacity(2 * WORDS);
        for (k, w) in ws.iter().enumerate() {
            let h = b.word(&format!("{name}{k}"), (*w).into());
            out.push(*w - h * T16);
            out.push(h.into());
        }
        out
    };
    let (la, lb, ld, lq) = (
        limbs("a", &a),
        limbs("b", &bw),
        limbs("d", &d),
        limbs("q", &q),
    );
    limbs("r", &r);
    let carries: Vec<PolyAddress> = (0..2 * WORDS - 1)
        .map(|k| b.col(&format!("carry{k}")))
        .collect();
    for (k, c) in carries.iter().enumerate() {
        b.bounded(&format!("carry{k}"), *c + live * CARRY_OFFSET, CARRY_BITS);
    }
    // Σ_{i + j = m} x_i·y_j, the limb products at position m.
    let at = |x: &[Expr], y: &[Expr], m: usize| {
        let mut e = Expr::default();
        for i in 0..x.len() {
            if m >= i && m - i < y.len() {
                e = e + x[i].clone() * y[m - i].clone();
            }
        }
        e
    };
    for k in 0..2 * WORDS {
        let mut e = at(&la, &lb, 2 * k) + at(&la, &lb, 2 * k + 1) * T16
            - at(&lq, &ld, 2 * k)
            - at(&lq, &ld, 2 * k + 1) * T16;
        if k < WORDS {
            e = e - r[k];
        }
        if k > 0 {
            e = e + carries[k - 1];
        }
        if k < 2 * WORDS - 1 {
            e = e - carries[k] * T32;
        }
        b.gate(&format!("chunk{k}"), e);
    }
    let borrows: Vec<PolyAddress> = (0..WORDS - 1)
        .map(|k| b.bit(&format!("borrow{k}")))
        .collect();
    for k in 0..WORDS {
        let mut g = d[k] - r[k];
        if k == 0 {
            g = g - live;
        } else {
            g = g - borrows[k - 1];
        }
        if k < WORDS - 1 {
            g = g + borrows[k] * T32;
        }
        b.word(&format!("bound{k}"), g);
    }
    b
}

/// The family's circuit over `2^trace_vars` rows; at least `2^16`, its
/// `RANGE16` table's, which the registry refuses below.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    spec().artifact(trace_vars)
}

/// The family's one channel, `RANGE16`.
pub fn channels() -> Vec<ChannelSpec> {
    spec().channels()
}
