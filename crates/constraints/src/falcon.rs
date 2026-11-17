//! The `FALCON512` precompile: the lattice check of Falcon-512 verification,
//! `s1 = (c − s2·h) mod (q, x^512 + 1)` centered to `[−6144, 6144]` and
//! `‖s1‖²`, as three circuits on `crate::delegation`'s builder, through the
//! CRT `x^512 + 1 = Π_{r < 16} (x^32 − β_r)` over `Z_q`, `q = 12289`.
//!
//! Since `x^32 ≡ β_r` mod `x^32 − β_r`, a polynomial's residue `r` has
//! coefficient `j < 32` equal to `Σ_{m < 16} V[r][m]·a_{32m + j}`, `V[r][m] =
//! β_r^m` ([`V`]): the sixteen coefficients `32m + j` of an array give
//! coefficient `j` of every residue. An array's word `16m + j`, at `ptr + 64m`
//! for `ptr` its word `j`'s address, holds coefficients `32m + 2j` and `32m +
//! 2j + 1`.
//!
//! - `FALCON`, one row a call: the frame's five words, `h`'s, `s2`'s and
//!   `c`'s addresses read and `‖s1‖²` written as `n_lo`, a word, and `n_hi`,
//!   below `2^16`; the three chains started at their arrays with `acc = 0` and
//!   ended, `s2`'s and `h`'s at `acc = 0` and `c`'s at `acc = n_lo + 2^32·n_hi`.
//! - `FALCON_SPLIT`, 64 rows a call, row `16P + j` column `j` of chain `P`
//!   (`s2`, `h`, `c`: `delegation::falcon::CHAINS`): the control `(ptr, acc)`
//!   received and `(ptr + 4, acc + Σ s²)` sent; the sixteen words at `ptr +
//!   64m` read and written back at the call's timestamp, each a word, its
//!   halfwords `v_{m,0}`, `v_{m,1}` coefficients `32m + 2j` and `32m + 2j + 1`;
//!   a witness `s_{m,e} ∈ [−6144, 6144]`; and for each residue `r` and `e`,
//!   `Σ_m V[r][m]·(v_{m,e} − s_{m,e}) = rr_{r,e} + q·kk_{r,e}`, the pair
//!   `(rr_{r,0}, rr_{r,1})` sent. Rows 48–63 are padding.
//! - `FALCON_PRODUCT`, 16 rows a call, row `r`: the 48 pairs of residue `r`
//!   received, `a` from chain `s2`, `b` from `h`, `d` from `c` (coefficient
//!   `2j + e` from column `j`), each below `2^16`, and `a·b ≡ d` mod `(x^32 −
//!   β_r, q)` coefficient by coefficient: `Σ_{i+j=k} a_i·b_j + β_r·W_k − d_k =
//!   q·w_k`, `W_k = Σ_{i+j=k+32} a_i·b_j` committed and `w_k ∈ [0, 2^48)` as
//!   three `RANGE16` chunks.
//!
//! ## The space
//!
//! ```text
//! tuple                                    written by              read by
//! (cycle, σ, ptr, acc), a control          FALCON, σ = start(P)    FALCON, σ = start(P) + 16
//!                                          SPLIT(P, j), σ + 1      SPLIT(P, j), σ = start(P) + j
//! (64·cycle + place(P, j), r, rr_0, rr_1)  SPLIT(P, j), r < 16     PRODUCT(r)
//! ```
//!
//! `start(P) = 16 + 17P` and `place(P, j) = 17P + j` ([`start`], [`place`]).
//! A split row holds `key = 64·cycle + σ − 16`, its place, by a gate.
//!
//! ## Why every key is written once and read once
//!
//! The space's reads and writes are equal multisets: nothing initializes it
//! and no final reads it.
//!
//! *Controls and residues never meet.* A split row bounds `σ − 16` in
//! `RANGE16`, so its controls' timestamps `σ` and `σ + 1` lie in `[16, 2^16 +
//! 17)`, as the frame's `16..=66` do, while a residue's is `r < 16`: a literal
//! in a split row, the one-hot's integer in a product row.
//!
//! *The split rows are the chains.* Fix an address `A` and let `n_t` count the
//! split rows of cycle `A` and stamp `t`. At `(A, t)` the writes are the frame
//! row's start at `t`, if any, and the `n_{t−1}` rows before; the reads its end
//! at `t` and the `n_t` rows at `t`. So `n_t = n_{t−1} + [t a start] − [t an
//! end]`, with `n_t = 0` below 16. A frame row is its anchor's, one a
//! requesting cycle (`docs/spec/precompiles.md` §2): at any other `A` there is
//! no start and no end and `n` is 0 throughout, and at a call's cycle the
//! starts `16, 33, 50` and ends `32, 49, 66` give `n_t = 1` on `start(P) + j`,
//! `j < 16`, and 0 elsewhere. Every split row is one position `(P, j)` of one
//! call, its `cycle` the requesting ecall's, an integer below `2^36`; every
//! control key is written once and read once, so row `(P, j)` receives what
//! row `(P, j − 1)` sent: `ptr = ptr_P + 4j` and the running `acc`.
//!
//! *The product rows are the residues.* A split row's key `64·cycle + place`
//! names its call and position, `place < 64` ([`KEY`]), so each residue key is
//! written once. A product row of one-hot `r` reads `(base + ρ, r)` for every
//! place `ρ`; its read at `ρ = 0` is written, so `base = 64·c + u` for a call
//! `c` and a place `u`. Were `u ≠ 0`, some place `ρ` would put `(u + ρ) mod 64`
//! where no call writes ([`NO_SHIFT`], checked at compile time). So `base =
//! 64·c`, the row reads exactly call `c`'s 48 pairs of residue `r`, and since
//! each is written once there is exactly one product row per call and residue.
//!
//! ## Why the rows are the check
//!
//! Row `(P, j)` reads the words `ptr_P + 4j + 64m`, `m < 16`: each array's 256
//! words once each, at the call's timestamp, written back unchanged. An array
//! overlapping another or the frame would access a word twice at one
//! timestamp, which no memory history allows. Each word is bounded as a load
//! bounds the word it reads, so an array may lie in the advice and the
//! coefficients are its halfwords, each below `2^16`, read mod `q`.
//!
//! A split identity's sum is below `2^34` in size, `rr` is below `2^16` at its
//! reader and `kk ∈ [−2^31, 2^31)`, so it holds over the integers and `rr_{r,e}
//! ≡ Σ_m V[r][m]·(v_{m,e} − s_{m,e})` mod `q`: coefficient `2j + e` of residue
//! `r` of `array_P − s`. Each chain's `acc` sums its rows' `Σ s²`, below
//! `512·6144² < 2^35`: the frame ends `s2`'s and `h`'s at the literal 0, so
//! their `s` are all 0, and `c`'s at `n = n_lo + 2^32·n_hi`, which with `n_lo`
//! a word and `n_hi` below `2^16` is that sum's integer, written as its two
//! words. So `a`, `b` and `d` are residue `r` of `s2`, `h` and `c − s1`, `s1`
//! the coefficients chain `c` holds, each in `[−6144, 6144]`, and `n =
//! ‖s1‖²`.
//!
//! A product identity's left side is below `2^51` in size and `q·w_k` below
//! `2^62`, so it holds over the integers: `A·B ≡ D` mod `(x^32 − β_r, q)`. The
//! `β_r` are 16 distinct roots of `y^16 + 1` (checked at compile time), so
//! `x^512 + 1` is the product of the coprime `x^32 − β_r` and `s2·h ≡ c − s1`
//! mod `(q, x^512 + 1)`. A coefficient in `[−6144, 6144]` is its class's
//! centered representative, `q = 2·6144 + 1`: `s1` is the centered `(c − s2·h)
//! mod q`, and `n` its squared norm.

use alloc::format;
use alloc::vec::Vec;

use constants::delegation::falcon::{ARRAYS, C, CHAINS, FRAME, N, NORM_HI, NORM_LO, Q};
use constants::{address_space, ecall, family};

use crate::delegation::{access, frame, Builder, Part};
use crate::family::{sum, Expr, T16, T32};
use crate::lookup::ChannelSpec;
use crate::{CircuitArtifact, PolyAddress};

/// Residues of the CRT, the roots `β_r` of `y^16 + 1`.
pub const RESIDUES: usize = 16;
/// A residue's coefficients: `x^32 − β_r` is degree 32.
pub const DEGREE: usize = N / RESIDUES;
/// Blocks of an array: coefficient `32m + j` is block `m`'s `j`.
pub const BLOCKS: usize = N / DEGREE;
/// Split rows a chain: column `j` holds coefficients `2j` and `2j + 1` of
/// every block, one word of each.
pub const COLUMNS: usize = DEGREE / 2;
/// The bound on a coefficient of `s1`: `[−BOUND, BOUND]`, `q = 2·BOUND + 1`.
pub const BOUND: u64 = (Q - 1) / 2;
/// The first control stamp: every control's timestamp is at least this, and
/// every residue's below it.
pub const FIRST: u64 = RESIDUES as u64;
/// Stamps a chain takes: its sixteen rows' and its end.
pub const STRIDE: u64 = COLUMNS as u64 + 1;
/// The multiple of a call's cycle its residue keys start at: every place is
/// below it.
pub const KEY: u64 = 64;

/// Chain `p`'s first stamp, the control its frame row sends; its end is
/// `start(p) + 16`.
pub const fn start(p: usize) -> u64 {
    FIRST + STRIDE * p as u64
}

/// The place of split row `(p, j)`'s residues among its call's [`KEY`] keys.
pub const fn place(p: usize, j: usize) -> u64 {
    STRIDE * p as u64 + j as u64
}

const fn pow_mod(base: u64, mut e: u64) -> u64 {
    let (mut acc, mut x) = (1, base % Q);
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * x % Q;
        }
        x = x * x % Q;
        e >>= 1;
    }
    acc
}

/// `ζ = 11^384 mod q`, a primitive 32nd root of unity: 11 generates `Z_q*`,
/// of order `12288 = 32·384`.
pub const ZETA: u64 = pow_mod(11, (Q - 1) / 32);

/// `β_r = ζ^(2r + 1)`: the roots of `y^16 + 1`, so `x^512 + 1 = Π_r (x^32 −
/// β_r)`.
pub const BETA: [u64; RESIDUES] = {
    let mut out = [0; RESIDUES];
    let mut r = 0;
    while r < RESIDUES {
        out[r] = pow_mod(ZETA, 2 * r as u64 + 1);
        r += 1;
    }
    out
};

/// `V[r][m] = β_r^m mod q`: what block `m` weighs in residue `r`.
pub const V: [[u64; BLOCKS]; RESIDUES] = {
    let mut out = [[0; BLOCKS]; RESIDUES];
    let mut r = 0;
    while r < RESIDUES {
        let mut m = 0;
        while m < BLOCKS {
            out[r][m] = pow_mod(BETA[r], m as u64);
            m += 1;
        }
        r += 1;
    }
    out
};

/// Whether `x` is a place, `place(p, j)` for some chain and column.
const fn is_place(x: u64) -> bool {
    let (p, j) = (x / STRIDE, x % STRIDE);
    p < CHAINS.len() as u64 && j < COLUMNS as u64
}

/// For every place `u ≠ 0`, a place `x` with `(u + x) mod KEY` no place: a
/// product row whose base is `u` places past a call's reads a residue key no
/// call writes.
pub const NO_SHIFT: () = {
    let mut u = 1;
    while u < KEY {
        if is_place(u) {
            let mut missing = false;
            let mut x = 0;
            while x < KEY {
                if is_place(x) && !is_place((u + x) % KEY) {
                    missing = true;
                }
                x += 1;
            }
            assert!(missing, "a shifted base reads only written residues");
        }
        u += 1;
    }
};

const _: () = NO_SHIFT;

const _: () = {
    assert!(RESIDUES * DEGREE == N && BLOCKS * DEGREE == N && 2 * COLUMNS == DEGREE);
    assert!(CHAINS.len() * BLOCKS * COLUMNS == ARRAYS && Q == 2 * BOUND + 1);
    // Residue timestamps sit below every control's.
    assert!(FIRST >= RESIDUES as u64);
    // Every place is below KEY, so 64·cycle + place names both.
    assert!(place(CHAINS.len() - 1, COLUMNS - 1) < KEY);
    // ζ has order 32; the β_r are distinct roots of y^16 + 1.
    assert!(pow_mod(ZETA, 16) == Q - 1);
    let mut r = 0;
    while r < RESIDUES {
        assert!(pow_mod(BETA[r], 16) == Q - 1);
        let mut t = 0;
        while t < r {
            assert!(BETA[t] != BETA[r]);
            t += 1;
        }
        r += 1;
    }
    // The registry's words an entry and rows a call: a row a chain's column,
    // padded to a power of two, and a row a residue.
    let t = &constants::delegation::TYPES;
    let columns = (CHAINS.len() * COLUMNS).next_power_of_two() as u32;
    assert!(t[9].0 == family::FALCON && t[9].2 == FRAME && t[9].3 == 1);
    assert!(t[10].0 == family::FALCON_SPLIT && t[10].2 == ARRAYS && t[10].3 == columns);
    assert!(t[11].0 == family::FALCON_PRODUCT && t[11].2 == ARRAYS);
    assert!(t[11].3 == RESIDUES as u32);
};

/// The chain of `c`, whose `acc` is `‖s1‖²`.
const C_CHAIN: usize = 2;
const _: () = assert!(CHAINS[C_CHAIN] == C);

// ---------------------------------------------------------------------------
// The circuits
// ---------------------------------------------------------------------------

/// A control of the call at `cycle`: `(FALCON, cycle, stamp, ptr, acc)`.
fn control(cycle: PolyAddress, stamp: Part, ptr: Part, acc: Part) -> [Part; 4] {
    [Part::of(cycle), stamp, ptr, acc]
}

/// `FALCON`: the frame, the norm's two words, the chains started and ended.
///
/// ```text
/// frame         five words, w3 and w4 written (delegation::frame)
/// n_lo          write_3 a word                    n_hi_range   write_4 < 2^16
/// n_rule        n − write_3 − 2^32·write_4
/// st{P}_rule    st_P − start(P)·live
/// write  (cycle, st_P, ptr_P, 0)                  ptr_P = read of word CHAINS[P]
/// read   (cycle, st_P + 16, end_P, 0)  P = s2, h  (cycle, st_2 + 16, end_2, n)
/// ```
///
/// `end_P` is free: the chain's last row sent `ptr_P + 64`.
fn frame_row() -> Builder {
    let mut b = Builder::new(family::FALCON);
    let live = b.live;
    let f = frame(&mut b, ecall::FALCON512, FRAME, |j| j >= NORM_LO);
    let (lo, hi) = (f.words[NORM_LO].write, f.words[NORM_HI].write);
    b.word("n_lo", lo.into());
    b.range16("n_hi_range", hi.into());
    let n = b.mcol("n");
    b.gate("n_rule", n - lo - hi * T32);
    let space = address_space::FALCON;
    for (p, word) in CHAINS.iter().enumerate() {
        let st = b.mcol(&format!("st{p}"));
        b.gate(&format!("st{p}_rule"), st - live * start(p));
        let end = b.mcol(&format!("end{p}"));
        let ptr = Part::of(f.words[*word].read);
        let begun = control(f.cycle, Part::of(st), ptr, Part::default());
        b.leaf(true, &format!("write_start{p}"), space, begun);
        let acc = match p == C_CHAIN {
            true => Part::of(n),
            false => Part::default(),
        };
        let ended = control(f.cycle, Part::plus(st, COLUMNS as u64), Part::of(end), acc);
        b.leaf(false, &format!("read_end{p}"), space, ended);
    }
    b
}

/// `FALCON_SPLIT`: column `j` of chain `P`, its stamp `σ = start(P) + j`.
///
/// ```text
/// stamp_range   σ − 16 < 2^16                key_rule   key − 64·cycle − σ + 16
/// a{m}_rule     a_m − ptr − 64m·live, m ≥ 1  a_0 = ptr
/// w{m}          the word at a_m, read and written back at 4·cycle +
///               FRAME_DELTA, its gap in [0, 2^38), and a word: v_{m,1} its
///               high halfword, v_{m,0} = read_m − 2^16·v_{m,1}
/// s{m}_{e}      s + 6144 < 2^16 and 6144 − s < 2^16
/// acc_rule      acc_out − acc − Σ_{m,e} s_{m,e}²
/// res{r}_{e}    Σ_m V[r][m]·(v_{m,e} − s_{m,e}) − rr_{r,e} − q·kk_{r,e}
/// kk{r}_{e}     kk + 2^31 a word
/// read   (cycle, σ, ptr, acc)
/// write  (cycle, σ + 1, ptr + 4, acc_out); (key, r, rr_{r,0}, rr_{r,1}), r < 16
/// ```
fn split() -> Builder {
    let mut b = Builder::new(family::FALCON_SPLIT);
    let live = b.live;
    let [cycle, stamp, key, ptr, acc, acc_out] =
        ["cycle", "stamp", "key", "ptr", "acc", "acc_out"].map(|c| b.mcol(c));
    b.range16("stamp_range", stamp - live * FIRST);
    b.gate("key_rule", key - cycle * KEY - stamp + live * FIRST);
    let mut addr = Vec::with_capacity(BLOCKS);
    addr.push(ptr);
    for m in 1..BLOCKS {
        let a = b.mcol(&format!("a{m}"));
        b.gate(&format!("a{m}_rule"), a - ptr - live * (64 * m as u64));
        addr.push(a);
    }
    let read_ts: Vec<PolyAddress> = (0..BLOCKS)
        .map(|m| b.mcol(&format!("w{m}_read_ts")))
        .collect();
    let read: Vec<PolyAddress> = (0..BLOCKS)
        .map(|m| b.mcol(&format!("w{m}_read_value")))
        .collect();
    let rr: Vec<[PolyAddress; 2]> = (0..RESIDUES)
        .map(|r| [0, 1].map(|e| b.mcol(&format!("rr{r}_{e}"))))
        .collect();
    let mut high = Vec::with_capacity(BLOCKS);
    for m in 0..BLOCKS {
        let name = format!("w{m}");
        access(
            &mut b,
            &name,
            cycle,
            Part::of(addr[m]),
            read_ts[m],
            read[m],
            read[m],
        );
        // A word, as a load holds the word it reads: an advised word could be
        // any field element, and the coefficients must be its halfwords.
        high.push(b.word(&name, read[m].into()));
    }
    let halves = |m: usize| [read[m] - high[m] * T16, Expr::from(high[m])];
    let s: Vec<[PolyAddress; 2]> = (0..BLOCKS)
        .map(|m| [0, 1].map(|e| b.col(&format!("s{m}_{e}"))))
        .collect();
    let mut squares = acc_out - acc;
    for (m, pair) in s.iter().enumerate() {
        for (e, x) in pair.iter().enumerate() {
            b.range16(&format!("s{m}_{e}_low"), *x + live * BOUND);
            b.range16(&format!("s{m}_{e}_high"), live * BOUND - *x);
            squares = squares - *x * *x;
        }
    }
    b.gate("acc_rule", squares);
    for (r, pair) in rr.iter().enumerate() {
        for (e, out) in pair.iter().enumerate() {
            let kk = b.col(&format!("kk{r}_{e}"));
            b.word(&format!("kk{r}_{e}"), kk + live * (1u64 << 31));
            let mut rule = -Expr::from(*out) - kk * Q;
            for (m, v) in V[r].iter().enumerate() {
                let [lo, hi] = halves(m);
                let half = if e == 0 { lo } else { hi };
                rule = rule + (half - s[m][e]) * *v;
            }
            b.gate(&format!("res{r}_{e}"), rule);
        }
    }
    let space = address_space::FALCON;
    let received = control(cycle, Part::of(stamp), Part::of(ptr), Part::of(acc));
    b.leaf(false, "read_control", space, received);
    let sent = control(
        cycle,
        Part::plus(stamp, 1),
        Part::plus(ptr, 4),
        Part::of(acc_out),
    );
    b.leaf(true, "write_control", space, sent);
    for (r, [lo, hi]) in rr.iter().enumerate() {
        let parts = [
            Part::of(key),
            Part::constant(r as u64),
            Part::of(*lo),
            Part::of(*hi),
        ];
        b.leaf(true, &format!("write_res{r}"), space, parts);
    }
    b
}

/// `FALCON_PRODUCT`: residue `r`, `o_r` its one-hot bit.
///
/// ```text
/// one_o         Σ o − live                    r_rule   r − Σ_r r·o_r
/// base{P}_rule  base_P − base_0 − 17P·live, P ≥ 1
/// {a,b,d}{i}    < 2^16
/// wrap{k}_rule  W_k − Σ_{i+j=k+32} a_i·b_j, k < 31
/// prod{k}       Σ_{i+j=k} a_i·b_j + (Σ_r β_r·o_r)·W_k − d_k − q·Σ_c 2^16c·w_{k,c}
/// w{k}_c{c}     < 2^16, c < 3
/// read   (base_P + j, r, x_{2j}, x_{2j+1}), x = a, b, d for P = s2, h, c
/// ```
fn product() -> Builder {
    let mut b = Builder::new(family::FALCON_PRODUCT);
    let live = b.live;
    let r = b.mcol("r");
    let base = [0, 1, 2].map(|p| b.mcol(&format!("base{p}")));
    let x = ["a", "b", "d"].map(|n| {
        (0..DEGREE)
            .map(|i| b.mcol(&format!("{n}{i}")))
            .collect::<Vec<PolyAddress>>()
    });
    let o: Vec<PolyAddress> = (0..RESIDUES).map(|i| b.bit(&format!("o{i}"))).collect();
    b.gate("one_o", sum(&o) - live);
    let (mut rule, mut beta) = (Expr::from(r), Expr::default());
    for (i, bit) in o.iter().enumerate() {
        rule = rule - *bit * i as u64;
        beta = beta + *bit * BETA[i];
    }
    b.gate("r_rule", rule);
    for (p, column) in base.iter().enumerate().skip(1) {
        let rule = *column - base[0] - live * (STRIDE * p as u64);
        b.gate(&format!("base{p}_rule"), rule);
    }
    for (n, xs) in ["a", "b", "d"].iter().zip(&x) {
        for (i, xi) in xs.iter().enumerate() {
            b.range16(&format!("{n}{i}_range"), (*xi).into());
        }
    }
    let [xa, xb, xd] = &x;
    let wrap: Vec<PolyAddress> = (0..DEGREE - 1)
        .map(|k| b.col(&format!("wrap{k}")))
        .collect();
    for (k, w) in wrap.iter().enumerate() {
        let mut e = Expr::from(*w);
        for i in k + 1..DEGREE {
            e = e - xa[i] * xb[k + DEGREE - i];
        }
        b.gate(&format!("wrap{k}_rule"), e);
    }
    for k in 0..DEGREE {
        let chunks = [0, 1, 2].map(|c| b.col(&format!("w{k}_c{c}")));
        let mut e = -Expr::from(xd[k]);
        for i in 0..=k {
            e = e + xa[i] * xb[k - i];
        }
        if let Some(w) = wrap.get(k) {
            e = e + beta.clone() * *w;
        }
        for (c, chunk) in chunks.iter().enumerate() {
            b.range16(&format!("w{k}_c{c}_range"), (*chunk).into());
            e = e - *chunk * (Q << (16 * c));
        }
        b.gate(&format!("prod{k}"), e);
    }
    for (p, (xs, at)) in x.iter().zip(base).enumerate() {
        for j in 0..COLUMNS {
            let parts = [
                Part::plus(at, j as u64),
                Part::of(r),
                Part::of(xs[2 * j]),
                Part::of(xs[2 * j + 1]),
            ];
            b.leaf(
                false,
                &format!("read_res{p}_{j}"),
                address_space::FALCON,
                parts,
            );
        }
    }
    b
}

/// `FALCON`'s circuit over `2^trace_vars` rows; at least `2^16`, its
/// `RANGE16` table's, which the registry refuses below.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    frame_row().artifact(trace_vars)
}

/// `FALCON`'s one channel, `RANGE16`.
pub fn channels() -> Vec<ChannelSpec> {
    frame_row().channels()
}

/// `FALCON_SPLIT`'s circuit over `2^trace_vars` rows, likewise.
pub fn split_artifact(trace_vars: u32) -> CircuitArtifact {
    split().artifact(trace_vars)
}

/// `FALCON_SPLIT`'s one channel, `RANGE16`.
pub fn split_channels() -> Vec<ChannelSpec> {
    split().channels()
}

/// `FALCON_PRODUCT`'s circuit over `2^trace_vars` rows, likewise.
pub fn product_artifact(trace_vars: u32) -> CircuitArtifact {
    product().artifact(trace_vars)
}

/// `FALCON_PRODUCT`'s one channel, `RANGE16`.
pub fn product_channels() -> Vec<ChannelSpec> {
    product().channels()
}
