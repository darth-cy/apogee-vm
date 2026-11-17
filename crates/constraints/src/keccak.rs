//! The `KECCAK_F1600` precompile: Keccak-f[1600] (FIPS 202) on the 50-word
//! frame at `a0`, in place, as three circuits on `crate::delegation`'s
//! builder. Every value a row holds of the state is a byte, and every byte
//! operation is one `XOR8` lookup `(a, b, e)`, `e = a ^ b`: from it
//! `a & b = (a + b − e)/2` and `!a & b = (b − a + e)/2` are linear, a byte
//! splits at bit `8 − s` against the mask `2^(8 − s) − 1`, and each of the
//! three is bounded to a byte. Lane `A[x][y]` is `x + 5y`; its byte `k` is
//! bits `8k..8k + 8`.
//!
//! - `KECCAK`, eight rows a call, row `y < 5` plane `y` of the frame: its ten
//!   words, read and written at the call's timestamp, their input and output
//!   bytes, the running column parity `P_out = P_in ⊕ in`, and at `y = 4`
//!   round 0's `D` from `C = P_out`. Row 0 reads the anchor; every row holds
//!   `room`, and the base and the cycle reach rows 1–4 through the chain.
//! - `KECCAK_RHO`, 128 rows a call, row `5t + y` the source plane `y` of
//!   round `t`: theta's `A' = A ⊕ D`, each lane rotated by `r[x][y] = 8q + s`
//!   (rho), and lane `x` sent to B-plane `2x + 3y`, slot `y` (pi). `D` runs
//!   through the round's five rows.
//! - `KECCAK_CHI`, 128 rows a call, row `5t + y` B-plane `y` of round `t`:
//!   chi, iota on lane `(0, 0)`, the running parity of the planes written,
//!   and at `y = 4` the next round's `D`, or at `t = 23` the output.
//!
//! A call's other rows, `KECCAK`'s 5–7 and the expansions' 120–127, are all
//! zero: padding.
//!
//! ## The space
//!
//! Two bytes of the call at `cycle` are the tuple `(KECCAK, cycle, stamp,
//! byte, byte)`. A group of tuples takes [`GROUP`] stamps from `GROUP·g`:
//! pair `i < 20` of a plane is lane `i / 4`'s bytes `2(i mod 4)` and
//! `2(i mod 4) + 1`; a B-plane's slot `x` is at `4x + m`, `m < 4`.
//!
//! ```text
//! group g             holds                       written by                  read by
//! 5s + y, s ≤ 24      plane y of A_s              KECCAK(y) at s = 0,         RHO(s, y), or
//!                                                 else CHI(s − 1, y)          KECCAK(y) at s = 24
//! 125 + 5t + y        D_t                         KECCAK(4) at (0, 0),        RHO(t, y)
//!                                                 CHI(t − 1, 4) at y = 0,
//!                                                 else RHO(t, y − 1)
//! 245 + 5t + y        B-plane y of round t        RHO(t, x), slot x           CHI(t, y)
//! 365 + 5t + y, y ≥ 1 CHI(t, < y)'s parity        CHI(t, y − 1)               CHI(t, y)
//! 485 + y, y ≥ 1      KECCAK(< y)'s parity,       KECCAK(y − 1)               KECCAK(y)
//!                     the base at BASE
//! ```
//!
//! A row's stamps are committed columns, each held by a linear gate to its
//! position through the plane one-hot `y0..y4` and, in the expansions, the
//! round one-hot `r0..r23` ([`frame_stamps`], [`rho_stamps`], [`chi_stamps`]);
//! a tuple adds its pair alone, below [`GROUP`].
//!
//! ## Why the rows are one permutation
//!
//! The space's reads and writes are equal multisets: nothing initializes it and
//! no final reads it. A row's position, `y` or `(t, y)`, is pinned by its
//! one-hots, each stamp to the exact integer its position names and each mask
//! (`pin`, `pout`, `dfwd`, `dnext`) to the bit, and the groups are disjoint,
//! so the key `(cycle, stamp)` of a live tuple names one group and one pair: one
//! kind of row (a family and a position) writes it, once a row, and one kind
//! reads it, once a row. Equal multisets then give every key at a cycle as many
//! writing rows as reading ones, so two kinds a group joins have equally many
//! rows there. The groups join every kind to `KECCAK(0)`: its parity chain to
//! `KECCAK(1..4)`, the planes to `RHO(0, ·)`, `D_0` to `RHO(0, 0)` and its chain
//! to `RHO(0, 1..4)`, the B-planes to `CHI(0, ·)`, and so on round by round to
//! `CHI(23, ·)`, whose planes `KECCAK(·)` reads. A `KECCAK(0)` row is its
//! anchor's, one a requesting cycle (`docs/spec/precompiles.md` §2), so at a
//! call's cycle there is exactly one row of each kind and at any other cycle
//! none: every key is written once and read once, and its reader holds what its
//! writer wrote. The base rides the parity chain, so row `y` accesses the words
//! at `base + 40y + 4j`, the frame's fifty once each at the call's timestamp,
//! and `room` holds them below `ADVICE_ORIGIN`.
//!
//! Each row computes its step exactly. `XOR8` bounds every byte a row reads or
//! computes, so `A' = A ⊕ D` byte by byte; the split's `lo` and `hi` are a
//! byte's low `8 − s` and high `s` bits and `B` the lane rotated; chi's
//! `!B[x+1] & B[x+2]` and every parity are the byte operations, `D` is
//! `C[x − 1] ⊕ rot1(C[x + 1])`, and iota XORs round `t`'s constant, whose
//! nonzero bytes are `delegation::keccak::IOTA_BYTES`. A frame row holds each
//! word to its four bytes, exact since a byte is below `2^8` and a word below
//! `2^32 < p`, so the words written are words. `KECCAK(y)` writes plane `y` of
//! Keccak-f[1600] of the frame it read.

use alloc::format;
use alloc::vec::Vec;

use constants::delegation::keccak::{FRAME, IOTA_BYTES, ROTATIONS, ROUNDS, ROUND_CONSTANTS};
use constants::{address_space, ecall, family, guest_memory};
use field::Fp;

use crate::delegation::{access, Builder, Part};
use crate::family::{k, sum, Expr};
use crate::lookup::ChannelSpec;
use crate::{CircuitArtifact, PolyAddress};

/// Planes in the state, rows of a call in `KECCAK`, rows of a round in the
/// expansions.
pub const PLANES: usize = 5;
/// Frame words a `KECCAK` row accesses: its plane's five lanes.
pub const WORDS: usize = FRAME / PLANES;
/// Byte pairs a plane is, one tuple each.
pub const PAIRS: usize = 20;
/// Stamps a group of tuples takes: its twenty pairs, and in a `KECCAK` parity
/// group the base at [`BASE`].
pub const GROUP: u64 = 32;
/// The base's place in a `KECCAK` parity group.
pub const BASE: u64 = 20;

const _: () = {
    assert!(WORDS * PLANES == FRAME && PAIRS == 4 * PLANES);
    assert!(BASE < GROUP && (PAIRS as u64) <= BASE);
    // The registry's rows a call and words an entry.
    let t = &constants::delegation::TYPES;
    assert!(t[6].0 == family::KECCAK && t[6].2 == FRAME && t[6].3 == 8);
    assert!(t[7].0 == family::KECCAK_RHO && t[7].2 == FRAME && t[7].3 == 128);
    assert!(t[8].0 == family::KECCAK_CHI && t[8].2 == FRAME && t[8].3 == 128);
    assert!(PLANES * ROUNDS <= 128 && PLANES <= 8);
};

// ---------------------------------------------------------------------------
// The stamps
// ---------------------------------------------------------------------------

/// A kind's groups, one a round and plane.
const KIND: u64 = (PLANES * ROUNDS) as u64;
/// The first group of `D`, after the planes `A_0..A_24`: 125. The B-planes'
/// is 245, CHI's parities' 365 and `KECCAK`'s 485.
const D_FIRST: u64 = KIND + PLANES as u64;

fn plane_group(s: usize, y: usize) -> u64 {
    (PLANES * s + y) as u64
}

fn d_group(t: usize, y: usize) -> u64 {
    D_FIRST + (PLANES * t + y) as u64
}

fn b_group(t: usize, y: usize) -> u64 {
    D_FIRST + KIND + (PLANES * t + y) as u64
}

fn p_group(t: usize, y: usize) -> u64 {
    D_FIRST + 2 * KIND + (PLANES * t + y) as u64
}

fn k_group(y: usize) -> u64 {
    D_FIRST + 3 * KIND + y as u64
}

/// `KECCAK` row `y`'s stamps: the plane it sends to `RHO(0, y)`, the plane it
/// receives from `CHI(23, y)`, the parity (and base) it receives from row
/// `y − 1`, and what it sends row `y + 1`, at `y = 4` `D_0` to `RHO(0, 0)`.
pub fn frame_stamps(y: usize) -> [u64; 4] {
    let next = match y {
        4 => d_group(0, 0),
        _ => k_group(y + 1),
    };
    [plane_group(0, y), plane_group(ROUNDS, y), k_group(y), next].map(|g| GROUP * g)
}

/// `KECCAK_RHO` row `(t, y)`'s stamps: its plane, its `D` and the `D` it
/// forwards to `(t, y + 1)`, then lane `x`'s B-plane `2x + 3y` and slot `y`
/// for each `x`.
pub fn rho_stamps(t: usize, y: usize) -> [u64; 8] {
    let mut out = [0; 8];
    out[0] = GROUP * plane_group(t, y);
    out[1] = GROUP * d_group(t, y);
    out[2] = GROUP * d_group(t, y + 1);
    for x in 0..PLANES {
        out[3 + x] = GROUP * b_group(t, (2 * x + 3 * y) % PLANES) + 4 * y as u64;
    }
    out
}

/// `KECCAK_CHI` row `(t, y)`'s stamps: its B-plane, the parity from
/// `(t, y − 1)`, what it sends `(t, y + 1)` or at `y = 4` `RHO(t + 1, 0)`, and
/// the plane it writes, `RHO(t + 1, y)`'s or at `t = 23` `KECCAK(y)`'s.
pub fn chi_stamps(t: usize, y: usize) -> [u64; 4] {
    let next = match y {
        4 => d_group(t + 1, 0),
        _ => p_group(t, y + 1),
    };
    [b_group(t, y), p_group(t, y), next, plane_group(t + 1, y)].map(|g| GROUP * g)
}

// ---------------------------------------------------------------------------
// Pieces
// ---------------------------------------------------------------------------

/// A plane's forty bytes, `[x][k]`: lane `x`, byte `k`.
type Plane = [[PolyAddress; 8]; PLANES];

/// Forty columns `{prefix}{x}_{k}`, `M` where a leaf reads them.
fn plane(b: &mut Builder, prefix: &str, memory: bool) -> Plane {
    core::array::from_fn(|x| {
        core::array::from_fn(|k| {
            let name = format!("{prefix}{x}_{k}");
            match memory {
                true => b.mcol(&name),
                false => b.col(&name),
            }
        })
    })
}

/// An `M` column held boolean, which a leaf may take as its mask.
fn mbit(b: &mut Builder, name: &str) -> PolyAddress {
    let x = b.mcol(name);
    b.gate(&format!("{name}_boolean"), x - x * x);
    x
}

/// `n` bits `{prefix}{i}`, one-hot on a live row: `Σ bits = live`.
fn one_hot(b: &mut Builder, prefix: &str, n: usize, memory: bool) -> Vec<PolyAddress> {
    let bits: Vec<PolyAddress> = (0..n)
        .map(|i| {
            let name = format!("{prefix}{i}");
            match memory {
                true => mbit(b, &name),
                false => b.bit(&name),
            }
        })
        .collect();
    let live = b.live;
    b.gate(&format!("one_{prefix}"), sum(&bits) - live);
    bits
}

/// A leaf mask `name`: an `M` bit held to `rule`, a function of the row's
/// position.
fn mask(b: &mut Builder, name: &str, rule: Expr) -> PolyAddress {
    let x = mbit(b, name);
    b.gate(&format!("{name}_rule"), x - rule);
    x
}

/// `M` stamp columns `names`, column `j` held to `at(t, y)[j]` through the
/// one-hots, `round` empty in `KECCAK`. A stamp is `f(t) + g(y)`, which the
/// gate `stamp − Σ_t r_t·f(t) − Σ_y y_y·g(y)` is linear in; asserted here.
fn stamps<const N: usize>(
    b: &mut Builder,
    names: [&str; N],
    plane: &[PolyAddress],
    round: &[PolyAddress],
    at: impl Fn(usize, usize) -> [u64; N],
) -> [PolyAddress; N] {
    let columns = names.map(|n| b.mcol(n));
    let rounds = round.len().max(1);
    for (j, column) in columns.iter().enumerate() {
        let f = |t: usize| at(t, 0)[j] - at(0, 0)[j];
        let g = |y: usize| at(0, y)[j];
        for t in 0..rounds {
            for y in 0..PLANES {
                assert_eq!(
                    at(t, y)[j],
                    f(t) + g(y),
                    "{}: a stamp not f(t) + g(y)",
                    names[j]
                );
            }
        }
        let mut e = Expr::from(*column);
        for (t, r) in round.iter().enumerate() {
            e = e - *r * f(t);
        }
        for (y, x) in plane.iter().enumerate() {
            e = e - *x * g(y);
        }
        b.gate(&format!("{}_rule", names[j]), e);
    }
    columns
}

/// Bytes `2(i mod 4)` and `2(i mod 4) + 1` of lane `i / 4`: pair `i`.
fn pair(p: &Plane, i: usize) -> (PolyAddress, PolyAddress) {
    let (x, k) = (i / 4, 2 * (i % 4));
    (p[x][k], p[x][k + 1])
}

/// A plane's twenty tuples at `stamp + i`, under `mask`.
fn plane_leaves(
    b: &mut Builder,
    (write, name): (bool, &str),
    mask: PolyAddress,
    cycle: PolyAddress,
    stamp: PolyAddress,
    p: &Plane,
) {
    for i in 0..PAIRS {
        let (lo, hi) = pair(p, i);
        let parts = [
            Part::of(cycle),
            Part::plus(stamp, i as u64),
            Part::of(lo),
            Part::of(hi),
        ];
        let (leaf, space) = (format!("{name}{i}"), address_space::KECCAK);
        b.leaf_under(mask, write, &leaf, space, parts);
    }
}

fn inverse(v: u64) -> Fp {
    Fp::from_u64(v).inverse().expect("a power of two is a unit")
}

/// `D[x] = C[x − 1] ⊕ rot1(C[x + 1])` from the parity `c`, under `sel`:
///
/// ```text
/// rot{x}_{j}   (0x7F·sel, c[x][j], s[x][j])          s = 0x7F ⊕ c
/// dxor{x}_{j}  (2·lo[x+1][j] + hi[x+1][j−1], c[x−1][j], d[x][j])
///              lo = c & 0x7F = (0x7F + c − s)/2, hi = c >> 7 = (c − 0x7F + s)/256
/// ```
///
/// `rot1(c)`'s byte `j` is `c_j`'s low seven bits up one and `c_{j−1}`'s top
/// bit below them.
fn theta_d(b: &mut Builder, sel: PolyAddress, c: &Plane, s: &Plane, d: &Plane) {
    for x in 0..PLANES {
        for j in 0..8 {
            let name = format!("rot{x}_{j}");
            b.xor8_under(sel, &name, sel * 0x7fu64, c[x][j].into(), s[x][j].into());
        }
    }
    for (x, out) in d.iter().enumerate() {
        let (up, down) = ((x + 1) % PLANES, (x + PLANES - 1) % PLANES);
        for (j, dj) in out.iter().enumerate() {
            let below = (j + 7) % 8;
            let low = sel * 0x7fu64 + c[up][j] - s[up][j];
            let high = (Expr::from(c[up][below]) - sel * 0x7fu64 + s[up][below]) * inverse(256);
            let name = format!("dxor{x}_{j}");
            b.xor8_under(sel, &name, low + high, c[down][j].into(), (*dj).into());
        }
    }
}

/// A round constant's byte `k`.
fn rc_byte(t: usize, k: usize) -> u64 {
    (ROUND_CONSTANTS[t] >> (8 * k)) & 0xff
}

/// Lane `A[x][y]`'s rotation as `(q, s)`, `r = 8q + s`, and the split's mask
/// `2^(8 − s) − 1`.
pub fn rotation(x: usize, y: usize) -> (usize, u32, u64) {
    let r = ROTATIONS[y][x];
    ((r / 8) as usize, r % 8, (1u64 << (8 - r % 8)) - 1)
}

// ---------------------------------------------------------------------------
// The circuits
// ---------------------------------------------------------------------------

/// `KECCAK`: plane `y` of the call at `cycle`, the frame at `base`.
///
/// ```text
/// one_y          Σ y_v − live                 the plane, one-hot (M: y0, y4 are masks)
/// number_rule    number − 0x0513·live         ra_rule   ra − base − Σ_v 40v·y_v
/// st_*_rule      the stamps, frame_stamps(y)  pin = live − y0, pout = live − y4
/// room           ADVICE_ORIGIN·live − 200·live − base, a word
/// w{j}           frame word 10y + j at ra + 4j, read and written at
///                4·cycle + FRAME_DELTA, its gap in [0, 2^38)
/// in_w{j}        read_j − Σ_k 256^k·in[j/2][4(j mod 2) + k]
/// out_w{j}       write_j − Σ_k 256^k·out[j/2][4(j mod 2) + k]
/// p_zero{x}_{k}  y0·p[x][k]                   no parity before plane 0
/// parity{x}_{k}  (p, in, q)                   q = p ⊕ in
/// rot, dxor      theta_d under y4             D_0 from C = q
/// read   anchor (DELEGATION, base, cycle, number) under y0
///        p at st_pin, the base at st_pin + BASE, under pin
///        out at st_recv, CHI(23, y)'s plane
/// write  in at st_send, RHO(0, y)'s plane
///        q at st_pout and the base at st_pout + BASE, under pout
///        d at st_pout under y4, RHO(0, 0)'s D_0
/// ```
fn frame_rows() -> Builder {
    let mut b = Builder::new(family::KECCAK);
    let live = b.live;
    let cycle = b.mcol("cycle");
    let number = b.mcol("number");
    b.gate("number_rule", number - live * ecall::KECCAK_F1600 as u64);
    let base = b.mcol("base");
    let ra = b.mcol("ra");
    let y = one_hot(&mut b, "y", PLANES, true);
    let mut rule = ra - base;
    for (v, bit) in y.iter().enumerate() {
        rule = rule - *bit * (4 * WORDS * v) as u64;
    }
    b.gate("ra_rule", rule);
    let names = ["st_send", "st_recv", "st_pin", "st_pout"];
    let [send, recv, st_pin, st_pout] = stamps(&mut b, names, &y, &[], |_, v| frame_stamps(v));
    let pin = mask(&mut b, "pin", live - y[0]);
    let pout = mask(&mut b, "pout", live - y[PLANES - 1]);
    let words: Vec<[PolyAddress; 3]> = (0..WORDS)
        .map(|j| ["read_ts", "read_value", "write_value"].map(|c| b.mcol(&format!("w{j}_{c}"))))
        .collect();
    let end = guest_memory::ADVICE_ORIGIN as u64 - 4 * FRAME as u64;
    b.word("room", live * end - base);
    for (j, [read_ts, read, write]) in words.iter().enumerate() {
        let (name, addr) = (format!("w{j}"), Part::plus(ra, 4 * j as u64));
        access(&mut b, &name, cycle, addr, *read_ts, *read, *write);
    }
    let input = plane(&mut b, "in", true);
    let output = plane(&mut b, "out", true);
    for (j, [_, read, write]) in words.iter().enumerate() {
        let (x, h) = (j / 2, 4 * (j % 2));
        let (mut r, mut w) = (Expr::from(*read), Expr::from(*write));
        for k in 0..4 {
            r = r - input[x][h + k] * (1u64 << (8 * k));
            w = w - output[x][h + k] * (1u64 << (8 * k));
        }
        b.gate(&format!("in_w{j}"), r);
        b.gate(&format!("out_w{j}"), w);
    }
    let p = plane(&mut b, "p", true);
    let q = plane(&mut b, "q", true);
    let d = plane(&mut b, "d", true);
    let s = plane(&mut b, "s", false);
    for x in 0..PLANES {
        for k in 0..8 {
            b.gate(&format!("p_zero{x}_{k}"), y[0] * p[x][k]);
            let name = format!("parity{x}_{k}");
            b.xor8(&name, p[x][k].into(), input[x][k].into(), q[x][k].into());
        }
    }
    theta_d(&mut b, y[PLANES - 1], &q, &s, &d);
    let anchor = [
        Part::of(base),
        Part::of(cycle),
        Part::of(number),
        Part::default(),
    ];
    let delegation = address_space::DELEGATION;
    b.leaf_under(y[0], false, "read_anchor", delegation, anchor);
    let space = address_space::KECCAK;
    let chain = |stamp| {
        [
            Part::of(cycle),
            Part::plus(stamp, BASE),
            Part::of(base),
            Part::default(),
        ]
    };
    b.leaf_under(pin, false, "read_base", space, chain(st_pin));
    b.leaf_under(pout, true, "write_base", space, chain(st_pout));
    plane_leaves(&mut b, (false, "read_p"), pin, cycle, st_pin, &p);
    plane_leaves(&mut b, (false, "read_out"), live, cycle, recv, &output);
    plane_leaves(&mut b, (true, "write_in"), live, cycle, send, &input);
    plane_leaves(&mut b, (true, "write_q"), pout, cycle, st_pout, &q);
    plane_leaves(&mut b, (true, "write_d"), y[PLANES - 1], cycle, st_pout, &d);
    b
}

/// `KECCAK_RHO`: source plane `y` of round `t`.
///
/// ```text
/// one_y, one_r     the plane and the round, one-hot (W)
/// st_*_rule        the stamps, rho_stamps(t, y)        dfwd = live − y4
/// theta{x}_{k}     (a, d, t)                           t = A' = A ⊕ D[x]
/// split{x}_{k}     (Σ_v y_v·m[x][v], t, s)             s = m ⊕ t, m = 2^(8 − s) − 1
/// b{x}_{j}_rule    b − Σ_v y_v·(2^s·lo_{j−q} + hi_{j−q−1})   (q, s) of r[x][v]
///                  lo = (m + t − s)/2, hi = (t − m + s)/2^(9 − s)
/// read   a at st_a, the plane; d at st_din
/// write  d at st_dout under dfwd, to (t, y + 1)
///        lane x's 8 bytes at st_b{x} + m, m < 4: B-plane 2x + 3y, slot y
/// ```
///
/// The split's mask, the shifts and the byte indices are the plane's, so the
/// rotation's gates are degree 2 through the plane's bits.
fn rho() -> Builder {
    let mut b = Builder::new(family::KECCAK_RHO);
    let live = b.live;
    let cycle = b.mcol("cycle");
    let a = plane(&mut b, "a", true);
    let d = plane(&mut b, "d", true);
    let rotated = plane(&mut b, "b", true);
    let y = one_hot(&mut b, "y", PLANES, false);
    let r = one_hot(&mut b, "r", ROUNDS, false);
    let names = [
        "st_a", "st_din", "st_dout", "st_b0", "st_b1", "st_b2", "st_b3", "st_b4",
    ];
    let st = stamps(&mut b, names, &y, &r, rho_stamps);
    let dfwd = mask(&mut b, "dfwd", live - y[PLANES - 1]);
    let t = plane(&mut b, "t", false);
    let s = plane(&mut b, "s", false);
    let half = inverse(2);
    for x in 0..PLANES {
        let mut m = Expr::default();
        for (v, bit) in y.iter().enumerate() {
            m = m + *bit * rotation(x, v).2;
        }
        for kk in 0..8 {
            let name = format!("theta{x}_{kk}");
            b.xor8(&name, a[x][kk].into(), d[x][kk].into(), t[x][kk].into());
            let name = format!("split{x}_{kk}");
            b.xor8(&name, m.clone(), t[x][kk].into(), s[x][kk].into());
        }
        for (j, out) in rotated[x].iter().enumerate() {
            let mut e = Expr::from(*out);
            for (v, bit) in y.iter().enumerate() {
                let (q, sh, m) = rotation(x, v);
                let (lo, hi) = ((j + 8 - q) % 8, (j + 15 - q) % 8);
                let up = Fp::from_u64(1 << sh) * half;
                let down = inverse(1 << (9 - sh));
                let low = (Expr::from(t[x][lo]) - s[x][lo] + k(m)) * up;
                let high = (Expr::from(t[x][hi]) + s[x][hi] - k(m)) * down;
                e = e - *bit * (low + high);
            }
            b.gate(&format!("b{x}_{j}_rule"), e);
        }
    }
    plane_leaves(&mut b, (false, "read_a"), live, cycle, st[0], &a);
    plane_leaves(&mut b, (false, "read_d"), live, cycle, st[1], &d);
    plane_leaves(&mut b, (true, "write_d"), dfwd, cycle, st[2], &d);
    for x in 0..PLANES {
        for m in 0..4 {
            let parts = [
                Part::of(cycle),
                Part::plus(st[3 + x], m as u64),
                Part::of(rotated[x][2 * m]),
                Part::of(rotated[x][2 * m + 1]),
            ];
            let name = format!("write_b{x}_{m}");
            b.leaf(true, &name, address_space::KECCAK, parts);
        }
    }
    b
}

/// `KECCAK_CHI`: B-plane `y` of round `t`.
///
/// ```text
/// one_y, one_r     the plane and the round, one-hot (W)
/// st_*_rule        the stamps, chi_stamps(t, y)
/// pin = live − y0, pout = live − y4, dnext = y4 − y4·r23
/// chi_e{x}_{k}     (b[x+1], b[x+2], e)                 e = B[x+1] ⊕ B[x+2]
/// chi{x}_{k}       ((b[x+2] − b[x+1] + e)/2, b[x], a)   a = B[x] ⊕ (!B[x+1] & B[x+2]);
///                  c0_k in a[0][k]'s place, k ∈ IOTA_BYTES
/// iota{k}          (Σ_t r_t·RC_t[k], c0_k, a[0][k]) under y0
/// iota_keep{k}     (live − y0)·(a[0][k] − c0_k)
/// p_zero{x}_{k}    y0·p[x][k]                          parity{x}_{k}  (p, a, q)
/// rot, dxor        theta_d under dnext                 D_{t+1} from C = q
/// read   b's lane x at st_b + 4x + m, m < 4; p at st_pin under pin
/// write  a at st_a, the plane A_{t+1}[·][y]
///        q at st_pout under pout; d at st_pout under dnext, D_{t+1}
/// ```
fn chi() -> Builder {
    let mut b = Builder::new(family::KECCAK_CHI);
    let live = b.live;
    let cycle = b.mcol("cycle");
    let lanes = plane(&mut b, "b", true);
    let p = plane(&mut b, "p", true);
    let q = plane(&mut b, "q", true);
    let a = plane(&mut b, "a", true);
    let d = plane(&mut b, "d", true);
    let y = one_hot(&mut b, "y", PLANES, false);
    let r = one_hot(&mut b, "r", ROUNDS, false);
    let names = ["st_b", "st_pin", "st_pout", "st_a"];
    let [st_b, st_pin, st_pout, st_a] = stamps(&mut b, names, &y, &r, chi_stamps);
    let last = y[PLANES - 1];
    let pin = mask(&mut b, "pin", live - y[0]);
    let pout = mask(&mut b, "pout", live - last);
    let dnext = mask(&mut b, "dnext", last - last * r[ROUNDS - 1]);
    let e = plane(&mut b, "e", false);
    let c0 = IOTA_BYTES.map(|kk| b.col(&format!("c0_{kk}")));
    let s = plane(&mut b, "s", false);
    let half = inverse(2);
    for x in 0..PLANES {
        let (x1, x2) = ((x + 1) % PLANES, (x + 2) % PLANES);
        for kk in 0..8 {
            let (b1, b2) = (lanes[x1][kk], lanes[x2][kk]);
            let name = format!("chi_e{x}_{kk}");
            b.xor8(&name, b1.into(), b2.into(), e[x][kk].into());
            let and = (b2 - b1 + e[x][kk]) * half;
            let out = match IOTA_BYTES.iter().position(|i| *i == kk) {
                Some(n) if x == 0 => c0[n],
                _ => a[x][kk],
            };
            let name = format!("chi{x}_{kk}");
            b.xor8(&name, and, lanes[x][kk].into(), out.into());
        }
    }
    for (n, kk) in IOTA_BYTES.iter().enumerate() {
        let mut rc = Expr::default();
        for (t, bit) in r.iter().enumerate() {
            rc = rc + *bit * rc_byte(t, *kk);
        }
        let name = format!("iota{kk}");
        b.xor8_under(y[0], &name, rc, c0[n].into(), a[0][*kk].into());
        let keep = (live - y[0]) * (Expr::from(a[0][*kk]) - c0[n]);
        b.gate(&format!("iota_keep{kk}"), keep);
    }
    for x in 0..PLANES {
        for kk in 0..8 {
            b.gate(&format!("p_zero{x}_{kk}"), y[0] * p[x][kk]);
            let name = format!("parity{x}_{kk}");
            b.xor8(&name, p[x][kk].into(), a[x][kk].into(), q[x][kk].into());
        }
    }
    theta_d(&mut b, dnext, &q, &s, &d);
    for (x, lane) in lanes.iter().enumerate() {
        for m in 0..4 {
            let parts = [
                Part::of(cycle),
                Part::plus(st_b, (4 * x + m) as u64),
                Part::of(lane[2 * m]),
                Part::of(lane[2 * m + 1]),
            ];
            let name = format!("read_b{x}_{m}");
            b.leaf(false, &name, address_space::KECCAK, parts);
        }
    }
    plane_leaves(&mut b, (false, "read_p"), pin, cycle, st_pin, &p);
    plane_leaves(&mut b, (true, "write_a"), live, cycle, st_a, &a);
    plane_leaves(&mut b, (true, "write_q"), pout, cycle, st_pout, &q);
    plane_leaves(&mut b, (true, "write_d"), dnext, cycle, st_pout, &d);
    b
}

/// `KECCAK`'s circuit over `2^trace_vars` rows; at least `2^16`, its
/// `RANGE16` and `XOR8` tables', which the registry refuses below.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    frame_rows().artifact(trace_vars)
}

/// `KECCAK`'s channels, `RANGE16` and `XOR8`.
pub fn channels() -> Vec<ChannelSpec> {
    frame_rows().channels()
}

/// `KECCAK_RHO`'s circuit over `2^trace_vars` rows, likewise.
pub fn rho_artifact(trace_vars: u32) -> CircuitArtifact {
    rho().artifact(trace_vars)
}

/// `KECCAK_RHO`'s one channel, `XOR8`.
pub fn rho_channels() -> Vec<ChannelSpec> {
    rho().channels()
}

/// `KECCAK_CHI`'s circuit over `2^trace_vars` rows, likewise.
pub fn chi_artifact(trace_vars: u32) -> CircuitArtifact {
    chi().artifact(trace_vars)
}

/// `KECCAK_CHI`'s one channel, `XOR8`.
pub fn chi_channels() -> Vec<ChannelSpec> {
    chi().channels()
}
