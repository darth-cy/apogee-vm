//! The `FALCON512_DECODE` precompile (`docs/spec/precompiles.md` §8): the
//! Falcon-512 encoding at the frame's source decoded into 512 coefficients
//! mod `q` at its destination, a public key's `h` or a signature's `s2`, as
//! one circuit on `crate::delegation`'s builder, `FALCON_DECODE`: [`ROWS`]
//! rows a call, row `r` coefficients `4r..4r + 3`, one a **slot**, and its row
//! 0, `first`, also the frame.
//!
//! The stream is the source's bytes in address order, MSB first, read a
//! 32-bit **limb** at a time: a source word, little-endian, is the limb `BE`
//! of its bytes reversed. Between codewords a call's state is
//!
//! ```text
//! m     the mode, 0 a key and 1 a signature
//! o     the bit offset in the current limb, in [0, 32)
//! E     2^(32 − o)
//! A     the limb's bits before o, at its top: a multiple of E below 2^32
//! sa    the current limb's address
//! acc   Σ |s|² so far
//! da    DST + 8r, row r's two output words'
//! ```
//!
//! A slot takes one codeword `C` of `L` bits at `o`: a key's field `x`, `L =
//! 14`; a signature's sign `b`, 7 low bits, `k` zeros and a one, `C = (128b +
//! low)·2^(k+1) + 1`, `L = 9 + k`, `|s| = low + 128k`. Where `o + L ≥ 32` it
//! completes the limb (`c = 1`), and its **port** reads the limb's word.
//!
//! ## The columns and the rules
//!
//! ```text
//! row         M live first rest cycle stamp m o_in e_in a_in sa_in acc_in da
//!               o_out sa_out acc_out
//! first_boolean  first − first²       rest_rule   rest − live + first
//! rest_boolean   rest − rest²         m_boolean   m − m²
//! frame       FRAME words under first, MODE and END written
//!             (delegation::frame_under): src, dst, mode read; norm, end written
//! start_o     first·o_in                     start_a      first·a_in
//! start_e     first·(e_in − 2^32)            start_m      first·(m − mode)
//! start_sa    first·(sa_in − src)            start_acc    first·acc_in
//! start_da    first·(da − dst)               start_stamp  first·stamp
//! slot u      W b k_0..k_3 (bits) low p1 p2 pow x csig cw mag bs inv z a_h16,
//!               the port's bytes β_0..β_3 and gap chunks;
//!             M c e a sa (u ≥ 1) and the port's read_ts and word w;
//!             in: o, E, A, sa the row's or slot u − 1's o', e, a, sa'
//!   c_boolean     c − c²             c_live   c − c·live    0 off a live row
//!   p1_rule       p1 − live − k0 − 3k1 − 3k0k1         p1 = 2^(k0 + 2k1)
//!   p2_rule       p2 − live − 15k2 − 255k3 − 3825k2k3  p2 = 2^(4k2 + 8k3)
//!   pow_rule      pow − 2·p1·p2                        pow = 2^(k + 1), k = Σ 2^i·k_i
//!   keyk          (live − m)·(k − 5)                   a key's L = 14
//!   keyx          m·x                                  a signature's x = 0
//!   csig_rule     csig − (128b + low)·pow − live
//!   cw_rule       cw − m·csig − x                      C
//!   mag_rule      mag − m·(low + 128k)                 |s|, 0 for a key
//!   bs_rule       bs − b·mag                           mz   bs·inv − b
//!   e_out         256·e·pow − E·live − (2^32 − 1)·E·c  e = 2^(32 − o')
//!   z_rule        z − cw·e
//!   limb          2^32·A + g·z − 2^32·c·BE − g·a,      g = c + 2^32·(live − c)
//!   port          w − Σ_j 2^8j·β_j                     BE = Σ_j 2^(24 − 8j)·β_j
//!   sa'_rule      sa' − sa − 4c                        o' = o + 9·live + k − 32c
//!   RANGE16       low < 2^7; x, (q − 1)·live − x; o' < 2^5; a a word, its low
//!                 halfword plus 59·c below 2^16; β_j < 2^8; the port's gap
//!   leaves        (RAM, sa, read_ts, w) read and written back, under c
//! row out     o_out_rule  o_out − o'_3    sa_out the last sa'    E, A out: e_3, a_3
//!             acc_rule    acc_out − acc_in − Σ_u mag_u²
//!             out{i}_rule write_i − v_2i − 2^16·v_2i+1,  v = x + mag + q·b − 2·bs,
//!             the word at da + 4i, an access (delegation::access)
//! frame row   M o_e e_e a_e sa_e acc_e f, the flush port's read_ts and word;
//!             W f_inv zz, the flush port's bytes and gap chunks
//!   norm        norm − acc_e
//!   end         end − 8·sa_e + 8·src − o_e
//!   key_end     (first − mode)·(end − 7168)
//!   zz_rule     zz − mode·(5000 − end)              zz < 2^16
//!   f_inverse   o_e·f_inv − f   f_zero  (first − f)·o_e     f = first·[o_e ≠ 0]
//!   f_boolean   f − f²
//!   flush       BE_f − a_e, the flush port at sa_e under f
//! space 9     read  (cycle, stamp + j, in_j) under rest
//!             write (cycle, stamp + 4 + j, out_j)
//!             read  (cycle, 512 + j, end_j) under first
//!             (m, o), (E, A), (sa, acc), (da, 0) for j = 0..4: in the row's
//!             in-state, out its out-state with da + 8, end (mode, o_e),
//!             (e_e, a_e), (sa_e, acc_e), (dst + 1024, 0)
//! ```
//!
//! Every leaf's mask is a bit, by its booleanity rule, and zero wherever `live`
//! is: `first` as `rest = −first` is a bit there, `c` by `c_live`, and `f` as
//! `f_inverse` and `f_zero` are `gadgets::is_zero` over `o_e` with its `z` the
//! column `first − f`, so `f = first·[o_e ≠ 0]`.
//!
//! ## Why the rows are the call
//!
//! Space 9 has no init and no final: its reads and writes are equal multisets.
//! Fix a cycle and let `n_t` count its rows of stamp `t` under `rest`. A row
//! reads `t..t + 4` and writes `t + 4..t + 8`; a frame row, its anchor's and
//! one a call, writes `4..8` (`start_stamp`) and reads `512..516`. So `N_s =
//! n_s + n_{s−1} + n_{s−2} + n_{s−3}` has `N_s − N_{s−4} = [4 ≤ s < 8] − [512 ≤
//! s < 516]` for every `s` in `F_p`. As 4 generates `F_p`, its solutions
//! differ by a constant on all of `F_p`, which `p` rows would need: `N_s = [4 ≤
//! s < 512]`, and counts being nonnegative, `n_t = 1` exactly at `t = 4, 8, …,
//! 508`. A call is 128 rows, of stamps `0, 4, …, 508`, each reading what the
//! one before wrote and its frame row what the last wrote: `m` is `mode` and
//! `da = dst + 8r` throughout.
//!
//! ## Why it is the decoding
//!
//! By induction `A` is a multiple of `E = 2^(32 − o)` below `2^32`: at the
//! start, in either mode, 0 at 0, the limb empty. `C < 2^L`: a key's `x < q <
//! 2^14`, a signature's `C < 2^(k+9)`; and `L ≤ 24`. The bound on `o'` puts
//! `o + L − 32c` in `[0, 32)`, so `c = [o + L ≥ 32]` and `e = 2^(32 − o')`,
//! the next slot's `E`.
//!
//! - `c = 0`: `limb` is `2^32·(A + C·e − a) = 0` with `A + C·e < 2^32` and `a`
//!   a word, so `a = A + C·2^(32 − o − L)` over the integers, a multiple of
//!   `e`: `C` placed after `A`'s bits.
//! - `c = 1`: `o' ≤ 23`, so `2^32·A + C·e ≤ 2^64 − 2^9 < p`, and `2^32·BE + a
//!   < p`: `BE` is four bytes and `a`'s low halfword plus `59 = 2^64 − p` is
//!   one, so `a ≤ 2^32 − 60` (the call's `a` is a multiple of `2^9`). The two
//!   sides are equal integers: `BE`, the limb the port read, is `A`'s bits
//!   then `C`'s first `32 − o`, and `a` is `C`'s last `o'` bits at the next
//!   limb's top. Without the 59 an all-ones limb would read as `p` less: a
//!   key's zeros where the source holds `0xFFFFFFFF`.
//!
//! So the codewords are the stream: every completed limb read once, at `sa =
//! src + 4·(limbs before)`. The stream ends at bit `end = 8·(sa_e − src) +
//! o_e`; a key's is 7168, on a limb, and a signature's at most 5000 (`zz`).
//! Where `o_e ≠ 0` the flush reads the partial limb at `sa_e` and `flush`
//! holds it to `a_e`, both below `2^32`, so as integers: its first `o_e` bits
//! are the stream's and the rest zeros. Where `o_e = 0`, `a_e = 0`: nothing
//! is read and the port's bytes are zeros; off the frame row `f = 0` and `a_e`
//! is in no leaf. `csig ≥ 1` and its `k` zeros are what a codeword is; `mz`
//! refuses `−0`, and a key's `b`, its `mag` 0. Each `v` is the coefficient: a
//! key's `x < q`, `|s|` or `q − |s|`, below `q`; `norm` is `Σ |s|² < 2^31`,
//! exact.

use alloc::format;
use alloc::vec::Vec;

use constants::delegation::falcon::{N, Q};
use constants::delegation::falcon_decode::{
    DST, END, FRAME, KEY_END, MODE, OUTPUT, ROWS, SIGNATURE_BITS, SLOTS, SRC, WORDS,
};
use constants::delegation::Per;
use constants::{address_space, ecall, family};

use crate::delegation::{access, access_under, frame_under, Builder, Part};
use crate::family::{k as konst, Expr, T16, T32};
use crate::lookup::ChannelSpec;
use crate::{CircuitArtifact, PolyAddress};

/// A limb's bits: the source is read a word at a time.
pub const LIMB: u64 = 32;
/// A key coefficient's bits.
pub const FIELD_BITS: u64 = 14;
/// A codeword's bits but its zeros: the sign, the low bits and the one.
pub const CODEWORD: u64 = 9;
/// A signature coefficient's low bits.
pub const LOW_BITS: u32 = 7;
/// The bits of `k`, a codeword's zeros: at most 15.
pub const K_BITS: usize = 4;
/// A key field's `k`: its 14 bits less [`CODEWORD`].
pub const KEY_K: u64 = FIELD_BITS - CODEWORD;
/// A row's state tuples, at `stamp + j`.
pub const TUPLES: u64 = 4;
/// The end state's stamp, past the last row's, which the frame row reads.
pub const END_STAMP: u64 = ROWS as u64 * TUPLES;
/// A row's output bytes, its two words.
pub const ROW_BYTES: u64 = 4 * (SLOTS / 2) as u64;
/// `2^64 − p`, 59: a completing slot's `a` is at most `2^32 − 1 − WRAP`.
pub const WRAP: u64 = 0u64.wrapping_sub(field::A64_C5);

const _: () = {
    // Four slots a row, two coefficients an output word.
    assert!(ROWS * SLOTS == N && SLOTS.is_multiple_of(2) && OUTPUT == ROWS * SLOTS / 2);
    assert!(END_STAMP == ROWS as u64 * TUPLES && ROW_BYTES * ROWS as u64 == 4 * OUTPUT as u64);
    // A key: 512 fields of 14 bits, each below q.
    assert!(KEY_END as u64 == FIELD_BITS * N as u64);
    assert!(Q < 1 << FIELD_BITS);
    // A codeword's longest is 24 bits, a key's 14 among them: one spans two
    // limbs at most, and completing one leaves o' ≤ 23, so e ≥ 2^9 > 59:
    // 2^32·A + C·e ≤ 2^64 − e < p, and a, a multiple of e, has its low
    // halfword plus 59 below 2^16.
    let longest = CODEWORD + (1 << K_BITS) - 1;
    assert!(FIELD_BITS <= longest && longest < LIMB);
    let least: u64 = 1 << (LIMB - (longest - 1));
    assert!(WRAP == 59 && least > WRAP && least <= 1 << 16);
    // o' < 32 is RANGE16 of 2^11·o'; |s| ≤ 2047, Σ|s|² < 2^31.
    assert!(LIMB == 1 << 5);
    let most = (1 << LOW_BITS) - 1 + (1 << LOW_BITS) * ((1 << K_BITS) - 1);
    assert!(most == 2047 && (N as u64) * most * most < 1 << 31);
    assert!(SIGNATURE_BITS < 1 << 16);
    // The registry's words an entry and rows a call.
    let t = &constants::delegation::TYPES[7];
    assert!(t.0 == family::FALCON_DECODE && t.1 == ecall::FALCON512_DECODE);
    assert!(t.2 == WORDS && t.3 == ROWS as u32 && matches!(t.4, Per::Decode));
};

/// A port: the four bytes of the word `w`, `<name>_b0..3`, each below `2^8`,
/// and `<name>_port`, `w` their little-endian value. Returns the limb, their
/// big-endian value.
fn port(b: &mut Builder, name: &str, w: PolyAddress) -> Expr {
    let (mut rule, mut limb) = (Expr::from(w), Expr::default());
    for j in 0..4 {
        let x = b.col(&format!("{name}_b{j}"));
        b.small(&format!("{name}_b{j}"), x, 8);
        rule = rule - x * (1u64 << (8 * j));
        limb = limb + x * (1u64 << (24 - 8 * j));
    }
    b.gate(&format!("{name}_port"), rule);
    limb
}

/// `FALCON_DECODE`, the module's table.
fn decode() -> Builder {
    let mut b = Builder::new(family::FALCON_DECODE);
    let live = b.live;
    let first = b.mcol("first");
    b.gate("first_boolean", first - first * first);
    let written = |j: usize| j == MODE || j == END;
    let f = frame_under(&mut b, first, ecall::FALCON512_DECODE, FRAME, written);
    let cycle = f.cycle;
    let (src, dst, mode) = (f.words[SRC].read, f.words[DST].read, f.words[MODE].read);
    let (norm, end) = (f.words[MODE].write, f.words[END].write);
    let [rest, stamp, m, o_in, e_in, a_in, sa_in, acc_in, da, o_out, sa_out, acc_out] = [
        "rest", "stamp", "m", "o_in", "e_in", "a_in", "sa_in", "acc_in", "da", "o_out", "sa_out",
        "acc_out",
    ]
    .map(|c| b.mcol(c));
    b.gate("rest_rule", rest - live + first);
    b.gate("rest_boolean", rest - rest * rest);
    b.gate("m_boolean", m - m * m);
    // The start, on the frame row: the limb empty, in either mode.
    b.gate("start_o", o_in * first);
    b.gate("start_e", (e_in - konst(T32)) * first);
    b.gate("start_a", a_in * first);
    b.gate("start_sa", (sa_in - src) * first);
    b.gate("start_acc", acc_in * first);
    b.gate("start_da", (da - dst) * first);
    b.gate("start_stamp", stamp * first);
    b.gate("start_m", (m - mode) * first);

    // The slots, each from the one before's out-state, slot 0 from the row's.
    let (mut o, mut e, mut a, mut sa) = (Expr::from(o_in), e_in, a_in, sa_in);
    let mut squares = acc_out - acc_in;
    let mut v = Vec::with_capacity(SLOTS);
    for u in 0..SLOTS {
        let bit = b.bit(&format!("b{u}"));
        let ks: Vec<PolyAddress> = (0..K_BITS).map(|i| b.bit(&format!("k{u}_{i}"))).collect();
        let k = (0..K_BITS).fold(Expr::default(), |s, i| s + ks[i] * (1u64 << i));
        let [low, p1, p2, pow, x, csig, cw, mag, bs, inv, z] = [
            "low", "p1_", "p2_", "pow", "x", "csig", "cw", "mag", "bs", "inv", "z",
        ]
        .map(|n| b.col(&format!("{n}{u}")));
        let [c, e_out, a_out] = ["c", "e", "a"].map(|n| b.mcol(&format!("{n}{u}")));
        b.gate(&format!("c{u}_boolean"), c - c * c);
        b.gate(&format!("c{u}_live"), c - c * live);
        let p1_rule = p1 - live - ks[0] - ks[1] * 3 - ks[0] * ks[1] * 3;
        b.gate(&format!("p1_{u}_rule"), p1_rule);
        let p2_rule = p2 - live - ks[2] * 15 - ks[3] * 255 - ks[2] * ks[3] * 3825;
        b.gate(&format!("p2_{u}_rule"), p2_rule);
        b.gate(&format!("pow{u}_rule"), pow - p1 * p2 * 2);
        b.gate(&format!("keyk{u}"), (live - m) * (k.clone() - konst(KEY_K)));
        b.gate(&format!("keyx{u}"), m * x);
        b.gate(
            &format!("csig{u}_rule"),
            csig - (bit * 128 + low) * pow - live,
        );
        b.gate(&format!("cw{u}_rule"), cw - m * csig - x);
        b.gate(&format!("mag{u}_rule"), mag - m * (k.clone() * 128 + low));
        b.gate(&format!("bs{u}_rule"), bs - bit * mag);
        b.gate(&format!("mz{u}"), bs * inv - bit);
        let placed = e_out * pow * 256 - e * live - e * c * (T32 - 1);
        b.gate(&format!("e_out{u}"), placed);
        b.gate(&format!("z{u}_rule"), z - cw * e_out);
        let name = format!("p{u}");
        let [read_ts, w] = ["read_ts", "read_value"].map(|n| b.mcol(&format!("{name}_{n}")));
        let be = port(&mut b, &name, w);
        let g = Expr::from(c) + (live - c) * T32;
        let limb = a * T32 + g.clone() * z - be * c * T32 - g * a_out;
        b.gate(&format!("limb{u}"), limb);
        access_under(&mut b, c, &name, cycle, Part::of(sa), read_ts, w, w);
        let next = o + live * CODEWORD + k - c * LIMB;
        b.range16(&format!("o{u}_range"), next.clone());
        b.range16(&format!("o{u}_scaled"), next.clone() * (1u64 << 11));
        b.small(&format!("low{u}"), low, LOW_BITS);
        b.range16(&format!("x{u}_low"), x.into());
        b.range16(&format!("x{u}_high"), live * (Q - 1) - x);
        let h = b.col(&format!("a{u}_h16"));
        b.range16(&format!("a{u}_hi_range"), h.into());
        b.range16(&format!("a{u}_lo_range"), a_out - h * T16 + c * WRAP);
        let (sa_next, label) = match u + 1 < SLOTS {
            true => (b.mcol(&format!("sa{}", u + 1)), format!("sa{}_rule", u + 1)),
            false => (sa_out, "sa_out_rule".into()),
        };
        b.gate(&label, sa_next - sa - c * 4);
        squares = squares - mag * mag;
        v.push(x + mag + bit * Q - bs * 2);
        (o, e, a, sa) = (next, e_out, a_out, sa_next);
    }
    b.gate("o_out_rule", o_out - o);
    b.gate("acc_rule", squares);
    for i in 0..SLOTS / 2 {
        let name = format!("out{i}");
        let [read_ts, read, write] =
            ["read_ts", "read_value", "write_value"].map(|n| b.mcol(&format!("{name}_{n}")));
        let rule = write - v[2 * i].clone() - v[2 * i + 1].clone() * T16;
        b.gate(&format!("{name}_rule"), rule);
        let at = Part::plus(da, 4 * i as u64);
        access(&mut b, &name, cycle, at, read_ts, read, write);
    }

    // The frame row's end state, NORM, END and the flush.
    let [o_e, e_e, a_e, sa_e, acc_e, fm] =
        ["o_e", "e_e", "a_e", "sa_e", "acc_e", "f"].map(|c| b.mcol(c));
    b.gate("norm", norm - acc_e);
    b.gate("end", end - sa_e * 8 + src * 8 - o_e);
    b.gate("key_end", (first - mode) * (end - konst(KEY_END as u64)));
    let zz = b.col("zz");
    b.gate("zz_rule", zz - mode * SIGNATURE_BITS as u64 + mode * end);
    b.range16("zz_range", zz.into());
    let f_inv = b.col("f_inv");
    b.gate("f_boolean", fm - fm * fm);
    b.gate("f_inverse", o_e * f_inv - fm);
    b.gate("f_zero", (first - fm) * o_e);
    let [read_ts, w] = ["flush_read_ts", "flush_read_value"].map(|c| b.mcol(c));
    let be = port(&mut b, "flush", w);
    access_under(&mut b, fm, "flush", cycle, Part::of(sa_e), read_ts, w, w);
    b.gate("flush", be - a_e);

    // The chain through space 9.
    let space = address_space::FALCON_DECODE;
    let pair = |x: PolyAddress, y: PolyAddress| [Part::of(x), Part::of(y)];
    let ins = [
        pair(m, o_in),
        pair(e_in, a_in),
        pair(sa_in, acc_in),
        [Part::of(da), Part::default()],
    ];
    let outs = [
        pair(m, o_out),
        pair(e, a),
        pair(sa_out, acc_out),
        [Part::plus(da, ROW_BYTES), Part::default()],
    ];
    let ends = [
        pair(mode, o_e),
        pair(e_e, a_e),
        pair(sa_e, acc_e),
        [Part::plus(dst, 4 * OUTPUT as u64), Part::default()],
    ];
    for (j, ((into, out), ended)) in ins.into_iter().zip(outs).zip(ends).enumerate() {
        let j = j as u64;
        let [x, y] = into;
        let parts = [Part::of(cycle), Part::plus(stamp, j), x, y];
        b.leaf_under(rest, false, &format!("receive{j}"), space, parts);
        let [x, y] = out;
        let parts = [Part::of(cycle), Part::plus(stamp, TUPLES + j), x, y];
        b.leaf(true, &format!("send{j}"), space, parts);
        let [x, y] = ended;
        let parts = [Part::of(cycle), Part::constant(END_STAMP + j), x, y];
        b.leaf_under(first, false, &format!("receive_end{j}"), space, parts);
    }
    b
}

/// `FALCON_DECODE`'s circuit over `2^trace_vars` rows; at least `2^16`, its
/// `RANGE16` table's, which the registry refuses below.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    decode().artifact(trace_vars)
}

/// `FALCON_DECODE`'s one channel, `RANGE16`.
pub fn channels() -> Vec<ChannelSpec> {
    decode().channels()
}

#[cfg(test)]
mod tests {
    use super::*;
    use constants::lookup_channel::RANGE16;

    /// The budgets, counted: at most `MAX_COMMITTED` committed columns, and
    /// `RANGE16`'s obligations each slot's 20, the outputs' gaps, the frame's
    /// gaps and room, `zz` and the flush's 12 — 119, a tree of 128 leaves
    /// with 8 obligations to spare before the next, 256.
    #[test]
    fn falcon_decode_keeps_its_budgets() {
        let a = artifact(16);
        let committed = a.memory.len() + a.witness.len() + a.setup.len();
        assert!(
            committed <= crate::delegation::MAX_COMMITTED,
            "{committed} committed"
        );
        let obligations = a.lookups.iter().filter(|l| l.channel == RANGE16).count();
        let slot = 2 + 2 + 2 + 2 + 2 * 4 + 4;
        let flush = 2 * 4 + 4;
        let want = SLOTS * slot + (SLOTS / 2) * 4 + FRAME * 4 + 2 + 1 + flush;
        assert_eq!((obligations, want), (119, 119));
        let leaves = (obligations + 1).next_power_of_two();
        assert_eq!((leaves, leaves - 1 - obligations), (128, 8));
    }
}
