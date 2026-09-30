//! The `KECCAK_F` delegation family's circuit: **one Keccak round a row**, over
//! the 51-word frame a delegation request handed over.
//!
//! `docs/spec/delegation.md` §6 is normative: the frame, the anchor, the three
//! request-side zeroings, the five transformations and the two frame checks.
//! This file is that document as data.
//!
//! # What changed at S26d, and why
//!
//! S21's row was a **whole** keccak-f[1600] permutation: 1,600 boolean state
//! columns, 24 seven-layer round blocks, 354,762 inner columns over 177 layers.
//! All 24 rounds and all 1,600 bits coexisted horizontally, so the row could
//! only be afforded at `2^8` — 256 permutations a shard — and five such shards
//! were **97%** of a measured mini-block's proof bytes
//! (`docs/spec/delegation.md` §9.1).
//!
//! This is the other trade. One row is one round, a permutation is 24
//! consecutive invocations, and what glues them is the same thing that glues
//! `EC_ADD`'s three: **the frame is ordinary RAM**, so the global memory
//! multiset proves round `r`'s written state is round `r + 1`'s read state, and
//! the guest's own proven loop supplies the round numbers. There is no second
//! cross-row mechanism, because there does not need to be one.
//!
//! The width that buys is the whole point. There is **no bit anywhere in this
//! circuit** but the structural selectors: the committed unit is a **byte**, and
//! every Boolean operation of the round is one obligation on the `XOR8` channel
//! — a virtual table of the 65,536 triples `(a, b, a ^ b)`
//! (`docs/spec/lookup.md` §14). `AND`, `ANDN` and `OR` are then *linear forms*
//! over the result, because `a & b = (a + b − (a ^ b)) / 2`, and so is a byte's
//! rotation: masking a byte's top `s` bits is one XOR against a literal, and
//! the rotated byte is a literal-weighted combination of the byte and its mask.
//!
//! The circuit is therefore **flat**, like `EC_ADD`'s and `MOD_MUL`'s: every
//! relation is a lookup or a degree-≤2 enforcing gate over base columns, no
//! relation produces an inner column, and the only inner columns in the whole
//! artifact are the two memory product trees, the two channels' fraction trees
//! and the halving phase. ~5,490 of them at `2^18` against 354,762, at 1,764
//! committed columns against 3,764.
//!
//! ```text
//! M[0]            cycle          the requesting cycle: the 51 frame writes ride
//!                                4·cycle + FRAME_DELTA = 4·cycle, the anchor's
//!                                teardown read 4·cycle + ANCHOR_DELTA = 4·cycle + 3,
//!                                and the anchor's answer tuple a literal 0
//! M[1]            live           the row mask, and the one mask every leaf carries
//! M[2]            base           the frame base pointer, and the anchor's address
//! M[3]            anchor_value   what the request wrote back on its mirror query
//! M[4 + 4j ..]    frame word j:  addr, read_ts, read_value, write_value
//! W[0..102]       gap chunks     two a frame read, the low one derived
//! W[102..106]     base_low, base_low_hi, base_room, base_room_hi
//! W[106..130]     round_sel      24 one-hot round selectors
//! W[130..134]     rc             the round constant's four nonzero bytes
//! W[134..334]     state_in       the input state, 25 lanes of 8 bytes
//! W[334..494]     parity         theta's five-fold XOR, four steps a byte
//! W[494..534]     c_mask         C ^ 0x80, which is theta's rotate-by-one
//! W[534..574]     theta_d        D[x], one byte a column
//! W[574..774]     theta_a        A' = A ^ D
//! W[774..950]     rho_mask       A' ^ mask(s), for the 22 lanes rho splits
//! W[950..1150]    rho_out        B, the state after rho and pi
//! W[1150..1350]   chi_and        B1 ^ B2, from which (!B1) & B2 is linear
//! W[1350..1550]   chi_out        chi's output
//! W[1550..1554]   iota_out       lane (0,0)'s four bytes after iota
//! W[1554..1556]   the RANGE16 and XOR8 multiplicity columns
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::{address_space, keccak as k, lookup_channel};
use field::Fr;

use crate::delegation as d;
use crate::lookup::ChannelSpec;
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

// ---------------------------------------------------------------------------
// What the ABI pins
// ---------------------------------------------------------------------------

/// Every byte position outside `constants::keccak::IOTA_BYTES` is zero in every
/// round constant, which is why iota is four obligations and not eight.
///
/// The constant is evaluated in `constants`; naming it here is what makes this
/// file's dependence on it explicit rather than a comment.
const _: () = k::IOTA_BYTES_ARE_THE_ONLY_ONES;

// ---------------------------------------------------------------------------
// The shape
// ---------------------------------------------------------------------------

/// Frame words: the round selector and the 50 state words.
const WORDS: usize = k::FRAME_WORDS;

/// Bytes in a lane, which is the committed unit's count per lane.
const LANE_BYTES: usize = k::LANE_BITS / 8;

/// Bytes in the state: the `W` block `state_in`, `theta_a`, `rho_out`,
/// `chi_and` and `chi_out` each occupy.
const STATE: usize = k::LANES * LANE_BYTES;

/// Bytes in theta's parity block: five columns of the state, eight bytes each.
const PARITY_BYTES: usize = 5 * LANE_BYTES;

/// Steps in one parity byte's XOR chain: five lanes fold in four XORs.
const PARITY_STEPS: usize = 4;

/// Lanes whose rho rotation is **not** a whole number of bytes, and so need a
/// byte split: every lane but the three at 0, 8 and 56.
const SPLIT_LANES: usize = 22;

/// `M[0]`: the requesting cycle, which stamps every write the invocation makes.
pub const CYCLE: PolyAddress = d::CYCLE;
/// `M[1]`: the row mask. One mask for the whole row — the 51 frame words and
/// the anchor are one invocation, live or not together.
pub const LIVE: PolyAddress = d::LIVE;
/// `M[2]`: the frame base pointer, and the anchor tuple's address.
pub const BASE: PolyAddress = d::BASE;
/// `M[3]`: the value the request wrote back on its mirror query.
pub const ANCHOR_VALUE: PolyAddress = d::ANCHOR_VALUE;

/// A frame word's field: the address it reads and writes.
pub const WORD_ADDR: u32 = d::WORD_ADDR;
/// A frame word's field: the timestamp of the write it reads.
pub const WORD_READ_TS: u32 = d::WORD_READ_TS;
/// A frame word's field: the word before the round.
pub const WORD_READ_VALUE: u32 = d::WORD_READ_VALUE;
/// A frame word's field: the word after it.
pub const WORD_WRITE_VALUE: u32 = d::WORD_WRITE_VALUE;

/// `M[4 + 4j + field]`: one field of frame word `j`.
pub fn word(j: usize, field: u32) -> PolyAddress {
    d::word(j, field)
}

/// `M` columns: the four head columns and four a frame word.
pub const MEMORY_COLUMNS: usize = d::HEAD_COLUMNS + 4 * WORDS;

// ---------------------------------------------------------------------------
// The witness layout, in order
// ---------------------------------------------------------------------------

const fn w(i: usize) -> PolyAddress {
    PolyAddress::Witness(i as u32)
}

const fn gap_chunks() -> usize {
    0
}

const fn base_block() -> usize {
    gap_chunks() + d::GAP_CHUNKS * WORDS
}

const fn round_sel_block() -> usize {
    base_block() + 4
}

const fn rc_block() -> usize {
    round_sel_block() + k::ROUNDS
}

const fn state_in_block() -> usize {
    rc_block() + k::IOTA_BYTES.len()
}

const fn parity_block() -> usize {
    state_in_block() + STATE
}

const fn c_mask_block() -> usize {
    parity_block() + PARITY_BYTES * PARITY_STEPS
}

const fn theta_d_block() -> usize {
    c_mask_block() + PARITY_BYTES
}

const fn theta_a_block() -> usize {
    theta_d_block() + PARITY_BYTES
}

const fn rho_mask_block() -> usize {
    theta_a_block() + STATE
}

const fn rho_out_block() -> usize {
    rho_mask_block() + SPLIT_LANES * LANE_BYTES
}

const fn chi_and_block() -> usize {
    rho_out_block() + STATE
}

const fn chi_out_block() -> usize {
    chi_and_block() + STATE
}

const fn iota_out_block() -> usize {
    chi_out_block() + STATE
}

const fn multiplicity_block() -> usize {
    iota_out_block() + k::IOTA_BYTES.len()
}

/// `W` columns: the layout above, and the two multiplicity columns last.
pub const WITNESS_COLUMNS: usize = multiplicity_block() + 2;

/// Chunk `c` of frame word `j`'s timestamp gap, `c < 2`, the low part derived.
pub fn gap_chunk(j: usize, c: usize) -> PolyAddress {
    w(gap_chunks() + d::GAP_CHUNKS * j + c)
}

/// `(base − RAM_ORIGIN) / 4`.
pub fn base_low() -> PolyAddress {
    w(base_block())
}

/// [`base_low`]'s high halfword.
pub fn base_low_hi() -> PolyAddress {
    w(base_block() + 1)
}

/// `2^31 − frame bytes − base`.
pub fn base_room() -> PolyAddress {
    w(base_block() + 2)
}

/// [`base_room`]'s high halfword.
pub fn base_room_hi() -> PolyAddress {
    w(base_block() + 3)
}

/// The one-hot selector of round `r`.
///
/// Twenty-four boolean columns, one degree-1 gate pinning the frame's round
/// word to them and one holding their sum to `live`, which is what makes the
/// round `[0, 24)` **structurally** and supplies the round constant as a
/// literal (`m_limb{k}_rule`'s pattern in `mod_mul`).
pub fn round_sel(r: usize) -> PolyAddress {
    w(round_sel_block() + r)
}

/// Byte `IOTA_BYTES[t]` of this row's round constant.
pub fn rc(t: usize) -> PolyAddress {
    w(rc_block() + t)
}

/// Byte `b` of the input state's lane `i`, `i = 5y + x`.
pub fn state_in(i: usize, b: usize) -> PolyAddress {
    w(state_in_block() + LANE_BYTES * i + b)
}

/// Step `s` of the parity chain at column `x`, byte `b`: `s = 0` is
/// `A[x][0] ^ A[x][1]` and `s = 3` is `C[x]` itself.
pub fn parity(x: usize, b: usize, s: usize) -> PolyAddress {
    w(parity_block() + PARITY_STEPS * (LANE_BYTES * x + b) + s)
}

/// `C[x]`'s byte `b`: the last step of its parity chain.
pub fn theta_c(x: usize, b: usize) -> PolyAddress {
    parity(x, b, PARITY_STEPS - 1)
}

/// `C[x][b] ^ 0x80`, from which `C[x][b] & 0x80` is linear — theta's
/// rotate-left-by-one.
pub fn c_mask(x: usize, b: usize) -> PolyAddress {
    w(c_mask_block() + LANE_BYTES * x + b)
}

/// `D[x]`'s byte `b`.
pub fn theta_d(x: usize, b: usize) -> PolyAddress {
    w(theta_d_block() + LANE_BYTES * x + b)
}

/// `A'[i] = A[i] ^ D[i mod 5]`, byte `b`.
pub fn theta_a(i: usize, b: usize) -> PolyAddress {
    w(theta_a_block() + LANE_BYTES * i + b)
}

/// `A'[i][b] ^ mask(s)` for a lane whose rotation is not a whole byte, `s`
/// being that rotation mod 8. Panics on a lane [`mask_slot`] gives no slot.
pub fn rho_mask(i: usize, b: usize) -> PolyAddress {
    let slot = mask_slot(i).expect("a lane whose rho rotation is a whole number of bytes");
    w(rho_mask_block() + LANE_BYTES * slot + b)
}

/// `B[i]`, the state after rho and pi, byte `b`.
pub fn rho_out(i: usize, b: usize) -> PolyAddress {
    w(rho_out_block() + LANE_BYTES * i + b)
}

/// `B[(X+1) mod 5][Y] ^ B[(X+2) mod 5][Y]` for output lane `i = 5Y + X`, byte
/// `b`, from which `(!B1) & B2` is `(B2 − B1 + this) / 2`.
pub fn chi_and(i: usize, b: usize) -> PolyAddress {
    w(chi_and_block() + LANE_BYTES * i + b)
}

/// Chi's output at lane `i`, byte `b`. For lane 0's four iota bytes this is the
/// value **before** iota; [`iota_out`] is after.
pub fn chi_out(i: usize, b: usize) -> PolyAddress {
    w(chi_out_block() + LANE_BYTES * i + b)
}

/// Lane `(0, 0)`'s byte `IOTA_BYTES[t]` after iota.
pub fn iota_out(t: usize) -> PolyAddress {
    w(iota_out_block() + t)
}

/// The `RANGE16` channel's multiplicity column.
pub fn range16_multiplicity() -> PolyAddress {
    w(multiplicity_block())
}

/// The `XOR8` channel's multiplicity column.
pub fn xor8_multiplicity() -> PolyAddress {
    w(multiplicity_block() + 1)
}

// ---------------------------------------------------------------------------
// The permutation's indexing
// ---------------------------------------------------------------------------

/// The lane index of `A[x][y]`: `5y + x`, which is the frame's lane order too.
fn lane(x: usize, y: usize) -> usize {
    5 * y + x
}

/// Lane `i`'s rho rotation, a rotate-**left** count in `[0, 64)`.
fn lane_rotation(i: usize) -> u32 {
    k::ROTATIONS[i / 5][i % 5]
}

/// Lane `i`'s slot in the `rho_mask` block, or `None` when its rotation is a
/// whole number of bytes and the rotation is a pure byte permutation.
fn mask_slot(i: usize) -> Option<usize> {
    if lane_rotation(i).is_multiple_of(8) {
        return None;
    }
    Some(
        (0..i)
            .filter(|j| !lane_rotation(*j).is_multiple_of(8))
            .count(),
    )
}

/// The input lane rho and pi place at output lane `(X, Y)`, and its rotation.
///
/// The forward map is `B[y][2x + 3y] = ROTL(A'[x][y], ROTATIONS[y][x])`, so
/// `(X, Y)` reads `y = X` and `x = (X + 3Y) mod 5` — the inverse of
/// `2x + 3y ≡ Y (mod 5)`, since `2·(X + 3Y) + 3X = 5X + 6Y`.
fn rho_pi_source(big_x: usize, big_y: usize) -> (usize, u32) {
    let x = (big_x + 3 * big_y) % 5;
    let y = big_x;
    (lane(x, y), k::ROTATIONS[y][x])
}

/// The frame word holding lane `i`'s half `h`, low half first.
fn lane_word(i: usize, h: usize) -> usize {
    k::STATE_WORD + 2 * i + h
}

/// The column holding lane `i`'s output byte `b`: iota's where iota touches it,
/// chi's everywhere else.
fn out_byte(i: usize, b: usize) -> PolyAddress {
    match k::IOTA_BYTES.iter().position(|p| *p == b) {
        Some(t) if i == 0 => iota_out(t),
        _ => chi_out(i, b),
    }
}

// ---------------------------------------------------------------------------
// Byte arithmetic over the XOR8 table
// ---------------------------------------------------------------------------

/// `1/2` in `Fr`, the coefficient that turns an XOR into an AND.
fn half() -> Fr {
    Fr::from_u64(2)
        .inverse()
        .expect("2 is invertible in a field of odd characteristic")
}

/// The byte mask of the top `s` bits, `0 < s < 8`.
fn top_mask(s: u32) -> u64 {
    256 - (1u64 << (8 - s))
}

/// A `Linear` expression over `terms` with `constant`.
fn expr(terms: Vec<(Coeff, PolyAddress)>, constant: Fr) -> GateDef {
    GateDef::Linear {
        terms,
        constant: Coeff::Literal(constant),
    }
}

/// One `XOR8` obligation: `(e0, e1, e2)` is a row of `(a, b, a ^ b)`.
///
/// Position 0 may be any literal-weighted linear form with a constant, which is
/// what lets every derived value of this circuit — a rotated byte, an `ANDN` —
/// be an operand without a column of its own. Positions 1 and 2 must be single
/// columns with unit coefficients, because `β^j·c` is not one `Coeff`
/// (`crate::lookup::row_denominator`), and that is exactly why `B` is committed.
///
/// **Membership bounds all three positions to `[0, 256)` individually.** That is
/// the property a packed key `a + 256·b` would not have, and every bound in
/// this circuit is one use of it.
fn xor8(name: String, e0: GateDef, b: PolyAddress, out: PolyAddress) -> LookupExpr {
    LookupExpr {
        name,
        channel: lookup_channel::XOR8,
        selector: LIVE,
        tuple: vec![
            e0,
            expr(vec![(d::lit(1), b)], Fr::ZERO),
            expr(vec![(d::lit(1), out)], Fr::ZERO),
        ],
    }
}

/// `a ^ b = out` with both operands single columns.
fn xor8_cols(name: String, a: PolyAddress, b: PolyAddress, out: PolyAddress) -> LookupExpr {
    xor8(name, expr(vec![(d::lit(1), a)], Fr::ZERO), b, out)
}

/// `ROTL64(v, r)`'s byte `j`, as a linear form over `v`'s byte columns and the
/// masked columns `m`, plus its constant.
///
/// Write `r = 8q + s`. Byte `j` of the rotation is
/// `2^s · lo(v[u]) + hi(v[w])` with `u = (j − q) mod 8`, `w = (j − q − 1) mod 8`,
/// `hi(x) = x >> (8 − s)` and `lo(x) = x − 2^{8−s}·hi(x)`. With
/// `m = v ^ mask(s)` the table pins, `v & mask(s) = (v + mask − m) / 2`, so
///
/// ```text
/// hi(v) = (v + mask − m) / 2^{9−s}      lo(v) = (v − mask + m) / 2
/// ```
///
/// and the byte is `2^{s−1}·(v[u] + m[u]) + 2^{s−9}·(v[w] − m[w])` plus
/// `mask·(2^{s−9} − 2^{s−1})`. Every weight is a literal `Fr`: `2^{s−9}` is the
/// inverse of `2^{9−s}`, and it is exact rather than approximate because `m` is
/// the true XOR, so `v & mask` is a genuine multiple of `2^{8−s}`.
///
/// At `s = 0` the rotation is a byte permutation and `m` is never read.
fn rotl_byte(
    byte: &dyn Fn(usize) -> PolyAddress,
    mask: &dyn Fn(usize) -> PolyAddress,
    r: u32,
    j: usize,
) -> (Vec<(Coeff, PolyAddress)>, Fr) {
    let (q, s) = ((r / 8) as usize, r % 8);
    let u = (j + LANE_BYTES - q % LANE_BYTES) % LANE_BYTES;
    if s == 0 {
        return (vec![(d::lit(1), byte(u))], Fr::ZERO);
    }
    let v = (u + LANE_BYTES - 1) % LANE_BYTES;
    let low = d::pow2(s) * half();
    let high = d::pow2(9 - s)
        .inverse()
        .expect("a power of two is invertible");
    (
        vec![
            (Coeff::Literal(low), byte(u)),
            (Coeff::Literal(low), mask(u)),
            (Coeff::Literal(high), byte(v)),
            (Coeff::Literal(-high), mask(v)),
        ],
        Fr::from_u64(top_mask(s)) * (high - low),
    )
}

// ---------------------------------------------------------------------------
// The enforcing gates
// ---------------------------------------------------------------------------

/// The round selector, the round constant it names, and the frame word it is
/// pinned to.
///
/// `one_round_a_live_row` is load-bearing and not decorative, for
/// `mod_mul::one_modulus_a_live_row`'s reason at its sharpest: the codes here
/// are `0..24`, so **every** pair sums to another round's word — `1 + 2 = 3` —
/// and without it a row could claim two rounds and XOR two round constants
/// into lane `(0,0)`.
fn selector_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for r in 0..k::ROUNDS {
        out.push((format!("round{r}_boolean"), d::booleanity(round_sel(r))));
    }
    {
        let mut terms = vec![(d::lit(1), word(k::ROUND_WORD, WORD_READ_VALUE))];
        for r in 0..k::ROUNDS {
            terms.push((d::neg(r as u64), round_sel(r)));
        }
        out.push(("round_rule".to_string(), d::linear(terms)));
    }
    {
        let mut terms: Vec<(Coeff, PolyAddress)> =
            (0..k::ROUNDS).map(|r| (d::lit(1), round_sel(r))).collect();
        terms.push((d::neg(1), LIVE));
        out.push(("one_round_a_live_row".to_string(), d::linear(terms)));
    }
    for (t, b) in k::IOTA_BYTES.iter().enumerate() {
        let mut terms = vec![(d::lit(1), rc(t))];
        for (r, constant) in k::ROUND_CONSTANTS.iter().enumerate() {
            let byte = (constant >> (8 * b)) & 0xff;
            if byte != 0 {
                terms.push((d::neg(byte), round_sel(r)));
            }
        }
        out.push((format!("rc{t}_rule"), d::linear(terms)));
    }
    out
}

/// The frame's words and the state's bytes, in both directions.
///
/// `input_w{j}` and `output_w{j}` are **ungated and degree 1**: both sides are
/// zero on the all-zero padding row, and each gate is the word's byte
/// decomposition *and* its 32-bit bound at once, the bytes being bounded by the
/// `XOR8` obligations that read them. That is why no frame word of this family
/// carries a `bound32` pair, where every one of `EC_ADD`'s does.
///
/// `writes_back_w{ROUND_WORD}` is the round selector surviving the call, so the
/// guest's next iteration overwrites a word it wrote and not one this circuit
/// invented.
fn frame_value_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = vec![(
        format!("writes_back_w{}", k::ROUND_WORD),
        d::linear(vec![
            (d::lit(1), word(k::ROUND_WORD, WORD_WRITE_VALUE)),
            (d::neg(1), word(k::ROUND_WORD, WORD_READ_VALUE)),
        ]),
    )];
    for i in 0..k::LANES {
        for h in 0..2 {
            let j = lane_word(i, h);
            let mut read = vec![(d::lit(1), word(j, WORD_READ_VALUE))];
            let mut write = vec![(d::lit(1), word(j, WORD_WRITE_VALUE))];
            for m in 0..4 {
                let b = 4 * h + m;
                let weight = Coeff::Literal(-d::pow2(8 * m as u32));
                read.push((weight, state_in(i, b)));
                write.push((weight, out_byte(i, b)));
            }
            out.push((format!("input_w{j}"), d::linear(read)));
            out.push((format!("output_w{j}"), d::linear(write)));
        }
    }
    out
}

/// `B = pi(rho(A'))`, one degree-1 gate a byte.
///
/// The rotation's constant rides `live`, as `sha256`'s round constants do: a
/// gate carrying a bare nonzero constant cannot hold on the all-zero padding
/// row, and `build::zero_on_zero_row` refuses it.
///
/// `B` is committed rather than derived because chi needs it at tuple position
/// 1, where only a unit-weighted column may sit — and every lane is `B0` for
/// itself, so there is no lane whose column could be dropped.
fn rho_pi_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for big_y in 0..5 {
        for big_x in 0..5 {
            let target = lane(big_x, big_y);
            let (source, r) = rho_pi_source(big_x, big_y);
            for j in 0..LANE_BYTES {
                let (terms, constant) =
                    rotl_byte(&|b| theta_a(source, b), &|b| rho_mask(source, b), r, j);
                let mut gate = vec![(d::lit(1), rho_out(target, j))];
                for (c, x) in terms {
                    let Coeff::Literal(v) = c else {
                        panic!("keccak: a rotation weight is a literal")
                    };
                    gate.push((Coeff::Literal(-v), x));
                }
                if constant != Fr::ZERO {
                    gate.push((Coeff::Literal(-constant), LIVE));
                }
                out.push((format!("rho_pi_l{target}_b{j}"), d::linear(gate)));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The round, as obligations
// ---------------------------------------------------------------------------

/// Theta, rho, pi, chi and iota as 1,020 `XOR8` obligations, in artifact order.
///
/// Nothing here is a gate. `theta`'s `D`, `rho`'s split and `chi`'s `ANDN` are
/// *linear forms* at tuple position 0, and the obligation is what pins each
/// output column — so the five transformations cost 1,020 fractions and no
/// inner column of their own.
fn round_lookups() -> Vec<LookupExpr> {
    let mut out: Vec<LookupExpr> = Vec::new();

    // theta, step 1: C[x] = A[x][0] ^ .. ^ A[x][4], four obligations a byte.
    for x in 0..5 {
        for b in 0..LANE_BYTES {
            for s in 0..PARITY_STEPS {
                let a = match s {
                    0 => state_in(lane(x, 0), b),
                    _ => parity(x, b, s - 1),
                };
                out.push(xor8_cols(
                    format!("parity_x{x}_b{b}_s{s}_xor"),
                    a,
                    state_in(lane(x, s + 1), b),
                    parity(x, b, s),
                ));
            }
        }
    }

    // theta, step 2a: C[x] ^ 0x80, which is C[x] & 0x80 and so ROTL(C[x], 1).
    for x in 0..5 {
        for b in 0..LANE_BYTES {
            out.push(xor8(
                format!("c_mask_x{x}_b{b}_xor"),
                expr(Vec::new(), Fr::from_u64(top_mask(1))),
                theta_c(x, b),
                c_mask(x, b),
            ));
        }
    }

    // theta, step 2b: D[x] = C[x−1] ^ ROTL(C[x+1], 1).
    for x in 0..5 {
        let up = (x + 1) % 5;
        for b in 0..LANE_BYTES {
            let (terms, constant) = rotl_byte(&|c| theta_c(up, c), &|c| c_mask(up, c), 1, b);
            out.push(xor8(
                format!("theta_d_x{x}_b{b}_xor"),
                expr(terms, constant),
                theta_c((x + 4) % 5, b),
                theta_d(x, b),
            ));
        }
    }

    // theta, step 3: A'[x][y] = A[x][y] ^ D[x].
    for y in 0..5 {
        for x in 0..5 {
            let i = lane(x, y);
            for b in 0..LANE_BYTES {
                out.push(xor8_cols(
                    format!("theta_a_l{i}_b{b}_xor"),
                    theta_d(x, b),
                    state_in(i, b),
                    theta_a(i, b),
                ));
            }
        }
    }

    // rho: the byte split each rotated lane needs, one obligation a byte
    // against the literal mask of its own rotation.
    for i in 0..k::LANES {
        if mask_slot(i).is_none() {
            continue;
        }
        let s = lane_rotation(i) % 8;
        for b in 0..LANE_BYTES {
            out.push(xor8(
                format!("rho_mask_l{i}_b{b}_xor"),
                expr(Vec::new(), Fr::from_u64(top_mask(s))),
                theta_a(i, b),
                rho_mask(i, b),
            ));
        }
    }

    // chi: out = B0 ^ ((!B1) & B2), two obligations a byte.
    for big_y in 0..5 {
        for big_x in 0..5 {
            let i = lane(big_x, big_y);
            let b1 = lane((big_x + 1) % 5, big_y);
            let b2 = lane((big_x + 2) % 5, big_y);
            for b in 0..LANE_BYTES {
                out.push(xor8_cols(
                    format!("chi_and_l{i}_b{b}_xor"),
                    rho_out(b1, b),
                    rho_out(b2, b),
                    chi_and(i, b),
                ));
                // `(!B1) & B2 = (B2 − B1 + (B1 ^ B2)) / 2`, all literals.
                let andn = expr(
                    vec![
                        (Coeff::Literal(half()), rho_out(b2, b)),
                        (Coeff::Literal(-half()), rho_out(b1, b)),
                        (Coeff::Literal(half()), chi_and(i, b)),
                    ],
                    Fr::ZERO,
                );
                out.push(xor8(
                    format!("chi_out_l{i}_b{b}_xor"),
                    andn,
                    rho_out(i, b),
                    chi_out(i, b),
                ));
            }
        }
    }

    // iota: lane (0,0) ^= RC[round], on the four bytes a round constant can
    // reach and no others.
    for (t, b) in k::IOTA_BYTES.iter().enumerate() {
        out.push(xor8_cols(
            format!("iota_out_b{b}_xor"),
            rc(t),
            chi_out(0, *b),
            iota_out(t),
        ));
    }

    out
}

/// Every obligation of the circuit: the frame's over `RANGE16`, then the
/// round's over `XOR8`.
fn lookups() -> Vec<LookupExpr> {
    let mut out = d::gap_lookups_range16(WORDS, &gap_chunk);
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
    out.extend(round_lookups());
    out
}

/// Every copower-scaled column, with the selector its scaled obligation
/// carries: each gap's top chunk and the two base decompositions' high
/// halfwords, all under `live`.
fn scaled_columns() -> Vec<(PolyAddress, PolyAddress)> {
    let mut out: Vec<(PolyAddress, PolyAddress)> = (0..WORDS)
        .map(|j| (gap_chunk(j, d::GAP_CHUNKS - 1), LIVE))
        .collect();
    out.push((base_low_hi(), LIVE));
    out.push((base_room_hi(), LIVE));
    out
}

// ---------------------------------------------------------------------------
// The artifact
// ---------------------------------------------------------------------------

/// The family's lookup channels: `RANGE16` for the frame, and `XOR8` for the
/// round.
///
/// Both tables are **virtual**, so neither costs a commitment, a setup column
/// or a movement of the SRS digest. `XOR8`'s three columns are closed forms of
/// the row index and its table is complete only at 16 variables or more, which
/// `crate::lookup::table_vars` reports and `family_circuit`'s derived floor
/// enforces before this function is ever called.
pub fn channels() -> Vec<ChannelSpec> {
    vec![
        ChannelSpec {
            channel: lookup_channel::RANGE16,
            table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
            multiplicity: range16_multiplicity(),
        },
        ChannelSpec {
            channel: lookup_channel::XOR8,
            table: crate::lookup::xor8_table(),
            multiplicity: xor8_multiplicity(),
        },
    ]
}

/// The circuit: one Keccak round a row, flat.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let mut enforcing =
        d::frame_gates_range16(WORDS, k::FRAME_BYTES as u64, base_low(), base_room());
    enforcing.extend(selector_gates());
    enforcing.extend(frame_value_gates());
    enforcing.extend(rho_pi_gates());

    let artifact = crate::memory::assemble(
        trace_vars,
        [d::memory_names(WORDS), witness_names(), Vec::new()],
        vec![
            (VirtualKind::Range16, "range16".to_string()),
            (VirtualKind::Xor8A, "xor8_a".to_string()),
            (VirtualKind::Xor8B, "xor8_b".to_string()),
            (VirtualKind::Xor8Out, "xor8_out".to_string()),
        ],
        d::leaves(address_space::DELEGATION_KECCAK_F, WORDS),
        enforcing,
        lookups(),
        &channels(),
    );
    if let Err(e) = crate::lookup::check_copowers(&artifact, &scaled_columns()) {
        panic!("keccak: {e}");
    }
    check_shape(&artifact);
    artifact
}

/// The `W` column names, mirroring the layout above name for name.
fn witness_names() -> Vec<String> {
    let mut out = Vec::with_capacity(WITNESS_COLUMNS);
    for j in 0..WORDS {
        for c in 0..d::GAP_CHUNKS {
            out.push(format!("gap{j}_c{c}"));
        }
    }
    out.push("base_low".to_string());
    out.push("base_low_hi".to_string());
    out.push("base_room".to_string());
    out.push("base_room_hi".to_string());
    for r in 0..k::ROUNDS {
        out.push(format!("round_sel{r}"));
    }
    for b in k::IOTA_BYTES {
        out.push(format!("rc_b{b}"));
    }
    for i in 0..k::LANES {
        for b in 0..LANE_BYTES {
            out.push(format!("state_in_l{i}_b{b}"));
        }
    }
    for x in 0..5 {
        for b in 0..LANE_BYTES {
            for s in 0..PARITY_STEPS {
                out.push(format!("parity_x{x}_b{b}_s{s}"));
            }
        }
    }
    for x in 0..5 {
        for b in 0..LANE_BYTES {
            out.push(format!("c_mask_x{x}_b{b}"));
        }
    }
    for x in 0..5 {
        for b in 0..LANE_BYTES {
            out.push(format!("theta_d_x{x}_b{b}"));
        }
    }
    for i in 0..k::LANES {
        for b in 0..LANE_BYTES {
            out.push(format!("theta_a_l{i}_b{b}"));
        }
    }
    for i in 0..k::LANES {
        if mask_slot(i).is_none() {
            continue;
        }
        for b in 0..LANE_BYTES {
            out.push(format!("rho_mask_l{i}_b{b}"));
        }
    }
    for i in 0..k::LANES {
        for b in 0..LANE_BYTES {
            out.push(format!("rho_out_l{i}_b{b}"));
        }
    }
    for i in 0..k::LANES {
        for b in 0..LANE_BYTES {
            out.push(format!("chi_and_l{i}_b{b}"));
        }
    }
    for i in 0..k::LANES {
        for b in 0..LANE_BYTES {
            out.push(format!("chi_out_l{i}_b{b}"));
        }
    }
    for b in k::IOTA_BYTES {
        out.push(format!("iota_out_b{b}"));
    }
    out.push("range16_multiplicity".to_string());
    out.push("xor8_multiplicity".to_string());
    out
}

/// The shape, asserted on every artifact this module emits.
///
/// S21's must-be-exact 4 read the same way and still applies: a bound that
/// exists only in a comment is not a bound, and a name check is what an
/// `assume_*` hypothesis cannot stand in for.
pub fn check_shape(a: &CircuitArtifact) {
    assert_eq!(a.memory.len(), MEMORY_COLUMNS, "keccak: M columns");
    assert_eq!(a.witness.len(), WITNESS_COLUMNS, "keccak: W columns");
    assert!(
        a.setup.is_empty(),
        "keccak: this family has no setup column"
    );
    assert_eq!(
        a.virtuals.len(),
        4,
        "keccak: range16 and XOR8's three columns"
    );
    assert_eq!(a.lookups.len(), lookups().len(), "keccak: obligations");
    assert_eq!(
        a.outputs.len(),
        6,
        "keccak: two memory roots and two channels"
    );

    let range16 = a
        .lookups
        .iter()
        .filter(|l| l.channel == lookup_channel::RANGE16)
        .count();
    let xor8 = a
        .lookups
        .iter()
        .filter(|l| l.channel == lookup_channel::XOR8)
        .count();
    assert_eq!(
        range16,
        4 * WORDS + 6,
        "keccak: four obligations a frame gap and three a base decomposition"
    );
    // The number this circuit's cost turns on: 1,020 fractions plus the
    // table's is 1,021, and a fraction tree is padded to a power of two, so
    // 1,024 leaves. Four more obligations would double the tree and cost 4,096
    // inner columns (`docs/spec/delegation.md` §6.5).
    assert_eq!(xor8, 1_020, "keccak: the round's obligations");
    assert!(
        (xor8 + 1).next_power_of_two() == 1_024,
        "keccak: the XOR8 fraction tree is 1,024 leaves and its slack is three \
         obligations; adding a fourth doubles it"
    );

    let named = |name: &str| a.relations.iter().any(|r| r.name == name);
    for name in [
        "live_boolean",
        "base_aligned",
        "base_in_window",
        "round_rule",
        "one_round_a_live_row",
        &format!("writes_back_w{}", k::ROUND_WORD),
    ] {
        assert!(named(name), "keccak: gate `{name}` is missing");
    }
    let count = |prefix: &str| {
        a.relations
            .iter()
            .filter(|r| r.name.starts_with(prefix))
            .count()
    };
    assert_eq!(count("addr_w"), WORDS, "keccak: one addr gate a frame word");
    assert_eq!(count("input_w"), k::STATE_WORDS, "keccak: input decodes");
    assert_eq!(count("output_w"), k::STATE_WORDS, "keccak: output decodes");
    for r in 0..k::ROUNDS {
        assert!(
            named(&format!("round{r}_boolean")),
            "keccak: round selector {r} has no booleanity gate"
        );
    }
    assert_eq!(count("rho_pi_l"), STATE, "keccak: one rho gate a byte");
    assert!(
        a.padding.zero_row_valid,
        "keccak: the all-zero row is a valid padding row"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rho and pi index map is a bijection on the 25 lanes, and its three
    /// whole-byte rotations are the ones `mask_slot` exempts.
    #[test]
    fn the_rho_pi_map_is_a_permutation() {
        let mut seen = [false; k::LANES];
        for big_y in 0..5 {
            for big_x in 0..5 {
                let (source, r) = rho_pi_source(big_x, big_y);
                assert!(!seen[source], "lane {source} is read twice");
                seen[source] = true;
                assert_eq!(r, lane_rotation(source), "the rotation is the lane's");
            }
        }
        assert!(seen.iter().all(|s| *s));
        assert_eq!(
            (0..k::LANES).filter(|i| mask_slot(*i).is_none()).count(),
            k::LANES - SPLIT_LANES
        );
        assert_eq!(
            (0..k::LANES).filter_map(mask_slot).max(),
            Some(SPLIT_LANES - 1)
        );
    }

    /// The rotation's literal weights reproduce `u64::rotate_left` on every
    /// lane's own offset, over every byte pattern of a small exhaustive set.
    ///
    /// This is the one place the circuit's arithmetic is checked against the
    /// operation it claims to be, at the level of the weights themselves: the
    /// forms `rotl_byte` returns are evaluated over `Fr` exactly as a gate
    /// would evaluate them.
    #[test]
    fn the_rotation_weights_are_rotate_left() {
        let value = |seed: u64, i: usize| -> u64 {
            let mut v = seed;
            for _ in 0..=i {
                v ^= v << 13;
                v ^= v >> 7;
                v ^= v << 17;
            }
            v
        };
        for i in 0..k::LANES {
            let r = lane_rotation(i);
            for trial in 0..4 {
                let lane_value = value(0x1234_5678_9abc_def1 + trial, i);
                let bytes = lane_value.to_le_bytes();
                let want = lane_value.rotate_left(r).to_le_bytes();
                let mask = if r.is_multiple_of(8) {
                    0
                } else {
                    top_mask(r % 8) as u8
                };
                for (j, want) in want.iter().enumerate() {
                    let (terms, constant) = rotl_byte(
                        &|b| PolyAddress::Witness(b as u32),
                        &|b| PolyAddress::Witness(8 + b as u32),
                        r,
                        j,
                    );
                    let mut got = constant;
                    for (c, x) in &terms {
                        let Coeff::Literal(v) = c else { unreachable!() };
                        let PolyAddress::Witness(idx) = x else {
                            unreachable!()
                        };
                        let cell = match *idx < 8 {
                            true => bytes[*idx as usize],
                            false => bytes[*idx as usize - 8] ^ mask,
                        };
                        got += *v * Fr::from_u64(cell as u64);
                    }
                    assert_eq!(
                        got,
                        Fr::from_u64(*want as u64),
                        "lane {i} (rotation {r}), byte {j}, trial {trial}"
                    );
                }
            }
        }
    }

    /// The witness layout's names are exactly its columns, each once.
    #[test]
    fn the_witness_names_are_the_layout() {
        let names = witness_names();
        assert_eq!(names.len(), WITNESS_COLUMNS);
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "a name is used twice");
    }

    /// The circuit builds at its channel floor, and at no lower height.
    ///
    /// `2^16` is the **floor** twice over — `RANGE16`'s table needs 16
    /// variables and so does `XOR8`'s, and Mercury needs an even count — and it
    /// is not the family's height: `DEFAULT_HEIGHTS` chooses `2^18` above it,
    /// and `crates/checker/tests/keccak.rs`'s
    /// `a_height_moves_only_the_halving_layers` builds that one.
    #[test]
    fn the_circuit_builds_at_its_channel_floor_and_no_lower() {
        let a = artifact(16);
        assert_eq!(a.trace_vars, 16);
        assert_eq!(a.outputs.len(), 6);
        assert_eq!(
            crate::lookup::table_vars(lookup_channel::XOR8),
            16,
            "the XOR8 table is 65,536 rows"
        );
        assert!(crate::family_circuit(constants::family::KECCAK_F, 8).is_none());
        assert!(crate::family_circuit(constants::family::KECCAK_F, 16).is_some());
    }
}
