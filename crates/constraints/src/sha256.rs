//! The `SHA256_COMP` family's circuit: one SHA-256 compression a row, invoked
//! by the `ecall::PRECOMPILE_SHA256_COMP` ecall and never decoded.
//!
//! `docs/spec/delegation.md` §15 is normative. One invocation is one row and
//! one row is one 64-byte block — the guest keeps the padding, the length
//! encoding and the block loop, exactly as `guest_sdk::keccak256` keeps the
//! sponge (§11).
//!
//! ```text
//! frame     M[0..100]: cycle live base anchor_value, then 4 per word
//! words 0..8                  the chaining state H0..H7, read and written
//! words 8..24                 the block's schedule words W0..W15, read only
//! W[0..972]       the frame's own: 38 gap bits a word, then the base's bounds
//! W[972..1740]    32 bits of every frame word's read value
//! W[1740..1996]   32 bits of the eight state words' written value
//! W[1996..2004]   the eight output carries, one bit each
//! W[2004..3540]   32 bits of the derived schedule words W16..W63
//! W[3540..3636]   48 schedule carries, two bits each
//! W[3636..5684]   32 bits of A1..A64, the round outputs' first working word
//! W[5684..7732]   32 bits of E1..E64
//! W[7732..7924]   64 round carries `ca`, three bits each
//! W[7924..8116]   64 round carries `ce`, three bits each
//! ```
//!
//! # The recurrence, rewritten over two words
//!
//! FIPS 180-4 shifts eight working words a round. Six of the eight are copies:
//! with `A_i` and `E_i` the values of `a` and `e` at the start of round `i`,
//!
//! ```text
//! B_i = A_{i-1}   C_i = A_{i-2}   D_i = A_{i-3}
//! F_i = E_{i-1}   G_i = E_{i-2}   H_i = E_{i-3}
//! ```
//!
//! so the whole compression is two sequences and nothing else:
//!
//! ```text
//! T1_i    = E_{i-3} + Sigma1(E_i) + Ch(E_i, E_{i-1}, E_{i-2}) + K_i + W_i
//! T2_i    = Sigma0(A_i) + Maj(A_i, A_{i-1}, A_{i-2})
//! A_{i+1} = T1_i + T2_i    - 2^32 * ca_i
//! E_{i+1} = A_{i-3} + T1_i - 2^32 * ce_i
//! ```
//!
//! with `A_0..A_{-3}` the state words `H0..H3` and `E_0..E_{-3}` the words
//! `H4..H7`. That is what the circuit enforces, one gate a round, and
//! `crates/constraints/src/sha256.rs`'s own test holds it against the
//! reference compression over the whole `guests/sha256-ops` corpus.
//!
//! **`T1` is never reduced**, which is why it is not a column: it is a sum of
//! five values below `2^32`, so below `5 * 2^32`, and only `A_{i+1}` and
//! `E_{i+1}` are brought back under `2^32`. Reducing `T1` as well would be two
//! more carries a round and the same answer, since both consumers take it
//! modulo `2^32`.
//!
//! **The carry widths are derived, not observed.** `T1 < 5 * 2^32` and
//! `T2 < 2 * 2^32` give `ca <= 6`, and `A_{i-3} + T1 < 6 * 2^32` gives
//! `ce <= 5`: three bits each, which is
//! [`constants::sha256::CARRY_A_BITS`]. The schedule's four-term sum gives
//! `cw <= 3` and the final `H_j + V_j` gives `co <= 1`.
//!
//! # Why three gate lists
//!
//! A three-way XOR is degree 3 in bits — `x^y^z = x+y+z-2(xy+yz+zx)+4xyz` —
//! so one helper a bit is unavoidable. This circuit **derives** the helper
//! rather than committing it: gate list 0 writes `p_t = x_t * y_t` into layer
//! 1, gate list 1 reads it and writes the XOR's 32-bit *value* into layer 2,
//! and gate list 2 holds the round, schedule and output equations, which are
//! degree 1 over layer 2. Committing the 9,216 helpers instead would make the
//! circuit flat and one gate list shorter, at 17,560 committed columns against
//! 8,216 — 1.69 MB of proof a shard against 1.33 MB, since a committed column
//! costs 96 wire bytes where an inner one costs 32.
//!
//! **`Ch` needs no helper at all.** `Ch(e,f,g) = g + e*f - e*g` is already
//! degree 2 in the bits, so its value is written at gate list 0 beside the
//! helpers. `Maj` needs one: `Maj(a,b,c) = pab + c*(a + b - 2*pab)`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::address_space;
use constants::memory as mem;
use constants::sha256 as f;
use field::Fr;

use crate::delegation as d;
use crate::{
    CircuitArtifact, Coeff, GateDef, Padding, PolyAddress, COEFFICIENT_ENCODING_CANONICAL_LE,
    FORMAT_VERSION,
};

/// The frame's words: the chaining state, then the block.
const WORDS: usize = f::FRAME_WORDS;

/// `M` columns: the frame's four head columns and four per word.
pub const MEMORY_COLUMNS: usize = d::HEAD_COLUMNS + 4 * WORDS;

/// Bits in a word.
const BITS: usize = 32;

/// Schedule words the circuit derives: `W16..W63`.
const DERIVED_WORDS: usize = f::ROUNDS - f::BLOCK_WORDS;

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

// --- the witness layout, in order ------------------------------------------

fn in_bits() -> usize {
    d::frame_witness(WORDS)
}
fn out_bits() -> usize {
    in_bits() + WORDS * BITS
}
fn out_carries() -> usize {
    out_bits() + f::STATE_WORDS * BITS
}
fn sched_bits() -> usize {
    out_carries() + f::STATE_WORDS
}
fn sched_carries() -> usize {
    sched_bits() + DERIVED_WORDS * BITS
}
fn a_bits() -> usize {
    sched_carries() + DERIVED_WORDS * f::CARRY_W_BITS
}
fn e_bits() -> usize {
    a_bits() + f::ROUNDS * BITS
}
fn ca_bits() -> usize {
    e_bits() + f::ROUNDS * BITS
}
fn ce_bits() -> usize {
    ca_bits() + f::ROUNDS * f::CARRY_A_BITS
}

/// `W[…]`: bit `t` of frame word `j`'s **read** value.
pub fn in_bit(j: usize, t: usize) -> PolyAddress {
    w(in_bits() + BITS * j + t)
}

/// `W[…]`: bit `t` of state word `j`'s **written** value.
pub fn out_bit(j: usize, t: usize) -> PolyAddress {
    w(out_bits() + BITS * j + t)
}

/// `W[…]`: state word `j`'s output carry, `H_j + V_j - 2^32 * co_j`.
pub fn out_carry(j: usize) -> PolyAddress {
    w(out_carries() + j)
}

/// `W[…]`: bit `t` of derived schedule word `W_i`, `16 <= i < 64`.
pub fn sched_bit(i: usize, t: usize) -> PolyAddress {
    w(sched_bits() + BITS * (i - f::BLOCK_WORDS) + t)
}

/// `W[…]`: bit `t` of derived schedule word `W_i`'s carry.
pub fn sched_carry_bit(i: usize, t: usize) -> PolyAddress {
    w(sched_carries() + f::CARRY_W_BITS * (i - f::BLOCK_WORDS) + t)
}

/// `W[…]`: bit `t` of round carry `ca_i`.
pub fn ca_bit(i: usize, t: usize) -> PolyAddress {
    w(ca_bits() + f::CARRY_A_BITS * i + t)
}

/// `W[…]`: bit `t` of round carry `ce_i`.
pub fn ce_bit(i: usize, t: usize) -> PolyAddress {
    w(ce_bits() + f::CARRY_E_BITS * i + t)
}

/// `W[…]`: bit `t` of `A_i`, the first working word at the start of round `i`.
///
/// `i` runs from `-3` to `ROUNDS`. The four non-positive indices are the frame
/// state words `H0..H3` — `A_0 = H0`, `A_{-1} = H1`, and so on — which is the
/// whole of `B`, `C` and `D`'s existence in this arithmetization.
pub fn a_bit(i: isize, t: usize) -> PolyAddress {
    if i <= 0 {
        in_bit((-i) as usize, t)
    } else {
        w(a_bits() + BITS * (i as usize - 1) + t)
    }
}

/// `W[…]`: bit `t` of `E_i`. The four non-positive indices are `H4..H7`.
pub fn e_bit(i: isize, t: usize) -> PolyAddress {
    if i <= 0 {
        in_bit(f::STATE_WORDS / 2 + (-i) as usize, t)
    } else {
        w(e_bits() + BITS * (i as usize - 1) + t)
    }
}

/// `W[…]`: bit `t` of schedule word `W_i`, `0 <= i < 64`. The first sixteen
/// are frame words; the rest the circuit derives.
pub fn w_bit(i: usize, t: usize) -> PolyAddress {
    if i < f::BLOCK_WORDS {
        in_bit(f::BLOCK_WORD + i, t)
    } else {
        sched_bit(i, t)
    }
}

/// The family's `W` columns.
pub const WITNESS_COLUMNS: usize = d::GAP_BITS * WORDS
    + d::BASE_LOW_BITS
    + d::BASE_ROOM_BITS
    + WORDS * BITS
    + f::STATE_WORDS * BITS
    + f::STATE_WORDS
    + DERIVED_WORDS * BITS
    + DERIVED_WORDS * f::CARRY_W_BITS
    + 2 * f::ROUNDS * BITS
    + f::ROUNDS * (f::CARRY_A_BITS + f::CARRY_E_BITS);

// --- the rotations FIPS 180-4 names ----------------------------------------

/// `Sigma0(a) = ROTR^2 ^ ROTR^13 ^ ROTR^22`.
const BIG_SIGMA0: [usize; 3] = [2, 13, 22];
/// `Sigma1(e) = ROTR^6 ^ ROTR^11 ^ ROTR^25`.
const BIG_SIGMA1: [usize; 3] = [6, 11, 25];
/// `sigma0(x) = ROTR^7 ^ ROTR^18 ^ SHR^3`.
const SMALL_SIGMA0: ([usize; 2], usize) = ([7, 18], 3);
/// `sigma1(x) = ROTR^17 ^ ROTR^19 ^ SHR^10`.
const SMALL_SIGMA1: ([usize; 2], usize) = ([17, 19], 10);

/// Bit `t` of `ROTR^r(x)` is bit `(t + r) mod 32` of `x`.
fn rotr(t: usize, r: usize) -> usize {
    (t + r) % BITS
}

/// Bit `t` of `SHR^s(x)` is bit `t + s` of `x`, or nothing past the top.
fn shr(t: usize, s: usize) -> Option<usize> {
    let k = t + s;
    (k < BITS).then_some(k)
}

// --- layer 1's helper columns ----------------------------------------------
//
// Layer 1 holds, in this order: the memory leaves, the carried scalars, the
// carried bits, and one `x*y` helper a bit for each three-way XOR. The offsets
// are arithmetic rather than searched, which is the whole reason
// `delegation::Assembly` exists.

/// Three-way XORs, in the order layer 1 writes their helpers: one per round
/// for `Sigma0`, `Sigma1` and `Maj`, then one per derived word for `sigma0`
/// and `sigma1`.
const XORS: usize = 3 * f::ROUNDS + 2 * DERIVED_WORDS;

/// Scalars layer 1 carries to layer 2, in order: `A_i` and `E_i` as values,
/// the four carries, every schedule word as a value, and `Ch_i`.
fn carried_scalars() -> usize {
    // A_{-3..=ROUNDS} and E likewise, ca, ce, cw, co, W_0..W_63, Ch_0..Ch_63,
    // the eight in/out state words as values, and `live`.
    //
    // **Spelled twice, and checked.** This arithmetic is what every layer
    // offset is built from and [`carried_scalar_list`] is what the columns are
    // built from; `artifact` asserts them equal, because the failure when they
    // disagree is a column silently aliased onto the next block rather than
    // anything a reader would see here.
    2 * (f::ROUNDS + 4)
        + 2 * f::ROUNDS
        + DERIVED_WORDS
        + f::STATE_WORDS
        + f::ROUNDS
        + f::ROUNDS
        + 2 * f::STATE_WORDS
        + 1
}

/// The first `A_i` whose **bits** are carried. `Maj(0)` reads `A_{-2}`, and
/// nothing reads `A_{-3}`'s bits — `A_{-3}` is a value only, the `D` of round
/// 0. A carried column no gate reads is one `validate` refuses.
const A_BIT_FIRST: isize = -2;
/// The last: `Sigma0(63)` and `Maj(63)` both read `A_63`; `A_64` is a value
/// only, the round-64 output.
const A_BIT_LAST: isize = f::ROUNDS as isize - 1;
/// `Sigma1(i)` reads `E_i` for `i < 64`, and `Ch` reads its three `E`s from the
/// **committed** bits at gate list 0, so no `E` below 0 is carried.
const E_BIT_FIRST: isize = 0;
/// The last `E_i` whose bits are carried.
const E_BIT_LAST: isize = f::ROUNDS as isize - 1;
/// `sigma0(W_{i-15})` for `i >= 16` reads `W_1` first.
const W_BIT_FIRST: usize = 1;
/// `sigma1(W_{i-2})` for `i < 64` reads `W_61` last.
const W_BIT_LAST: usize = f::ROUNDS - 3;

const fn span(first: isize, last: isize) -> usize {
    (last - first + 1) as usize
}

/// Bits layer 1 carries: exactly the `A_i`, `E_i` and `W_i` bits a three-way
/// XOR or a `Maj` reads, and no others.
///
/// `every_carried_bit_is_read` walks the nine hundred and sixty combinations
/// and holds every operand inside these ranges, so the ranges are checked
/// rather than asserted.
fn carried_bits() -> usize {
    (span(A_BIT_FIRST, A_BIT_LAST) + span(E_BIT_FIRST, E_BIT_LAST)) * BITS
        + span(W_BIT_FIRST as isize, W_BIT_LAST as isize) * BITS
}

/// A layer's columns are the memory tree's, then the carried scalars, then the
/// carried bits, then the layer's own work. The tree **halves** at each layer,
/// so every base below is a function of the layer and not a constant: layer 1
/// opens with 64 leaf columns and layer 2 with 32, which is a 32-column shift
/// in everything after them.
fn scalar_base(layer: usize) -> usize {
    tree_width(layer)
}

/// The carried bits live at **layer 1 only**: gate list 1 reads them to build
/// the three-way XORs' values, and gate list 2 reads values and nothing else,
/// so carrying a bit higher would be a column nothing reads — which `validate`
/// refuses, and rightly: a relation constructed and then dropped constrains
/// nothing.
fn bit_base() -> usize {
    scalar_base(1) + carried_scalars()
}

fn work_base(layer: usize) -> usize {
    let bits = if layer == 1 { carried_bits() } else { 0 };
    scalar_base(layer) + carried_scalars() + bits
}

/// Layer 1's width: the leaves, the carried columns, and one helper a bit.
fn layer1_width() -> usize {
    work_base(1) + XORS * BITS
}

/// `L1[…]`: the `x*y` helper of bit `t` of three-way XOR `k`.
fn helper(k: usize, t: usize) -> PolyAddress {
    d::inner(1, work_base(1) + k * BITS + t)
}

/// The three-way XOR index of round `i`'s `Sigma0`.
fn xor_sigma0(i: usize) -> usize {
    3 * i
}
/// … `Sigma1`.
fn xor_sigma1(i: usize) -> usize {
    3 * i + 1
}
/// … and `Maj`.
fn xor_maj(i: usize) -> usize {
    3 * i + 2
}
/// The index of derived word `i`'s `sigma0`.
fn xor_small0(i: usize) -> usize {
    3 * f::ROUNDS + 2 * (i - f::BLOCK_WORDS)
}
/// … and `sigma1`.
fn xor_small1(i: usize) -> usize {
    3 * f::ROUNDS + 2 * (i - f::BLOCK_WORDS) + 1
}

/// The carried scalars, in layer order. A scalar is carried by index, and this
/// enum is the index: the list is written once here and read by both the layer
/// that writes it and the layer that reads it.
#[derive(Clone, Copy)]
enum Scalar {
    /// `A_i`, `-3 <= i <= ROUNDS`.
    A(isize),
    /// `E_i`, likewise.
    E(isize),
    /// `ca_i`.
    Ca(usize),
    /// `ce_i`.
    Ce(usize),
    /// `cw_i`, `16 <= i < 64`.
    Cw(usize),
    /// `co_j`.
    Co(usize),
    /// `W_i`, `0 <= i < 64`.
    W(usize),
    /// `Ch_i`.
    Ch(usize),
    /// State word `j`'s read value.
    StateIn(usize),
    /// State word `j`'s written value.
    StateOut(usize),
    /// The row's `live` mask, carried so that the rounds' constants can ride
    /// it.
    ///
    /// **A padding row is an all-zero row**, and `K_i` is a nonzero literal, so
    /// a round gate stating `... - K_i = 0` outright cannot hold on one — which
    /// is the padding contract, not a nicety (`docs/spec/gkr.md`). The mask is
    /// a committed `M` column that only gate list 0 may read, so it has to be
    /// carried like any other value; one column a layer is the whole cost.
    Live,
}

/// `<stem><i>`, with a negative `i` spelled `m<|i|>`: an artifact name is
/// `[a-z0-9_]` and a minus sign is not in it.
fn index_name(stem: &str, i: isize) -> String {
    if i < 0 {
        format!("{stem}m{}", -i)
    } else {
        format!("{stem}{i}")
    }
}

impl Scalar {
    /// This scalar's offset within the carried block.
    fn index(self) -> usize {
        let a = 0;
        let e = a + f::ROUNDS + 4;
        let ca = e + f::ROUNDS + 4;
        let ce = ca + f::ROUNDS;
        let cw = ce + f::ROUNDS;
        let co = cw + DERIVED_WORDS;
        let ws = co + f::STATE_WORDS;
        let ch = ws + f::ROUNDS;
        let si = ch + f::ROUNDS;
        let so = si + f::STATE_WORDS;
        let live = so + f::STATE_WORDS;
        match self {
            Scalar::A(i) => a + (i + 3) as usize,
            Scalar::E(i) => e + (i + 3) as usize,
            Scalar::Ca(i) => ca + i,
            Scalar::Ce(i) => ce + i,
            Scalar::Cw(i) => cw + i - f::BLOCK_WORDS,
            Scalar::Co(j) => co + j,
            Scalar::W(i) => ws + i,
            Scalar::Ch(i) => ch + i,
            Scalar::StateIn(j) => si + j,
            Scalar::StateOut(j) => so + j,
            Scalar::Live => live,
        }
    }

    /// Its name, for the artifact's scratch listing.
    ///
    /// A name is `[a-z0-9_]` and nothing else, so the four non-positive
    /// indices — the state words standing in for `B`, `C`, `D` and `H` — spell
    /// `am3` rather than `a-3`.
    fn name(self) -> String {
        match self {
            Scalar::A(i) => index_name("a", i),
            Scalar::E(i) => index_name("e", i),
            Scalar::Ca(i) => format!("ca{i}"),
            Scalar::Ce(i) => format!("ce{i}"),
            Scalar::Cw(i) => format!("cw{i}"),
            Scalar::Co(j) => format!("co{j}"),
            Scalar::W(i) => format!("w{i}"),
            Scalar::Ch(i) => format!("ch{i}"),
            Scalar::StateIn(j) => format!("state_in{j}"),
            Scalar::StateOut(j) => format!("state_out{j}"),
            Scalar::Live => "live".to_string(),
        }
    }

    /// Its address at `layer`.
    fn at(self, layer: usize) -> PolyAddress {
        d::inner(layer, scalar_base(layer) + self.index())
    }
}

/// A carried bit's offset within the carried-bit block.
#[derive(Clone, Copy)]
enum CarriedBit {
    A(isize, usize),
    E(isize, usize),
    W(usize, usize),
}

impl CarriedBit {
    fn index(self) -> usize {
        let a = 0;
        let e = a + span(A_BIT_FIRST, A_BIT_LAST) * BITS;
        let ws = e + span(E_BIT_FIRST, E_BIT_LAST) * BITS;
        match self {
            CarriedBit::A(i, t) => a + (i - A_BIT_FIRST) as usize * BITS + t,
            CarriedBit::E(i, t) => e + (i - E_BIT_FIRST) as usize * BITS + t,
            CarriedBit::W(i, t) => ws + (i - W_BIT_FIRST) * BITS + t,
        }
    }
    fn name(self) -> String {
        match self {
            CarriedBit::A(i, t) => format!("{}_bit{t}", index_name("a", i)),
            CarriedBit::E(i, t) => format!("{}_bit{t}", index_name("e", i)),
            CarriedBit::W(i, t) => format!("w{i}_bit{t}"),
        }
    }
    fn committed(self) -> PolyAddress {
        match self {
            CarriedBit::A(i, t) => a_bit(i, t),
            CarriedBit::E(i, t) => e_bit(i, t),
            CarriedBit::W(i, t) => w_bit(i, t),
        }
    }
    /// Its address at layer 1, the only layer it exists at.
    fn at(self) -> PolyAddress {
        d::inner(1, bit_base() + self.index())
    }
}

/// Every carried bit, in layer order.
fn carried_bit_list() -> Vec<CarriedBit> {
    let mut out = Vec::with_capacity(carried_bits());
    for i in A_BIT_FIRST..=A_BIT_LAST {
        for t in 0..BITS {
            out.push(CarriedBit::A(i, t));
        }
    }
    for i in E_BIT_FIRST..=E_BIT_LAST {
        for t in 0..BITS {
            out.push(CarriedBit::E(i, t));
        }
    }
    for i in W_BIT_FIRST..=W_BIT_LAST {
        for t in 0..BITS {
            out.push(CarriedBit::W(i, t));
        }
    }
    out
}

/// Every carried scalar, in layer order, with the linear form layer 1 builds
/// it from. A value is `Σ 2^t · bit`, which is also that value's 32-bit bound
/// wherever its bits carry booleanity.
fn carried_scalar_list() -> Vec<(Scalar, Vec<(Coeff, PolyAddress)>)> {
    let bits_of = |f: &dyn Fn(usize) -> PolyAddress, n: usize| -> Vec<(Coeff, PolyAddress)> {
        (0..n).map(|t| (d::lit(1u64 << t), f(t))).collect()
    };
    let mut out: Vec<(Scalar, Vec<(Coeff, PolyAddress)>)> = Vec::new();
    for i in -3..=(f::ROUNDS as isize) {
        out.push((Scalar::A(i), bits_of(&|t| a_bit(i, t), BITS)));
    }
    for i in -3..=(f::ROUNDS as isize) {
        out.push((Scalar::E(i), bits_of(&|t| e_bit(i, t), BITS)));
    }
    for i in 0..f::ROUNDS {
        out.push((Scalar::Ca(i), bits_of(&|t| ca_bit(i, t), f::CARRY_A_BITS)));
    }
    for i in 0..f::ROUNDS {
        out.push((Scalar::Ce(i), bits_of(&|t| ce_bit(i, t), f::CARRY_E_BITS)));
    }
    for i in f::BLOCK_WORDS..f::ROUNDS {
        out.push((
            Scalar::Cw(i),
            bits_of(&|t| sched_carry_bit(i, t), f::CARRY_W_BITS),
        ));
    }
    for j in 0..f::STATE_WORDS {
        out.push((Scalar::Co(j), vec![(d::lit(1), out_carry(j))]));
    }
    for i in 0..f::ROUNDS {
        out.push((Scalar::W(i), bits_of(&|t| w_bit(i, t), BITS)));
    }
    for i in 0..f::ROUNDS {
        out.push((Scalar::Ch(i), Vec::new()));
    }
    for j in 0..f::STATE_WORDS {
        out.push((
            Scalar::StateIn(j),
            vec![(d::lit(1), word(j, d::WORD_READ_VALUE))],
        ));
    }
    for j in 0..f::STATE_WORDS {
        out.push((
            Scalar::StateOut(j),
            vec![(d::lit(1), word(j, d::WORD_WRITE_VALUE))],
        ));
    }
    out.push((Scalar::Live, vec![(d::lit(1), LIVE)]));
    out
}

/// `Ch(e, f, g) = g + e*f - e*g`, as a 32-bit value over committed bits.
///
/// Degree 2 already, so it needs no helper and is written at gate list 0
/// beside them. Each bit of the result is `g_t + e_t*f_t - e_t*g_t`, which is
/// 0 or 1 by inspection over the eight inputs, so the weighted sum is the
/// 32-bit value.
fn ch_gate(i: usize) -> GateDef {
    let mut linear: Vec<(Coeff, PolyAddress)> = Vec::new();
    let mut products: Vec<(Coeff, PolyAddress, PolyAddress)> = Vec::new();
    for t in 0..BITS {
        let e = e_bit(i as isize, t);
        let ff = e_bit(i as isize - 1, t);
        let g = e_bit(i as isize - 2, t);
        let two = d::lit(1u64 << t);
        linear.push((two, g));
        products.push((two, e, ff));
        products.push((d::neg(1u64 << t), e, g));
    }
    d::quadratic(linear, products)
}

/// The three-way XOR's value at layer 2, given its helpers at layer 1.
///
/// `x^y = x + y - 2p` with `p = x*y`, and `(x^y)^z = (x+y-2p) + z -
/// 2*z*(x+y-2p)`, which is degree 2 in `p`, `x`, `y` and `z` — all four at
/// layer 1, the helper because gate list 0 wrote it and the bits because gate
/// list 0 carried them.
fn xor3_value(k: usize) -> GateDef {
    let kind = xor_kind(k);
    let mut linear: Vec<(Coeff, PolyAddress)> = Vec::new();
    let mut products: Vec<(Coeff, PolyAddress, PolyAddress)> = Vec::new();
    for t in 0..BITS {
        let two = 1u64 << t;
        let p = helper(k, t);
        let x = xor_operand(kind, t, 0);
        let y = xor_operand(kind, t, 1);
        let z = xor_operand(kind, t, 2);
        // `x + y - 2p`, each term present only where the operand exists: a
        // `SHR` past the top contributes nothing, and the helper of a missing
        // operand is the literal 0 that gate list 0 wrote there.
        if let Some(x) = x {
            linear.push((d::lit(two), x.at()));
        }
        if let Some(y) = y {
            linear.push((d::lit(two), y.at()));
        }
        linear.push((d::neg(2 * two), p));
        if let Some(z) = z {
            linear.push((d::lit(two), z.at()));
            if let Some(x) = x {
                products.push((d::neg(2 * two), z.at(), x.at()));
            }
            if let Some(y) = y {
                products.push((d::neg(2 * two), z.at(), y.at()));
            }
            products.push((d::lit(4 * two), z.at(), p));
        }
    }
    d::quadratic(linear, products)
}

/// What a three-way combination reads, as **data**: a closure would be a
/// `dyn Fn`, which `prompts/00-master.md`'s anti-goal 2 bans, and the five
/// shapes are a five-arm enum either way.
#[derive(Clone, Copy)]
enum XorKind {
    /// `Sigma0(A_i)`: three rotations of one word.
    BigSigma0(isize),
    /// `Sigma1(E_i)`: likewise.
    BigSigma1(isize),
    /// `Maj(A_i, A_{i-1}, A_{i-2})`: three different words, no rotation. Not
    /// an XOR, but the same three operands and the same one helper a bit,
    /// which is why it shares this path.
    Maj(isize),
    /// `sigma0(W_src)`: two rotations and a shift.
    SmallSigma0(usize),
    /// `sigma1(W_src)`: likewise.
    SmallSigma1(usize),
}

/// Three-way combination `k`'s kind, by the order [`XORS`] counts them.
fn xor_kind(k: usize) -> XorKind {
    if k < 3 * f::ROUNDS {
        let i = (k / 3) as isize;
        match k % 3 {
            0 => XorKind::BigSigma0(i),
            1 => XorKind::BigSigma1(i),
            _ => XorKind::Maj(i),
        }
    } else {
        let j = (k - 3 * f::ROUNDS) / 2;
        let i = f::BLOCK_WORDS + j;
        if (k - 3 * f::ROUNDS).is_multiple_of(2) {
            XorKind::SmallSigma0(i - 15)
        } else {
            XorKind::SmallSigma1(i - 2)
        }
    }
}

/// Operand `which` of bit `t`, or `None` where a `SHR` has shifted it away.
fn xor_operand(kind: XorKind, t: usize, which: usize) -> Option<CarriedBit> {
    match kind {
        XorKind::BigSigma0(i) => Some(CarriedBit::A(i, rotr(t, BIG_SIGMA0[which]))),
        XorKind::BigSigma1(i) => Some(CarriedBit::E(i, rotr(t, BIG_SIGMA1[which]))),
        XorKind::Maj(i) => Some(CarriedBit::A(i - which as isize, t)),
        XorKind::SmallSigma0(src) => match which {
            0 | 1 => Some(CarriedBit::W(src, rotr(t, SMALL_SIGMA0.0[which]))),
            _ => shr(t, SMALL_SIGMA0.1).map(|u| CarriedBit::W(src, u)),
        },
        XorKind::SmallSigma1(src) => match which {
            0 | 1 => Some(CarriedBit::W(src, rotr(t, SMALL_SIGMA1.0[which]))),
            _ => shr(t, SMALL_SIGMA1.1).map(|u| CarriedBit::W(src, u)),
        },
    }
}

/// `Maj(a, b, c) = pab + c*(a + b - 2*pab)`, as a 32-bit value.
///
/// Not an XOR, but the same shape: one helper a bit, `pab = a_t * b_t`, and a
/// degree-2 combination of it with the third operand. Checked over all eight
/// inputs by this module's own test.
fn maj_value(i: usize) -> GateDef {
    let k = xor_maj(i);
    let mut linear: Vec<(Coeff, PolyAddress)> = Vec::new();
    let mut products: Vec<(Coeff, PolyAddress, PolyAddress)> = Vec::new();
    for t in 0..BITS {
        let two = 1u64 << t;
        let p = helper(k, t);
        let a = CarriedBit::A(i as isize, t).at();
        let b = CarriedBit::A(i as isize - 1, t).at();
        let c = CarriedBit::A(i as isize - 2, t).at();
        linear.push((d::lit(two), p));
        products.push((d::lit(two), c, a));
        products.push((d::lit(two), c, b));
        products.push((d::neg(2 * two), c, p));
    }
    d::quadratic(linear, products)
}

/// `L2[…]`: the value of three-way XOR `k` — `Sigma0`, `Sigma1`, `Maj`,
/// `sigma0` or `sigma1`.
fn xor_value(k: usize) -> PolyAddress {
    d::inner(2, work_base(2) + k)
}

/// The family's circuit over `2^trace_vars` rows.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let mut a = d::Assembly::new();
    let scalars = carried_scalar_list();
    let bits = carried_bit_list();
    assert_eq!(
        scalars.len(),
        carried_scalars(),
        "the carried-scalar count and the carried-scalar list disagree"
    );
    assert_eq!(
        bits.len(),
        carried_bits(),
        "the carried-bit count and the carried-bit list disagree"
    );

    // --- gate list 0 -> layer 1 --------------------------------------------
    let [reads, writes] = d::leaves(address_space::DELEGATION_SHA256_COMP, WORDS);
    let mut producing: Vec<(String, GateDef)> = reads.into_iter().chain(writes).collect();
    for (s, terms) in &scalars {
        let gate = match s {
            Scalar::Ch(i) => ch_gate(*i),
            _ => d::linear(terms.clone()),
        };
        producing.push((format!("{}_l1", s.name()), gate));
    }
    for b in &bits {
        producing.push((format!("{}_l1", b.name()), d::copy(b.committed())));
    }
    for k in 0..XORS {
        let kind = xor_kind(k);
        for t in 0..BITS {
            let gate = match (xor_operand(kind, t, 0), xor_operand(kind, t, 1)) {
                (Some(x), Some(y)) => GateDef::Product {
                    coeff: d::lit(1),
                    left: x.committed(),
                    right: y.committed(),
                },
                // A helper whose operands do not both exist is the literal 0,
                // which `xor3_value` then reads as the absent product.
                _ => d::linear(Vec::new()),
            };
            producing.push((format!("helper{k}_{t}"), gate));
        }
    }
    a.push(1, false, trace_vars, producing, list0_enforcing());

    // --- gate list 1 -> layer 2 --------------------------------------------
    let mut producing: Vec<(String, GateDef)> = tree_layer(1);
    for (s, _) in &scalars {
        producing.push((format!("{}_l2", s.name()), d::copy(s.at(1))));
    }
    for k in 0..XORS {
        let gate = if k < 3 * f::ROUNDS && k % 3 == 2 {
            maj_value(k / 3)
        } else {
            xor3_value(k)
        };
        producing.push((format!("xor{k}_value"), gate));
    }
    a.push(2, false, trace_vars, producing, Vec::new());

    // --- gate list 2 -> layer 3: the equations -----------------------------
    a.push(3, false, trace_vars, tree_layer(2), round_gates());

    // --- the memory tree's remaining reductions ----------------------------
    let mut layer = 4;
    while tree_width(layer - 1) > 2 {
        a.push(layer, false, trace_vars, tree_layer(layer - 1), Vec::new());
        layer += 1;
    }

    // --- the halving phase --------------------------------------------------
    let last = layer - 1;
    for step in 0..trace_vars as usize {
        let at = last + 1 + step;
        let producing = (0..2)
            .map(|i| {
                let name = if step + 1 == trace_vars as usize {
                    ["read_root", "write_root"][i].to_string()
                } else {
                    format!("halve_{at}_{i}")
                };
                (
                    name,
                    GateDef::TreeProduct {
                        input: d::inner(at - 1, tree_offset(at - 1) + i),
                    },
                )
            })
            .collect();
        a.push(
            at,
            true,
            trace_vars - step as u32 - 1,
            producing,
            Vec::new(),
        );
    }

    let top = last + trace_vars as usize;
    let committed = MEMORY_COLUMNS + WITNESS_COLUMNS;
    let artifact = CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars,
        memory: d::memory_names(WORDS),
        witness: witness_names(),
        setup: Vec::new(),
        virtuals: Vec::new(),
        layers: a.layers,
        relations: a.relations,
        lookups: Vec::new(),
        scratch: a.scratch,
        outputs: vec![
            d::inner(top, mem::READ_ROOT),
            d::inner(top, mem::WRITE_ROOT),
        ],
        padding: Padding {
            row: vec![Fr::ZERO; committed],
            zero_row_valid: true,
        },
    };
    if let Err(e) = artifact.validate() {
        panic!("sha256: {e}");
    }
    if let Err(e) = crate::memory::check_memory(&artifact) {
        panic!("sha256: {e}");
    }
    check_shape(&artifact);
    artifact
}

/// The memory tree's width at `layer`: `2 * leaves_a_side` halved once a
/// layer, and never below two.
fn tree_width(layer: usize) -> usize {
    let mut width = 2 * d::leaves_a_side(WORDS);
    for _ in 1..layer {
        if width > 2 {
            width /= 2;
        }
    }
    width
}

/// The tree's first column at `layer`. It is 0 at layer 1, where the leaves
/// come first, and 0 at every later layer too — the tree is written before the
/// carried columns at each of them.
fn tree_offset(_layer: usize) -> usize {
    0
}

/// The pairwise reduction that takes `layer`'s tree columns to `layer + 1`'s.
fn tree_layer(layer: usize) -> Vec<(String, GateDef)> {
    let width = tree_width(layer);
    let at = tree_offset(layer);
    if width > 2 {
        (0..width / 2)
            .map(|i| {
                (
                    format!("tree_{layer}_{i}"),
                    GateDef::Product {
                        coeff: d::lit(1),
                        left: d::inner(layer, at + 2 * i),
                        right: d::inner(layer, at + 2 * i + 1),
                    },
                )
            })
            .collect()
    } else {
        vec![
            (format!("read_up{layer}"), d::copy(d::inner(layer, at))),
            (format!("write_up{layer}"), d::copy(d::inner(layer, at + 1))),
        ]
    }
}

/// Gate list 0's enforcing gates: the frame's own, then every committed bit's
/// booleanity and every frame word's decode.
fn list0_enforcing() -> Vec<(String, GateDef)> {
    let mut out = d::frame_gates(WORDS, f::FRAME_BYTES as u64);

    // Every frame word's read value is its 32 bits, which is the word's 32-bit
    // bound and its decode at once.
    for j in 0..WORDS {
        for t in 0..BITS {
            out.push((format!("in{j}_bit{t}_boolean"), d::booleanity(in_bit(j, t))));
        }
        let mut terms = vec![(d::lit(1), word(j, d::WORD_READ_VALUE))];
        for t in 0..BITS {
            terms.push((d::neg(1u64 << t), in_bit(j, t)));
        }
        out.push((format!("in{j}_word"), d::linear(terms)));
    }

    // The eight written state words, likewise.
    for j in 0..f::STATE_WORDS {
        for t in 0..BITS {
            out.push((
                format!("out{j}_bit{t}_boolean"),
                d::booleanity(out_bit(j, t)),
            ));
        }
        let mut terms = vec![(d::lit(1), word(j, d::WORD_WRITE_VALUE))];
        for t in 0..BITS {
            terms.push((d::neg(1u64 << t), out_bit(j, t)));
        }
        out.push((format!("out{j}_word"), d::linear(terms)));
    }

    // The sixteen block words are written back unchanged: the guest's schedule
    // survives the call, and the invocation computes the state alone.
    for j in f::BLOCK_WORD..WORDS {
        out.push((
            format!("writes_back_w{j}"),
            d::linear(vec![
                (d::lit(1), word(j, d::WORD_WRITE_VALUE)),
                (d::neg(1), word(j, d::WORD_READ_VALUE)),
            ]),
        ));
    }

    // Every derived value's bits, and every carry's.
    for i in f::BLOCK_WORDS..f::ROUNDS {
        for t in 0..BITS {
            out.push((
                format!("w{i}_bit{t}_boolean"),
                d::booleanity(sched_bit(i, t)),
            ));
        }
        for t in 0..f::CARRY_W_BITS {
            out.push((
                format!("cw{i}_{t}_boolean"),
                d::booleanity(sched_carry_bit(i, t)),
            ));
        }
    }
    for i in 1..=f::ROUNDS {
        for t in 0..BITS {
            out.push((
                format!("a{i}_bit{t}_boolean"),
                d::booleanity(a_bit(i as isize, t)),
            ));
            out.push((
                format!("e{i}_bit{t}_boolean"),
                d::booleanity(e_bit(i as isize, t)),
            ));
        }
    }
    for i in 0..f::ROUNDS {
        for t in 0..f::CARRY_A_BITS {
            out.push((format!("ca{i}_{t}_boolean"), d::booleanity(ca_bit(i, t))));
        }
        for t in 0..f::CARRY_E_BITS {
            out.push((format!("ce{i}_{t}_boolean"), d::booleanity(ce_bit(i, t))));
        }
    }
    for j in 0..f::STATE_WORDS {
        out.push((format!("co{j}_boolean"), d::booleanity(out_carry(j))));
    }
    out
}

/// Gate list 2's enforcing gates: the message schedule, the sixty-four rounds
/// and the eight output words, every one degree 1 over layer 2.
fn round_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    let two32 = d::pow2(32);

    // W_i = sigma1(W_{i-2}) + W_{i-7} + sigma0(W_{i-15}) + W_{i-16} - 2^32 cw
    for i in f::BLOCK_WORDS..f::ROUNDS {
        out.push((
            format!("schedule_w{i}"),
            d::linear(vec![
                (d::lit(1), Scalar::W(i).at(2)),
                (Coeff::Literal(two32), Scalar::Cw(i).at(2)),
                (d::neg(1), xor_value(xor_small1(i))),
                (d::neg(1), Scalar::W(i - 7).at(2)),
                (d::neg(1), xor_value(xor_small0(i))),
                (d::neg(1), Scalar::W(i - 16).at(2)),
            ]),
        ));
    }

    // A_{i+1} = T1 + T2 - 2^32 ca,  E_{i+1} = A_{i-3} + T1 - 2^32 ce
    for i in 0..f::ROUNDS {
        let k = Fr::from_u64(f::ROUND_CONSTANTS[i] as u64);
        let t1: Vec<(Coeff, PolyAddress)> = vec![
            (d::lit(1), Scalar::E(i as isize - 3).at(2)),
            (d::lit(1), xor_value(xor_sigma1(i))),
            (d::lit(1), Scalar::Ch(i).at(2)),
            (d::lit(1), Scalar::W(i).at(2)),
        ];
        let mut a_terms = vec![
            (d::lit(1), Scalar::A(i as isize + 1).at(2)),
            (Coeff::Literal(two32), Scalar::Ca(i).at(2)),
            (d::neg(1), xor_value(xor_sigma0(i))),
            (d::neg(1), xor_value(xor_maj(i))),
        ];
        for (c, x) in &t1 {
            let Coeff::Literal(v) = c else {
                panic!("sha256: a round coefficient is a literal")
            };
            a_terms.push((Coeff::Literal(-*v), *x));
        }
        a_terms.push((Coeff::Literal(-k), Scalar::Live.at(2)));
        out.push((format!("round_a{i}"), d::linear(a_terms)));

        let mut e_terms = vec![
            (d::lit(1), Scalar::E(i as isize + 1).at(2)),
            (Coeff::Literal(two32), Scalar::Ce(i).at(2)),
            (d::neg(1), Scalar::A(i as isize - 3).at(2)),
        ];
        for (c, x) in &t1 {
            let Coeff::Literal(v) = c else {
                panic!("sha256: a round coefficient is a literal")
            };
            e_terms.push((Coeff::Literal(-*v), *x));
        }
        e_terms.push((Coeff::Literal(-k), Scalar::Live.at(2)));
        out.push((format!("round_e{i}"), d::linear(e_terms)));
    }

    // out_j = H_j + V_j - 2^32 co_j, with V the eight working words after the
    // last round: (A_64, A_63, A_62, A_61, E_64, E_63, E_62, E_61).
    for j in 0..f::STATE_WORDS {
        let v = if j < 4 {
            Scalar::A(f::ROUNDS as isize - j as isize)
        } else {
            Scalar::E(f::ROUNDS as isize - (j as isize - 4))
        };
        out.push((
            format!("output_h{j}"),
            d::linear(vec![
                (d::lit(1), Scalar::StateOut(j).at(2)),
                (Coeff::Literal(two32), Scalar::Co(j).at(2)),
                (d::neg(1), Scalar::StateIn(j).at(2)),
                (d::neg(1), v.at(2)),
            ]),
        ));
    }
    out
}

/// The family's lookup channels: **none**.
///
/// At `2^8` no channel's table fits — `RANGE16` needs sixteen variables and
/// `TIMESTAMP` nineteen (`docs/spec/lookup.md` §3) — so every bound this
/// circuit makes is a bit decomposition with a booleanity gate. That is the
/// rule `docs/spec/delegation.md` §9 states, and unlike `EC_ADD` this family
/// has no reason to leave it: its row is ~20,000 inner columns, so `2^16`
/// would be 42 GB of forward pass a shard.
pub fn channels() -> Vec<crate::lookup::ChannelSpec> {
    Vec::new()
}

/// The `W` column names, in layout order.
fn witness_names() -> Vec<String> {
    let mut out = d::witness_names(WORDS);
    for j in 0..WORDS {
        for t in 0..BITS {
            out.push(format!("in{j}_bit{t}"));
        }
    }
    for j in 0..f::STATE_WORDS {
        for t in 0..BITS {
            out.push(format!("out{j}_bit{t}"));
        }
    }
    for j in 0..f::STATE_WORDS {
        out.push(format!("co{j}"));
    }
    for i in f::BLOCK_WORDS..f::ROUNDS {
        for t in 0..BITS {
            out.push(format!("w{i}_bit{t}"));
        }
    }
    for i in f::BLOCK_WORDS..f::ROUNDS {
        for t in 0..f::CARRY_W_BITS {
            out.push(format!("cw{i}_{t}"));
        }
    }
    for i in 1..=f::ROUNDS {
        for t in 0..BITS {
            out.push(format!("a{i}_bit{t}"));
        }
    }
    for i in 1..=f::ROUNDS {
        for t in 0..BITS {
            out.push(format!("e{i}_bit{t}"));
        }
    }
    for i in 0..f::ROUNDS {
        for t in 0..f::CARRY_A_BITS {
            out.push(format!("ca{i}_{t}"));
        }
    }
    for i in 0..f::ROUNDS {
        for t in 0..f::CARRY_E_BITS {
            out.push(format!("ce{i}_{t}"));
        }
    }
    out
}

/// The shape this module intends, checked on every artifact it emits.
///
/// Counted on the emitted artifact rather than on the vectors handed in, which
/// is what makes it a check rather than a restatement.
pub fn check_shape(a: &CircuitArtifact) {
    assert_eq!(a.memory.len(), MEMORY_COLUMNS, "sha256: M width");
    assert_eq!(a.witness.len(), WITNESS_COLUMNS, "sha256: W width");
    assert!(a.setup.is_empty(), "sha256: no setup column");
    assert!(a.lookups.is_empty(), "sha256: no lookup");
    assert!(
        channels().is_empty(),
        "a delegation family at 2^8 has no channel"
    );
    assert_eq!(
        a.layers[0].width as usize,
        layer1_width(),
        "sha256: layer 1"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The circuit builds, validates and passes `check_memory` at its default
    /// height. `artifact` panics on any refusal, so construction is the test.
    #[test]
    fn the_circuit_builds_at_its_default_height() {
        let a = artifact(8);
        assert_eq!(a.trace_vars, 8);
        assert_eq!(a.outputs.len(), 2, "two memory roots, no channel");
    }

    /// The reference compression, and the arithmetization's own recurrence over
    /// `A_i` and `E_i` alone, agree — which is what makes the round gate the
    /// compression function rather than something near it.
    #[test]
    fn the_two_word_recurrence_is_the_compression_function() {
        // FIPS 180-4's eight-word shift, verbatim.
        fn reference(state: [u32; 8], block: [u32; 16]) -> [u32; 8] {
            let mut w = [0u32; 64];
            w[..16].copy_from_slice(&block);
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut dd, mut e, mut ff, mut g, mut h] = state;
            for (i, wi) in w.iter().enumerate() {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & ff) ^ (!e & g);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(f::ROUND_CONSTANTS[i])
                    .wrapping_add(*wi);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                h = g;
                g = ff;
                ff = e;
                e = dd.wrapping_add(t1);
                dd = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            let v = [a, b, c, dd, e, ff, g, h];
            let mut out = [0u32; 8];
            for j in 0..8 {
                out[j] = state[j].wrapping_add(v[j]);
            }
            out
        }

        // This circuit's recurrence: two sequences, `D_i = A_{i-3}` and
        // `H_i = E_{i-3}`, and the carries the witness commits.
        fn two_word(state: [u32; 8], block: [u32; 16]) -> ([u32; 8], u32, u32, u32, u32) {
            let mut w = [0u32; 64];
            w[..16].copy_from_slice(&block);
            let mut cw_max = 0;
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                let raw = s1 as u64 + w[i - 7] as u64 + s0 as u64 + w[i - 16] as u64;
                cw_max = cw_max.max((raw >> 32) as u32);
                w[i] = raw as u32;
            }
            // `A[i + 3]` holds `A_i`, so index 0..3 are `A_{-3}..A_{-1}`.
            let mut aa = vec![state[3], state[2], state[1], state[0]];
            let mut ee = vec![state[7], state[6], state[5], state[4]];
            let (mut ca_max, mut ce_max) = (0u32, 0u32);
            for i in 0..64 {
                let (ai, am1, am2, am3) = (aa[i + 3], aa[i + 2], aa[i + 1], aa[i]);
                let (ei, em1, em2, em3) = (ee[i + 3], ee[i + 2], ee[i + 1], ee[i]);
                let s1 = ei.rotate_right(6) ^ ei.rotate_right(11) ^ ei.rotate_right(25);
                let ch = em2 ^ (ei & (em1 ^ em2));
                let t1 =
                    em3 as u64 + s1 as u64 + ch as u64 + f::ROUND_CONSTANTS[i] as u64 + w[i] as u64;
                let s0 = ai.rotate_right(2) ^ ai.rotate_right(13) ^ ai.rotate_right(22);
                let maj = (ai & am1) ^ (ai & am2) ^ (am1 & am2);
                let t2 = s0 as u64 + maj as u64;
                ca_max = ca_max.max(((t1 + t2) >> 32) as u32);
                ce_max = ce_max.max(((am3 as u64 + t1) >> 32) as u32);
                aa.push((t1 + t2) as u32);
                ee.push((am3 as u64 + t1) as u32);
            }
            let v = [
                aa[67], aa[66], aa[65], aa[64], ee[67], ee[66], ee[65], ee[64],
            ];
            let mut out = [0u32; 8];
            let mut co_max = 0u32;
            for j in 0..8 {
                let raw = state[j] as u64 + v[j] as u64;
                co_max = co_max.max((raw >> 32) as u32);
                out[j] = raw as u32;
            }
            (out, ca_max, ce_max, cw_max, co_max)
        }

        let (mut ca, mut ce, mut cw, mut co) = (0u32, 0u32, 0u32, 0u32);
        for seed in 0..48u32 {
            let state: [u32; 8] =
                core::array::from_fn(|j| f::IV[j] ^ seed.wrapping_mul(0x9e37_79b9 + j as u32));
            let block: [u32; 16] =
                core::array::from_fn(|j| seed.wrapping_mul(2_654_435_761) ^ (j as u32 * 40_503));
            let (got, a, e, wv, o) = two_word(state, block);
            assert_eq!(got, reference(state, block), "seed {seed}");
            ca = ca.max(a);
            ce = ce.max(e);
            cw = cw.max(wv);
            co = co.max(o);
        }
        // The committed carry widths are derived ceilings, not observations;
        // this is the observation confirming they are not too small.
        assert!(ca < (1 << f::CARRY_A_BITS), "ca reached {ca}");
        assert!(ce < (1 << f::CARRY_E_BITS), "ce reached {ce}");
        assert!(cw < (1 << f::CARRY_W_BITS), "cw reached {cw}");
        assert!(co < (1 << f::CARRY_OUT_BITS), "co reached {co}");
    }

    /// Every operand of every three-way combination falls inside the carried
    /// ranges — derived by walking all 960 of them, not asserted.
    ///
    /// The ranges are what make the carried-bit block exactly as wide as gate
    /// list 1 reads. One too wide is a column `validate` refuses; one too
    /// narrow is an out-of-layer read it also refuses, so this test is the
    /// reason neither happens silently when a rotation constant changes.
    #[test]
    fn every_carried_bit_is_read() {
        let mut seen = 0usize;
        for k in 0..XORS {
            let kind = xor_kind(k);
            for t in 0..BITS {
                for which in 0..3 {
                    let Some(b) = xor_operand(kind, t, which) else {
                        continue;
                    };
                    seen += 1;
                    match b {
                        CarriedBit::A(i, _) => {
                            assert!((A_BIT_FIRST..=A_BIT_LAST).contains(&i), "A_{i}")
                        }
                        CarriedBit::E(i, _) => {
                            assert!((E_BIT_FIRST..=E_BIT_LAST).contains(&i), "E_{i}")
                        }
                        CarriedBit::W(i, _) => {
                            assert!((W_BIT_FIRST..=W_BIT_LAST).contains(&i), "W_{i}")
                        }
                    }
                    assert!(b.index() < carried_bits(), "{} out of block", b.name());
                }
            }
        }
        // Every combination has three operands a bit, less the bits the two
        // `SHR`s shift away: `sigma0` loses its top 3 and `sigma1` its top 10,
        // once per derived word.
        assert_eq!(
            seen,
            XORS * BITS * 3 - DERIVED_WORDS * (SMALL_SIGMA0.1 + SMALL_SIGMA1.1),
            "operands, less the shifts"
        );
    }

    /// Every layer's width is its parts', and the memory tree halves cleanly.
    ///
    /// The offsets in this module are arithmetic — `work_base(layer)` is the
    /// tree's width plus the carried block's — so a layer one column out would
    /// read a neighbour's column with no other symptom. This is the check that
    /// makes that impossible rather than unlikely.
    #[test]
    fn every_layer_is_as_wide_as_its_parts() {
        let a = artifact(8);
        assert_eq!(a.layers[0].width as usize, layer1_width(), "layer 1");
        assert_eq!(
            a.layers[1].width as usize,
            tree_width(2) + carried_scalars() + XORS,
            "layer 2: the halved tree, the carried scalars, and one value a XOR"
        );
        // Layers 3 upward are the memory tree alone, halving to two.
        let mut expect = tree_width(3);
        for k in 2..a.layers.len() {
            if a.layers[k].halving {
                assert_eq!(a.layers[k].width, 2, "halving layer {k}");
            } else {
                assert_eq!(a.layers[k].width as usize, expect, "tree layer {k}");
                expect = if expect > 2 { expect / 2 } else { 2 };
            }
        }
        assert_eq!(a.committed().len(), MEMORY_COLUMNS + WITNESS_COLUMNS);
    }

    /// `Ch`, `Maj` and the three-way XOR, as the circuit spells them, over
    /// every input — eight each, so exhaustive rather than sampled.
    #[test]
    fn the_degree_two_spellings_are_the_boolean_functions() {
        for x in 0..2u32 {
            for y in 0..2u32 {
                for z in 0..2u32 {
                    assert_eq!(z + x * y - x * z, (x & y) ^ ((1 - x) & z), "ch");
                    let pab = x * y;
                    assert_eq!(
                        pab + z * (x + y - 2 * pab),
                        (x & y) ^ (x & z) ^ (y & z),
                        "maj"
                    );
                    let p = x * y;
                    assert_eq!(
                        (x + y - 2 * p) + z - 2 * z * (x + y - 2 * p),
                        x ^ y ^ z,
                        "xor3"
                    );
                }
            }
        }
    }
}
