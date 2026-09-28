//! The elliptic-curve addition circuit, gate by gate.
//!
//! `docs/spec/delegation.md` §16 is what this suite restates: the 97-word
//! frame, the six-way (curve, group) selector, the anchor's two tuples, and the
//! nine reductions' shared identity `A·B + C·D + 1024·m² = q·m + out` with every
//! frame value and every `out` below `m`.
//!
//! The arithmetic is checked **row by row**: each row is built here and
//! evaluated alone through `checker::violated_relations`, its row-local scratch
//! computed by `gkr::gate_values`, exactly as `tests/mod_mul.rs` does and for
//! the same reason — this family carries the `RANGE16` channel
//! (`docs/spec/delegation.md` §10.3), whose table needs sixteen variables, so
//! the circuit exists only at `2^16` and a whole-shard forward pass is
//! impossible.
//!
//! # What is independent here, and what is transcribed
//!
//! The **operand structure** is transcribed: the four operands of each of the
//! nine slots are committed columns, so a witness builder has to know what the
//! circuit expects in them, and [`slots`] is that knowledge written twice.
//!
//! What is independent is the **answer**. [`expected`] computes each group's
//! three results from Renes–Costello–Batina Algorithm 7 over ordinary 256-bit
//! modular arithmetic — schoolbook multiplication and shift-and-subtract
//! division, sharing no line with `crates/emulator`'s executor or the prover's
//! fill — and [`the_reductions_are_the_group_law`] holds the `out` that comes
//! out of the limb identity's long division equal to it, slot for slot. So a
//! circuit whose schedule computed a different function of the same operands is
//! refused here even though this file spells that schedule out.
//!
//! Every negative control corrupts one cell of an otherwise honest witness, or
//! supplies an honest witness for a claim the circuit must refuse, and names
//! the relation that must catch it.
//!
//! # What is deliberately not here: an anchor twin
//!
//! `checker::assert_anchor_twins_refused` is not called for this family. The
//! anchor is one mechanism, built by `constraints::delegation` identically for
//! all six families and already proved refused at block level over four of
//! them in `tests/tamper.rs` — including `MOD_MUL`, which also carries a lookup
//! channel, so even that combination is not new. A fifth replay would be the
//! same mutation set at another re-proof in the slowest deferred suite, which
//! the root `CLAUDE.md`'s test rule exists to refuse.

use constants::ec_add as f;
use constants::{challenge_slot, guest_memory, memory as mem};
use constraints::delegation as dl;
use constraints::ec_add as c;
use constraints::{CircuitArtifact, PolyAddress};
use field::Fr;
use gkr::{gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use poly::{MultilinearPoly, PolyBacking};

/// The circuit's own height: `RANGE16`'s table needs sixteen variables, so a
/// channel-carrying family has exactly one.
const VARS: u32 = 16;

/// The rows this suite builds and evaluates. The other 65,528 are never
/// materialized: a relation is row-local, so one row is all an evaluation
/// needs.
const ROWS: usize = 8;

/// Limbs in a coordinate.
const L: usize = f::LIMBS;

/// Reductions one invocation performs.
const SLOTS: usize = 3;

/// A 256-bit value: eight 32-bit limbs in `u64` lanes, little-endian.
type V = [u64; L];

// ---------------------------------------------------------------------------
// 256-bit modular arithmetic, written here
// ---------------------------------------------------------------------------

fn below(x: &V, y: &V) -> bool {
    for k in (0..L).rev() {
        if x[k] != y[k] {
            return x[k] < y[k];
        }
    }
    false
}

/// `x − y` over eight limbs, wrapping.
fn sub_raw(x: &V, y: &V) -> V {
    let mut out = [0u64; L];
    let mut borrow = 0i64;
    for k in 0..L {
        let d = x[k] as i64 - y[k] as i64 - borrow;
        borrow = i64::from(d < 0);
        out[k] = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u64;
    }
    out
}

fn add_mod(a: &V, b: &V, m: &V) -> V {
    let mut out = [0u64; L];
    let mut carry = 0u64;
    for k in 0..L {
        let total = a[k] + b[k] + carry;
        out[k] = total & 0xffff_ffff;
        carry = total >> 32;
    }
    if carry != 0 || !below(&out, m) {
        out = sub_raw(&out, m);
    }
    out
}

fn sub_mod(a: &V, b: &V, m: &V) -> V {
    match below(a, b) {
        // `a + (m − b)`, which is below `2m`, so one conditional subtraction
        // closes it — and `a + m` need not fit eight limbs this way.
        true => add_mod(a, &sub_raw(m, b), m),
        false => sub_raw(a, b),
    }
}

fn mul_mod(a: &V, b: &V, m: &V) -> V {
    let wide = loose_mul(&loose(a), &loose(b));
    divmod(&normalize(&wide), m).1
}

fn scale_mod(k: u32, a: &V, m: &V) -> V {
    let mut s = [0u64; L];
    s[0] = k as u64;
    mul_mod(&s, a, m)
}

// ---------------------------------------------------------------------------
// Loose big integers: base 2^32, signed, little-endian
// ---------------------------------------------------------------------------

/// A value as signed base-`2^32` limbs, `Σ x_k · 2^{32k}`.
///
/// **Loose** because the circuit's operands are: an operand limb is a short
/// signed combination of frame limbs, so it is not confined to `[0, 2^32)` and
/// the limb identity does not require it to be. Every arithmetic function here
/// therefore works on limbs of any magnitude and normalizes only at the end.
type Loose = Vec<i128>;

fn loose(x: &V) -> Loose {
    x.iter().map(|w| *w as i128).collect()
}

fn loose_mul(a: &Loose, b: &Loose) -> Loose {
    let mut out = vec![0i128; a.len() + b.len()];
    for (i, ai) in a.iter().enumerate() {
        for (j, bj) in b.iter().enumerate() {
            out[i + j] += ai * bj;
        }
    }
    out
}

fn loose_add(a: &Loose, b: &Loose) -> Loose {
    let mut out = vec![0i128; a.len().max(b.len())];
    for (k, slot) in out.iter_mut().enumerate() {
        *slot = a.get(k).copied().unwrap_or(0) + b.get(k).copied().unwrap_or(0);
    }
    out
}

fn loose_scale(k: i128, a: &Loose) -> Loose {
    a.iter().map(|x| k * x).collect()
}

/// A loose value as canonical base-`2^32` limbs, by carry propagation.
///
/// Panics on a negative value, which is the point: every left-hand side this
/// suite normalizes is one the `1024·m²` offset is supposed to have made
/// non-negative, so a panic here is that claim failing rather than a test
/// bug swallowed.
fn normalize(x: &Loose) -> Vec<u32> {
    let mut out = vec![0u32; x.len() + 2];
    let mut carry = 0i128;
    for (k, limb) in x.iter().enumerate() {
        let total = limb + carry;
        let low = total.rem_euclid(1 << 32);
        out[k] = low as u32;
        carry = (total - low) >> 32;
    }
    let mut k = x.len();
    while carry != 0 {
        assert!(k < out.len(), "the value does not fit the normalized width");
        let low = carry.rem_euclid(1 << 32);
        out[k] = low as u32;
        carry = (carry - low) >> 32;
        k += 1;
    }
    assert!(
        carry >= 0,
        "the value is negative: the offset did not cover it"
    );
    out
}

/// `(x / m, x mod m)` by shift-and-subtract from the top bit.
fn divmod(x: &[u32], m: &V) -> (Vec<u32>, V) {
    let mut q = vec![0u32; x.len()];
    // One lane above `m`'s eight: the remainder is below `m < 2^256` before
    // each step, so doubling it reaches `2^257`.
    let mut rem = [0u64; L + 1];
    for bit in (0..32 * x.len()).rev() {
        let mut carry = ((x[bit / 32] >> (bit % 32)) & 1) as u64;
        for lane in rem.iter_mut() {
            let total = (*lane << 1) | carry;
            *lane = total & 0xffff_ffff;
            carry = total >> 32;
        }
        assert_eq!(carry, 0, "the remainder overflowed its lanes");
        let ge = rem[L] != 0 || {
            let narrow: V = core::array::from_fn(|k| rem[k]);
            !below(&narrow, m)
        };
        if ge {
            let narrow: V = core::array::from_fn(|k| rem[k]);
            let reduced = sub_raw(&narrow, m);
            for (k, lane) in reduced.iter().enumerate() {
                rem[k] = *lane;
            }
            rem[L] = 0;
            q[bit / 32] |= 1 << (bit % 32);
        }
    }
    (q, core::array::from_fn(|k| rem[k]))
}

// ---------------------------------------------------------------------------
// The twelve frame values and the nine slots
// ---------------------------------------------------------------------------

const X1: usize = 0;
const Y1: usize = 1;
const Z1: usize = 2;
const X2: usize = 3;
const Y2: usize = 4;
const Z2: usize = 5;
const XX: usize = 6;
const YY: usize = 7;
const ZZ: usize = 8;
const M4: usize = 9;
const M5: usize = 10;
const M6: usize = 11;

/// The frame word each value starts at, in the same order
/// `constraints::ec_add::VALUES` uses — which is what makes `c::diff(v, i)`
/// and this file's `v` the same index.
const VALUE_WORD: [usize; 12] = [
    f::X1_WORD,
    f::Y1_WORD,
    f::Z1_WORD,
    f::X2_WORD,
    f::Y2_WORD,
    f::Z2_WORD,
    f::XX_WORD,
    f::YY_WORD,
    f::ZZ_WORD,
    f::M4_WORD,
    f::M5_WORD,
    f::M6_WORD,
];

/// Which groups read each value, so a `< m` chain is asserted where the circuit
/// gates it and nowhere else.
const VALUE_GROUPS: [&[usize]; 12] = [
    &[0, 1],
    &[0, 1],
    &[0, 1],
    &[0, 1],
    &[0, 1],
    &[0, 1],
    &[2],
    &[2],
    &[2],
    &[2],
    &[2],
    &[2],
];

/// One term of one operand: a frame value's limb, or one of the three
/// curve-scaled helpers', times a small signed coefficient.
#[derive(Clone, Copy)]
enum Term {
    Frame(usize, i64),
    Bzz3(i64),
    Byz3(i64),
    Bxx9(i64),
}

/// One reduction: four operands and the frame word its result is written to.
struct Slot {
    ops: [&'static [Term]; 4],
    out_word: usize,
}

/// Group `g`'s three slots, transcribed from `docs/spec/delegation.md` §16.
///
/// **`D` carries the sign.** Slot 0 of group 2 is `xy·ym − byz3·xz`, and the
/// identity has one shape for every group, so the minus rides `D` — which is
/// `xx + zz − m6` where the other slots' is `m6 − xx − zz`.
fn slots(g: usize) -> [Slot; SLOTS] {
    const XY: &[Term] = &[Term::Frame(M4, 1), Term::Frame(XX, -1), Term::Frame(YY, -1)];
    const YZ: &[Term] = &[Term::Frame(M5, 1), Term::Frame(YY, -1), Term::Frame(ZZ, -1)];
    const XZ: &[Term] = &[Term::Frame(M6, 1), Term::Frame(XX, -1), Term::Frame(ZZ, -1)];
    const NXZ: &[Term] = &[Term::Frame(XX, 1), Term::Frame(ZZ, 1), Term::Frame(M6, -1)];
    const YM: &[Term] = &[Term::Frame(YY, 1), Term::Bzz3(-1)];
    const YP: &[Term] = &[Term::Frame(YY, 1), Term::Bzz3(1)];
    const BYZ3: &[Term] = &[Term::Byz3(1)];
    const BXX9: &[Term] = &[Term::Bxx9(1)];
    const XX3: &[Term] = &[Term::Frame(XX, 3)];
    const NONE: &[Term] = &[];
    const fn one(v: usize) -> &'static [Term] {
        // A `const fn` cannot return a reference to a temporary, so the six
        // single-term operands are spelled out below rather than built here.
        match v {
            X1 => &[Term::Frame(X1, 1)],
            Y1 => &[Term::Frame(Y1, 1)],
            Z1 => &[Term::Frame(Z1, 1)],
            X2 => &[Term::Frame(X2, 1)],
            Y2 => &[Term::Frame(Y2, 1)],
            _ => &[Term::Frame(Z2, 1)],
        }
    }
    const XPY1: &[Term] = &[Term::Frame(X1, 1), Term::Frame(Y1, 1)];
    const XPY2: &[Term] = &[Term::Frame(X2, 1), Term::Frame(Y2, 1)];
    const YPZ1: &[Term] = &[Term::Frame(Y1, 1), Term::Frame(Z1, 1)];
    const YPZ2: &[Term] = &[Term::Frame(Y2, 1), Term::Frame(Z2, 1)];
    const XPZ1: &[Term] = &[Term::Frame(X1, 1), Term::Frame(Z1, 1)];
    const XPZ2: &[Term] = &[Term::Frame(X2, 1), Term::Frame(Z2, 1)];

    match g {
        0 => [
            Slot {
                ops: [one(X1), one(X2), NONE, NONE],
                out_word: f::XX_WORD,
            },
            Slot {
                ops: [one(Y1), one(Y2), NONE, NONE],
                out_word: f::YY_WORD,
            },
            Slot {
                ops: [one(Z1), one(Z2), NONE, NONE],
                out_word: f::ZZ_WORD,
            },
        ],
        1 => [
            Slot {
                ops: [XPY1, XPY2, NONE, NONE],
                out_word: f::M4_WORD,
            },
            Slot {
                ops: [YPZ1, YPZ2, NONE, NONE],
                out_word: f::M5_WORD,
            },
            Slot {
                ops: [XPZ1, XPZ2, NONE, NONE],
                out_word: f::M6_WORD,
            },
        ],
        _ => [
            Slot {
                ops: [XY, YM, BYZ3, NXZ],
                out_word: f::X1_WORD,
            },
            Slot {
                ops: [YP, YM, BXX9, XZ],
                out_word: f::Y1_WORD,
            },
            Slot {
                ops: [YZ, YP, XX3, XY],
                out_word: f::Z1_WORD,
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// One invocation, and everything the witness needs of it
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Invocation {
    cycle: u64,
    base: u32,
    code: u32,
    /// The frame's 97 read words.
    frame: Vec<u32>,
}

/// One slot's whole witness: four loose operands, the quotient, the result and
/// the fifteen signed carries.
struct Reduction {
    ops: [Loose; 4],
    q: Vec<u32>,
    out: V,
    carries: Vec<i128>,
}

impl Invocation {
    /// One invocation, with the selector written into **frame word 0**.
    ///
    /// `selector_rule` is `frame[0] - Σ code_i·selector_i = 0`, so the frame
    /// word and the selector columns are one claim and a witness that sets only
    /// the columns is refused — which is the gate working. A real guest writes
    /// the word before each of the three calls, which is what
    /// `guest_sdk::recursion::ec_add_complete` does.
    fn new(cycle: u64, base: u32, code: u32, mut frame: Vec<u32>) -> Invocation {
        frame[f::SELECTOR_WORD] = code;
        Invocation {
            cycle,
            base,
            code,
            frame,
        }
    }

    fn group(&self) -> usize {
        f::reduction_group(self.code).expect("a selectable code")
    }
    fn m(&self) -> V {
        let limbs = f::modulus(self.code).expect("a selectable code");
        core::array::from_fn(|k| limbs[k] as u64)
    }
    fn b3(&self) -> u32 {
        f::b3(self.code).expect("a selectable code")
    }
    /// Frame value `v`'s eight limbs.
    fn value(&self, v: usize) -> V {
        core::array::from_fn(|k| self.frame[VALUE_WORD[v] + k] as u64)
    }

    /// The three helper columns, **limb by limb and not reduced**: the circuit's
    /// gates are `bzz3_k = b3·zz_k`, so a helper is a loose value whose limbs
    /// are small multiples of the frame's and whose *value* is `b3·zz`.
    fn helpers(&self) -> (Loose, Loose, Loose) {
        let b3 = self.b3() as i128;
        let l = |v: usize| -> Loose { self.value(v).iter().map(|w| *w as i128).collect() };
        let (zz, yy, m5, xx) = (l(ZZ), l(YY), l(M5), l(XX));
        let bzz3 = (0..L).map(|k| b3 * zz[k]).collect();
        let byz3 = (0..L).map(|k| b3 * (m5[k] - yy[k] - zz[k])).collect();
        let bxx9 = (0..L).map(|k| 3 * b3 * xx[k]).collect();
        (bzz3, byz3, bxx9)
    }

    /// One operand's eight loose limbs.
    fn operand(&self, terms: &[Term]) -> Loose {
        let (bzz3, byz3, bxx9) = self.helpers();
        let mut out = vec![0i128; L];
        for term in terms {
            let (source, coefficient) = match *term {
                Term::Frame(v, cf) => (
                    self.value(v).iter().map(|w| *w as i128).collect::<Loose>(),
                    cf,
                ),
                Term::Bzz3(cf) => (bzz3.clone(), cf),
                Term::Byz3(cf) => (byz3.clone(), cf),
                Term::Bxx9(cf) => (bxx9.clone(), cf),
            };
            for k in 0..L {
                out[k] += coefficient as i128 * source[k];
            }
        }
        out
    }

    /// Slot `r`'s reduction, solved from the identity rather than assumed.
    fn reduction(&self, r: usize) -> Reduction {
        let m = self.m();
        let slot = &slots(self.group())[r];
        let ops: [Loose; 4] = core::array::from_fn(|which| self.operand(slot.ops[which]));
        // `A·B + C·D + 1024·m²`, which the offset makes non-negative.
        let lhs = loose_add(
            &loose_add(&loose_mul(&ops[0], &ops[1]), &loose_mul(&ops[2], &ops[3])),
            &loose_scale(
                f::OFFSET_MULTIPLE as i128,
                &loose_mul(&loose(&m), &loose(&m)),
            ),
        );
        let (q, out) = divmod(&normalize(&lhs), &m);
        for (k, limb) in q.iter().enumerate().skip(f::QUOTIENT_LIMBS) {
            assert_eq!(*limb, 0, "the quotient needs limb {k}");
        }
        let carries = carries_of(&ops, &q, &out, &m);
        Reduction {
            ops,
            q,
            out,
            carries,
        }
    }

    /// The frame's 97 write words: every word unchanged but the three this
    /// group's slots compute.
    fn write(&self) -> Vec<u32> {
        let mut out = self.frame.clone();
        let g = self.group();
        for r in 0..SLOTS {
            let word = slots(g)[r].out_word;
            let value = self.reduction(r).out;
            for k in 0..L {
                out[word + k] = value[k] as u32;
            }
        }
        out
    }

    /// The timestamp gap every frame word carries: `4·cycle + FRAME_DELTA − 0 − 1`,
    /// the read stamp being 0 because the frame's words are untouched before
    /// the call.
    fn gap(&self) -> u64 {
        mem::TS_STEP * self.cycle + constants::delegation::FRAME_DELTA - 1
    }
}

/// `Σ_{i+j=k} x_i·y_j`, one position of a loose schoolbook product.
fn part(x: &[i128], y: &[i128], k: usize) -> i128 {
    (0..x.len())
        .filter_map(|i| k.checked_sub(i).filter(|j| *j < y.len()).map(|j| (i, j)))
        .map(|(i, j)| x[i] * y[j])
        .sum()
}

/// The fifteen signed carries of one slot's sixteen limb equations.
///
/// `P_k + O_k − S_k − out_k + c_{k−1} − 2^32·c_k = 0`, and the last position
/// has no outgoing carry — which is the closing condition, asserted here.
fn carries_of(ops: &[Loose; 4], q: &[u32], out: &V, m: &V) -> Vec<i128> {
    let ml = loose(m);
    let ql: Loose = q.iter().map(|w| *w as i128).collect();
    let mut carries = Vec::new();
    let mut carry = 0i128;
    for k in 0..f::POSITIONS {
        let mut lhs = part(&ops[0], &ops[1], k)
            + part(&ops[2], &ops[3], k)
            + f::OFFSET_MULTIPLE as i128 * part(&ml, &ml, k)
            - part(&ql, &ml, k)
            + carry;
        if let Some(limb) = out.get(k) {
            lhs -= *limb as i128;
        }
        assert_eq!(lhs.rem_euclid(1 << 32), 0, "position {k} does not divide");
        carry = lhs / (1 << 32);
        if k < f::CARRIES {
            carries.push(carry);
        }
    }
    assert_eq!(carry, 0, "the identity leaves a carry");
    carries
}

/// The borrow chain of `x − y` over eight 32-bit limbs.
fn borrow_chain(x: &V, y: &V) -> ([u64; L], [u64; L]) {
    let (mut diff, mut borrow) = ([0u64; L], [0u64; L]);
    let mut carry = 0i64;
    for i in 0..L {
        let d = x[i] as i64 - y[i] as i64 - carry;
        carry = i64::from(d < 0);
        diff[i] = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u64;
        borrow[i] = carry as u64;
    }
    (diff, borrow)
}

// ---------------------------------------------------------------------------
// Algorithm 7 over plain modular arithmetic: the independent answer
// ---------------------------------------------------------------------------

/// Group `g`'s three results for the frame `i` carries, computed from the
/// group law and not from the limb identity.
///
/// This is the suite's one independent statement. [`Invocation::reduction`]
/// solves the circuit's identity; this computes what the answer is supposed to
/// be, and `the_reductions_are_the_group_law` holds them equal.
fn expected(i: &Invocation) -> [V; SLOTS] {
    let m = &i.m();
    let b3 = i.b3();
    let v = |k: usize| i.value(k);
    match i.group() {
        0 => [
            mul_mod(&v(X1), &v(X2), m),
            mul_mod(&v(Y1), &v(Y2), m),
            mul_mod(&v(Z1), &v(Z2), m),
        ],
        1 => [
            mul_mod(&add_mod(&v(X1), &v(Y1), m), &add_mod(&v(X2), &v(Y2), m), m),
            mul_mod(&add_mod(&v(Y1), &v(Z1), m), &add_mod(&v(Y2), &v(Z2), m), m),
            mul_mod(&add_mod(&v(X1), &v(Z1), m), &add_mod(&v(X2), &v(Z2), m), m),
        ],
        _ => {
            let (xx, yy, zz) = (v(XX), v(YY), v(ZZ));
            let xy = sub_mod(&sub_mod(&v(M4), &xx, m), &yy, m);
            let yz = sub_mod(&sub_mod(&v(M5), &yy, m), &zz, m);
            let xz = sub_mod(&sub_mod(&v(M6), &xx, m), &zz, m);
            let bzz3 = scale_mod(b3, &zz, m);
            let ym = sub_mod(&yy, &bzz3, m);
            let yp = add_mod(&yy, &bzz3, m);
            let byz3 = scale_mod(b3, &yz, m);
            let xx3 = scale_mod(3, &xx, m);
            let bxx9 = scale_mod(3 * b3, &xx, m);
            [
                sub_mod(&mul_mod(&xy, &ym, m), &mul_mod(&byz3, &xz, m), m),
                add_mod(&mul_mod(&yp, &ym, m), &mul_mod(&bxx9, &xz, m), m),
                add_mod(&mul_mod(&yz, &yp, m), &mul_mod(&xx3, &xy, m), m),
            ]
        }
    }
}

// ---------------------------------------------------------------------------
// The witness
// ---------------------------------------------------------------------------

fn column(values: Vec<Fr>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(values))
}

/// A signed integer as an `Fr`. `Fr` has no `from_u128`, so a 128-bit
/// magnitude goes in as two 64-bit halves.
fn signed(x: i128) -> Fr {
    let magnitude = |m: u128| {
        let shift = Fr::from_u64(1 << 32) * Fr::from_u64(1 << 32);
        Fr::from_u64((m >> 64) as u64) * shift + Fr::from_u64(m as u64)
    };
    match x < 0 {
        true => -magnitude(x.unsigned_abs()),
        false => magnitude(x as u128),
    }
}

/// One invocation with everything the witness reads of it solved **once**.
///
/// Without this the builder calls [`Invocation::reduction`] per column per row
/// — some `10^5` long divisions over 530-bit values, which is minutes rather
/// than the second the evaluation itself takes.
struct Row {
    inv: Invocation,
    write: Vec<u32>,
    helpers: (Loose, Loose, Loose),
    reductions: Vec<Reduction>,
    /// Each frame value's `(differences, borrows)` against the row's modulus.
    chains: Vec<([u64; L], [u64; L])>,
    /// Each slot's `out`'s own chain.
    out_chains: Vec<([u64; L], [u64; L])>,
}

impl Row {
    fn of(inv: Invocation) -> Row {
        let m = inv.m();
        let reductions: Vec<Reduction> = (0..SLOTS).map(|r| inv.reduction(r)).collect();
        let chains = (0..VALUE_WORD.len())
            .map(|v| borrow_chain(&inv.value(v), &m))
            .collect();
        let out_chains = reductions
            .iter()
            .map(|red| borrow_chain(&red.out, &m))
            .collect();
        Row {
            write: inv.write(),
            helpers: inv.helpers(),
            reductions,
            chains,
            out_chains,
            inv,
        }
    }
}

/// The honest witness of `live`, padded to [`ROWS`] with zero rows.
fn witness(live: &[Row]) -> Vec<(PolyAddress, MultilinearPoly)> {
    assert!(live.len() <= ROWS);
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    let mut push = |address: PolyAddress, of: &dyn Fn(&Row) -> Fr| {
        let values = (0..ROWS)
            .map(|r| live.get(r).map_or(Fr::ZERO, of))
            .collect();
        out.push((address, column(values)));
    };
    let u = |x: u64| Fr::from_u64(x);

    push(c::CYCLE, &|i| u(i.inv.cycle));
    push(c::LIVE, &|_| Fr::ONE);
    push(c::BASE, &|i| u(i.inv.base as u64));
    push(c::ANCHOR_VALUE, &|_| Fr::ZERO);
    for j in 0..f::FRAME_WORDS {
        push(c::word(j, dl::WORD_ADDR), &move |i| {
            u(i.inv.base as u64 + 4 * j as u64)
        });
        push(c::word(j, dl::WORD_READ_TS), &|_| Fr::ZERO);
        push(c::word(j, dl::WORD_READ_VALUE), &move |i| {
            u(i.inv.frame[j] as u64)
        });
        push(c::word(j, dl::WORD_WRITE_VALUE), &move |i| {
            u(i.write[j] as u64)
        });
    }
    // The gap, as two RANGE16 chunks a word: chunk `c` holds bits
    // `[16(c+1), 16(c+2))`, the low sixteen being proven by the scaled
    // obligation rather than committed.
    for j in 0..f::FRAME_WORDS {
        for ch in 0..dl::GAP_CHUNKS {
            push(c::gap_chunk(j, ch), &move |i| {
                u((i.inv.gap() >> (16 * (ch as u32 + 1))) & 0xffff)
            });
        }
    }
    let low = |i: &Row| ((i.inv.base - guest_memory::RAM_ORIGIN) / 4) as u64;
    let room = |i: &Row| (1u64 << 31) - f::FRAME_BYTES as u64 - i.inv.base as u64;
    for (address, pick, shift) in [
        (c::base_low(), &low as &dyn Fn(&Row) -> u64, 0),
        (c::base_low_hi(), &low as &dyn Fn(&Row) -> u64, 16),
        (c::base_room(), &room as &dyn Fn(&Row) -> u64, 0),
        (c::base_room_hi(), &room as &dyn Fn(&Row) -> u64, 16),
    ] {
        push(address, &move |i| u(pick(i) >> shift));
    }
    // Every frame word's read value carries a 32-bit bound as its high
    // halfword — including word 0, the selector, whose is 0.
    for j in 0..f::FRAME_WORDS {
        push(c::word_high(j), &move |i| u((i.inv.frame[j] >> 16) as u64));
    }
    for (s, code) in f::CODES.into_iter().enumerate() {
        push(c::selector(s), &move |i| match i.inv.code == code {
            true => Fr::ONE,
            false => Fr::ZERO,
        });
    }
    for k in 0..L {
        push(c::m_limb(k), &move |i| u(i.inv.m()[k]));
    }
    push(c::b3(), &|i| u(i.inv.b3() as u64));
    for k in 0..L {
        push(c::bzz3_limb(k), &move |i| signed(i.helpers.0[k]));
    }
    for k in 0..L {
        push(c::byz3_limb(k), &move |i| signed(i.helpers.1[k]));
    }
    for k in 0..L {
        push(c::bxx9_limb(k), &move |i| signed(i.helpers.2[k]));
    }
    // Every frame value's `< m` chain. Computed for all twelve on every row:
    // the identity `v_i − m_i − b_{i−1} + 2^32 b_i = d_i` holds for any `v`,
    // and what the group gates is only the conclusion `b_7 = 1`.
    for v in 0..VALUE_WORD.len() {
        for i in 0..L {
            push(c::diff(v, i), &move |row| u(row.chains[v].0[i]));
        }
        for i in 0..L {
            push(c::diff_hi(v, i), &move |row| u(row.chains[v].0[i] >> 16));
        }
        for i in 0..L {
            push(c::borrow(v, i), &move |row| u(row.chains[v].1[i]));
        }
    }
    for r in 0..SLOTS {
        for which in 0..4 {
            for k in 0..L {
                push(c::operand(r, which, k), &move |i| {
                    signed(i.reductions[r].ops[which][k])
                });
            }
        }
        for k in 0..L {
            push(c::out_limb(r, k), &move |i| u(i.reductions[r].out[k]));
        }
        for k in 0..L {
            push(c::out_hi(r, k), &move |i| u(i.reductions[r].out[k] >> 16));
        }
        for k in 0..f::QUOTIENT_LIMBS {
            push(c::q_limb(r, k), &move |i| u(i.reductions[r].q[k] as u64));
        }
        for k in 0..f::QUOTIENT_LIMBS {
            push(c::q_hi(r, k), &move |i| {
                u((i.reductions[r].q[k] >> 16) as u64)
            });
        }
        // Each carry as the unsigned `carry + 2^46`, then its two chunks.
        let offset = move |i: &Row, k: usize| -> u64 {
            (i.reductions[r].carries[k] + (1i128 << f::CARRY_OFFSET_BITS)) as u64
        };
        for k in 0..f::CARRIES {
            push(c::carry(r, k), &move |i| u(offset(i, k)));
        }
        for k in 0..f::CARRIES {
            for ch in 0..2 {
                push(c::carry_chunk(r, k, ch), &move |i| {
                    u((offset(i, k) >> (16 * (ch as u32 + 1))) & 0xffff)
                });
            }
        }
        for i_limb in 0..L {
            push(c::out_diff(r, i_limb), &move |i| {
                u(i.out_chains[r].0[i_limb])
            });
        }
        for i_limb in 0..L {
            push(c::out_diff_hi(r, i_limb), &move |i| {
                u(i.out_chains[r].0[i_limb] >> 16)
            });
        }
        for i_limb in 0..L {
            push(c::out_borrow(r, i_limb), &move |i| {
                u(i.out_chains[r].1[i_limb])
            });
        }
    }
    // The channel's multiplicity is `crates/trace`'s and no gate reads it, but
    // `a.committed()` names it, so the column has to exist. Zero is what a
    // multiplicity is on a row the table does not hold.
    out.push((c::multiplicity_column(), column(vec![Fr::ZERO; ROWS])));
    out
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

fn challenges_for(a: &CircuitArtifact) -> ExternalChallenges {
    let mut ch = ExternalChallenges::new();
    for (slot, value) in [
        (challenge_slot::MEM_GAMMA, 3u64),
        (challenge_slot::MEM_ALPHA_ADDR, 5),
        (challenge_slot::MEM_ALPHA_TS, 7),
        (challenge_slot::MEM_ALPHA_VAL, 11),
    ] {
        ch.insert(slot, Fr::from_u64(value));
    }
    insert_lookup_challenges(&mut ch, Fr::from_u64(13), Fr::from_u64(17), a);
    ch
}

fn corrupt(
    mut columns: Vec<(PolyAddress, MultilinearPoly)>,
    address: PolyAddress,
    row: usize,
    value: Fr,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let slot = columns
        .iter_mut()
        .find(|(a, _)| *a == address)
        .unwrap_or_else(|| panic!("{address} is not a committed column"));
    let mut values: Vec<Fr> = (0..ROWS).map(|r| slot.1.get(r)).collect();
    values[row] = value;
    slot.1 = MultilinearPoly::new(PolyBacking::Fr(values));
    columns
}

/// One row of a column set as a witness row of `a`, its scratch computed
/// row-locally by the engine's own gate kernel.
fn witness_row(
    a: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    row: usize,
) -> checker::WitnessRow {
    let committed: Vec<Fr> = a
        .committed()
        .into_iter()
        .map(|address| {
            columns
                .iter()
                .find(|(at, _)| *at == address)
                .unwrap_or_else(|| panic!("no column for {address}"))
                .1
                .get(row)
        })
        .collect();
    let virtuals: Vec<Fr> = a
        .virtuals
        .iter()
        .map(|(k, _)| virtual_at_row(*k, row))
        .collect();
    let ch = challenges_for(a);
    let mut scratch = vec![Fr::ZERO; a.scratch.len()];
    let mut lower = committed.clone();
    for k in 0..a.depth() {
        if a.layers[k].halving {
            break;
        }
        let v: &[Fr] = if k == 0 { &virtuals } else { &[] };
        let values = gate_values(a, k, &lower, &[], v, &ch);
        let produced = values[..a.layers[k].producing.len()].to_vec();
        for (j, value) in produced.iter().enumerate() {
            let address = PolyAddress::Inner {
                layer: k as u32 + 1,
                offset: j as u32,
            };
            let slot = a
                .scratch
                .iter()
                .position(|s| s.address == address)
                .expect("every inner column has a scratch slot");
            scratch[slot] = *value;
        }
        lower = produced;
    }
    checker::WitnessRow {
        committed,
        row,
        scratch,
    }
}

/// The relation the corrupted row must break, or a panic saying nothing did.
fn refusal(a: &CircuitArtifact, columns: Vec<(PolyAddress, MultilinearPoly)>) -> String {
    for row in 0..ROWS {
        let violated =
            checker::violated_relations(a, &witness_row(a, &columns, row), &challenges_for(a));
        if let Some(name) = violated.first() {
            return name.clone();
        }
    }
    panic!("the corrupted witness satisfies every gate")
}

fn assert_every_row_holds(a: &CircuitArtifact, columns: &[(PolyAddress, MultilinearPoly)]) {
    for row in 0..ROWS {
        let violated =
            checker::violated_relations(a, &witness_row(a, columns, row), &challenges_for(a));
        assert!(violated.is_empty(), "row {row} breaks {violated:?}");
    }
}

// ---------------------------------------------------------------------------
// The honest rows
// ---------------------------------------------------------------------------

/// A pseudo-random value below `m`.
fn wide(rng: &mut test_support::Rng, m: &V) -> V {
    let raw: V = core::array::from_fn(|_| rng.next_u64() & 0xffff_ffff);
    divmod(&normalize(&loose(&raw)), m).1
}

fn base_of(k: u32) -> u32 {
    guest_memory::RAM_ORIGIN + 4 * 1024 * k
}

/// A frame holding one point pair, with the six intermediate lanes zero.
fn frame_of(p: [V; 3], q: [V; 3]) -> Vec<u32> {
    let mut frame = vec![0u32; f::FRAME_WORDS];
    for (v, value) in [p[0], p[1], p[2], q[0], q[1], q[2]].into_iter().enumerate() {
        for k in 0..L {
            frame[VALUE_WORD[v] + k] = value[k] as u32;
        }
    }
    frame
}

/// Seven live invocations: both curves' three groups over one point pair each,
/// and a seventh at the **widest** operands group 2 admits.
///
/// The group-2 rows read intermediates this function computes with
/// [`expected`], so the three rows of a curve are one real addition and not
/// three unrelated frames — which is what makes the write-back and the
/// group-gated `< m` chains mean anything.
fn honest() -> Vec<Row> {
    let mut rng = test_support::Rng::new(0x5236_0526);
    let mut live: Vec<Invocation> = Vec::new();
    let mut cycle = 7u64;
    let mut slot = 1u32;

    for curve in 0..2 {
        let codes: [u32; 3] = core::array::from_fn(|g| {
            f::group_code(curve, g).expect("both curves name all three groups")
        });
        let m: V = {
            let limbs = f::modulus(codes[0]).expect("a selectable code");
            core::array::from_fn(|k| limbs[k] as u64)
        };
        let p = [wide(&mut rng, &m), wide(&mut rng, &m), wide(&mut rng, &m)];
        let q = [wide(&mut rng, &m), wide(&mut rng, &m), wide(&mut rng, &m)];
        let mut frame = frame_of(p, q);

        // Group 0, then group 1, each writing its three lanes into the frame
        // the next row reads — which is exactly what the three invocations of
        // one addition do through memory.
        for code in codes.iter().take(2) {
            let invocation = Invocation::new(cycle, base_of(slot), *code, frame.clone());
            frame = invocation.write();
            live.push(invocation);
            cycle += 2;
            slot += 1;
        }
        live.push(Invocation::new(cycle, base_of(slot), codes[2], frame));
        cycle += 2;
        slot += 1;
    }

    // The widest row the family admits: secp256k1's group 2 — `b3 = 21`, so
    // its `bxx9` is `63·xx` — with every intermediate at `m − 1`. This is the
    // row `CARRY_OFFSET_BITS = 45` is sized for, and a bound off by one bit
    // refuses it.
    let code = f::group_code(0, 2).expect("secp256k1 names group 2");
    let m: V = {
        let limbs = f::modulus(code).expect("a selectable code");
        core::array::from_fn(|k| limbs[k] as u64)
    };
    let mut one = [0u64; L];
    one[0] = 1;
    let top = sub_raw(&m, &one);
    let mut frame = vec![0u32; f::FRAME_WORDS];
    for v in [XX, YY, ZZ, M4, M5, M6] {
        for k in 0..L {
            frame[VALUE_WORD[v] + k] = top[k] as u32;
        }
    }
    live.push(Invocation::new(cycle, base_of(slot), code, frame));
    live.into_iter().map(Row::of).collect()
}

// ---------------------------------------------------------------------------
// The circuit keeps every rule
// ---------------------------------------------------------------------------

#[test]
fn the_circuit_keeps_every_rule() {
    let a = c::artifact(VARS);
    a.validate().expect("the circuit is a circuit");
    checker::check_laws(&a).expect("the standalone validators agree");
    checker::check_padding(&a).expect("the padding contract holds");
    checker::check_padding_identity(&a).expect("a padding row is the product's identity");
    constraints::memory::check_memory(&a).expect("the memory provenance rules hold");
    constraints::lookup::check_discharge(&a, &c::channels()).expect("the channel discharges");
    c::check_shape(&a);
}

#[test]
fn it_is_the_one_delegation_family_with_a_channel() {
    // `docs/spec/delegation.md` §10.3's amendment, as an assertion: this family
    // and `MOD_MUL` carry `RANGE16` at `2^16`, and the other four carry none.
    let channels = c::channels();
    assert_eq!(channels.len(), 1);
    assert_eq!(
        channels[0].channel,
        constants::lookup_channel::RANGE16,
        "the channel is RANGE16, whose table needs sixteen variables"
    );
    assert!(
        constraints::family_circuit(constants::family::EC_ADD, VARS - 2).is_none(),
        "the registry must refuse this family below the channel's width"
    );
    assert!(constraints::family_circuit(constants::family::EC_ADD, VARS).is_some());
}

#[test]
fn an_honest_witness_satisfies_every_gate() {
    let a = c::artifact(VARS);
    assert_every_row_holds(&a, &witness(&honest()));
}

/// The nine reductions compute Renes–Costello–Batina Algorithm 7, and not
/// merely *some* function the identity happens to close over.
///
/// This is the suite's independent statement: the `out` solved from the limb
/// identity, against the group law over plain modular arithmetic.
#[test]
fn the_reductions_are_the_group_law() {
    for row in honest() {
        let want = expected(&row.inv);
        for (r, expect) in want.iter().enumerate() {
            assert_eq!(
                row.reductions[r].out,
                *expect,
                "group {} slot {r} is not the group law",
                row.inv.group()
            );
        }
    }
}

/// The three lanes a group writes are its three results, and every other lane
/// comes back unchanged — including the two input points, which the next
/// invocation of the same addition still needs.
#[test]
fn the_written_frame_is_the_reduction_and_nothing_else() {
    for row in honest() {
        let written: Vec<usize> = (0..SLOTS)
            .map(|r| slots(row.inv.group())[r].out_word)
            .collect();
        for j in 0..f::FRAME_WORDS {
            let owner = written.iter().position(|w| (*w..*w + L).contains(&j));
            match owner {
                Some(r) => assert_eq!(
                    row.write[j] as u64,
                    row.reductions[r].out[j - written[r]],
                    "word {j} is slot {r}'s result"
                ),
                None => assert_eq!(row.write[j], row.inv.frame[j], "word {j} moved"),
            }
        }
    }
}

/// Group 2's three invocations of one addition, read back as a point.
///
/// The three rows `honest` builds for a curve are one real addition, so the
/// last row's three results are `X3`, `Y3` and `Z3` — and this holds them
/// against Algorithm 7 run end to end in one expression, which is the check
/// that the *split into three invocations* is the same function as the whole.
#[test]
fn the_three_invocations_are_one_addition() {
    let live = honest();
    for curve in 0..2 {
        let first = &live[3 * curve].inv;
        let last = &live[3 * curve + 2];
        let m = &first.m();
        let b3 = first.b3();
        let v = |k: usize| first.value(k);
        // Algorithm 7 in one go, from the two points the first row read.
        let xx = mul_mod(&v(X1), &v(X2), m);
        let yy = mul_mod(&v(Y1), &v(Y2), m);
        let zz = mul_mod(&v(Z1), &v(Z2), m);
        let m4 = mul_mod(&add_mod(&v(X1), &v(Y1), m), &add_mod(&v(X2), &v(Y2), m), m);
        let m5 = mul_mod(&add_mod(&v(Y1), &v(Z1), m), &add_mod(&v(Y2), &v(Z2), m), m);
        let m6 = mul_mod(&add_mod(&v(X1), &v(Z1), m), &add_mod(&v(X2), &v(Z2), m), m);
        let xy = sub_mod(&sub_mod(&m4, &xx, m), &yy, m);
        let yz = sub_mod(&sub_mod(&m5, &yy, m), &zz, m);
        let xz = sub_mod(&sub_mod(&m6, &xx, m), &zz, m);
        let bzz3 = scale_mod(b3, &zz, m);
        let ym = sub_mod(&yy, &bzz3, m);
        let yp = add_mod(&yy, &bzz3, m);
        let want = [
            sub_mod(
                &mul_mod(&xy, &ym, m),
                &mul_mod(&scale_mod(b3, &yz, m), &xz, m),
                m,
            ),
            add_mod(
                &mul_mod(&yp, &ym, m),
                &mul_mod(&scale_mod(3 * b3, &xx, m), &xz, m),
                m,
            ),
            add_mod(
                &mul_mod(&yz, &yp, m),
                &mul_mod(&scale_mod(3, &xx, m), &xy, m),
                m,
            ),
        ];
        for (r, expect) in want.iter().enumerate() {
            assert_eq!(last.reductions[r].out, *expect, "curve {curve}, slot {r}");
        }
    }
}

// ---------------------------------------------------------------------------
// The negative controls
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_result_limb_is_refused() {
    let a = c::artifact(VARS);
    // The low limb of group 0's first reduction. **Two** gates see it and both
    // must: `out0_canonical0`, the first limb of the result's own `< m` borrow
    // chain, and `slot0_limb0`, where the identity's position 0 closes. The
    // chain comes first in relation order, so that is the name; that the
    // identity also catches it is what `a_wrong_quotient_limb_is_refused` shows,
    // the quotient being a value only the identity reads.
    let broken = corrupt(witness(&honest()), c::out_limb(0, 0), 0, Fr::from_u64(1));
    assert_eq!(refusal(&a, broken), "out0_canonical0");
}

#[test]
fn a_wrong_quotient_limb_is_refused() {
    let a = c::artifact(VARS);
    let honest_q = witness(&honest())
        .into_iter()
        .find(|(at, _)| *at == c::q_limb(0, 0))
        .expect("the column exists")
        .1
        .get(0);
    let broken = corrupt(
        witness(&honest()),
        c::q_limb(0, 0),
        0,
        honest_q + Fr::from_u64(1),
    );
    assert_eq!(refusal(&a, broken), "slot0_limb0");
}

#[test]
fn a_wrong_operand_is_refused_by_its_own_pin() {
    let a = c::artifact(VARS);
    // An operand is a committed column pinned by a degree-2 gate to a bounded
    // combination of frame limbs, and that pin *is* its bound — so the gate
    // that catches a moved operand is the pin and not the product.
    let honest_op = witness(&honest())
        .into_iter()
        .find(|(at, _)| *at == c::operand(0, 0, 0))
        .expect("the column exists")
        .1
        .get(0);
    let broken = corrupt(
        witness(&honest()),
        c::operand(0, 0, 0),
        0,
        honest_op + Fr::from_u64(1),
    );
    assert_eq!(refusal(&a, broken), "operand0_0_0_rule");
}

#[test]
fn a_wrong_helper_limb_is_refused() {
    let a = c::artifact(VARS);
    // `bzz3_k = b3 · zz_k` is a per-limb identity, not a modular product, and
    // it is what carries the curve constant into the formula.
    let honest_h = witness(&honest())
        .into_iter()
        .find(|(at, _)| *at == c::bzz3_limb(0))
        .expect("the column exists")
        .1
        .get(2);
    let broken = corrupt(
        witness(&honest()),
        c::bzz3_limb(0),
        2,
        honest_h + Fr::from_u64(1),
    );
    assert_eq!(refusal(&a, broken), "bzz3_0_rule");
}

#[test]
fn a_wrong_curve_constant_is_refused() {
    let a = c::artifact(VARS);
    // `b3` is pinned to the selector's literal: 21 for secp256k1, 9 for BN254.
    // Swapping one for the other is a correct addition **on the wrong curve**,
    // which nothing else in the row would notice.
    let broken = corrupt(witness(&honest()), c::b3(), 0, Fr::from_u64(9));
    assert_eq!(refusal(&a, broken), "b3_rule");
}

#[test]
fn a_wrong_modulus_limb_is_refused() {
    let a = c::artifact(VARS);
    let honest_m = witness(&honest())
        .into_iter()
        .find(|(at, _)| *at == c::m_limb(0))
        .expect("the column exists")
        .1
        .get(0);
    let broken = corrupt(
        witness(&honest()),
        c::m_limb(0),
        0,
        honest_m + Fr::from_u64(1),
    );
    assert_eq!(refusal(&a, broken), "m_limb0_rule");
}

#[test]
fn a_selector_that_is_not_the_frames_is_refused() {
    let a = c::artifact(VARS);
    // The selector columns claim a (curve, group) pair and `selector_rule`
    // ties that claim to the frame word the guest wrote. Moving the frame word
    // alone is a row computing one group's formula while claiming another's.
    let broken = corrupt(
        witness(&honest()),
        c::word(f::SELECTOR_WORD, dl::WORD_READ_VALUE),
        0,
        Fr::from_u64(f::BN254_G1 as u64),
    );
    let name = refusal(&a, broken);
    assert!(
        name.contains("selector"),
        "a frame selector out of step with its columns was caught by {name}"
    );
}

#[test]
fn two_selectors_at_once_are_refused() {
    let a = c::artifact(VARS);
    // Booleanity permits any subset, so what makes the six a partition is that
    // they sum to `live`. Setting a second one keeps every bit boolean.
    let other = (0..f::CODES.len())
        .find(|s| f::CODES[*s] != honest()[0].inv.code)
        .expect("six codes");
    let broken = corrupt(witness(&honest()), c::selector(other), 0, Fr::ONE);
    let name = refusal(&a, broken);
    assert!(
        name.contains("selector") || name.contains("one_"),
        "two live selectors were caught by {name}"
    );
}

#[test]
fn a_result_at_or_above_the_modulus_is_refused() {
    let a = c::artifact(VARS);
    // `out + m` with the quotient one lower satisfies the limb identity over
    // the integers just as well, so what makes `out` *the* reduction is its own
    // borrow chain. Corrupting the chain's last borrow is that check, directly.
    let broken = corrupt(witness(&honest()), c::out_borrow(0, L - 1), 0, Fr::ZERO);
    let name = refusal(&a, broken);
    assert!(
        name.contains("out") || name.contains("borrow"),
        "an unreduced result was caught by {name}"
    );
}

#[test]
fn an_unreduced_frame_value_is_refused_on_the_group_that_reads_it() {
    let a = c::artifact(VARS);
    // A frame value's `< m` chain is what bounds the honest quotient below nine
    // limbs. It is gated on the groups that read the value, so corrupting the
    // conclusion has to be refused on a row of one of those groups — and row 0
    // is a group-0 row, which reads `x1`.
    assert_eq!(VALUE_GROUPS[X1], &[0, 1]);
    let broken = corrupt(witness(&honest()), c::borrow(X1, L - 1), 0, Fr::ZERO);
    let name = refusal(&a, broken);
    assert!(
        name.contains("x1") || name.contains("borrow") || name.contains("chain"),
        "an unreduced x1 was caught by {name}"
    );
}

#[test]
fn a_wrong_carry_is_refused() {
    let a = c::artifact(VARS);
    let honest_c = witness(&honest())
        .into_iter()
        .find(|(at, _)| *at == c::carry(0, 0))
        .expect("the column exists")
        .1
        .get(0);
    let broken = corrupt(
        witness(&honest()),
        c::carry(0, 0),
        0,
        honest_c + Fr::from_u64(1),
    );
    assert_eq!(refusal(&a, broken), "slot0_limb0");
}

#[test]
fn a_frame_word_rewritten_that_no_group_computes_is_refused() {
    let a = c::artifact(VARS);
    // The two input points survive every call: a group-0 row writes `xx`, `yy`
    // and `zz` and leaves `X1..Z2` alone, or the second invocation of the same
    // addition reads operands the first has changed.
    let broken = corrupt(
        witness(&honest()),
        c::word(f::X1_WORD, dl::WORD_WRITE_VALUE),
        0,
        Fr::from_u64(0xdead_beef),
    );
    let name = refusal(&a, broken);
    assert!(
        name.contains("write"),
        "a rewritten input coordinate was caught by {name}"
    );
}

#[test]
fn a_frame_word_above_its_bound_is_refused_by_the_channel_alone() {
    // A frame word's 32-bit bound is a `RANGE16` obligation on its high
    // halfword, not a relation — so the thing that refuses an out-of-range word
    // is the channel, and `violated_relations` must stay silent. This is the
    // one place the two kinds of refusal are told apart.
    let a = c::artifact(VARS);
    let broken = corrupt(
        witness(&honest()),
        c::word_high(f::X1_WORD),
        0,
        Fr::from_u64(0x1_0000),
    );
    for row in 0..ROWS {
        let violated =
            checker::violated_relations(&a, &witness_row(&a, &broken, row), &challenges_for(&a));
        // The word and its halfword now disagree, which *is* a relation — what
        // this test pins is that the halfword's range is the channel's business
        // and the channel names it.
        assert!(
            violated.iter().all(|r| !r.contains("range")),
            "row {row}: a range obligation is not a relation, and {violated:?} says it is"
        );
    }
    let named = checker::violated_lookups(&a, &witness_row(&a, &broken, 0));
    assert!(
        named.iter().any(|n| n.contains("x1") || n.contains("word")),
        "the channel does not name the out-of-range word: {named:?}"
    );
}

#[test]
fn a_padding_row_holds_and_a_live_one_next_to_it_does_too() {
    // The padding contract is checked structurally by `check_padding`; this is
    // the arithmetic half — that an all-zero row satisfies every gate of a
    // circuit whose identity carries a `1024·m²` offset and whose carries carry
    // a `2^46` one. Both ride `live`, and a padding row is where that shows.
    let a = c::artifact(VARS);
    let columns = witness(&honest());
    let violated = checker::violated_relations(
        &a,
        &witness_row(&a, &columns, ROWS - 1),
        &challenges_for(&a),
    );
    assert!(violated.is_empty(), "the padding row breaks {violated:?}");
}

#[test]
fn a_height_moves_only_the_halving_layers() {
    // A delegation family's height adds one halving list per variable and
    // changes no gate (`docs/spec/delegation.md` §9.2), which is what made
    // `MOD_MUL`'s raise a re-pin and not a redesign.
    let lo = c::artifact(VARS);
    let hi = c::artifact(VARS + 2);
    let d = (hi.trace_vars - lo.trace_vars) as usize;

    let committed = |a: &CircuitArtifact| (a.memory.len(), a.witness.len(), a.setup.len());
    assert_eq!(committed(&lo), committed(&hi), "committed width");
    // **Enforcing** gates and not every relation: a halving list *produces* one
    // node per output, so the total relation count grows with the height by
    // exactly `outputs * d` and only the enforcing half is height-invariant.
    let enforcing = |a: &CircuitArtifact| a.relations.iter().filter(|r| r.output.is_none()).count();
    assert_eq!(enforcing(&lo), enforcing(&hi), "enforcing gates");
    assert_eq!(lo.lookups.len(), hi.lookups.len(), "lookups");
    assert_eq!(lo.outputs.len(), hi.outputs.len(), "outputs");

    let halving = |a: &CircuitArtifact| a.layers.iter().filter(|l| l.halving).count();
    assert_eq!(
        halving(&hi) - halving(&lo),
        d,
        "one halving list per variable"
    );
    assert_eq!(hi.layers.len() - lo.layers.len(), d, "and no other list");

    let inner = |a: &CircuitArtifact| a.layers.iter().map(|l| l.width as usize).sum::<usize>();
    assert_eq!(
        inner(&hi) - inner(&lo),
        hi.outputs.len() * d,
        "each halving list carries one node per output"
    );
}
