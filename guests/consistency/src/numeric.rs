//! Numbers: integer arithmetic at every width, the 64- and 128-bit multiply
//! and divide, casts, floating point and its text, integer text, and a small
//! bignum written here.
//!
//! Almost none of this is hardware on the guest. RV32IMAC multiplies and
//! divides 32-bit words; everything wider is a compiler-builtins routine
//! (`__multi3`, `__udivti3`, `__divdi3`, ...), and with no F or D extension
//! every float operation, comparison and conversion is one too (`__adddf3`,
//! `__fixdfsi`, `__floatuntisf`, `fmod`, ...). The host runs the same Rust on
//! its own hardware. IEEE-754's basic operations are correctly rounded and
//! `%` is exact, so the two must agree bit for bit, and a section that differs
//! names the routine family that did.
//!
//! Most sections are fingerprints ([`Fold`]); the ones a person would read
//! first when a fingerprint differs -- the float edge cases, float and integer
//! text, and the bignum's decimals -- are text.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt::{self, Write};
use core::hint::black_box;
use core::num::{FpCategory, NonZero, Saturating, Wrapping};

use crate::{Ctx, Fault, Rng};

pub const TAGS: (u8, u8) = (0x10, 0x1f);

/// Every integer type's methods, on random and edge operands.
const TAG_INT_OPS: u8 = 0x10;
/// 64- and 128-bit multiply, divide and remainder, and the 32-bit widening
/// products.
const TAG_WIDE: u8 = 0x11;
/// `as` between every pair of integer types, and from each to `f32` and `f64`.
const TAG_INT_CASTS: u8 = 0x12;
/// Float to integer (saturating), `f64` to `f32` and back, `u128` to and from
/// `f64`.
const TAG_FLOAT_CASTS: u8 = 0x13;
/// `f64` and `f32` arithmetic, comparisons and the sign and step methods.
const TAG_FLOAT_ARITH: u8 = 0x14;
/// Text: rounding ties, subnormals, signed zeros, overflow, one per line.
const TAG_FLOAT_EDGES: u8 = 0x15;
/// Text: edge floats through `Display`, `Debug`, `LowerExp` and precisions.
const TAG_FLOAT_FORMAT: u8 = 0x16;
/// Random floats formatted, and parsed back to the same bits.
const TAG_FLOAT_ROUND_TRIP: u8 = 0x17;
/// Text: edge strings through `parse::<f64>` and `parse::<f32>`, then a
/// fingerprint of generated decimal strings.
const TAG_FLOAT_PARSE: u8 = 0x18;
/// Text: integers in every radix and flag, then a fingerprint of random ones.
const TAG_INT_FORMAT: u8 = 0x19;
/// Text: `from_str_radix` edge cases, then a fingerprint of generated strings.
const TAG_INT_PARSE: u8 = 0x1a;
/// Text: `TryFrom`, `NonZero`, `Wrapping`, `Saturating` and `char` digits.
const TAG_CONVERSIONS: u8 = 0x1b;
/// Text: the bignum's decimals, and its identities on random operands.
const TAG_BIGNUM: u8 = 0x1c;
/// Text: the payload's tokens read as numbers, and its bytes as one.
const TAG_PAYLOAD: u8 = 0x1d;

const FAULT_ADD_OVERFLOW: u8 = 0x10;
const FAULT_DIVIDE_BY_ZERO: u8 = 0x11;
const FAULT_DIVIDE_OVERFLOW: u8 = 0x12;
const FAULT_SHIFT_OVERFLOW: u8 = 0x13;

pub const FAULTS: &[Fault] = &[
    Fault {
        code: FAULT_ADD_OVERFLOW,
        what: "two u32s at or above 2^31, added: attempt to add with overflow",
    },
    Fault {
        code: FAULT_DIVIDE_BY_ZERO,
        what: "a u128 divided by q*d + r - n of the last division: attempt to divide by zero",
    },
    Fault {
        code: FAULT_DIVIDE_OVERFLOW,
        what: "i32::MIN, rebuilt from a random shift, over its own signum: attempt to divide \
               with overflow",
    },
    Fault {
        code: FAULT_SHIFT_OVERFLOW,
        what: "1u32 shifted by a float's leading zeros with bit 5 set: attempt to shift left \
               with overflow",
    },
];

pub fn run(cx: &mut Ctx) {
    let scale = cx.scale();

    let ops = int_ops(cx.rng(), scale);
    cx.section(TAG_INT_OPS, &ops.bytes());
    if cx.fault(FAULT_ADD_OVERFLOW) {
        black_box(add_past_u32(cx.rng()));
    }

    let (wide, last) = wide(cx.rng(), scale);
    cx.section(TAG_WIDE, &wide.bytes());
    if cx.fault(FAULT_DIVIDE_BY_ZERO) {
        black_box(divide_by_residue(last));
    }

    let casts = int_casts(cx.rng(), scale);
    cx.section(TAG_INT_CASTS, &casts.bytes());
    if cx.fault(FAULT_DIVIDE_OVERFLOW) {
        black_box(divide_min_by_signum(cx.rng()));
    }

    let casts = float_casts(cx.rng(), scale);
    cx.section(TAG_FLOAT_CASTS, &casts.bytes());

    let (arith, last) = float_arith(cx.rng(), scale);
    cx.section(TAG_FLOAT_ARITH, &arith.bytes());
    if cx.fault(FAULT_SHIFT_OVERFLOW) {
        black_box(shift_by_leading_zeros(last));
    }

    let text = float_edges(cx.rng(), scale);
    cx.section(TAG_FLOAT_EDGES, text.as_bytes());
    let text = float_format(cx.rng(), scale);
    cx.section(TAG_FLOAT_FORMAT, text.as_bytes());
    let trip = float_round_trip(cx.rng(), scale);
    cx.section(TAG_FLOAT_ROUND_TRIP, trip.as_bytes());
    let text = float_parse(cx.rng(), scale);
    cx.section(TAG_FLOAT_PARSE, text.as_bytes());

    let text = int_format(cx.rng(), scale);
    cx.section(TAG_INT_FORMAT, text.as_bytes());
    let text = int_parse(cx.rng(), scale);
    cx.section(TAG_INT_PARSE, text.as_bytes());
    let text = conversions(cx.rng(), scale);
    cx.section(TAG_CONVERSIONS, text.as_bytes());

    let text = bignum(cx.rng(), scale);
    cx.section(TAG_BIGNUM, text.as_bytes());
    let text = payload(cx.payload(), scale);
    cx.section(TAG_PAYLOAD, text.as_bytes());
}

// ---------------------------------------------------------------------------
// The faults
// ---------------------------------------------------------------------------

/// Two operands with the top bit set, so the sum needs 33 bits.
fn add_past_u32(rng: &mut Rng) -> u32 {
    let a = black_box(rng.next_u32() | 0x8000_0000);
    let b = black_box(rng.next_u32() | 0x8000_0000);
    a + b
}

/// The last division `wide` checked, `n = q*d + r`, so its residue is zero.
fn divide_by_residue(last: Division) -> u128 {
    let zero = black_box(last.q * last.d + last.r - last.n);
    last.n / zero
}

/// `(MIN >> k) << k` is `MIN` for every `k` below 32, and its signum is -1.
fn divide_min_by_signum(rng: &mut Rng) -> i32 {
    let k = rng.next_u32() % 32;
    let min = black_box((i32::MIN >> k) << k);
    min / min.signum()
}

/// A `u64`'s leading zeros are at most 64, so with bit 5 set the amount is
/// 32..=96: never a valid shift of a `u32`.
fn shift_by_leading_zeros(x: f64) -> u32 {
    let amount = black_box(x.to_bits().leading_zeros() | 32);
    1u32 << amount
}

// ---------------------------------------------------------------------------
// Fingerprints and text
// ---------------------------------------------------------------------------

/// A running fingerprint that takes a 64-bit word per step.
///
/// [`crate::Digest`] takes a byte per step, and at the guest's opt-level 0
/// fingerprinting a result that way costs several times more than computing
/// it, so the sections that fold thousands of results use this and emit its
/// final word. Each step is a bijection of the state for a fixed input -- xor,
/// multiply by an odd constant, xor-shift by half -- so a single differing
/// result always changes the final word.
struct Fold(u64);

impl Fold {
    fn new() -> Fold {
        Fold(0x6a09_e667_f3bc_c908)
    }

    fn word(&mut self, v: u64) {
        let x = (self.0 ^ v).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.0 = x ^ (x >> 32);
    }

    /// Any integer, widened: signed types sign-extend, which is as
    /// deterministic as the value itself.
    fn int(&mut self, v: u128) {
        self.word(v as u64);
        self.word((v >> 64) as u64);
    }

    fn opt(&mut self, v: Option<u128>) {
        match v {
            Some(v) => self.int(v),
            None => self.word(0x4e6f_6e65),
        }
    }

    fn flag(&mut self, b: bool) {
        self.word(u64::from(b));
    }

    /// Every NaN folds to one: which NaN an operation produces is the
    /// platform's business, and `hazards` is where that is declared.
    fn f64(&mut self, v: f64) {
        self.word(if v.is_nan() {
            0x7ff8_0000_0000_0000
        } else {
            v.to_bits()
        });
    }

    fn f32(&mut self, v: f32) {
        self.word(u64::from(if v.is_nan() {
            0x7fc0_0000
        } else {
            v.to_bits()
        }));
    }

    /// For `min` and `max`, which may return either zero when given `+0.0`
    /// and `-0.0`: Rust leaves that choice unspecified, so the sign of a zero
    /// result is not folded.
    fn f64_unsigned_zero(&mut self, v: f64) {
        self.f64(if v == 0.0 { 0.0 } else { v });
    }

    fn f32_unsigned_zero(&mut self, v: f32) {
        self.f32(if v == 0.0 { 0.0 } else { v });
    }

    fn ordering(&mut self, o: Option<Ordering>) {
        self.word(match o {
            Some(Ordering::Less) => 1,
            Some(Ordering::Equal) => 2,
            Some(Ordering::Greater) => 3,
            None => 4,
        });
    }

    fn bytes(&self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

/// Formatting straight into the fingerprint, eight bytes a step, so the
/// fingerprinted text is never allocated. A `write!` delivers its text in
/// pieces; the pieces are the same on every target because the formatting
/// code is.
impl Write for Fold {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.word(s.len() as u64);
        for chunk in s.as_bytes().chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.word(u64::from_le_bytes(word));
        }
        Ok(())
    }
}

/// One line of a text section. Writing into a `String` cannot fail.
fn say(text: &mut String, line: fmt::Arguments) {
    text.write_fmt(line).expect("a String takes any text");
    text.push('\n');
}

/// `write!` into a [`Fold`], which cannot fail either.
fn fold_fmt(f: &mut Fold, text: fmt::Arguments) {
    f.write_fmt(text).expect("a Fold takes any text");
}

/// A float as its bits in hex, or `NaN`: which NaN is the platform's.
struct Hex64(f64);

impl fmt::Display for Hex64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_nan() {
            f.write_str("NaN")
        } else {
            write!(f, "{:016x}", self.0.to_bits())
        }
    }
}

struct Hex32(f32);

impl fmt::Display for Hex32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_nan() {
            f.write_str("NaN")
        } else {
            write!(f, "{:08x}", self.0.to_bits())
        }
    }
}

/// `base + per * scale`, the size of a scaled loop.
fn scaled(base: u32, per: u32, scale: u32) -> u32 {
    base + per * scale
}

/// 128 random bits shifted right by a random amount, so small magnitudes are
/// as common as large ones.
fn spread128(rng: &mut Rng) -> u128 {
    let raw = u128::from(rng.next_u64()) | (u128::from(rng.next_u64()) << 64);
    raw >> rng.below(128)
}

fn spread64(rng: &mut Rng) -> u64 {
    rng.next_u64() >> rng.below(64)
}

// ---------------------------------------------------------------------------
// Integer methods
// ---------------------------------------------------------------------------

/// An operand: one of the type's edge values a third of the time, else random
/// bits of a random magnitude.
macro_rules! pick {
    ($rng:ident, $edges:ident, $t:ty) => {
        if $rng.chance(1, 3) {
            $edges[$rng.index($edges.len())]
        } else {
            spread128($rng) as $t
        }
    };
}

/// What signed and unsigned types share. Every operation that can panic is
/// taken in its checked form, or only on operands where it cannot.
macro_rules! common_ops {
    ($f:ident, $t:ty, $a:ident, $b:ident, $s:ident, $e:ident) => {
        $f.int($a.wrapping_add($b) as u128);
        $f.int($a.wrapping_sub($b) as u128);
        $f.int($a.wrapping_mul($b) as u128);
        $f.opt($a.checked_add($b).map(|v| v as u128));
        $f.opt($a.checked_sub($b).map(|v| v as u128));
        $f.opt($a.checked_mul($b).map(|v| v as u128));
        $f.opt($a.checked_div($b).map(|v| v as u128));
        $f.opt($a.checked_rem($b).map(|v| v as u128));
        $f.opt($a.checked_div_euclid($b).map(|v| v as u128));
        $f.opt($a.checked_rem_euclid($b).map(|v| v as u128));
        let (v, o) = $a.overflowing_add($b);
        $f.int(v as u128);
        $f.flag(o);
        let (v, o) = $a.overflowing_sub($b);
        $f.int(v as u128);
        $f.flag(o);
        let (v, o) = $a.overflowing_mul($b);
        $f.int(v as u128);
        $f.flag(o);
        $f.int($a.saturating_add($b) as u128);
        $f.int($a.saturating_sub($b) as u128);
        $f.int($a.saturating_mul($b) as u128);
        if $b != 0 {
            $f.int($a.wrapping_div($b) as u128);
            $f.int($a.wrapping_rem($b) as u128);
            $f.int($a.wrapping_div_euclid($b) as u128);
            $f.int($a.wrapping_rem_euclid($b) as u128);
            let (v, o) = $a.overflowing_div($b);
            $f.int(v as u128);
            $f.flag(o);
            let (v, o) = $a.overflowing_rem($b);
            $f.int(v as u128);
            $f.flag(o);
        }
        $f.opt($a.checked_neg().map(|v| v as u128));
        $f.int($a.wrapping_neg() as u128);
        $f.int($a.wrapping_shl($s) as u128);
        $f.int($a.wrapping_shr($s) as u128);
        $f.opt($a.checked_shl($s).map(|v| v as u128));
        $f.opt($a.checked_shr($s).map(|v| v as u128));
        $f.int($a.unbounded_shl($s) as u128);
        $f.int($a.unbounded_shr($s) as u128);
        $f.int($a.rotate_left($s) as u128);
        $f.int($a.rotate_right($s) as u128);
        $f.opt($a.checked_pow($e).map(|v| v as u128));
        $f.int($a.wrapping_pow($e) as u128);
        $f.int($a.saturating_pow($e) as u128);
        let (v, o) = $b.overflowing_pow($e);
        $f.int(v as u128);
        $f.flag(o);
        $f.int(u128::from($a.leading_zeros()));
        $f.int(u128::from($a.trailing_zeros()));
        $f.int(u128::from($a.count_ones()));
        $f.int(u128::from($b.count_zeros()));
        $f.int(u128::from($a.leading_ones()));
        $f.int(u128::from($b.trailing_ones()));
        $f.int($a.swap_bytes() as u128);
        $f.int($a.reverse_bits() as u128);
        $f.int(<$t>::from_be_bytes($a.to_le_bytes()) as u128);
        $f.int(<$t>::from_le_bytes($b.to_be_bytes()) as u128);
        $f.int(<$t>::from_be($a) as u128);
        $f.opt($a.checked_ilog2().map(u128::from));
        $f.opt($a.checked_ilog10().map(u128::from));
        $f.opt($a.checked_ilog($b).map(u128::from));
        $f.int($a.midpoint($b) as u128);
        $f.int($a.min($b) as u128);
        $f.int($a.max($b) as u128);
        $f.ordering(Some($a.cmp(&$b)));
        let bound = $s as $t;
        $f.int($a.clamp($b.min(bound), $b.max(bound)) as u128);
    };
}

/// One function per unsigned type: `pairs` operand pairs through every
/// method, and the unsigned-only ones.
macro_rules! unsigned_ops {
    ($name:ident, $t:ty, $signed:ty) => {
        fn $name(f: &mut Fold, rng: &mut Rng, pairs: u32) {
            let edges: [$t; 9] = [
                0,
                1,
                2,
                <$t>::MAX,
                <$t>::MAX - 1,
                <$t>::MAX >> 1,
                !(<$t>::MAX >> 1),
                0x55,
                <$t>::MAX / 3,
            ];
            for _ in 0..pairs {
                let a: $t = pick!(rng, edges, $t);
                let b: $t = pick!(rng, edges, $t);
                let s = rng.next_u32() % (2 * <$t>::BITS);
                let e = rng.next_u32() % (<$t>::BITS + 4);
                common_ops!(f, $t, a, b, s, e);
                f.int(a.isqrt() as u128);
                f.flag(a.is_power_of_two());
                f.opt(a.checked_next_power_of_two().map(|v| v as u128));
                f.opt(a.checked_next_multiple_of(b).map(|v| v as u128));
                f.flag(a.is_multiple_of(b));
                if b != 0 {
                    f.int(a.div_ceil(b) as u128);
                }
                f.opt(a.checked_add_signed(b as $signed).map(|v| v as u128));
                f.int(a.wrapping_add_signed(b as $signed) as u128);
                f.int(a.saturating_add_signed(b as $signed) as u128);
                let (v, o) = a.overflowing_add_signed(b as $signed);
                f.int(v as u128);
                f.flag(o);
                f.int(a.abs_diff(b) as u128);
                f.int(a.cast_signed() as u128);
            }
        }
    };
}

/// One function per signed type, likewise.
macro_rules! signed_ops {
    ($name:ident, $t:ty, $unsigned:ty) => {
        fn $name(f: &mut Fold, rng: &mut Rng, pairs: u32) {
            let edges: [$t; 10] = [
                0,
                1,
                2,
                -1,
                <$t>::MAX,
                <$t>::MIN,
                <$t>::MAX - 1,
                <$t>::MIN + 1,
                <$t>::MAX >> 1,
                <$t>::MIN >> 1,
            ];
            for _ in 0..pairs {
                let a: $t = pick!(rng, edges, $t);
                let b: $t = pick!(rng, edges, $t);
                let s = rng.next_u32() % (2 * <$t>::BITS);
                let e = rng.next_u32() % (<$t>::BITS + 4);
                common_ops!(f, $t, a, b, s, e);
                f.opt(a.checked_abs().map(|v| v as u128));
                f.int(a.wrapping_abs() as u128);
                let (v, o) = a.overflowing_abs();
                f.int(v as u128);
                f.flag(o);
                f.int(a.saturating_abs() as u128);
                f.int(a.unsigned_abs() as u128);
                f.int(a.saturating_neg() as u128);
                f.int(a.signum() as u128);
                f.flag(a.is_negative());
                f.flag(b.is_positive());
                // The panicking forms, on the one operand they cannot panic
                // on. Widened as signed, as every other result here is.
                if a != <$t>::MIN {
                    let (abs, neg): ($t, $t) = (a.abs(), -a);
                    f.int(abs as u128);
                    f.int(neg as u128);
                }
                f.int(a.abs_diff(b) as u128);
                f.opt(a.checked_isqrt().map(|v| v as u128));
                f.opt(a.checked_add_unsigned(b as $unsigned).map(|v| v as u128));
                f.opt(a.checked_sub_unsigned(b as $unsigned).map(|v| v as u128));
                f.int(a.wrapping_add_unsigned(b as $unsigned) as u128);
                f.int(a.saturating_sub_unsigned(b as $unsigned) as u128);
                f.int(a.cast_unsigned() as u128);
                f.int(a.rem_euclid(if b == 0 { 1 } else { b.saturating_abs() }) as u128);
            }
        }
    };
}

unsigned_ops!(u8_ops, u8, i8);
unsigned_ops!(u16_ops, u16, i16);
unsigned_ops!(u32_ops, u32, i32);
unsigned_ops!(u64_ops, u64, i64);
unsigned_ops!(u128_ops, u128, i128);
signed_ops!(i8_ops, i8, u8);
signed_ops!(i16_ops, i16, u16);
signed_ops!(i32_ops, i32, u32);
signed_ops!(i64_ops, i64, u64);
signed_ops!(i128_ops, i128, u128);

const INT_OPS: [fn(&mut Fold, &mut Rng, u32); 10] = [
    u8_ops, u16_ops, u32_ops, u64_ops, u128_ops, i8_ops, i16_ops, i32_ops, i64_ops, i128_ops,
];

/// The integer types through their methods, the widths the guest has in
/// hardware and the ones it does not alike.
///
/// One type per round, from a random start, because a round of one type is
/// some eighty operations and a run at scale 0 has a whole workload's budget
/// to fit in. At [`crate::MAX_SCALE`] every type goes round at least once.
fn int_ops(rng: &mut Rng, scale: u32) -> Fold {
    let mut f = Fold::new();
    let start = rng.index(INT_OPS.len());
    for k in 0..=(scale as usize) {
        INT_OPS[(start + k) % INT_OPS.len()](&mut f, rng, 1);
    }
    f
}

// ---------------------------------------------------------------------------
// Wide multiply and divide
// ---------------------------------------------------------------------------

/// A division [`wide`] checked: `n = q*d + r` and `r < d`.
#[derive(Clone, Copy)]
struct Division {
    n: u128,
    d: u128,
    q: u128,
    r: u128,
}

fn signed64(rng: &mut Rng) -> i64 {
    let v = spread64(rng) as i64;
    if rng.chance(1, 2) {
        v.wrapping_neg()
    } else {
        v
    }
}

/// On RV32 a 64-bit product is inline `mul`/`mulhu`, but a 64-bit quotient is
/// `__udivdi3` or `__divdi3`, and every 128-bit product and quotient is a call
/// (`__multi3`, `__udivti3`, `__umodti3`, `__divti3`, `__modti3`). The 32-bit
/// widening products are where `mulh`, `mulhu` and `mulhsu` come from.
fn wide(rng: &mut Rng, scale: u32) -> (Fold, Division) {
    let mut f = Fold::new();
    let mut last = Division {
        n: 1,
        d: 1,
        q: 1,
        r: 0,
    };
    for _ in 0..scaled(1, 1, scale) {
        let (a, b) = (spread64(rng), spread64(rng).max(1));
        f.word(a.wrapping_mul(b));
        f.word(a / b);
        f.word(a % b);
        f.int(u128::from(a) * u128::from(b));

        let (x, y) = (signed64(rng), signed64(rng));
        f.int((i128::from(x) * i128::from(y)) as u128);
        if y != 0 {
            f.word(x.wrapping_div(y) as u64);
            f.word(x.wrapping_rem(y) as u64);
            f.opt(x.checked_div_euclid(y).map(|v| v as u128));
            f.opt(x.checked_rem_euclid(y).map(|v| v as u128));
        }

        let (n, d) = (spread128(rng), spread128(rng).max(1));
        let (q, r) = (n / d, n % d);
        f.int(q);
        f.int(r);
        f.int(n.wrapping_mul(d));
        f.flag(q * d + r == n && r < d);
        last = Division { n, d, q, r };
        // The common case in practice: a 128-bit value over a 64-bit one.
        f.int(n / u128::from(b));
        f.int(n % u128::from(b));

        let sign = |v: u128, rng: &mut Rng| {
            if rng.chance(1, 2) {
                (v as i128).wrapping_neg()
            } else {
                v as i128
            }
        };
        let (g, h) = (sign(n, rng), sign(d, rng));
        f.int(g.wrapping_div(h) as u128);
        f.int(g.wrapping_rem(h) as u128);
        f.opt(g.checked_div_euclid(h).map(|v| v as u128));
        f.opt(g.checked_rem_euclid(h).map(|v| v as u128));
        f.int(g.wrapping_mul(h) as u128);

        let (p, s) = (rng.next_u32(), rng.next_u32() >> rng.below(32));
        f.word(u64::from(p) * u64::from(s));
        f.word((i64::from(p as i32) * i64::from(s as i32)) as u64);
        f.word((i64::from(p as i32) * i64::from(s)) as u64);
        f.opt(p.checked_div(s).map(u128::from));
        f.opt(p.checked_rem(s).map(u128::from));
        if s != 0 {
            f.word((p as i32).wrapping_div(s as i32) as u64);
            f.word((p as i32).wrapping_rem(s as i32) as u64);
        }
    }
    (f, last)
}

// ---------------------------------------------------------------------------
// Casts
// ---------------------------------------------------------------------------

/// `$v as` every integer type and both float types.
macro_rules! cast_all {
    ($f:ident, $v:expr) => {{
        let v = $v;
        $f.int(v as u8 as u128);
        $f.int(v as i8 as u128);
        $f.int(v as u16 as u128);
        $f.int(v as i16 as u128);
        $f.int(v as u32 as u128);
        $f.int(v as i32 as u128);
        $f.int(v as u64 as u128);
        $f.int(v as i64 as u128);
        $f.int(v as i128 as u128);
        $f.f64(v as f64);
        $f.f32(v as f32);
    }};
}

/// Integers where an int-to-float conversion has to round: one past each
/// mantissa's reach, ties either side of even, and the `u128` values that
/// round to `f32::MAX` or overflow it.
const CAST_EDGES: [u128; 12] = [
    0,
    (1 << 24) + 1,
    (1 << 24) + 3,
    (1 << 53) + 1,
    (1 << 53) + 3,
    (1 << 63) + (1 << 10),
    u64::MAX as u128,
    1 << 64,
    (1 << 127) + (1 << 103),
    (1 << 127) + (1 << 104) + (1 << 103),
    u128::MAX - (1 << 103),
    u128::MAX,
];

fn int_casts(rng: &mut Rng, scale: u32) -> Fold {
    let mut f = Fold::new();
    for _ in 0..1 + scale / 2 {
        let raw = if rng.chance(1, 4) {
            CAST_EDGES[rng.index(CAST_EDGES.len())]
        } else {
            spread128(rng)
        };
        cast_all!(f, raw as u8);
        cast_all!(f, raw as i8);
        cast_all!(f, raw as u16);
        cast_all!(f, raw as i16);
        cast_all!(f, raw as u32);
        cast_all!(f, raw as i32);
        cast_all!(f, raw as u64);
        cast_all!(f, raw as i64);
        cast_all!(f, raw);
        cast_all!(f, raw as i128);
        f.int(u128::from(raw as u8 as char));
    }
    f
}

/// `2^e`, for `e` in the normal range `-1022..=1023`, built from its bits
/// because `powi` is `std`'s.
fn pow2(e: i32) -> f64 {
    f64::from_bits(((e + 1023) as u64) << 52)
}

/// Floats a conversion or an operation treats specially: signed zeros, the
/// integer boundaries each saturating cast clamps at and the halves beside
/// them, subnormals, the ends of the range, infinities and a NaN.
const F64_EDGES: [f64; 32] = [
    0.0,
    -0.0,
    0.5,
    -0.5,
    0.999_999_999_999_999_9,
    -1.0,
    1.5,
    2.5,
    -2.5,
    127.5,
    -128.5,
    255.5,
    256.0,
    65_535.5,
    -32_768.5,
    2_147_483_647.5,
    2_147_483_648.0,
    -2_147_483_648.5,
    -2_147_483_649.0,
    4_294_967_295.5,
    4_294_967_296.0,
    9_223_372_036_854_775_808.0,
    -9_223_372_036_854_775_808.0,
    18_446_744_073_709_551_616.0,
    1.7e38,
    3.402_823_5e38,
    f64::MAX,
    f64::MIN_POSITIVE,
    f64::from_bits(1),
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
];

/// A float from one of four families: an edge, arbitrary bits (NaNs
/// included), a random integer scaled by a power of two, or a value within a
/// quarter of a power of two.
fn float_value(rng: &mut Rng) -> f64 {
    match rng.below(4) {
        0 => F64_EDGES[rng.index(F64_EDGES.len())],
        1 => f64::from_bits(rng.next_u64()),
        2 => signed64(rng) as f64 * pow2(-(rng.below(90) as i32)),
        _ => {
            let near = pow2(rng.below(140) as i32);
            let off = (rng.below(5) as f64 - 2.0) * 0.25;
            if rng.chance(1, 2) {
                near + off
            } else {
                -near - off
            }
        }
    }
}

/// Float to integer is saturating in Rust -- NaN to 0, out of range to the
/// nearer end -- whatever the hardware does; `f64 as f32` rounds and can
/// overflow; `u128` to and from `f64` are calls on both targets.
fn float_casts(rng: &mut Rng, scale: u32) -> Fold {
    let mut f = Fold::new();
    for _ in 0..scaled(1, 1, scale) {
        let x = float_value(rng);
        f.int(x as u8 as u128);
        f.int(x as i8 as u128);
        f.int(x as u16 as u128);
        f.int(x as i16 as u128);
        f.int(x as u32 as u128);
        f.int(x as i32 as u128);
        f.int(x as u64 as u128);
        f.int(x as i64 as u128);
        f.int(x as u128);
        f.int(x as i128 as u128);
        let y = x as f32;
        f.f32(y);
        f.f64(f64::from(y));
        f.f64((x as u128) as f64);
        f.f64((x as i128) as f64);

        let z = f32::from_bits(rng.next_u32());
        f.f64(f64::from(z));
        f.f32(f64::from(z) as f32);
        f.int(z as u8 as u128);
        f.int(z as i32 as u128);
        f.int(z as u64 as u128);
        f.int(z as i128 as u128);
    }
    f
}

// ---------------------------------------------------------------------------
// Float arithmetic
// ---------------------------------------------------------------------------

fn category(c: FpCategory) -> u64 {
    match c {
        FpCategory::Nan => 1,
        FpCategory::Infinite => 2,
        FpCategory::Zero => 3,
        FpCategory::Subnormal => 4,
        FpCategory::Normal => 5,
    }
}

/// Everything `core` offers an `f64` pair. `total_cmp` and the sign tests
/// look only at `a` and `b`, which are inputs: a NaN an operation produced
/// never reaches them.
fn arith64(f: &mut Fold, a: f64, b: f64) -> f64 {
    let product = a * b;
    f.f64(a + b);
    f.f64(a - b);
    f.f64(product);
    f.f64(a / b);
    f.f64(a % b);
    f.f64(-a);
    f.f64(a.abs());
    f.f64(a.signum());
    f.f64(a.copysign(b));
    f.f64(a.recip());
    f.f64(a.to_degrees());
    f.f64(b.to_radians());
    f.f64(a.midpoint(b));
    f.f64(a.next_up());
    f.f64(b.next_down());
    f.ordering(a.partial_cmp(&b));
    f.ordering(Some(a.total_cmp(&b)));
    f.flag(a == b);
    f.flag(a < b);
    f.flag(a >= b);
    f.f64_unsigned_zero(a.min(b));
    f.f64_unsigned_zero(a.max(b));
    if !b.is_nan() {
        f.f64(a.clamp(-b.abs(), b.abs()));
    }
    f.word(category(a.classify()));
    f.flag(a.is_sign_negative());
    f.flag(b.is_subnormal());
    f.f64(a * pow2(-1000) * pow2(-60));
    f.f64(b * pow2(1000) * pow2(20));
    product
}

fn arith32(f: &mut Fold, a: f32, b: f32) {
    f.f32(a + b);
    f.f32(a - b);
    f.f32(a * b);
    f.f32(a / b);
    f.f32(a % b);
    f.f32(-a);
    f.f32(a.abs());
    f.f32(a.signum());
    f.f32(a.copysign(b));
    f.f32(a.recip());
    f.f32(a.to_degrees());
    f.f32(b.to_radians());
    f.f32(a.midpoint(b));
    f.f32(a.next_up());
    f.f32(b.next_down());
    f.ordering(a.partial_cmp(&b));
    f.ordering(Some(a.total_cmp(&b)));
    f.flag(a <= b);
    f.f32_unsigned_zero(a.min(b));
    f.f32_unsigned_zero(a.max(b));
    if !b.is_nan() {
        f.f32(a.clamp(-b.abs(), b.abs()));
    }
    f.word(category(b.classify()));
}

/// Random pairs through both widths, then a sequential sum, which is only
/// deterministic because every addition in it is correctly rounded.
fn float_arith(rng: &mut Rng, scale: u32) -> (Fold, f64) {
    let mut f = Fold::new();
    let mut last = 0.0;
    for _ in 0..scaled(1, 1, scale) {
        let (a, b) = (float_value(rng), float_value(rng));
        last = arith64(&mut f, a, b);
        let (c, d) = if rng.chance(1, 2) {
            (a as f32, b as f32)
        } else {
            (
                f32::from_bits(rng.next_u32()),
                f32::from_bits(rng.next_u32()),
            )
        };
        arith32(&mut f, c, d);
    }
    let terms = scaled(6, 6, scale);
    let sum: f64 = (1..=terms).map(|i| 1.0 / f64::from(i)).sum();
    let alternating: f32 = (1..=terms)
        .map(|i| {
            let sign = if i.is_multiple_of(2) { -1.0 } else { 1.0 };
            sign / i as f32
        })
        .sum();
    f.f64(sum);
    f.f32(alternating);
    (f, last)
}

// ---------------------------------------------------------------------------
// Float edge cases, as text
// ---------------------------------------------------------------------------

/// Which rows of a `len`-row table a run prints: `count` consecutive ones
/// from a random start, wrapping. Every row is printed by some input, and a
/// small run prints few: text is what costs most per byte at opt-level 0.
fn window(rng: &mut Rng, len: usize, count: u32) -> impl Fn(usize) -> bool {
    let start = rng.index(len);
    let count = (count as usize).min(len);
    move |i| (i + len - start) % len < count
}

fn bb(x: f64) -> f64 {
    black_box(x)
}

fn bb32(x: f32) -> f32 {
    black_box(x)
}

/// The cases IEEE-754 pins down exactly -- ties to even, gradual underflow,
/// signed zeros, overflow, exact remainders -- computed at run time from
/// opaque operands, so neither compiler folds them with its own arithmetic.
fn float_edges(rng: &mut Rng, scale: u32) -> String {
    let one = bb(1.0);
    let zero = bb(0.0);
    let tiny = bb(f64::from_bits(1));
    let max = bb(f64::MAX);
    let inf = bb(f64::INFINITY);
    let min_positive = bb(f64::MIN_POSITIVE);
    let wide: [(&str, f64); 30] = [
        ("0.1 + 0.2", bb(0.1) + bb(0.2)),
        ("0.1 * 3", bb(0.1) * bb(3.0)),
        ("1 / 3", one / bb(3.0)),
        ("1 + 2^-53, a tie to even", one + pow2(-53)),
        ("1 + (2^-53 + 2^-78)", one + (pow2(-53) + pow2(-78))),
        (
            "(1 + 2^-52) + 2^-53, a tie up",
            (one + pow2(-52)) + pow2(-53),
        ),
        ("2^53 + 1", bb(9_007_199_254_740_992.0) + one),
        ("MIN_POSITIVE / 2", min_positive / bb(2.0)),
        ("MIN_POSITIVE - 2^-1074", min_positive - tiny),
        ("2^-1074 / 2, a tie to 0", tiny / bb(2.0)),
        ("3 * 2^-1074 / 2, a tie up", tiny * bb(3.0) / bb(2.0)),
        ("2^-1074 * 0.75", tiny * bb(0.75)),
        ("1e-308 / 1e10", bb(1e-308) / bb(1e10)),
        ("MAX * 2", max * bb(2.0)),
        ("MAX + 2^970, a tie up", max + pow2(970)),
        ("MAX + 2^969", max + pow2(969)),
        ("-0 + 0", -zero + zero),
        ("-0 - 0", -zero - zero),
        ("0 * -1", zero * bb(-1.0)),
        ("1 / -0", one / -zero),
        ("-1 / inf", bb(-1.0) / inf),
        ("inf + -inf", inf + bb(f64::NEG_INFINITY)),
        ("0 / -0", zero / bb(-0.0)),
        ("-5.5 % 2", bb(-5.5) % bb(2.0)),
        ("5.5 % -2", bb(5.5) % bb(-2.0)),
        ("-0 % 1", -zero % one),
        ("1 % inf", one % inf),
        ("MAX % 3", max % bb(3.0)),
        ("next_up(0)", zero.next_up()),
        ("midpoint(MAX, -MAX / 2)", max.midpoint(-max / bb(2.0))),
    ];
    let f32_max = bb32(f32::MAX);
    let narrow: [(&str, f32); 12] = [
        ("f32 16777216 + 1", bb32(16_777_216.0) + bb32(1.0)),
        ("f32 0.1 + 0.2", bb32(0.1) + bb32(0.2)),
        ("f32 MIN_POSITIVE / 2", bb32(f32::MIN_POSITIVE) / bb32(2.0)),
        ("f32 2^-149 / 2", bb32(f32::from_bits(1)) / bb32(2.0)),
        ("f32 MAX * 2", f32_max * bb32(2.0)),
        ("f32 -7.5 % 2", bb32(-7.5) % bb32(2.0)),
        ("0.1f64 as f32", bb(0.1) as f32),
        ("(1 + 2^-24) as f32, a tie", (one + pow2(-24)) as f32),
        (
            "(1 + 2^-24 + 2^-50) as f32",
            (one + pow2(-24) + pow2(-50)) as f32,
        ),
        (
            "(f32 MAX + 2^103) as f32, a tie up",
            (f64::from(f32_max) + pow2(103)) as f32,
        ),
        ("1e39 as f32", bb(1e39) as f32),
        ("MIN_POSITIVE as f32", min_positive as f32),
    ];

    let mut text = String::new();
    let show = window(rng, wide.len(), scaled(3, 3, scale));
    for (i, (what, v)) in wide.iter().enumerate() {
        if show(i) {
            say(&mut text, format_args!("{what}: {} {v:?}", Hex64(*v)));
        }
    }
    let show = window(rng, narrow.len(), scaled(1, 1, scale));
    for (i, (what, v)) in narrow.iter().enumerate() {
        if show(i) {
            say(&mut text, format_args!("{what}: {} {v:?}", Hex32(*v)));
        }
    }
    text
}

// ---------------------------------------------------------------------------
// Float text
// ---------------------------------------------------------------------------

/// Values whose text is worth reading: the thresholds where `Debug` switches
/// to exponent form, halves that `{:.0}` and `{:.2}` round to even, and the
/// non-finite ones.
const FORMAT_VALUES: [f64; 16] = [
    0.0,
    -0.0,
    1.0,
    -1.5,
    0.1,
    2.5,
    0.125,
    123_456.789,
    1e15,
    1e16,
    1e-5,
    1e-4,
    9_007_199_254_740_992.0,
    1e21,
    f64::INFINITY,
    f64::NAN,
];

fn float_format(rng: &mut Rng, scale: u32) -> String {
    let mut text = String::new();
    let show = window(rng, FORMAT_VALUES.len(), 1 + scale / 2);
    for (i, v) in FORMAT_VALUES.iter().enumerate() {
        if show(i) {
            let v = bb(*v);
            say(
                &mut text,
                format_args!("{v} {v:?} {v:e} {v:.2} {v:+.3e}|{v:^+10.1E}|"),
            );
        }
    }
    if scale >= 2 {
        let third = bb32(1.0) / bb32(3.0);
        let big = bb32(16_777_217.0);
        say(
            &mut text,
            format_args!("f32 {third} {third:?} {third:e} {big} {big:e}"),
        );
    }
    // Exact decimal expansions, which take core's bignum (Dragon) path and
    // cost tens of thousands of guest instructions apiece.
    if scale >= 4 {
        let exact = bb(0.1) * bb(1.0 + rng.below(4) as f64);
        say(
            &mut text,
            format_args!("{exact:.30} {:.25e}", bb(f64::from_bits(1))),
        );
    }
    text
}

/// A float to format: arbitrary bits, or a family value, never a NaN, whose
/// text round-trips only as "NaN".
fn finite_or_infinite(rng: &mut Rng) -> f64 {
    let v = if rng.chance(1, 2) {
        f64::from_bits(rng.next_u64())
    } else {
        float_value(rng)
    };
    if v.is_nan() {
        f64::from_bits(v.to_bits() & !(1 << 62))
    } else {
        v
    }
}

/// Random floats through `Display`, `Debug`, `LowerExp` and `UpperExp`, each
/// parsed back and required to be the same bits: Rust promises shortest
/// round-trip text, so a failure is a formatting or parsing bug, and fixed
/// and exponent precisions besides. One `String` is reused, so the loop
/// allocates only as it first grows.
fn float_round_trip(rng: &mut Rng, scale: u32) -> String {
    let mut f = Fold::new();
    let mut buf = String::new();
    let (mut formats, mut failed) = (0u32, 0u32);
    for _ in 0..1 + scale / 2 {
        let x = finite_or_infinite(rng);
        // Formatting a float costs thousands of guest instructions, so a
        // small run takes the two forms a person reads and a larger one all
        // four.
        for spec in 0..if scale == 0 { 2 } else { 4 } {
            buf.clear();
            let written = match spec {
                0 => write!(buf, "{x}"),
                1 => write!(buf, "{x:?}"),
                2 => write!(buf, "{x:e}"),
                _ => write!(buf, "{x:E}"),
            };
            written.expect("a String takes any text");
            fold_fmt(&mut f, format_args!("{buf}"));
            formats += 1;
            if buf.parse::<f64>().map(f64::to_bits) != Ok(x.to_bits()) {
                failed += 1;
            }
        }
        let digits = rng.below(30) as usize;
        if scale >= 2 {
            fold_fmt(&mut f, format_args!("{x:.digits$e}"));
            if x.abs() < 1e30 {
                fold_fmt(&mut f, format_args!("{x:.digits$}"));
            }
        }

        let y = f32::from_bits(rng.next_u32());
        if scale >= 1 && !y.is_nan() {
            buf.clear();
            write!(buf, "{y}").expect("a String takes any text");
            fold_fmt(&mut f, format_args!("{buf} {y:?} {y:e}"));
            formats += 1;
            if buf.parse::<f32>().map(f32::to_bits) != Ok(y.to_bits()) {
                failed += 1;
            }
        }
    }
    let mut text = String::new();
    say(
        &mut text,
        format_args!(
            "{formats} formats, {failed} did not parse back; {:016x}",
            f.0
        ),
    );
    text
}

/// The result of parsing `s` as both widths, as text.
fn parse_both(out: &mut dyn Write, s: &str) -> fmt::Result {
    match s.parse::<f64>() {
        Ok(v) => write!(out, "f64 {}", Hex64(v))?,
        Err(e) => write!(out, "f64 error {e}")?,
    }
    match s.parse::<f32>() {
        Ok(v) => write!(out, " f32 {}", Hex32(v)),
        Err(e) => write!(out, " f32 error {e}"),
    }
}

/// Strings `parse::<f64>` treats specially: empty, signs alone, leading or
/// trailing dots, underscores, whitespace, hex, the spellings of infinity and
/// NaN, overflow and underflow, the halfway points around the smallest
/// subnormal, the largest finite value, and `2^53 + 1`, and a tie decided by
/// its twentieth digit.
const PARSE_EDGES: [&str; 30] = [
    "",
    "-",
    "+0.0",
    "-0",
    ".5",
    "5.",
    ".",
    "-.5e1",
    "1e",
    "e5",
    "1_000",
    " 1",
    "0x10",
    "inf",
    "-infinity",
    "+Inf",
    "nan",
    "infinit",
    "1e309",
    "1e-400",
    "2.4703282292062327e-324",
    "2.4703282292062328e-324",
    "1.7976931348623158e308",
    "1.7976931348623159e308",
    "9007199254740993",
    "9007199254740993.00000000000000000001",
    "3.4028236e38",
    "7.006492e-46",
    "00000000001.5E3",
    "123456789012345678901234567890e-30",
];

/// A decimal string, sometimes with a sign, a fraction and an exponent,
/// sometimes long enough for the slow path, and now and then with a
/// character that makes it invalid.
fn decimal(rng: &mut Rng, buf: &mut String) {
    buf.clear();
    match rng.below(4) {
        0 => buf.push('-'),
        1 => buf.push('+'),
        _ => {}
    }
    let long = rng.chance(1, 6);
    let digits = 1 + rng.below(if long { 60 } else { 19 });
    let point = rng.below(digits + 1);
    for i in 0..digits {
        if i == point && rng.chance(2, 3) {
            buf.push('.');
        }
        buf.push(char::from(b'0' + rng.below(10) as u8));
    }
    if rng.chance(1, 2) {
        buf.push(if rng.chance(1, 2) { 'e' } else { 'E' });
        if rng.chance(1, 2) {
            buf.push('-');
        }
        let exponent = rng.below(340);
        write!(buf, "{exponent}").expect("a String takes any text");
    }
    if rng.chance(1, 12) {
        buf.push(['_', 'x', ' ', 'e', '.'][rng.index(5)]);
    }
}

fn float_parse(rng: &mut Rng, scale: u32) -> String {
    let mut text = String::new();
    let show = window(rng, PARSE_EDGES.len(), 1 + scale / 2);
    for (i, s) in PARSE_EDGES.iter().enumerate() {
        if show(i) {
            write!(text, "{s:?}: ").expect("a String takes any text");
            parse_both(&mut text, s).expect("a String takes any text");
            text.push('\n');
        }
    }
    let mut f = Fold::new();
    let mut buf = String::new();
    let generated = scaled(1, 2, scale);
    for _ in 0..generated {
        decimal(rng, &mut buf);
        fold_fmt(&mut f, format_args!("{buf}"));
        parse_both(&mut f, &buf).expect("a Fold takes any text");
    }
    say(
        &mut text,
        format_args!("{generated} generated: {:016x}", f.0),
    );
    text
}

// ---------------------------------------------------------------------------
// Integer text
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Width {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    U128,
    I128,
}

const WIDTHS: [Width; 10] = [
    Width::U8,
    Width::I8,
    Width::U16,
    Width::I16,
    Width::U32,
    Width::I32,
    Width::U64,
    Width::I64,
    Width::U128,
    Width::I128,
];

/// `from_str_radix` into the type `w` names, as text: the value, or the
/// error's `Display`.
fn parse_int(out: &mut dyn Write, s: &str, radix: u32, w: Width) -> fmt::Result {
    macro_rules! parse {
        ($t:ty) => {
            match <$t>::from_str_radix(s, radix) {
                Ok(v) => write!(out, "{v}"),
                Err(e) => write!(out, "{e}"),
            }
        };
    }
    match w {
        Width::U8 => parse!(u8),
        Width::I8 => parse!(i8),
        Width::U16 => parse!(u16),
        Width::I16 => parse!(i16),
        Width::U32 => parse!(u32),
        Width::I32 => parse!(i32),
        Width::U64 => parse!(u64),
        Width::I64 => parse!(i64),
        Width::U128 => parse!(u128),
        Width::I128 => parse!(i128),
    }
}

/// One value under the flags a person would compare by eye.
macro_rules! int_line {
    ($text:ident, $v:expr) => {{
        let v = black_box($v);
        say(
            &mut $text,
            format_args!("{v} {v:x} {v:o} {v:#x} {v:+08}|{v:e}|{v:^9}|"),
        );
    }};
}

/// Every flag, into a fingerprint.
macro_rules! int_text {
    ($f:ident, $v:expr) => {{
        let v = $v;
        fold_fmt(
            &mut $f,
            format_args!("{v} {v:X} {v:o} {v:b} {v:#x} {v:+} {v:>40}|{v:e}|{v:.3e}|{v:#?}"),
        );
    }};
}

fn int_format(rng: &mut Rng, scale: u32) -> String {
    let mut text = String::new();
    let r = rng.next_u64();
    let show = window(rng, 12, 1 + scale / 2);
    for i in (0..12).filter(|&i| show(i)) {
        match i {
            0 => int_line!(text, i8::MIN),
            1 => int_line!(text, u8::MAX),
            2 => int_line!(text, -1i16),
            3 => int_line!(text, r as u16),
            4 => int_line!(text, i32::MIN),
            5 => int_line!(text, r as i32),
            6 => int_line!(text, u32::MAX),
            7 => int_line!(text, i64::MIN),
            8 => int_line!(text, r),
            9 => int_line!(text, u128::MAX),
            10 => int_line!(text, i128::MIN),
            _ => int_line!(text, -i128::from(r) * 3),
        }
    }
    if scale >= 1 {
        let (a, b, c) = black_box((r as u8, r as i8, (r >> 8) as i16));
        say(
            &mut text,
            format_args!("{a:<#010b}|{b:#b}|{c:#o}|{c:+#07x}|{a:.2e}"),
        );
    }

    // One width per round, for the reason `int_ops` takes one type per round.
    let mut f = Fold::new();
    let start = rng.index(10);
    for k in 0..=(scale as usize / 2) {
        let raw = spread128(rng);
        match (start + k) % 10 {
            0 => int_text!(f, raw as u8),
            1 => int_text!(f, raw as i8),
            2 => int_text!(f, raw as u16),
            3 => int_text!(f, raw as i16),
            4 => int_text!(f, raw as u32),
            5 => int_text!(f, raw as i32),
            6 => int_text!(f, raw as u64),
            7 => int_text!(f, raw as i64),
            8 => int_text!(f, raw),
            _ => int_text!(f, raw as i128),
        }
    }
    say(&mut text, format_args!("random: {:016x}", f.0));
    text
}

/// Strings `from_str_radix` must refuse or take at a boundary: empty, a sign
/// alone, a sign on an unsigned type, each type's ends and one past them in
/// several radices, case, underscores, whitespace, a `0x` prefix, non-ASCII
/// digits, and leading zeros beyond the type's width.
const INT_PARSE_EDGES: [(&str, u32, Width); 30] = [
    ("", 10, Width::I32),
    ("-", 10, Width::I32),
    ("+", 16, Width::U8),
    ("-0", 10, Width::U8),
    ("+12", 10, Width::U8),
    ("-128", 10, Width::I8),
    ("128", 10, Width::I8),
    ("-129", 10, Width::I8),
    ("256", 10, Width::U8),
    ("ff", 16, Width::U8),
    ("FF", 16, Width::I8),
    ("-80", 16, Width::I8),
    ("zz", 36, Width::U16),
    ("-Zz", 36, Width::I16),
    ("1_000", 10, Width::U32),
    (" 1", 10, Width::U32),
    ("1 ", 10, Width::U32),
    ("0x10", 16, Width::U32),
    ("11111111111111111111111111111111", 2, Width::U32),
    ("100000000000000000000000000000000", 2, Width::U32),
    ("7fffffffffffffff", 16, Width::I64),
    ("-8000000000000000", 16, Width::I64),
    ("8000000000000000", 16, Width::I64),
    ("1777777777777777777777", 8, Width::U64),
    ("340282366920938463463374607431768211455", 10, Width::U128),
    ("340282366920938463463374607431768211456", 10, Width::U128),
    ("-170141183460469231731687303715884105729", 10, Width::I128),
    ("\u{663}", 10, Width::U8),
    ("\u{ff11}", 10, Width::U8),
    ("0000000000000000000000000000000000000001", 2, Width::I8),
];

/// A string of digits in `radix`, sometimes signed, sometimes empty or with a
/// character no radix up to 36 takes, and long enough to overflow any type.
fn digits(rng: &mut Rng, radix: u32, buf: &mut String) {
    buf.clear();
    match rng.below(5) {
        0 => buf.push('-'),
        1 => buf.push('+'),
        _ => {}
    }
    for _ in 0..rng.below(42) {
        let d = char::from_digit(rng.below(u64::from(radix)) as u32, radix)
            .expect("a digit below the radix");
        buf.push(if rng.chance(1, 2) {
            d.to_ascii_uppercase()
        } else {
            d
        });
    }
    if rng.chance(1, 10) {
        buf.push(['_', ' ', '.', 'z', '\u{e9}'][rng.index(5)]);
    }
}

fn int_parse(rng: &mut Rng, scale: u32) -> String {
    let mut text = String::new();
    let show = window(rng, INT_PARSE_EDGES.len(), 1 + scale / 2);
    for (i, (s, radix, w)) in INT_PARSE_EDGES.iter().enumerate() {
        if show(i) {
            write!(text, "{s:?} radix {radix} as {w:?}: ").expect("a String takes any text");
            parse_int(&mut text, s, *radix, *w).expect("a String takes any text");
            text.push('\n');
        }
    }

    let mut f = Fold::new();
    let mut buf = String::new();
    let generated = scaled(2, 2, scale);
    for _ in 0..generated {
        let radix = 2 + rng.below(35) as u32;
        let w = WIDTHS[rng.index(WIDTHS.len())];
        digits(rng, radix, &mut buf);
        fold_fmt(&mut f, format_args!("{buf}"));
        parse_int(&mut f, &buf, radix, w).expect("a Fold takes any text");
    }

    // Each value's text in radix 2, 8, 10 and 16, parsed back. At least once,
    // so the `failed` tally below is a tally and not a constant zero.
    let mut failed = 0u32;
    for _ in 0..1 + scale / 2 {
        let v = spread128(rng) as i128;
        let v = if rng.chance(1, 2) {
            v
        } else {
            v.wrapping_neg()
        };
        for (radix, spec) in [(2, 0), (8, 1), (10, 2), (16, 3)] {
            buf.clear();
            match spec {
                0 => write!(buf, "{:b}", v.unsigned_abs()),
                1 => write!(buf, "{:o}", v.unsigned_abs()),
                2 => write!(buf, "{}", v.unsigned_abs()),
                _ => write!(buf, "{:x}", v.unsigned_abs()),
            }
            .expect("a String takes any text");
            if u128::from_str_radix(&buf, radix) != Ok(v.unsigned_abs()) {
                failed += 1;
            }
            if v < 0 {
                buf.insert(0, '-');
            }
            if i128::from_str_radix(&buf, radix) != Ok(v) {
                failed += 1;
            }
        }
    }
    say(
        &mut text,
        format_args!(
            "{generated} generated: {:016x}; {failed} did not parse back",
            f.0
        ),
    );
    text
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

/// A `Result` as text: the value, or the error's `Display`.
struct Shown<T, E>(Result<T, E>);

impl<T: fmt::Display, E: fmt::Display> fmt::Display for Shown<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Ok(v) => write!(f, "{v}"),
            Err(e) => write!(f, "<{e}>"),
        }
    }
}

/// `$v` into every integer type through `TryFrom`, `None` where it does not
/// fit.
macro_rules! try_all {
    ($f:ident, $v:expr) => {{
        let v = $v;
        $f.opt(u8::try_from(v).ok().map(u128::from));
        $f.opt(i8::try_from(v).ok().map(|x| x as u128));
        $f.opt(u16::try_from(v).ok().map(u128::from));
        $f.opt(i16::try_from(v).ok().map(|x| x as u128));
        $f.opt(u32::try_from(v).ok().map(u128::from));
        $f.opt(i32::try_from(v).ok().map(|x| x as u128));
        $f.opt(u64::try_from(v).ok().map(u128::from));
        $f.opt(i64::try_from(v).ok().map(|x| x as u128));
        $f.opt(i128::try_from(v).ok().map(|x| x as u128));
    }};
}

/// The conversion traits and the integer wrappers, on operands drawn from the
/// generator: `TryFrom` and its error, `NonZero`, `Wrapping`, `Saturating`,
/// `char` digits and code points, the lossless `From`s, and the iterator
/// folds over integers.
fn conversions(rng: &mut Rng, scale: u32) -> String {
    let mut text = String::new();
    let r = black_box(rng.next_u64());
    let x = r as i32;
    let a = r as u8;
    let show = window(rng, 6, 1 + scale / 2);
    for i in (0..6).filter(|&i| show(i)) {
        match i {
            0 => say(
                &mut text,
                format_args!(
                    "{x} as u8 {:?} i8 {:?} u16 {:?} u32 {:?} i64 {:?}",
                    u8::try_from(x).ok(),
                    i8::try_from(x).ok(),
                    u16::try_from(x).ok(),
                    u32::try_from(x).ok(),
                    i64::from(x),
                ),
            ),
            1 => say(
                &mut text,
                format_args!(
                    "{} | {} | {} | {}",
                    Shown(u8::try_from(black_box(256u32))),
                    Shown(i64::try_from(black_box(u64::MAX))),
                    Shown(u64::try_from(black_box(1u128 << 64) - 1)),
                    Shown(u8::try_from(black_box('\u{e9}'))),
                ),
            ),
            2 => {
                let n = NonZero::new(r | 1).expect("odd is nonzero");
                say(
                    &mut text,
                    format_args!(
                        "NonZero {n}: {} {} {:?} {} {} {} {:?} {:?}",
                        n.leading_zeros(),
                        n.trailing_zeros(),
                        n.checked_mul(n),
                        n.saturating_mul(n),
                        n.ilog2(),
                        n.ilog10(),
                        NonZero::new(black_box(x) & 0xf0),
                        NonZero::new(x | 1).map(|n| n.unsigned_abs()),
                    ),
                );
            }
            3 => {
                let b = (r >> 8) as i16;
                say(
                    &mut text,
                    format_args!(
                        "Wrapping {} {} {} {} {} | Saturating {} {} {} {}",
                        Wrapping(a) + Wrapping(200),
                        Wrapping(i16::MIN) - Wrapping(b),
                        Wrapping(r as u32) * Wrapping(u32::MAX),
                        -Wrapping(black_box(i32::MIN)),
                        Wrapping(r) << 70,
                        Saturating(a) + Saturating(200),
                        Saturating(i16::MIN) - Saturating(b),
                        Saturating(-100i8) * Saturating(a as i8),
                        Saturating(black_box(i32::MIN)) / Saturating(-1),
                    ),
                );
            }
            4 => {
                let d = (r % 36) as u32;
                say(
                    &mut text,
                    format_args!(
                        "char {:?} {:?} {:?} {:?} {:?} {:?} {} {:?} {}",
                        char::from_digit(d, 36),
                        'Z'.to_digit(36),
                        '8'.to_digit(8),
                        char::from_u32(black_box(0xd800)),
                        char::from_u32(black_box(0x1_f980)),
                        char::from_u32((r >> 32) as u32 % 0x11_0000),
                        u32::from('\u{e9}'),
                        char::from(a),
                        char::from(a).is_ascii_hexdigit(),
                    ),
                );
            }
            _ => {
                let top = 18 + r % 5;
                say(
                    &mut text,
                    format_args!(
                        "From {} {} {:?} {:?} {:?} {:?} | fold {:?} {} {}",
                        i32::from(black_box(true)),
                        u8::from(black_box(false)),
                        f64::from(r as u32),
                        f64::from(x),
                        f32::from(r as u16),
                        f64::from(bb32(1.1)),
                        (1..=top).try_fold(1u64, |acc, k| acc.checked_mul(k)),
                        (0..r % 1000).map(|k| k * k).sum::<u64>(),
                        (1..=10u64).rev().fold(0, |acc, k| acc * 10 + k),
                    ),
                );
            }
        }
    }

    let mut f = Fold::new();
    for _ in 0..1 + scale / 4 {
        let raw = spread128(rng);
        try_all!(f, raw as u8);
        try_all!(f, raw as i16);
        try_all!(f, raw as u32);
        try_all!(f, raw as i64);
        try_all!(f, raw);
        try_all!(f, raw as i128);
    }
    say(&mut text, format_args!("try_from: {:016x}", f.0));
    text
}

// ---------------------------------------------------------------------------
// A bignum
// ---------------------------------------------------------------------------

/// A natural number as little-endian base-2^32 limbs with no zero top limb,
/// so zero is the empty vector and equal numbers are equal vectors. The kind
/// of code a guest author writes when a `u128` runs out: `u64` intermediates,
/// carries and borrows, and Knuth's division.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Big(Vec<u32>);

impl Big {
    fn from_u128(mut v: u128) -> Big {
        let mut limbs = Vec::new();
        while v != 0 {
            limbs.push(v as u32);
            v >>= 32;
        }
        Big(limbs)
    }

    /// `limbs` random limbs, the top one nonzero.
    fn random(rng: &mut Rng, limbs: usize) -> Big {
        let mut v: Vec<u32> = (0..limbs).map(|_| rng.next_u32()).collect();
        if let Some(top) = v.last_mut() {
            *top |= 1 << rng.below(32);
        }
        Big(v)
    }

    fn trimmed(mut limbs: Vec<u32>) -> Big {
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
        Big(limbs)
    }

    fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    fn to_u128(&self) -> Option<u128> {
        if self.0.len() > 4 {
            return None;
        }
        Some(
            self.0
                .iter()
                .rev()
                .fold(0u128, |acc, &limb| (acc << 32) | u128::from(limb)),
        )
    }

    fn cmp(&self, other: &Big) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.iter().rev().cmp(other.0.iter().rev()))
    }

    fn add(&self, other: &Big) -> Big {
        let (long, short) = if self.0.len() >= other.0.len() {
            (self, other)
        } else {
            (other, self)
        };
        let mut sum = Vec::with_capacity(long.0.len() + 1);
        let mut carry = 0u64;
        for (i, &limb) in long.0.iter().enumerate() {
            let t = u64::from(limb) + u64::from(short.0.get(i).copied().unwrap_or(0)) + carry;
            sum.push(t as u32);
            carry = t >> 32;
        }
        sum.push(carry as u32);
        Big::trimmed(sum)
    }

    /// `self - other`, for `self >= other`.
    fn sub(&self, other: &Big) -> Big {
        let mut diff = Vec::with_capacity(self.0.len());
        let mut borrow = false;
        for (i, &limb) in self.0.iter().enumerate() {
            let (t, b1) = limb.overflowing_sub(other.0.get(i).copied().unwrap_or(0));
            let (t, b2) = t.overflowing_sub(u32::from(borrow));
            diff.push(t);
            borrow = b1 || b2;
        }
        assert!(!borrow, "Big::sub of a larger number");
        Big::trimmed(diff)
    }

    /// Schoolbook: `limb * limb + limb + carry` is at most `2^64 - 1`.
    fn mul(&self, other: &Big) -> Big {
        if self.is_zero() || other.is_zero() {
            return Big(Vec::new());
        }
        let mut product = vec![0u32; self.0.len() + other.0.len()];
        for (i, &a) in self.0.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.0.iter().enumerate() {
                let t = u64::from(product[i + j]) + u64::from(a) * u64::from(b) + carry;
                product[i + j] = t as u32;
                carry = t >> 32;
            }
            product[i + other.0.len()] = carry as u32;
        }
        Big::trimmed(product)
    }

    fn divmod_small(&self, d: u32) -> (Big, u32) {
        assert!(d != 0, "Big::divmod_small by zero");
        let mut quotient = vec![0u32; self.0.len()];
        let mut rem = 0u64;
        for (i, &limb) in self.0.iter().enumerate().rev() {
            let cur = (rem << 32) | u64::from(limb);
            quotient[i] = (cur / u64::from(d)) as u32;
            rem = cur % u64::from(d);
        }
        (Big::trimmed(quotient), rem as u32)
    }

    /// Knuth's algorithm D (TAOCP 4.3.1), in Hacker's Delight's form:
    /// normalise so the divisor's top limb has its top bit set, estimate each
    /// quotient limb from the top two limbs, correct the estimate at most
    /// twice, multiply and subtract, and add back in the rare case the
    /// estimate was still one too large.
    fn divmod(&self, divisor: &Big) -> (Big, Big) {
        assert!(!divisor.is_zero(), "Big::divmod by zero");
        if self.cmp(divisor) == Ordering::Less {
            return (Big(Vec::new()), self.clone());
        }
        if divisor.0.len() == 1 {
            let (q, r) = self.divmod_small(divisor.0[0]);
            return (q, Big::from_u128(u128::from(r)));
        }
        let n = divisor.0.len();
        let m = self.0.len() - n;
        let shift = divisor.0[n - 1].leading_zeros();
        let v = shl_limbs(&divisor.0, shift, false);
        let mut u = shl_limbs(&self.0, shift, true);
        let mut quotient = vec![0u32; m + 1];
        let base = 1u64 << 32;
        let (top, next) = (u64::from(v[n - 1]), u64::from(v[n - 2]));
        for j in (0..=m).rev() {
            let num = (u64::from(u[j + n]) << 32) | u64::from(u[j + n - 1]);
            let mut qhat = num / top;
            let mut rhat = num % top;
            while qhat >= base || qhat * next > ((rhat << 32) | u64::from(u[j + n - 2])) {
                qhat -= 1;
                rhat += top;
                if rhat >= base {
                    break;
                }
            }
            let mut borrow = 0i64;
            let mut carry = 0u64;
            for (i, &limb) in v.iter().enumerate() {
                let p = qhat * u64::from(limb) + carry;
                carry = p >> 32;
                let t = i64::from(u[i + j]) - (p & 0xffff_ffff) as i64 + borrow;
                u[i + j] = t as u32;
                borrow = t >> 32;
            }
            let t = i64::from(u[j + n]) - carry as i64 + borrow;
            u[j + n] = t as u32;
            if t < 0 {
                qhat -= 1;
                let mut carry = 0u64;
                for (i, &limb) in v.iter().enumerate() {
                    let s = u64::from(u[i + j]) + u64::from(limb) + carry;
                    u[i + j] = s as u32;
                    carry = s >> 32;
                }
                u[j + n] = u[j + n].wrapping_add(carry as u32);
            }
            quotient[j] = qhat as u32;
        }
        u.truncate(n);
        let rem = shr_limbs(&u, shift);
        (Big::trimmed(quotient), Big::trimmed(rem))
    }

    /// `self^exp mod m`, left to right, one bit of `exp` at a time.
    fn modpow(&self, exp: &Big, m: &Big) -> Big {
        let base = self.divmod(m).1;
        let mut acc = Big::from_u128(1).divmod(m).1;
        for &limb in exp.0.iter().rev() {
            for bit in (0..32).rev() {
                acc = acc.mul(&acc).divmod(m).1;
                if (limb >> bit) & 1 == 1 {
                    acc = acc.mul(&base).divmod(m).1;
                }
            }
        }
        acc
    }

    /// Decimal, nine digits per division by 10^9.
    fn to_decimal(&self) -> String {
        if self.is_zero() {
            return String::from("0");
        }
        let mut chunks = Vec::new();
        let mut rest = self.clone();
        while !rest.is_zero() {
            let (q, r) = rest.divmod_small(1_000_000_000);
            chunks.push(r);
            rest = q;
        }
        let mut text = String::new();
        let mut chunks = chunks.iter().rev();
        if let Some(first) = chunks.next() {
            write!(text, "{first}").expect("a String takes any text");
        }
        for chunk in chunks {
            write!(text, "{chunk:09}").expect("a String takes any text");
        }
        text
    }
}

/// `limbs << shift` for `shift < 32`, with one more limb when `extend` so the
/// top bits have somewhere to go.
fn shl_limbs(limbs: &[u32], shift: u32, extend: bool) -> Vec<u32> {
    let mut out = Vec::with_capacity(limbs.len() + 1);
    let mut carry = 0u32;
    for &limb in limbs {
        out.push((limb << shift) | carry);
        carry = if shift == 0 { 0 } else { limb >> (32 - shift) };
    }
    if extend {
        out.push(carry);
    }
    out
}

fn shr_limbs(limbs: &[u32], shift: u32) -> Vec<u32> {
    let mut out = vec![0u32; limbs.len()];
    for (i, &limb) in limbs.iter().enumerate() {
        let high = match limbs.get(i + 1) {
            Some(&next) if shift != 0 => next << (32 - shift),
            _ => 0,
        };
        out[i] = (limb >> shift) | high;
    }
    out
}

/// Decimals of known numbers, a Fermat test on a Mersenne prime, and random
/// operands through every identity the operations must satisfy, cross-checked
/// against native `u128` arithmetic wherever the operands fit.
fn bignum(rng: &mut Rng, scale: u32) -> String {
    let mut text = String::new();
    let one = Big::from_u128(1);

    let n = 8 + scale;
    let factorial = (1..=u128::from(n)).fold(one.clone(), |acc, k| acc.mul(&Big::from_u128(k)));
    say(&mut text, format_args!("{n}! = {}", factorial.to_decimal()));

    // 2^p - 1 for a Mersenne exponent p: prime, so 3^(2^p - 2) = 1 mod it.
    let p = [13u32, 31, 61, 89, 127][(scale as usize / 4).min(4)];
    let mut mersenne = Big::from_u128(1);
    for _ in 0..p {
        mersenne = mersenne.add(&mersenne);
    }
    let mersenne = mersenne.sub(&one);
    let exponent = mersenne.sub(&Big::from_u128(2));
    let fermat = Big::from_u128(3).modpow(&exponent, &mersenne);
    say(
        &mut text,
        format_args!(
            "2^{p} - 1 = {}; 3^(2^{p} - 2) mod it = {}",
            mersenne.to_decimal(),
            fermat.to_decimal()
        ),
    );

    let mut f = Fold::new();
    let (mut checked, mut failed) = (0u32, 0u32);
    let mut check = |ok: bool| {
        checked += 1;
        if !ok {
            failed += 1;
        }
    };
    let mut last = Big(Vec::new());
    for _ in 0..1 + scale / 2 {
        let (long, short) = (
            1 + rng.index(3 + scale as usize),
            1 + rng.index(2 + scale as usize / 2),
        );
        let (a, b) = (Big::random(rng, long), Big::random(rng, short));
        let sum = a.add(&b);
        let product = a.mul(&b);
        let (q, r) = a.divmod(&b);
        check(q.mul(&b).add(&r) == a && r.cmp(&b) == Ordering::Less);
        check(product.divmod(&b) == (a.clone(), Big(Vec::new())));
        check(sum.sub(&b) == a);
        if let (Some(x), Some(y)) = (a.to_u128(), b.to_u128()) {
            check(q.to_u128() == Some(x / y) && r.to_u128() == Some(x % y));
            check(sum.to_u128() == x.checked_add(y));
            check(product.to_u128() == x.checked_mul(y));
        }
        let (qs, rs) = a.divmod_small(rng.next_u32() | 1);
        for limb in q.0.iter().chain(&r.0).chain(&product.0).chain(&qs.0) {
            f.word(u64::from(*limb));
        }
        f.word(u64::from(rs));
        last = product;
    }
    if scale >= 2 {
        let m = Big::random(rng, 2 + scale as usize / 4);
        let e = Big::random(rng, 1);
        let power = Big::random(rng, 2).modpow(&e, &m);
        for limb in &power.0 {
            f.word(u64::from(*limb));
        }
    }
    say(
        &mut text,
        format_args!("a random product: {}", last.to_decimal()),
    );
    say(
        &mut text,
        format_args!("{checked} identities, {failed} failed; {:016x}", f.0),
    );
    text
}

// ---------------------------------------------------------------------------
// The payload
// ---------------------------------------------------------------------------

/// The payload as a person would feed a program numbers: its longest valid
/// UTF-8 prefix split into tokens, each parsed as an integer and a float, and
/// its leading bytes read as one big-endian number.
fn payload(bytes: &[u8], scale: u32) -> String {
    let take = bytes.len().min(64 + 64 * scale as usize);
    let bytes = &bytes[..take];
    let valid = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => core::str::from_utf8(&bytes[..e.valid_up_to()]).expect("the valid prefix"),
    };
    let mut text = String::new();
    let mut f = Fold::new();
    let (mut tokens, mut ints, mut floats) = (0u32, 0u32, 0u32);
    for token in valid
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .take(2 + 2 * scale as usize)
    {
        tokens += 1;
        fold_fmt(&mut f, format_args!("{token}"));
        match token.parse::<i64>() {
            Ok(v) => {
                ints += 1;
                f.int(v as u128);
            }
            Err(e) => fold_fmt(&mut f, format_args!("{e}")),
        }
        match token.parse::<f64>() {
            Ok(v) => {
                floats += 1;
                f.f64(v);
            }
            Err(e) => fold_fmt(&mut f, format_args!("{e}")),
        }
        f.opt(u128::from_str_radix(token, 36).ok());
    }
    say(
        &mut text,
        format_args!(
            "{} bytes, {} valid; {tokens} tokens, {ints} integers, {floats} floats; {:016x}",
            bytes.len(),
            valid.len(),
            f.0
        ),
    );

    let lead = &bytes[..bytes.len().min(8 + 4 * scale as usize)];
    let limbs: Vec<u32> = lead
        .rchunks(4)
        .map(|chunk| chunk.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
        .collect();
    let number = Big::trimmed(limbs);
    let decimal = number.to_decimal();
    let digit_sum: u32 = decimal.bytes().map(|b| u32::from(b - b'0')).sum();
    say(
        &mut text,
        format_args!("leading bytes as a number: {decimal}, digit sum {digit_sum}"),
    );
    text
}
