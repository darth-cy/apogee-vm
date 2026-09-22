//! The non-native arithmetic gadgets `ECRECOVER` is built from: one
//! **congruence** over the integers with its carry chain, the **canonicality**
//! complement, the **bound** that decomposes a column into range-checked
//! chunks, and the **128-bit-half equality** that is the only safe way to
//! compare two 256-bit values in `Fr`.
//!
//! `docs/spec/ecrecover.md` §3 is normative and this file is that section as
//! data. Four things there are load-bearing and each is a gate here rather
//! than a comment:
//!
//! 1. the last position carries **no outgoing carry term at all** — writing one
//!    and zeroing it makes every congruence in the circuit vacuous (§3.2);
//! 2. every witnessed value is proved **canonical**, not merely limb-bounded,
//!    or the honest quotient needs a fifth limb and the honest prover has no
//!    witness (§3.3);
//! 3. every equality is on **two 128-bit halves**, because a 256-bit value
//!    recomposed to one `Fr` is 6-to-1 (§3.4);
//! 4. a carry is range-checked **after an offset**, because it is signed.
//!
//! Nothing here knows about secp256k1: the modulus is an operand, the width is
//! a parameter, and the reduced-width instances the tests exercise
//! exhaustively are the same code as the 256-bit one.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use constants::lookup_channel;
use field::Fr;

use crate::{Coeff, GateDef, LookupExpr, PolyAddress};

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

/// A small signed integer literal, as a coefficient.
fn signed(v: i64) -> Coeff {
    if v < 0 {
        Coeff::Literal(-Fr::from_u64(v.unsigned_abs()))
    } else {
        Coeff::Literal(Fr::from_u64(v as u64))
    }
}

/// `2^bits`, for `bits` up to 127.
pub fn two_pow(bits: u32) -> Fr {
    assert!(bits < 128, "two_pow: {bits} bits is past what this builds");
    let half = Fr::from_u64(1u64 << (bits / 2));
    let rest = Fr::from_u64(1u64 << (bits - bits / 2));
    half * rest
}

// ---------------------------------------------------------------------------
// The width
// ---------------------------------------------------------------------------

/// How a non-native value is cut up: how many limbs, how wide a limb, and how
/// wide the chunks a limb's range check is written in.
///
/// The 256-bit instance is [`Width::SECP256K1`]. The tests instantiate narrow
/// ones — four limbs of two bits, say — and check the same builders
/// exhaustively there, which is the only way a carry chain gets checked on
/// every input it can see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Width {
    /// Limbs a value, low limb first.
    pub limbs: usize,
    /// Bits a limb. The radix is `2^limb_bits`.
    pub limb_bits: u32,
    /// Bits a range-check chunk. Must divide `limb_bits`, so a limb is bounded
    /// **exactly** at `2^limb_bits` and not at some wider power.
    pub chunk_bits: u32,
}

impl Width {
    /// secp256k1: four 64-bit limbs, each four 16-bit chunks on `RANGE16`.
    pub const SECP256K1: Width = Width {
        limbs: constants::secp256k1::LIMBS,
        limb_bits: constants::secp256k1::LIMB_BITS,
        chunk_bits: constants::secp256k1::LIMB_BITS / constants::secp256k1::CHUNKS_PER_LIMB as u32,
    };

    /// Chunks a limb.
    pub fn chunks_per_limb(&self) -> usize {
        assert!(
            self.chunk_bits > 0 && self.limb_bits.is_multiple_of(self.chunk_bits),
            "a chunk width must divide a limb width, or a limb is bounded at the \
             wrong power of two"
        );
        (self.limb_bits / self.chunk_bits) as usize
    }

    /// Positions the congruence has: a product of two `limbs`-limb values
    /// reaches position `2·limbs − 2`, so there are `2·limbs − 1` of them.
    pub fn positions(&self) -> usize {
        2 * self.limbs - 1
    }

    /// Carries the chain has: one per position but the last, which has none.
    pub fn carries(&self) -> usize {
        self.positions() - 1
    }

    /// The radix `2^limb_bits`.
    pub fn radix(&self) -> Fr {
        two_pow(self.limb_bits)
    }
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// One column bounded to `[0, 2^(chunk_bits·chunks + bits))` by a decomposition:
/// `chunks` range-checked chunks and `bits` booleans above them.
///
/// The booleans are not a stylistic choice. A carry needs 68 bits of room and
/// the channel's chunks are 16 wide; five chunks would cost five obligations
/// and bound it at `2^80`, four chunks and four booleans cost four obligations
/// and four degree-2 gates and bound it at exactly `2^68`. The bound has to be
/// exact for the magnitude argument of `docs/spec/ecrecover.md` §3.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bound {
    /// The prefix of every gate and obligation name.
    pub prefix: String,
    /// The column being bounded.
    pub value: PolyAddress,
    /// Its chunks, low first, each `chunk_bits` wide.
    pub chunks: Vec<PolyAddress>,
    /// Boolean columns above the chunks, low first.
    pub bits: Vec<PolyAddress>,
    /// The selector every obligation and every gate carries: the row's
    /// liveness, or a narrower boolean the caller holds boolean itself.
    pub selector: PolyAddress,
}

impl Bound {
    /// The recomposition gate and one booleanity gate a bit.
    pub fn gates(&self, width: Width) -> Vec<(String, GateDef)> {
        let mut terms: Vec<(Coeff, PolyAddress)> =
            vec![(Coeff::Literal(Fr::MINUS_ONE), self.value)];
        for (j, c) in self.chunks.iter().enumerate() {
            terms.push((Coeff::Literal(two_pow(width.chunk_bits * j as u32)), *c));
        }
        let above = width.chunk_bits * self.chunks.len() as u32;
        for (j, b) in self.bits.iter().enumerate() {
            terms.push((Coeff::Literal(two_pow(above + j as u32)), *b));
        }
        let mut out = vec![(
            format!("{}_recomposes", self.prefix),
            GateDef::Linear {
                terms,
                constant: lit(0),
            },
        )];
        for (j, b) in self.bits.iter().enumerate() {
            out.push((
                format!("{}_bit_{j}_is_boolean", self.prefix),
                GateDef::Quadratic {
                    constant: lit(0),
                    linear: vec![(Coeff::Literal(Fr::MINUS_ONE), *b)],
                    products: vec![(lit(1), *b, *b)],
                },
            ));
        }
        out
    }

    /// One `RANGE16` obligation a chunk. The booleans are bounded by their
    /// gates and carry no obligation.
    pub fn lookups(&self) -> Vec<LookupExpr> {
        self.chunks
            .iter()
            .enumerate()
            .map(|(j, c)| LookupExpr {
                name: format!("{}_chunk_{j}", self.prefix),
                channel: lookup_channel::RANGE16,
                selector: self.selector,
                tuple: vec![GateDef::Linear {
                    terms: vec![(lit(1), *c)],
                    constant: lit(0),
                }],
            })
            .collect()
    }

    /// The bound this proves, in bits.
    pub fn bits_bounded(&self, width: Width) -> u32 {
        width.chunk_bits * self.chunks.len() as u32 + self.bits.len() as u32
    }
}

// ---------------------------------------------------------------------------
// The congruence
// ---------------------------------------------------------------------------

/// One congruence, as `docs/spec/ecrecover.md` §3.1 writes it:
///
/// ```text
/// Σ_m c_m·A_m·B_m  +  Σ_j d_j·C_j  +  K·P  =  Q·P            over ℤ
/// ```
///
/// Every operand is a list of limb columns, low limb first, and every
/// coefficient is a **literal of the shape** — never a column, which would put
/// the gate at degree 3.
///
/// `K` is the multiple of the modulus that keeps the left side non-negative;
/// with the coefficients this family uses, `K = 1` always suffices, and the
/// gadget does not check it — a `K` too small makes an honest witness
/// unrepresentable, not a dishonest one acceptable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Congruence {
    /// The prefix of every gate name.
    pub prefix: String,
    pub width: Width,
    /// `c_m·A_m·B_m`. Two is the most the magnitude argument of §3.2 allows.
    pub products: Vec<(i64, Vec<PolyAddress>, Vec<PolyAddress>)>,
    /// `d_j·C_j`.
    pub addends: Vec<(i64, Vec<PolyAddress>)>,
    /// The modulus's limb columns. An operand rather than a literal, so one
    /// row shape serves both `p` and `n` without a coefficient that varies.
    pub modulus: Vec<PolyAddress>,
    /// `K`.
    pub offset: u64,
    /// The witnessed quotient's limb columns.
    pub quotient: Vec<PolyAddress>,
    /// The carries `t_0 .. t_{positions−2}`, **each offset by
    /// `2^(carry_bits − 1)`**: they are signed, and what is committed and
    /// range-checked is `t_k + 2^(carry_bits − 1)`.
    pub carries: Vec<PolyAddress>,
    /// The width of a carry's range check, offset included.
    pub carry_bits: u32,
}

impl Congruence {
    /// One gate a position: `positions()` of them, the last **without an
    /// outgoing carry term**.
    pub fn gates(&self) -> Vec<(String, GateDef)> {
        let w = self.width;
        assert_eq!(
            self.carries.len(),
            w.carries(),
            "{}: a congruence of {} positions has {} carries",
            self.prefix,
            w.positions(),
            w.carries()
        );
        assert_eq!(
            self.modulus.len(),
            w.limbs,
            "{}: the modulus is a value of the same width",
            self.prefix
        );
        assert_eq!(
            self.quotient.len(),
            w.limbs,
            "{}: the quotient is a value of the same width",
            self.prefix
        );
        assert!(
            self.carry_bits > w.limb_bits,
            "{}: a carry needs more room than a limb",
            self.prefix
        );

        let radix = w.radix();
        let carry_offset = two_pow(self.carry_bits - 1);
        let last = w.positions() - 1;

        (0..w.positions())
            .map(|k| {
                let mut products: Vec<(Coeff, PolyAddress, PolyAddress)> = Vec::new();
                let mut linear: Vec<(Coeff, PolyAddress)> = Vec::new();
                let mut constant = Fr::ZERO;

                // Σ_m c_m · Σ_{i+j=k} A_{m,i}·B_{m,j}
                for (c, a, b) in &self.products {
                    assert_eq!(a.len(), w.limbs, "{}: an operand is off width", self.prefix);
                    assert_eq!(b.len(), w.limbs, "{}: an operand is off width", self.prefix);
                    for i in 0..w.limbs {
                        if k >= i && k - i < w.limbs {
                            products.push((signed(*c), a[i], b[k - i]));
                        }
                    }
                }
                // − Σ_{i+j=k} Q_i·P_j. `P` is an operand, so this is a product
                // like any other and the shape serves every modulus.
                for i in 0..w.limbs {
                    if k >= i && k - i < w.limbs {
                        products.push((signed(-1), self.quotient[i], self.modulus[k - i]));
                    }
                }
                // Σ_j d_j·C_{j,k}, and K·P_k. Both are limb-aligned, so they
                // reach the low positions only.
                if k < w.limbs {
                    for (d, c) in &self.addends {
                        assert_eq!(c.len(), w.limbs, "{}: an addend is off width", self.prefix);
                        linear.push((signed(*d), c[k]));
                    }
                    if self.offset != 0 {
                        linear.push((lit(self.offset), self.modulus[k]));
                    }
                }
                // The carry chain. `t_k = committed − 2^(carry_bits − 1)`, so
                // every appearance of a carry drags its offset into the
                // constant.
                if k > 0 {
                    linear.push((lit(1), self.carries[k - 1]));
                    constant -= carry_offset;
                }
                if k < last {
                    linear.push((Coeff::Literal(-radix), self.carries[k]));
                    constant += radix * carry_offset;
                }

                (
                    format!("{}_position_{k}", self.prefix),
                    GateDef::Quadratic {
                        constant: Coeff::Literal(constant),
                        linear,
                        products,
                    },
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Canonicality
// ---------------------------------------------------------------------------

/// `value < modulus`, by the complement `value + complement = modulus − 1`
/// with a borrow chain. `docs/spec/ecrecover.md` §3.3.
///
/// The modulus is odd — `p` and `n` both are — so `modulus − 1` is the
/// modulus's limbs with 1 off the lowest, and the whole chain stays linear.
/// The complement's limbs are bounded by the caller like any other value's;
/// without that the chain proves nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Canonical {
    pub prefix: String,
    pub width: Width,
    /// The value's limb columns.
    pub value: Vec<PolyAddress>,
    /// The complement's limb columns.
    pub complement: Vec<PolyAddress>,
    /// The modulus's limb columns.
    pub modulus: Vec<PolyAddress>,
    /// `limbs − 1` borrow columns, low first. Each is held boolean here.
    pub borrows: Vec<PolyAddress>,
}

impl Canonical {
    pub fn gates(&self) -> Vec<(String, GateDef)> {
        let w = self.width;
        assert_eq!(
            self.borrows.len(),
            w.limbs - 1,
            "{}: a {}-limb complement has {} borrows",
            self.prefix,
            w.limbs,
            w.limbs - 1
        );
        let radix = w.radix();
        let mut out = Vec::new();
        for k in 0..w.limbs {
            // value_k + complement_k + borrow_in − (modulus − 1)_k − radix·borrow_out = 0
            let mut terms = vec![
                (lit(1), self.value[k]),
                (lit(1), self.complement[k]),
                (Coeff::Literal(Fr::MINUS_ONE), self.modulus[k]),
            ];
            if k > 0 {
                terms.push((lit(1), self.borrows[k - 1]));
            }
            if k + 1 < w.limbs {
                terms.push((Coeff::Literal(-radix), self.borrows[k]));
            }
            // The `− 1` of `modulus − 1` sits on the lowest limb.
            let constant = if k == 0 { lit(1) } else { lit(0) };
            out.push((
                format!("{}_limb_{k}", self.prefix),
                GateDef::Linear { terms, constant },
            ));
        }
        for (k, b) in self.borrows.iter().enumerate() {
            out.push((
                format!("{}_borrow_{k}_is_boolean", self.prefix),
                GateDef::Quadratic {
                    constant: lit(0),
                    linear: vec![(Coeff::Literal(Fr::MINUS_ONE), *b)],
                    products: vec![(lit(1), *b, *b)],
                },
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Equality, on halves
// ---------------------------------------------------------------------------

/// The `128 / limb_bits` limbs of half `h` of a value, as one linear form.
///
/// A half is `Σ 2^(limb_bits·i)·x_i` over the limbs it spans, and it is
/// injective because the half is below `2^128 < |Fr|`. The whole value is
/// **not**: `⌊p/|Fr|⌋ = 5`, so six canonical 256-bit values recompose to zero
/// (`docs/spec/ecrecover.md` §3.4). Nothing in this family may take that sum.
pub fn half(width: Width, value: &[PolyAddress], h: usize) -> Vec<(Coeff, PolyAddress)> {
    let per = half_limbs(width);
    assert!(h < width.limbs / per, "half {h} is past the value");
    (0..per)
        .map(|i| {
            (
                Coeff::Literal(two_pow(width.limb_bits * i as u32)),
                value[h * per + i],
            )
        })
        .collect()
}

/// Limbs a half. The halves are each at most 128 bits wide, so that their
/// recomposition into one `Fr` is injective.
pub fn half_limbs(width: Width) -> usize {
    let per = (128 / width.limb_bits) as usize;
    let per = per.min(width.limbs);
    assert!(
        per > 0 && width.limbs.is_multiple_of(per),
        "a value's limbs must divide into halves of at most 128 bits"
    );
    per
}

/// `left = right`, as one gate a half.
pub fn equal(
    prefix: &str,
    width: Width,
    left: &[PolyAddress],
    right: &[PolyAddress],
) -> Vec<(String, GateDef)> {
    let halves = width.limbs / half_limbs(width);
    (0..halves)
        .map(|h| {
            let mut terms = half(width, left, h);
            for (c, a) in half(width, right, h) {
                let Coeff::Literal(v) = c else {
                    unreachable!("a half's coefficients are literals")
                };
                terms.push((Coeff::Literal(-v), a));
            }
            (
                format!("{prefix}_half_{h}"),
                GateDef::Linear {
                    terms,
                    constant: lit(0),
                },
            )
        })
        .collect()
}
