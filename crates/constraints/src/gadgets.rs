//! The two gadgets S17 froze for every later family: the witnessed-inverse
//! **is-zero** test, and the **comparison** that settles signed and unsigned
//! ordering in one degree-2 equation. `docs/spec/jump-branch-slt.md` §3 is
//! normative.
//!
//! Both return gates and lookups as data, and a family's circuit puts them in
//! its `memory::FamilySpec`. S14's x0 rule is built on [`is_zero`]; S17's
//! jump/branch/slt family is the first to use both; S18 takes them for its
//! magnitude comparisons and its `rem ≠ 0` test, and S19 for `amomin`/`amomax`.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use constants::{generic_table, lookup_channel};
use field::Fr;

use crate::{Coeff, GateDef, LookupExpr, PolyAddress};

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

/// A sign lookup's key is `hi + SIGN_BASE + 1` for a halfword `hi`, which is
/// above every AND key only because `U16GetSign`'s base is past the AND
/// table's 256 keys, and below every `ShiftPowers` key only because S18's base
/// is past `U16GetSign`'s `2^16` (`docs/spec/lookup.md` §9). A caller must
/// still bound the key it looks up: the ranges being disjoint is what makes an
/// *in-range* key unambiguous, not what keeps an out-of-range one out
/// (`docs/spec/shift-bitwise.md` §3.3).
const _: () = assert!(generic_table::SIGN_BASE >= generic_table::AND_BASE + 256);
const _: () = assert!(generic_table::SHIFT_BASE >= generic_table::SIGN_BASE + (1 << 16));

/// The witnessed-inverse is-zero gadget over the linear form
/// `x = Σ c_i·x_i`, with witness columns `inv` and `z`:
///
/// ```text
/// x·inv + z − enable = 0
/// z·x = 0
/// ```
///
/// Where `enable` is 0 or 1 — which the caller establishes — the two force
/// `z = enable·[x = 0]`: at `x ≠ 0` the second gives `z = 0` and the first
/// `inv = enable/x`; at `x = 0` the first gives `z = enable`. So `z` is
/// boolean with no gate of its own, and a row whose `enable` is 0 has
/// `z = 0`, which keeps the all-zero row valid. Both gates are degree 2.
///
/// S14's x0 rule is this over `x = addr`, enabled by the `rd` query's mask, so
/// its bytes are the frame fixtures' (`docs/spec/memory.md` §2.4).
pub fn is_zero(
    x: &[(Coeff, PolyAddress)],
    inv: PolyAddress,
    z: PolyAddress,
    enable: PolyAddress,
) -> [GateDef; 2] {
    [
        GateDef::Quadratic {
            constant: lit(0),
            linear: vec![(lit(1), z), (Coeff::Literal(Fr::MINUS_ONE), enable)],
            products: x.iter().map(|(c, v)| (*c, *v, inv)).collect(),
        },
        GateDef::Quadratic {
            constant: lit(0),
            linear: vec![],
            products: x.iter().map(|(c, v)| (*c, *v, z)).collect(),
        },
    ]
}

/// One comparison `lhs < rhs`, signed or unsigned, by its columns.
///
/// Every field names a committed column but `prefix`, which names the
/// comparison's gates and lookups, and `signed`, whose columns' sum is the
/// signed-compare flag `sc`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comparison {
    /// The prefix of every gate and lookup name the gadget returns.
    pub prefix: String,
    /// Every obligation's selector: the row's liveness, boolean.
    pub selector: PolyAddress,
    /// Bits whose sum is `sc`: 1 on a signed comparison, 0 on an unsigned one.
    /// The caller holds the sum to 0 or 1 on every selected row.
    pub signed: Vec<PolyAddress>,
    /// The left operand, and its high halfword and sign.
    pub lhs: PolyAddress,
    pub lhs_hi: PolyAddress,
    pub lhs_sign: PolyAddress,
    /// The right operand, and its high halfword and sign.
    pub rhs: PolyAddress,
    pub rhs_hi: PolyAddress,
    pub rhs_sign: PolyAddress,
    /// 1 exactly when `lhs < rhs` in the ordering `sc` selects.
    pub lt: PolyAddress,
    /// The distance `D + 2^32·lt` below, and its high halfword.
    pub gap: PolyAddress,
    pub gap_hi: PolyAddress,
}

/// The comparison's one equation over a `word_bits`-bit word:
///
/// ```text
/// 0 = lhs − rhs − 2^w·sc·lhs_sign + 2^w·sc·rhs_sign + 2^w·lt − gap
/// ```
///
/// With `D = lhs − rhs − 2^w·sc·(lhs_sign − rhs_sign)` — the difference of the
/// two operands read in two's complement where `sc` is 1, so mixed signs are
/// never a case split — `D` lies in `(−2^w, 2^w)`, and `gap = D + 2^w·lt` in
/// `[0, 2^w)` with `lt` boolean has exactly one solution: `lt = 0` at `D ≥ 0`,
/// where `lt = 1` puts `gap` at `2^w` or above, and `lt = 1` at `D < 0`, where
/// `lt = 0` makes `gap` a negative field element. Degree 2: each `sc` term is
/// one of the `signed` bits times a sign.
///
/// [`comparison`] builds it at 32 bits, which is the only width a proof uses.
/// The width is a parameter so that the exhaustive reduced-width check
/// (S17 acceptance 2) evaluates this gate and not a transcription of it.
///
/// Panics unless `word_bits` is between 1 and 32.
pub fn comparison_equation(c: &Comparison, word_bits: u32) -> GateDef {
    assert!(
        (1..=32).contains(&word_bits),
        "a comparison's word is 1 to 32 bits wide, not {word_bits}"
    );
    let word = Fr::from_u64(1 << word_bits);
    let mut products = Vec::new();
    for bit in &c.signed {
        products.push((Coeff::Literal(-word), *bit, c.lhs_sign));
        products.push((Coeff::Literal(word), *bit, c.rhs_sign));
    }
    GateDef::Quadratic {
        constant: lit(0),
        linear: vec![
            (lit(1), c.lhs),
            (Coeff::Literal(Fr::MINUS_ONE), c.rhs),
            (Coeff::Literal(word), c.lt),
            (Coeff::Literal(Fr::MINUS_ONE), c.gap),
        ],
        products,
    }
}

/// The comparison gadget at 32 bits: its gates and its lookups, in the order
/// a family appends them.
///
/// ```text
/// gates     <p>_order          comparison_equation at 32 bits
///           <p>_lt_boolean     lt − lt·lt
/// range16   <p>_lhs_hi_range   lhs_hi                 <p>_lhs_lo_range   lhs − 2^16·lhs_hi
///           <p>_rhs_hi_range   rhs_hi                 <p>_rhs_lo_range   rhs − 2^16·rhs_hi
///           <p>_gap_hi_range   gap_hi                 <p>_gap_lo_range   gap − 2^16·gap_hi
/// generic   <p>_lhs_get_sign   (lhs_hi + SIGN_BASE, lhs_sign, 0)
///           <p>_rhs_get_sign   (rhs_hi + SIGN_BASE, rhs_sign, 0)
/// ```
///
/// every lookup under `selector`. On a selected row the range pairs make each
/// operand and `gap` a 32-bit integer and each `_hi` its true high halfword
/// (`docs/spec/memory.md` §7), which bounds each `U16GetSign` key into that
/// table's range — `docs/spec/lookup.md` §4's precondition — so each sign is
/// its operand's bit 31. The `gap` bound is what carries the ordering: it
/// leaves one `(lt, gap)` per sign quadrant ([`comparison_equation`]).
///
/// The equation and `lt`'s booleanity are ungated, so they hold on every row;
/// an unselected row satisfies them with whatever `gap` its values need, and
/// the all-zero row with zeros.
pub fn comparison(c: &Comparison) -> (Vec<(String, GateDef)>, Vec<LookupExpr>) {
    let p = &c.prefix;
    let gates = vec![
        (format!("{p}_order"), comparison_equation(c, 32)),
        (
            format!("{p}_lt_boolean"),
            GateDef::Quadratic {
                constant: lit(0),
                linear: vec![(lit(1), c.lt)],
                products: vec![(Coeff::Literal(Fr::MINUS_ONE), c.lt, c.lt)],
            },
        ),
    ];
    let range = |name: String, terms: Vec<(Coeff, PolyAddress)>| LookupExpr {
        name,
        channel: lookup_channel::RANGE16,
        selector: c.selector,
        tuple: vec![GateDef::Linear {
            terms,
            constant: lit(0),
        }],
    };
    let halfword = lookup_channel::BITS[lookup_channel::RANGE16 as usize];
    let half = Coeff::Literal(-Fr::from_u64(1 << halfword));
    let sign = |name: String, hi: PolyAddress, bit: PolyAddress| LookupExpr {
        name,
        channel: lookup_channel::GENERIC,
        selector: c.selector,
        tuple: vec![
            GateDef::Linear {
                terms: vec![(lit(1), hi)],
                constant: lit(generic_table::SIGN_BASE as u64),
            },
            GateDef::Linear {
                terms: vec![(lit(1), bit)],
                constant: lit(0),
            },
            GateDef::Linear {
                terms: vec![],
                constant: lit(0),
            },
        ],
    };
    let mut lookups = Vec::new();
    for (side, value, hi) in [
        ("lhs", c.lhs, c.lhs_hi),
        ("rhs", c.rhs, c.rhs_hi),
        ("gap", c.gap, c.gap_hi),
    ] {
        lookups.push(range(format!("{p}_{side}_hi_range"), vec![(lit(1), hi)]));
        lookups.push(range(
            format!("{p}_{side}_lo_range"),
            vec![(lit(1), value), (half, hi)],
        ));
    }
    lookups.push(sign(format!("{p}_lhs_get_sign"), c.lhs_hi, c.lhs_sign));
    lookups.push(sign(format!("{p}_rhs_get_sign"), c.rhs_hi, c.rhs_sign));
    (gates, lookups)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two halfwords are the comparison's word: the range pairs bound exactly
    /// the 32 bits the equation's `2^32` assumes.
    #[test]
    fn two_range16_halves_are_the_comparison_word() {
        assert_eq!(
            2 * lookup_channel::BITS[lookup_channel::RANGE16 as usize],
            32
        );
    }

    fn a_comparison() -> Comparison {
        let w = PolyAddress::Witness;
        Comparison {
            prefix: "cmp".into(),
            selector: PolyAddress::Memory(1),
            signed: vec![w(0)],
            lhs: PolyAddress::Memory(2),
            lhs_hi: w(1),
            lhs_sign: w(2),
            rhs: w(3),
            rhs_hi: w(4),
            rhs_sign: w(5),
            lt: w(6),
            gap: w(7),
            gap_hi: w(8),
        }
    }

    /// The sign lookup's tuple is the generic table's width.
    #[test]
    fn a_sign_lookup_has_the_generic_tables_width_and_key_base() {
        let (gates, lookups) = comparison(&a_comparison());
        assert_eq!(gates.len(), 2);
        assert_eq!(lookups.len(), 8);
        for l in lookups
            .iter()
            .filter(|l| l.channel == lookup_channel::GENERIC)
        {
            assert_eq!(l.tuple.len(), generic_table::WIDTH);
        }
    }

    /// The equation is built for a word of 1 to 32 bits, and for no other.
    #[test]
    fn a_word_of_1_and_of_32_bits_builds() {
        comparison_equation(&a_comparison(), 1);
        comparison_equation(&a_comparison(), 32);
    }

    #[test]
    #[should_panic(expected = "a comparison's word is 1 to 32 bits wide, not 0")]
    fn a_word_of_no_bits_is_refused() {
        comparison_equation(&a_comparison(), 0);
    }

    #[test]
    #[should_panic(expected = "a comparison's word is 1 to 32 bits wide, not 33")]
    fn a_word_of_33_bits_is_refused() {
        comparison_equation(&a_comparison(), 33);
    }
}
