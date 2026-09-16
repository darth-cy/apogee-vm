//! The LogUp channels, as data: how a lookup expression's tuple is gated and
//! compressed into one denominator, what a channel's table side is, and the
//! fraction tree that discharges a whole channel.
//!
//! `docs/spec/lookup.md` is normative. A channel claims
//!
//! ```text
//! Σ_rows Σ_l 1/(E_l + g)  −  Σ_rows mult/(T + g)  =  0
//! ```
//!
//! with `E_l` row `y`'s gated tuple compressed by `β` and `T` the table row's,
//! and proves it as a tree of fractions whose root pair `(num, den)` a verifier
//! holds to `num = 0` and `den != 0`. Every fraction of the leaf level is one
//! `(num, den)` pair of gate-list-0 columns: a row's is `(1, E_l + g)`, the
//! table's is `(−mult, T + g)`, and the level is padded to a power of two with
//! the neutral fraction `(0, 1)`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::{challenge_slot, lookup_channel};
use field::Fr;

use crate::build::{self, Combine, Tree};
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

/// `β^j`'s coefficient: the literal 1 at `j = 0`, and the derived slot
/// `challenge_slot::LOOKUP_BETA_POWERS[j - 1]` above it. Panics past
/// `lookup_channel::MAX_TUPLE`.
pub fn beta_power(j: usize) -> Coeff {
    match j {
        0 => lit(1),
        _ => {
            assert!(
                j <= challenge_slot::LOOKUP_BETA_POWERS.len(),
                "a lookup tuple has at most {} columns; column {j} needs a beta power that \
                 constants::challenge_slot does not define",
                lookup_channel::MAX_TUPLE
            );
            Coeff::Challenge(challenge_slot::LOOKUP_BETA_POWERS[j - 1])
        }
    }
}

/// A channel's table, as the circuit reads it, and its one multiplicity column.
/// `docs/spec/lookup.md` §3 and §4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelSpec {
    /// One of `constants::lookup_channel`.
    pub channel: u32,
    /// The table's columns, one per tuple position and in the same order every
    /// lookup expression of the channel uses: a range channel's one virtual
    /// table, a table channel's committed `S` columns.
    pub table: Vec<PolyAddress>,
    /// `W[i]`: the channel's one multiplicity column, last in the witness
    /// subtree.
    pub multiplicity: PolyAddress,
}

/// Where a channel's gated tuple sends a row its selector switches off, and
/// what it adds to a participating row's key. `docs/spec/lookup.md` §4.
enum Gating {
    /// `flag·expr`, the neutral tuple being the all-zero one. A range table's
    /// row 0 is the value 0, a real and in-range entry, so no offset reserves
    /// it: "0 is in range" is what a switched-off row claims, and it is true.
    Range,
    /// `flag·(key + 1)` on column 0 and `flag·v_j` on the rest, the neutral
    /// tuple being the all-zero `ZeroEntry` row. The `+ 1` is what keeps a real
    /// entry off the all-zero tuple, so the neutral row answers only the rows
    /// that are switched off.
    ZeroEntry,
    /// `flag·(v_j + 1) − 1` on every column, the neutral tuple being
    /// `MINUS_ONE` in every column: S11's decoded table is `MINUS_ONE`-padded
    /// and has no all-zero row, so its padding row is the neutral entry. The
    /// one documented exemption from the `ZeroEntry` rule (S15 must-be-exact
    /// 4).
    MinusOne,
}

fn gating(channel: u32) -> Gating {
    match channel {
        lookup_channel::TIMESTAMP | lookup_channel::RANGE16 => Gating::Range,
        lookup_channel::GENERIC => Gating::ZeroEntry,
        lookup_channel::DECODER => Gating::MinusOne,
        other => panic!("channel {other} is not in constants::lookup_channel"),
    }
}

/// The channel's denominator constant: `g`, or `g − Σ_{j < width} β^j` where
/// the neutral tuple is `MINUS_ONE` in every column.
fn neutral(channel: u32) -> Coeff {
    match gating(channel) {
        Gating::Range | Gating::ZeroEntry => Coeff::Challenge(challenge_slot::LOOKUP_G),
        Gating::MinusOne => Coeff::Challenge(challenge_slot::LOOKUP_DECODER_NEUTRAL),
    }
}

/// `E_l + g`, one row's gated tuple compressed and shifted: the denominator of
/// its fraction. `docs/spec/lookup.md` §5.
///
/// With `s` the selector, `e_j` the tuple's `j`-th expression and `o_j` the
/// channel's offset there, the gated tuple is `s·(e_j + o_j) + n_j`, `n_j`
/// being the neutral value `MinusOne` gating subtracts, so
///
/// ```text
/// E_l + g = Σ_j β^j·s·e_j  +  Σ_j β^j·o_j·s  +  (g + Σ_j β^j·n_j)
/// ```
///
/// which is one `Quadratic`: every term of `e_j` becomes the product
/// `(β^j·c, s, x)`, each nonzero offset a linear term `(β^j·o_j, s)`, and the
/// bracket the constant, a drawn slot or a derived one.
///
/// Panics unless every expression is a `Linear` with literal coefficients, and
/// unless every expression above position 0 has unit coefficients and no
/// constant: `β^j·c` is one coefficient only when `β^0 = 1` makes it a literal,
/// or when `c = 1` makes it the slot itself.
pub fn row_denominator(l: &LookupExpr) -> GateDef {
    let s = l.selector;
    let (mut linear, mut products) = (Vec::new(), Vec::new());
    let mut offset_0 = Fr::ZERO;
    for (j, e) in l.tuple.iter().enumerate() {
        let GateDef::Linear { terms, constant } = e else {
            panic!("lookup `{}`: expression {j} is not a Linear gate", l.name);
        };
        let Coeff::Literal(k) = *constant else {
            panic!(
                "lookup `{}`: expression {j} has a challenge constant",
                l.name
            );
        };
        let offset = match gating(l.channel) {
            Gating::Range => Fr::ZERO,
            Gating::ZeroEntry if j == 0 => Fr::ONE,
            Gating::ZeroEntry => Fr::ZERO,
            Gating::MinusOne => Fr::ONE,
        };
        for (c, x) in terms {
            let Coeff::Literal(c) = *c else {
                panic!(
                    "lookup `{}`: expression {j} has a challenge coefficient",
                    l.name
                );
            };
            let weight = match j {
                0 => Coeff::Literal(c),
                _ => {
                    assert_eq!(
                        c,
                        Fr::ONE,
                        "lookup `{}`: expression {j} weights {x} by a coefficient other than 1, \
                         and β^{j}·c is not one Coeff",
                        l.name
                    );
                    beta_power(j)
                }
            };
            products.push((weight, s, *x));
        }
        // `β^j·(k + o_j)·s`: a literal at j = 0, and the slot itself above it,
        // which needs `k + o_j` to be 0 or 1.
        match j {
            0 => offset_0 = k + offset,
            _ => {
                let scale = k + offset;
                assert!(
                    scale == Fr::ZERO || scale == Fr::ONE,
                    "lookup `{}`: expression {j} carries the constant {k:?}, and β^{j}·(k + o) \
                     is not one Coeff",
                    l.name
                );
                if scale == Fr::ONE {
                    linear.push((beta_power(j), s));
                }
            }
        }
    }
    if offset_0 != Fr::ZERO {
        linear.insert(0, (Coeff::Literal(offset_0), s));
    }
    GateDef::Quadratic {
        constant: neutral(l.channel),
        linear,
        products,
    }
}

/// `T + g`, the channel's table row compressed and shifted: a `Linear` over the
/// table's columns weighted by the powers of `β`.
pub fn table_denominator(spec: &ChannelSpec) -> GateDef {
    GateDef::Linear {
        terms: spec
            .table
            .iter()
            .enumerate()
            .map(|(j, t)| (beta_power(j), *t))
            .collect(),
        constant: Coeff::Challenge(challenge_slot::LOOKUP_G),
    }
}

/// The channel's fraction tree: the leaf level's `(num, den)` columns in
/// column order, one fraction per lookup expression, then the table's, then
/// neutral `(0, 1)` fractions up to a power of two.
///
/// `lookups` are the artifact's lookups of this channel, in artifact order, and
/// name their fractions.
fn channel_tree(spec: &ChannelSpec, lookups: &[&LookupExpr]) -> Tree {
    let one = GateDef::Linear {
        terms: Vec::new(),
        constant: lit(1),
    };
    let zero = GateDef::Linear {
        terms: Vec::new(),
        constant: lit(0),
    };
    let channel = lookup_channel::NAMES[spec.channel as usize];
    let mut leaves: Vec<(String, GateDef)> = Vec::new();
    for l in lookups {
        leaves.push((format!("{}_num", l.name), one.clone()));
        leaves.push((format!("{}_den", l.name), row_denominator(l)));
    }
    leaves.push((
        format!("{channel}_table_num"),
        GateDef::Linear {
            terms: vec![(Coeff::Literal(Fr::MINUS_ONE), spec.multiplicity)],
            constant: lit(0),
        },
    ));
    leaves.push((format!("{channel}_table_den"), table_denominator(spec)));
    let fractions = (lookups.len() + 1).next_power_of_two();
    for i in 0..fractions - lookups.len() - 1 {
        leaves.push((format!("{channel}_pad_{i}_num"), zero.clone()));
        leaves.push((format!("{channel}_pad_{i}_den"), one.clone()));
    }
    Tree {
        combine: Combine::Fraction,
        leaves,
        prefix: channel.to_string(),
    }
}

/// Every channel's fraction tree, in `specs` order, over the lookups of
/// `lookups`. Each channel's lookups are taken in artifact order, so a lookup's
/// position in its channel's leaf level is where the artifact lists it.
///
/// Panics unless every channel `lookups` names has a spec, every spec has at
/// least one lookup, every lookup of a channel has the channel's tuple width,
/// and `bits <= trace_vars` for a range channel — a table of `2^trace_vars`
/// rows holds at most that many values, so a narrower circuit cannot carry a
/// wider range (`docs/spec/lookup.md` §3).
pub(crate) fn channel_trees(
    lookups: &[LookupExpr],
    specs: &[ChannelSpec],
    trace_vars: u32,
) -> Vec<Tree> {
    let mut trees = Vec::new();
    for spec in specs {
        let channel = spec.channel;
        let name = lookup_channel::NAMES
            .get(channel as usize)
            .unwrap_or_else(|| panic!("channel {channel} is not in constants::lookup_channel"));
        let width = spec.table.len();
        assert!(
            width >= 1 && width <= lookup_channel::MAX_TUPLE,
            "channel `{name}`: a table of {width} columns is not between 1 and {}",
            lookup_channel::MAX_TUPLE
        );
        if lookup_channel::IS_RANGE[channel as usize] {
            let bits = lookup_channel::BITS[channel as usize];
            assert_eq!(
                width, 1,
                "channel `{name}`: a range channel looks up one expression, not {width}"
            );
            assert!(
                bits <= trace_vars,
                "channel `{name}`: a {bits}-bit range table needs {bits} variables, and this \
                 circuit has {trace_vars}"
            );
        }
        let mine: Vec<&LookupExpr> = lookups.iter().filter(|l| l.channel == channel).collect();
        assert!(
            !mine.is_empty(),
            "channel `{name}` has a table and a multiplicity column but no lookup"
        );
        for l in &mine {
            assert_eq!(
                l.tuple.len(),
                width,
                "lookup `{}` has {} expressions, and channel `{name}`'s table has {width} columns",
                l.name,
                l.tuple.len()
            );
        }
        trees.push(channel_tree(spec, &mine));
    }
    trees
}

/// The virtual table a range channel looks into, or `None` for a table
/// channel. `docs/spec/lookup.md` §3.
pub fn range_table(channel: u32) -> Option<VirtualKind> {
    match channel {
        lookup_channel::TIMESTAMP => Some(VirtualKind::Range19),
        lookup_channel::RANGE16 => Some(VirtualKind::Range16),
        _ => None,
    }
}

/// `outputs[2·i]` and `outputs[2·i + 1]` are channel `specs[i]`'s root pair,
/// counting from `first`, the first output a channel owns.
pub fn channel_roots(first: usize, i: usize) -> (usize, usize) {
    (first + 2 * i, first + 2 * i + 1)
}

/// Every lookup of `artifact` is discharged by exactly one leaf denominator of
/// its channel's fraction tree, and no leaf denominator discharges two.
///
/// This is the construction-time twin of the discharge rule (S15 must-be-exact
/// 7): `channel_trees` builds the leaves from the lookup list, so the check is
/// over the *finished* artifact, which is what makes a dropped or duplicated
/// obligation visible. It matches by normalized expansion, so a leaf renamed,
/// reordered or rewritten into an equal polynomial still counts, and one that
/// reads another lookup's columns does not.
///
/// Assumes an artifact that passed [`CircuitArtifact::validate`].
pub fn check_discharge(a: &CircuitArtifact) -> Result<(), String> {
    let list = &a.layers[0];
    let leaves: Vec<&GateDef> = list.producing.iter().map(|e| &e.gate).collect();
    let mut used = vec![0usize; leaves.len()];
    for l in &a.lookups {
        let want = crate::laws::normal_form(&row_denominator(l));
        let hits: Vec<usize> = (0..leaves.len())
            .filter(|&j| crate::laws::normal_form(leaves[j]) == want)
            .collect();
        if hits.len() != 1 {
            return Err(format!(
                "lookup discharge: lookup `{}` is the denominator of {} gate-list-0 columns; \
                 exactly one discharges it",
                l.name,
                hits.len()
            ));
        }
        used[hits[0]] += 1;
    }
    for (j, count) in used.iter().enumerate() {
        if *count > 1 {
            let name = &a.scratch[j].name;
            return Err(format!(
                "lookup discharge: column `{name}` is the denominator of {count} lookups; a \
                 lookup is discharged once"
            ));
        }
    }
    Ok(())
}

/// Every column a copower scales also carries a direct range check of its own.
///
/// A copower turns a row-varying bound `x < p` into the fixed `x·p' < 2^32`,
/// where `p·p' = 2^32`. That half bounds nothing alone: `p'` is a unit in `Fr`,
/// so `x = s·p'^{-1}` sweeps a coset of `2^32` elements, almost none of them
/// small integers, and the range check on `s` sees nothing wrong. The scaled
/// bound says `x` is under this row's width **given** `x` is bounded; only the
/// direct check establishes that.
///
/// `scaled` names, per copower-scaled column, the column `x` the scaling reads.
/// Refuses any of them that no `RANGE16` obligation of `a` bounds directly — a
/// lookup whose one expression is `x` alone, with a unit coefficient and no
/// constant. S18 and S19 consume this.
pub fn check_copowers(a: &CircuitArtifact, scaled: &[PolyAddress]) -> Result<(), String> {
    for x in scaled {
        let direct = a.lookups.iter().any(|l| {
            l.channel == lookup_channel::RANGE16
                && matches!(
                    l.tuple.as_slice(),
                    [GateDef::Linear { terms, constant }]
                        if *constant == lit(0)
                            && terms.as_slice() == [(Coeff::Literal(Fr::ONE), *x)]
                )
        });
        if !direct {
            return Err(format!(
                "copower pairing: {x} is copower-scaled, but no range16 obligation bounds it \
                 directly, and a scaled bound alone bounds nothing"
            ));
        }
    }
    Ok(())
}

/// The prefix a tree of channel `channel` is named with, for a caller reading
/// an artifact's scratch bijection back.
pub fn channel_prefix(channel: u32) -> &'static str {
    lookup_channel::NAMES[channel as usize]
}

/// A product tree over `leaves`, named `prefix`: the shape `constraints::memory`
/// builds, exposed so a circuit that joins memory leaves to lookup channels can
/// assemble both at once.
pub(crate) fn product_tree(prefix: &str, leaves: Vec<(String, GateDef)>) -> Tree {
    Tree {
        combine: Combine::Product,
        leaves,
        prefix: build::name(prefix),
    }
}
