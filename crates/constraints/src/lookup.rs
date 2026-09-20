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

use crate::build::{Combine, Tree};
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
/// column order — **the table's fraction first**, then one per lookup
/// expression, then neutral `(0, 1)` fractions up to a power of two.
///
/// The table goes first so that the tree's first pair-addition, which combines
/// leaves 0 and 1, is literally `1/(w_0 + g) − mult/(T + g)`: the node
/// S15 must-be-exact 1 pins. Put it last and that node appears nowhere in a
/// channel with more than one lookup, because the row fractions pair with each
/// other.
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
    let mut leaves: Vec<(String, GateDef)> = vec![
        (
            format!("{channel}_table_num"),
            GateDef::Linear {
                terms: vec![(Coeff::Literal(Fr::MINUS_ONE), spec.multiplicity)],
                constant: lit(0),
            },
        ),
        (format!("{channel}_table_den"), table_denominator(spec)),
    ];
    for l in lookups {
        leaves.push((format!("{}_num", l.name), one.clone()));
        leaves.push((format!("{}_den", l.name), row_denominator(l)));
    }
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
/// Panics unless every spec has at least one lookup, every lookup of a channel
/// has the channel's tuple width, the channel's multiplicity is a **witness**
/// column, a range channel's table is the virtual kind its bound names, and
/// `bits <= trace_vars` for a range channel — a table of `2^trace_vars` rows
/// holds at most that many values, so a narrower circuit cannot carry a wider
/// range (`docs/spec/lookup.md` §3).
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
            (1..=lookup_channel::MAX_TUPLE).contains(&width),
            "channel `{name}`: a table of {width} columns is not between 1 and {}",
            lookup_channel::MAX_TUPLE
        );
        // The multiplicity is committed per shard, before `g` and `β` are
        // drawn (`docs/spec/lookup.md` §2 and §7). A setup column is fixed at
        // key generation and a memory column belongs to the multiset argument;
        // either would be a count the channel's own witness does not carry.
        assert!(
            matches!(spec.multiplicity, PolyAddress::Witness(_)),
            "channel `{name}`: its multiplicity is {}, and a multiplicity is a witness column",
            spec.multiplicity
        );
        if lookup_channel::IS_RANGE[channel as usize] {
            let bits = lookup_channel::BITS[channel as usize];
            assert_eq!(
                width, 1,
                "channel `{name}`: a range channel looks up one expression, not {width}"
            );
            // The table is the kind the bound names, and nothing else: a range
            // channel discharged against another kind's closed form proves a
            // different range than the channel declares.
            let kind = range_table(channel).expect("a range channel has a virtual table");
            assert_eq!(
                spec.table[0],
                PolyAddress::Virtual(kind),
                "channel `{name}`: its table is {}, not the {kind:?} its bound names",
                spec.table[0]
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

/// Every lookup of `artifact` is discharged by exactly one gate-list-0 column,
/// no column discharges two, every channel in `specs` has exactly one table
/// fraction, and — where `specs` is given — each of those columns is a leaf of
/// **its own channel's** fraction tree: a lookup's denominator of the channel
/// it names, a table fraction of the channel whose table it compresses.
///
/// This is the construction-time twin of the discharge rule (S15 must-be-exact
/// 7): `channel_trees` builds the leaves from the lookup list, so the check is
/// over the *finished* artifact, which is what makes a dropped, duplicated or
/// misrouted obligation visible. It matches by normalized expansion, so a leaf
/// renamed, reordered or rewritten into an equal polynomial still counts, and
/// one that reads another lookup's columns does not.
///
/// The channel half needs `specs`, because which output pair is which channel's
/// root is the caller's knowledge and not the artifact's: the output map is the
/// memory roots, if any, then one `(num, den)` pair per channel in `specs`
/// order. Passing an empty `specs` runs the column half alone, which is all an
/// artifact by itself can say — and the table half not at all, a table fraction
/// being a thing only a spec names.
///
/// Assumes an artifact that passed [`CircuitArtifact::validate`].
pub fn check_discharge(a: &CircuitArtifact, specs: &[ChannelSpec]) -> Result<(), String> {
    let list = &a.layers[0];
    let leaves: Vec<&GateDef> = list.producing.iter().map(|e| &e.gate).collect();
    let cones = channel_cones(a, specs)?;
    let one = crate::laws::normal_form(&GateDef::Linear {
        terms: Vec::new(),
        constant: lit(1),
    });
    // A lookup's fraction is `(1, E_l + g)`, so the column before its
    // denominator is its numerator and is the literal 1. Without this, a
    // numerator moved to 0 turns the fraction into 0 and drops the obligation
    // while every other check still sees the denominator where it was.
    let numerator = |j: usize, name: &str| -> Result<(), String> {
        match j
            .checked_sub(1)
            .filter(|i| crate::laws::normal_form(leaves[*i]) == one)
        {
            Some(_) => Ok(()),
            None => Err(format!(
                "lookup discharge: lookup `{name}`'s fraction has no numerator of 1 beside its \
                 denominator, so its row contributes nothing"
            )),
        }
    };
    let mut used = vec![0usize; leaves.len()];
    for (i, spec) in specs.iter().enumerate() {
        // The channel's own table fraction: `(−mult, T + g)`, and exactly one of
        // it. Without it a channel sums its rows against nothing.
        let want = crate::laws::normal_form(&table_denominator(spec));
        let all: Vec<usize> = (0..leaves.len())
            .filter(|&j| crate::laws::normal_form(leaves[j]) == want)
            .collect();
        let channel = lookup_channel::NAMES[spec.channel as usize];
        // Inside the channel's own cone, for the reason a lookup's denominator
        // is: a table fraction that sits in another channel's tree leaves this
        // channel summing its rows against a table it did not declare, and the
        // other channel subtracting a count of rows it does not hold. Both
        // trees still hold one table fraction and both numerators are where
        // they should be, so the cone walk is the only half that sees it.
        // Counting inside the cone is also what lets two channels share a
        // table: over the whole list each would match the other's column and a
        // correct circuit would be refused.
        let hits: Vec<usize> = all
            .iter()
            .copied()
            .filter(|j| cones[i].contains(j))
            .collect();
        if hits.is_empty() && !all.is_empty() {
            return Err(format!(
                "lookup discharge: channel `{channel}`'s table fraction is a column outside its \
                 own fraction tree, so the channel sums its rows against another table"
            ));
        }
        if hits.len() != 1 {
            return Err(format!(
                "lookup discharge: channel `{channel}`'s table is the denominator of {} columns \
                 of its fraction tree; exactly one is its fraction",
                hits.len()
            ));
        }
        let mult = crate::laws::normal_form(&GateDef::Linear {
            terms: vec![(Coeff::Literal(Fr::MINUS_ONE), spec.multiplicity)],
            constant: lit(0),
        });
        let named = hits[0]
            .checked_sub(1)
            .is_some_and(|i| crate::laws::normal_form(leaves[i]) == mult);
        if !named {
            return Err(format!(
                "lookup discharge: channel `{channel}`'s table fraction has no numerator \
                 `−{}` beside its denominator",
                spec.multiplicity
            ));
        }
        used[hits[0]] += 1;
    }
    for l in &a.lookups {
        let want = crate::laws::normal_form(&row_denominator(l));
        let all: Vec<usize> = (0..leaves.len())
            .filter(|&j| crate::laws::normal_form(leaves[j]) == want)
            .collect();
        // The count is per channel, not per circuit: the two range channels
        // gate and neutralize identically (§4), so one lookup's denominator gate
        // can be another channel's leaf byte for byte, and counting over the
        // whole list would refuse two obligations that are each discharged
        // exactly once. Where `specs` names the channel, count inside its cone,
        // and a lookup whose every match is outside it is misrouted rather than
        // missing.
        let channel = lookup_channel::NAMES[l.channel as usize];
        let cone = specs
            .iter()
            .position(|s| s.channel == l.channel)
            .map(|i| &cones[i]);
        let hits: Vec<usize> = match cone {
            Some(c) => all.iter().copied().filter(|j| c.contains(j)).collect(),
            None => all.clone(),
        };
        if cone.is_some() && hits.is_empty() && !all.is_empty() {
            return Err(format!(
                "lookup discharge: lookup `{}` is discharged by a column outside channel \
                 `{channel}`'s fraction tree, so it is summed against another table",
                l.name
            ));
        }
        if hits.len() != 1 {
            return Err(match cone {
                Some(_) => format!(
                    "lookup discharge: lookup `{}` is the denominator of {} columns of channel \
                     `{channel}`'s fraction tree; exactly one discharges it",
                    l.name,
                    hits.len()
                ),
                None => format!(
                    "lookup discharge: lookup `{}` is the denominator of {} gate-list-0 columns; \
                     exactly one discharges it",
                    l.name,
                    hits.len()
                ),
            });
        }
        numerator(hits[0], &l.name)?;
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

/// The gate-list-0 columns each channel's root pair is computed from, in
/// `specs` order: the cone below `outputs[first + 2i]` and `outputs[first + 2i + 1]`,
/// walked down layer by layer, with `first` the output past the memory roots.
fn channel_cones(a: &CircuitArtifact, specs: &[ChannelSpec]) -> Result<Vec<Vec<usize>>, String> {
    let first = a.outputs.len().checked_sub(2 * specs.len()).ok_or(format!(
        "lookup discharge: {} outputs for {} channels",
        a.outputs.len(),
        specs.len()
    ))?;
    let offset = |address: PolyAddress| match address {
        PolyAddress::Inner { offset, .. } => Ok(offset as usize),
        other => Err(format!(
            "lookup discharge: output {other} is not an inner column"
        )),
    };
    let mut cones = Vec::with_capacity(specs.len());
    for i in 0..specs.len() {
        // Walk down from the two roots: at each list, replace the set of
        // columns by the columns its gates read.
        let mut live = alloc::collections::BTreeSet::new();
        live.insert(offset(a.outputs[first + 2 * i])?);
        live.insert(offset(a.outputs[first + 2 * i + 1])?);
        // At each list above 0, replace the set of columns by the columns its
        // gates read. Gate list 0's operands are base columns, so the set that
        // survives the walk is the channel's leaf columns.
        for k in (1..a.depth()).rev() {
            let mut below = alloc::collections::BTreeSet::new();
            for &j in &live {
                for op in a.layers[k].producing[j].gate.operands() {
                    if let PolyAddress::Inner { offset, .. } = op {
                        below.insert(offset as usize);
                    }
                }
            }
            live = below;
        }
        cones.push(live.into_iter().collect());
    }
    Ok(cones)
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
/// Each entry of `scaled` is a copower-scaled column `x` and the **selector**
/// the scaled obligation carries. Refuses any of them that no `RANGE16`
/// obligation of `a` **under that same selector** bounds directly, which is
/// either shape of `docs/spec/memory.md` §7:
///
/// - a halfword: one obligation whose expression is `x` alone;
/// - a 32-bit value: a witnessed high chunk `h` with obligations on `h` and on
///   `x − 2^16·h`, the convention every 32-bit column in this VM is bounded by.
///
/// **The selector is half the check.** S17 matched an obligation on its
/// expression alone, so a circuit whose direct pair sat under a narrower
/// selector than its scaled obligation passed: on a row the narrow selector
/// switches off, the direct bound is vacuous and the scaled one is back to
/// bounding nothing. Requiring the same selector is conservative — a direct
/// bound under a genuinely *broader* selector is also sound — and conservative
/// is the right side to be on for a check whose failure mode is silent.
///
/// S18 consumes this for the shift family's residue; S19 for its own.
pub fn check_copowers(
    a: &CircuitArtifact,
    scaled: &[(PolyAddress, PolyAddress)],
) -> Result<(), String> {
    // A `RANGE16` obligation under `selector` whose expression is exactly
    // `terms`, in any order, with no constant.
    let bounded = |selector: PolyAddress, terms: &[(Coeff, PolyAddress)]| {
        a.lookups.iter().any(|l| {
            let [GateDef::Linear {
                terms: got,
                constant,
            }] = l.tuple.as_slice()
            else {
                return false;
            };
            l.channel == lookup_channel::RANGE16
                && l.selector == selector
                && *constant == lit(0)
                && got.len() == terms.len()
                && terms.iter().all(|t| got.contains(t))
        })
    };
    let one = Coeff::Literal(Fr::ONE);
    let half = Coeff::Literal(-Fr::from_u64(1 << 16));
    for (x, selector) in scaled {
        // The halfword shape, then the 32-bit one over every column that could
        // be its high chunk.
        let direct = bounded(*selector, &[(one, *x)])
            || (0..a.witness.len() as u32)
                .map(PolyAddress::Witness)
                .any(|h| {
                    bounded(*selector, &[(one, h)]) && bounded(*selector, &[(one, *x), (half, h)])
                });
        if !direct {
            return Err(format!(
                "copower pairing: {x} is copower-scaled under {selector}, but no range16 \
                 obligation under that selector bounds it directly — neither alone nor as a \
                 high chunk and a remainder — and a scaled bound alone bounds nothing"
            ));
        }
    }
    Ok(())
}

/// A product tree over `leaves`, named `prefix`: the shape `constraints::memory`
/// builds, exposed so a circuit that joins memory leaves to lookup channels can
/// assemble both at once.
pub(crate) fn product_tree(prefix: &str, leaves: Vec<(String, GateDef)>) -> Tree {
    Tree {
        combine: Combine::Product,
        leaves,
        prefix: prefix.to_string(),
    }
}
