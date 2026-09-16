//! The LogUp multiplicity columns: one counter per channel per table row,
//! counted in one pass over the trace, and the recount that refuses a column
//! disagreeing with it.
//!
//! `docs/spec/lookup.md` §7. A multiplicity is committed **before** `g` and `β`
//! are drawn, so the counting is over **raw** gated tuples and never over a
//! compressed one: nothing here reads a challenge.
//!
//! A table of `2^n` rows over fewer distinct tuples repeats, so a value can sit
//! at several rows. The counter credits the **lowest** row holding the tuple,
//! which is the one convention both sides can recompute.

use std::collections::BTreeMap;

use constants::lookup_channel;
use constraints::lookup::ChannelSpec;
use constraints::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};
use field::Fr;
use gkr_verify::virtual_at_row;
use poly::{MultilinearPoly, PolyBacking};

/// One channel's multiplicity column, `(address, column)`, in `specs` order.
///
/// Row `t` of channel `c`'s column counts how many gated tuples over the whole
/// trace are the tuple of table row `t` — one increment per lookup expression
/// on each row, the rows their selector switches off included, since those
/// contribute the channel's neutral entry and it is a table row like any other.
///
/// Refuses a gated tuple that is a row of no table row, naming the row and the
/// lookup: the honest prover cannot balance a channel over one, and a value a
/// table does not hold is exactly what the obligation forbids. Refuses a
/// column the base does not hold, and a lookup whose expression a row cannot
/// evaluate.
///
/// Does NOT cover: the challenges, which it never reads; whether the artifact's
/// channels are the ones `specs` names; the lookup rules, which it assumes.
pub fn build_multiplicities(
    artifact: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    specs: &[ChannelSpec],
) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let rows = 1usize << artifact.trace_vars;
    let mut out = Vec::new();
    for spec in specs {
        let name = channel_name(spec.channel)?;
        let width = spec.table.len();
        let mine: Vec<&LookupExpr> = artifact
            .lookups
            .iter()
            .filter(|l| l.channel == spec.channel)
            .collect();
        // Every column a lookup or the table names, resolved once: reading one
        // by address per row is quadratic in the column count, and reading an
        // expression through `GateDef::operands` allocates per row.
        let source = |address: PolyAddress| resolve(artifact, columns, address);
        let table: Vec<Source> = spec
            .table
            .iter()
            .map(|t| source(*t))
            .collect::<Result<_, _>>()?;
        let mut resolved: Vec<Resolved> = Vec::new();
        for l in &mine {
            if l.tuple.len() != width {
                return Err(format!(
                    "multiplicities: lookup `{}` has {} expressions and channel `{name}`'s table \
                     has {width} columns",
                    l.name,
                    l.tuple.len()
                ));
            }
            let mut tuple = Vec::with_capacity(width);
            for e in &l.tuple {
                let GateDef::Linear { terms, constant } = e else {
                    return Err(format!(
                        "multiplicities: lookup `{}` has an expression that is not Linear",
                        l.name
                    ));
                };
                let literal = |c: &Coeff| match c {
                    Coeff::Literal(v) => Ok(*v),
                    Coeff::Challenge(slot) => Err(format!(
                        "multiplicities: lookup `{}` weights a term by challenge slot {slot}",
                        l.name
                    )),
                };
                let mut weighted = Vec::with_capacity(terms.len());
                for (c, x) in terms {
                    weighted.push((literal(c)?, source(*x)?));
                }
                tuple.push((weighted, literal(constant)?));
            }
            resolved.push((source(l.selector)?, tuple));
        }

        // One pass over the trace, counting per *distinct gated tuple* rather
        // than per table row: a table of 2^20 rows has 2^20 of those, and a
        // trace looks up a handful.
        let mut wanted: BTreeMap<Key, u32> = BTreeMap::new();
        let mut tuple = vec![Fr::ZERO; width];
        for row in 0..rows {
            for (selector, expressions) in &resolved {
                let s = read(columns, selector, row);
                for (j, (terms, constant)) in expressions.iter().enumerate() {
                    let raw = terms.iter().fold(*constant, |acc, (c, src)| {
                        acc + *c * read(columns, src, row)
                    });
                    tuple[j] = gate(spec.channel, j, s, raw);
                }
                *wanted.entry(key(&tuple)).or_insert(0) += 1;
            }
        }
        // One pass over the table, crediting the **lowest** row holding each
        // tuple: a table over fewer distinct tuples than rows repeats, and the
        // lowest row is the convention both sides recompute.
        let mut counts = vec![0u32; rows];
        for (row, count) in counts.iter_mut().enumerate() {
            if wanted.is_empty() {
                break;
            }
            for (j, t) in table.iter().enumerate() {
                tuple[j] = read(columns, t, row);
            }
            if let Some(found) = wanted.remove(&key(&tuple)) {
                *count = found;
            }
        }
        if !wanted.is_empty() {
            return Err(format!(
                "multiplicities: {} tuple(s) looked up in channel `{name}` are rows its table \
                 does not hold",
                wanted.len()
            ));
        }
        out.push((
            spec.multiplicity,
            MultilinearPoly::new(PolyBacking::U32(counts)),
        ));
    }
    Ok(out)
}

/// One lookup, resolved: its selector, and per tuple position the
/// literal-weighted sources and the constant.
type Resolved = (Source, Vec<(Vec<(Fr, Source)>, Fr)>);

/// Where one value of the counting is read.
#[derive(Clone, Copy, Debug)]
enum Source {
    /// A committed column, by its position in `columns`.
    Column(usize),
    /// A virtual table, by its closed form at the row.
    Virtual(VirtualKind),
}

fn resolve(
    artifact: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    address: PolyAddress,
) -> Result<Source, String> {
    if let PolyAddress::Virtual(kind) = address {
        if !artifact.virtuals.iter().any(|(v, _)| *v == kind) {
            return Err(format!(
                "multiplicities: {address} is read but the artifact does not list it"
            ));
        }
        return Ok(Source::Virtual(kind));
    }
    columns
        .iter()
        .position(|(a, _)| *a == address)
        .map(Source::Column)
        .ok_or(format!("multiplicities: no column {address} was given"))
}

fn read(columns: &[(PolyAddress, MultilinearPoly)], src: &Source, row: usize) -> Fr {
    match src {
        Source::Column(i) => columns[*i].1.get(row),
        Source::Virtual(kind) => virtual_at_row(*kind, row),
    }
}

/// The recount, S15 must-be-exact 11: `given`'s multiplicity columns are
/// exactly [`build_multiplicities`]'s, cell for cell. A column that disagrees
/// is a build error, named by its channel and the first row that differs.
pub fn check_multiplicities(
    artifact: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    specs: &[ChannelSpec],
    given: &[(PolyAddress, MultilinearPoly)],
) -> Result<(), String> {
    let recount = build_multiplicities(artifact, columns, specs)?;
    if given.len() != recount.len() {
        return Err(format!(
            "multiplicities: {} columns given for {} channels",
            given.len(),
            recount.len()
        ));
    }
    for ((address, want), (spec, (_, got))) in recount.iter().zip(specs.iter().zip(given)) {
        let name = channel_name(spec.channel)?;
        if want.num_vars() != got.num_vars() {
            return Err(format!(
                "multiplicities: channel `{name}`'s column has {} variables, not {}",
                got.num_vars(),
                want.num_vars()
            ));
        }
        for row in 0..1usize << want.num_vars() {
            if want.get(row) != got.get(row) {
                return Err(format!(
                    "multiplicities: channel `{name}`'s {address} differs at row {row}"
                ));
            }
        }
    }
    Ok(())
}

fn channel_name(channel: u32) -> Result<&'static str, String> {
    lookup_channel::NAMES
        .get(channel as usize)
        .copied()
        .ok_or(format!("multiplicities: channel {channel} is not one"))
}

/// A tuple's map key: its columns' canonical bytes, `MAX_TUPLE` wide and zero
/// past the tuple, so it is `Copy` and a row costs no allocation.
type Key = [[u8; 32]; lookup_channel::MAX_TUPLE];

fn key(tuple: &[Fr]) -> Key {
    let mut out = [[0u8; 32]; lookup_channel::MAX_TUPLE];
    for (slot, v) in out.iter_mut().zip(tuple) {
        *slot = v.to_bytes();
    }
    out
}

/// The gated value of tuple position `j`. The three conventions of
/// `docs/spec/lookup.md` §4: a range channel gates to 0, the generic channel to
/// the all-zero `ZeroEntry` with its key offset by one, and the decoder channel
/// to `MINUS_ONE` in every column.
fn gate(channel: u32, j: usize, s: Fr, raw: Fr) -> Fr {
    match channel {
        lookup_channel::GENERIC if j == 0 => s * (raw + Fr::ONE),
        lookup_channel::DECODER => s * (raw + Fr::ONE) - Fr::ONE,
        _ => s * raw,
    }
}
