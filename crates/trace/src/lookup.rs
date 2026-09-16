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
use constraints::{CircuitArtifact, LookupExpr, PolyAddress};
use field::Fr;
use gkr_verify::{eval_gate, virtual_at_row, ExternalChallenges};
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
        let mine: Vec<&LookupExpr> = artifact
            .lookups
            .iter()
            .filter(|l| l.channel == spec.channel)
            .collect();
        // One pass over the trace, counting per *distinct looked-up tuple*
        // rather than per table row: a table of 2^20 rows has 2^20 of those and
        // a trace looks up a handful.
        let mut wanted: BTreeMap<Vec<[u8; 32]>, u32> = BTreeMap::new();
        for row in 0..rows {
            for l in &mine {
                let tuple = gated_tuple(artifact, columns, l, row, spec.table.len())?;
                *wanted.entry(key(&tuple)).or_insert(0) += 1;
            }
        }
        // One pass over the table, crediting the **lowest** row holding each
        // tuple: a table over fewer distinct tuples than rows repeats, and the
        // lowest row is the convention both sides recompute.
        let mut counts = vec![0u32; rows];
        for row in 0..rows {
            if wanted.is_empty() {
                break;
            }
            let mut tuple = Vec::with_capacity(spec.table.len());
            for t in &spec.table {
                tuple.push(value(artifact, columns, *t, row)?);
            }
            if let Some(count) = wanted.remove(&key(&tuple)) {
                counts[row] = count;
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

/// A tuple's map key: its columns' canonical bytes.
fn key(tuple: &[Fr]) -> Vec<[u8; 32]> {
    tuple.iter().map(|v| v.to_bytes()).collect()
}

/// A lookup's gated tuple at `row`, `docs/spec/lookup.md` §4: the raw
/// expressions, each gated by the selector under the channel's convention.
fn gated_tuple(
    artifact: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    l: &LookupExpr,
    row: usize,
    width: usize,
) -> Result<Vec<Fr>, String> {
    if l.tuple.len() != width {
        return Err(format!(
            "multiplicities: lookup `{}` has {} expressions and its channel's table has {width} \
             columns",
            l.name,
            l.tuple.len()
        ));
    }
    let s = value(artifact, columns, l.selector, row)?;
    let literal_only = ExternalChallenges::new();
    let mut tuple = Vec::with_capacity(width);
    for (j, e) in l.tuple.iter().enumerate() {
        let mut operands = Vec::new();
        for op in e.operands() {
            operands.push(value(artifact, columns, op, row)?);
        }
        let raw = eval_gate(e, &operands, &literal_only);
        tuple.push(gate(l.channel, j, s, raw));
    }
    Ok(tuple)
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

/// A column's value at `row`: a virtual table's closed form, or the committed
/// column `columns` holds at that address.
fn value(
    artifact: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    address: PolyAddress,
    row: usize,
) -> Result<Fr, String> {
    if let PolyAddress::Virtual(kind) = address {
        if !artifact.virtuals.iter().any(|(v, _)| *v == kind) {
            return Err(format!(
                "multiplicities: {address} is read but the artifact does not list it"
            ));
        }
        return Ok(virtual_at_row(kind, row));
    }
    columns
        .iter()
        .find(|(a, _)| *a == address)
        .map(|(_, c)| c.get(row))
        .ok_or(format!("multiplicities: no column {address} was given"))
}
