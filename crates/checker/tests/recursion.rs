//! The recursion format's field families and the field memory's windows
//! (`docs/spec/recursion.md` §2-§5), over `guests/field-ops`' own trace.
//!
//! Two statements, and between them every new circuit meets the executor and
//! the fill that produce its rows:
//!
//! * **Every row holds.** Each of `FR_OP`, `P2_FIELD` and `FIELD_IO` is filled
//!   by `prover::family_fill` from the trace and evaluated row by row —
//!   every relation through `checker::violated_relations`, every range
//!   obligation through `checker::violated_lookups` — on every live row and a
//!   padding row. `P2_FIELD`'s next state comes from the emulator's
//!   `transcript::poseidon2_permute` and its intermediates from
//!   `constraints::p2_field::permutation_witness`, so a permutation the circuit
//!   spells differently from the transcript breaks `r63_out*` here.
//! * **The field memory balances.** Every field leaf the three families'
//!   circuits evaluate, with the field window's teardown and init, cancels:
//!   reads times teardowns equals writes times inits. A slot or an offset the
//!   circuit and the executor disagree on is a tuple with no partner.
//!
//! A whole proof of the statement is the deferred half.

mod common;

use common::traced_exiting_at;
use constants::{challenge_slot, family};
use constraints::{recursion_circuit, CircuitArtifact, PolyAddress};
use field::Fr;
use gkr::{gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use poly::MultilinearPoly;
use program::{decode_program, ProgramParams};
use prover::{family_fill, Program, ShardRows, ShardSource};
use trace::FrameSlice;

/// The three delegation families' height: `RANGE16`'s floor.
const VARS: u32 = 16;
/// The field window's: the menu's smallest, which covers every cell the
/// guest touches.
const WINDOW_VARS: u32 = 8;

/// `field-ops` traced at `2^VARS`, with the program a fill reads.
fn setup() -> (common::Traced, Program) {
    let t = traced_exiting_at("field-ops", 0, 14, 1 << VARS);
    let params = ProgramParams {
        heights: [1 << VARS; family::COUNT as usize],
        ..ProgramParams::defaults()
    };
    let (tables, config) = decode_program(&t.image, &params).expect("field-ops decodes");
    assert!(config.is_recursion());
    let program = Program {
        image: t.image.clone(),
        tables,
        config,
    };
    (t, program)
}

/// Slots 1-4 at fixed values, the lookup slots, and for a field window its
/// derived slot 5.
fn challenges(a: &CircuitArtifact, window: Option<u32>) -> ExternalChallenges {
    let mut ch = ExternalChallenges::new();
    for (slot, value) in [
        (challenge_slot::MEM_GAMMA, 3u64),
        (challenge_slot::MEM_ALPHA_ADDR, 5),
        (challenge_slot::MEM_ALPHA_TS, 7),
        (challenge_slot::MEM_ALPHA_VAL, 11),
    ] {
        ch.insert(slot, Fr::from_u64(value));
    }
    if let Some(w) = window {
        ch = gkr_verify::field_window_challenges(&ch, w, a.trace_vars);
    }
    insert_lookup_challenges(&mut ch, Fr::from_u64(13), Fr::from_u64(17), a);
    ch
}

/// One row of a column set as a witness row of `a`, its scratch computed
/// row-locally by the engine's own gate kernel; a committed column the fill
/// does not write — a multiplicity — reads 0, which no relation reads.
fn witness_row(
    a: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    row: usize,
    ch: &ExternalChallenges,
) -> checker::WitnessRow {
    let committed: Vec<Fr> = a
        .committed()
        .into_iter()
        .map(|address| {
            columns
                .iter()
                .find(|(at, _)| *at == address)
                .map_or(Fr::ZERO, |(_, c)| c.get(row))
        })
        .collect();
    let virtuals: Vec<Fr> = a
        .virtuals
        .iter()
        .map(|(k, _)| virtual_at_row(*k, row))
        .collect();
    let mut scratch = vec![Fr::ZERO; a.scratch.len()];
    let mut lower = committed.clone();
    for k in 0..a.depth() {
        if a.layers[k].halving {
            break;
        }
        let v: &[Fr] = if k == 0 { &virtuals } else { &[] };
        let values = gate_values(a, k, &lower, &[], v, ch);
        let produced = values[..a.layers[k].producing.len()].to_vec();
        for (j, value) in produced.iter().enumerate() {
            let address = PolyAddress::Inner {
                layer: k as u32 + 1,
                offset: j as u32,
            };
            if let Some(slot) = a.scratch.iter().position(|s| s.address == address) {
                scratch[slot] = *value;
            }
        }
        lower = produced;
    }
    checker::WitnessRow {
        committed,
        row,
        scratch,
    }
}

/// The value of the producing relation `name` on `w`: a leaf's is
/// `define_<leaf>`.
fn relation(a: &CircuitArtifact, w: &checker::WitnessRow, name: &str) -> Fr {
    let r = a
        .relations
        .iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no relation {name}"));
    w.scratch[r
        .output
        .unwrap_or_else(|| panic!("{name} produces nothing")) as usize]
}

/// The field accesses' names in each family, in leaf order.
fn field_accesses(f: u32) -> Vec<String> {
    match f {
        family::FR_OP => ["a", "b", "d"].map(String::from).to_vec(),
        family::P2_FIELD => {
            let mut out: Vec<String> = (0..3).map(|i| format!("state{i}")).collect();
            out.extend(["x".to_string(), "y".to_string()]);
            out.extend((0..3).map(|i| format!("next{i}")));
            out
        }
        family::FIELD_IO => vec!["cell".to_string()],
        _ => unreachable!(),
    }
}

/// Every relation and every range obligation holds on every live row and a
/// padding row of the three families' shards, and the field leaves they
/// evaluate cancel against the field window's.
#[test]
fn the_field_families_hold_and_the_field_memory_balances() {
    let (t, program) = setup();
    let (mut reads, mut writes) = (Fr::ONE, Fr::ONE);
    for f in [family::FR_OP, family::P2_FIELD, family::FIELD_IO] {
        let name = program::family_name(f);
        let trace = t
            .traces
            .delegation(f)
            .expect("a declared family has a buffer");
        let src = ShardSource {
            program: &program,
            input: &[],
            advice: &[],
            rows: ShardRows::Invocations(FrameSlice::shard(trace, 0, 1 << VARS)),
            index: 0,
            height: 1 << VARS,
            window: 0,
        };
        let columns =
            family_fill(f).expect("a fill")(&src).unwrap_or_else(|e| panic!("{name}: {e}"));
        let a = recursion_circuit(f, VARS).expect("the circuit").artifact;
        let ch = challenges(&a, None);
        for row in 0..=trace.len() {
            let w = witness_row(&a, &columns, row, &ch);
            let broken = checker::violated_relations(&a, &w, &ch);
            assert!(broken.is_empty(), "{name} row {row} breaks {broken:?}");
            let out = checker::violated_lookups(&a, &w);
            assert!(
                out.is_empty(),
                "{name} row {row} leaves {out:?} out of range"
            );
            if row < trace.len() {
                for access in field_accesses(f) {
                    reads *= relation(&a, &w, &format!("define_read_{access}"));
                    writes *= relation(&a, &w, &format!("define_write_{access}"));
                }
            }
        }
    }
    // The window: teardown on the read side, init on the write side.
    let state = t.log.state();
    assert_eq!(state.field_windows(1 << WINDOW_VARS), 1);
    let src = ShardSource {
        program: &program,
        input: &[],
        advice: &[],
        rows: ShardRows::Window(state),
        index: 0,
        height: 1 << WINDOW_VARS,
        window: 0,
    };
    let columns = family_fill(family::FIELD_WINDOWS).expect("a fill")(&src).expect("it fills");
    let a = recursion_circuit(family::FIELD_WINDOWS, WINDOW_VARS)
        .expect("the circuit")
        .artifact;
    let ch = challenges(&a, Some(0));
    for row in 0..1 << WINDOW_VARS {
        let w = witness_row(&a, &columns, row, &ch);
        reads *= relation(&a, &w, "define_teardown");
        writes *= relation(&a, &w, "define_init");
    }
    assert_eq!(reads, writes, "the field memory's tuples do not cancel");
}
