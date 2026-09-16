//! The tamper-twin harness, S16: re-prove a statement with a witness or a
//! boundary changed, as an honest prover would prove the changed witness, and
//! verify one shard of it through `verifier::verify_shard`.
//!
//! "As an honest prover would" is the whole method. A tampered cell is written
//! into the columns the honest fill produced; each channel's multiplicities are
//! then recounted over the tampered columns, **channel by channel**, unless that
//! channel's multiplicity column is itself tampered or its recount is
//! impossible — a tuple its table does not hold — in which case that channel
//! keeps its honest counts and every other channel is still recounted; a memory
//! column's change is recommitted in a new global commit phase; and every shard
//! of the new statement is proved again.
//! So the proof that reaches the verifier is the best one the tampered witness
//! has, and the class of the check that refuses it is the class of what the
//! tamper broke (`docs/spec/shard-proof.md` §6). A tamper that breaks nothing
//! verifies, and the harness says so.

use std::mem::discriminant;
use std::slice;

use constraints::PolyAddress;
use field::Fr;
use gkr_verify::BoundaryFinals;
use poly::{MultilinearPoly, PolyBacking};
use program::FamilyId;
use prover::{
    global_commit_phase, prove_shard_columns, public_inputs, shard_columns, statement_inputs,
    GlobalCommitState, ProverSetup, ProvingContext, StatementInputs,
};
use trace::{build_multiplicities, TraceArchive};
use verifier::{verify_shard, PublicInputs, ShardProof, VerifyError};
use verifier_core::statement_shards;

/// One committed cell of one shard, and the value it is set to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub family: FamilyId,
    pub shard: u32,
    pub address: PolyAddress,
    pub row: usize,
    pub value: Fr,
}

/// A tamper: cells rewritten in the witness, and optionally the statement's
/// boundary scalars replaced — the public exit status staying the honest one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tamper {
    pub cells: Vec<Cell>,
    pub boundary: Option<BoundaryFinals>,
}

/// An honest statement, proved once, and the means to prove it again changed.
pub struct TamperHarness<'a> {
    setup: &'a ProverSetup,
    archive: &'a TraceArchive,
    inputs: StatementInputs,
    global: GlobalCommitState,
    proofs: Vec<ShardProof>,
    public: PublicInputs,
}

/// `column` with `row` set to `value`.
fn with_cell(column: &MultilinearPoly, row: usize, value: Fr) -> MultilinearPoly {
    let mut values: Vec<Fr> = (0..column.len()).map(|i| column.get(i)).collect();
    values[row] = value;
    MultilinearPoly::new(PolyBacking::Fr(values))
}

impl<'a> TamperHarness<'a> {
    /// Prove `archive`'s statement honestly, and assert every shard of it
    /// verifies: a harness whose honest twin fails can tell nothing apart.
    pub fn new(setup: &'a ProverSetup, archive: &'a TraceArchive) -> TamperHarness<'a> {
        let inputs = statement_inputs(setup, archive).unwrap_or_else(|e| panic!("{e}"));
        let (global, proofs, public) = prove_all(setup, archive, &inputs, &[], true, None);
        for p in &proofs {
            assert_eq!(
                verify_shard(&setup.vk, p, &public),
                Ok(()),
                "the honest twin of shard ({}, {}) verifies",
                p.family,
                p.shard_index
            );
        }
        TamperHarness {
            setup,
            archive,
            inputs,
            global,
            proofs,
            public,
        }
    }

    /// The honest statement and its proofs, in statement order.
    pub fn honest(&self) -> (&PublicInputs, &[ShardProof]) {
        (&self.public, &self.proofs)
    }

    /// An honest cell's value, as the fill wrote it.
    pub fn cell(&self, family: FamilyId, shard: u32, address: PolyAddress, row: usize) -> Fr {
        let windows = &self.inputs.windows;
        let columns = shard_columns(self.setup, self.archive, family, shard, windows)
            .unwrap_or_else(|e| panic!("{e}"));
        columns
            .iter()
            .find(|(a, _)| *a == address)
            .unwrap_or_else(|| panic!("shard ({family}, {shard}) has no {address}"))
            .1
            .get(row)
    }

    /// Prove the statement again with `tamper` applied, and verify shard
    /// `target` of it through `verify_shard`: the verdict.
    pub fn run(&self, tamper: &Tamper, target: (FamilyId, u32)) -> Result<(), VerifyError> {
        let global_changes = tamper.boundary.is_some()
            || tamper
                .cells
                .iter()
                .any(|c| matches!(c.address, PolyAddress::Memory(_)));
        let (_, proofs, public) = if global_changes {
            let mut inputs = self.inputs.clone();
            if let Some(b) = tamper.boundary {
                inputs.boundary = b;
            }
            let shards = statement_shards(&self.setup.vk.config, &inputs.shard_counts);
            for c in &tamper.cells {
                let PolyAddress::Memory(i) = c.address else {
                    continue;
                };
                let at = position(&shards, (c.family, c.shard));
                let column = &mut inputs.memory_columns[at][i as usize];
                *column = with_cell(column, c.row, c.value);
            }
            prove_all(self.setup, self.archive, &inputs, &tamper.cells, true, None)
        } else {
            let honest = (self.global.clone(), self.proofs.clone());
            prove_all(
                self.setup,
                self.archive,
                &self.inputs,
                &tamper.cells,
                false,
                Some(honest),
            )
        };
        let shards = statement_shards(&self.setup.vk.config, &public.shard_counts);
        verify_shard(&self.setup.vk, &proofs[position(&shards, target)], &public)
    }

    /// Assert `run` refuses with `expected`'s class: its variant, whatever the
    /// reason or layer — except a `Lookup`, whose channel must be `expected`'s
    /// too, since which table refuses a tamper is what a lookup twin is about.
    pub fn assert_rejects(&self, tamper: &Tamper, target: (FamilyId, u32), expected: VerifyError) {
        match self.run(tamper, target) {
            Err(e) if same_class(&e, &expected) => {}
            other => panic!("expected a {expected:?}-class refusal of {tamper:?}, got {other:?}"),
        }
    }

    /// Assert `run` still verifies: the tamper changed nothing validity sees.
    pub fn assert_verifies(&self, tamper: &Tamper, target: (FamilyId, u32)) {
        if let Err(e) = self.run(tamper, target) {
            panic!("expected {tamper:?} to still verify, got {e:?}");
        }
    }
}

/// `assert_rejects`' comparison: the variant, and a `Lookup`'s channel.
fn same_class(e: &VerifyError, expected: &VerifyError) -> bool {
    match expected {
        VerifyError::Lookup { .. } => e == expected,
        _ => discriminant(e) == discriminant(expected),
    }
}

fn position(shards: &[(FamilyId, u32)], shard: (FamilyId, u32)) -> usize {
    shards
        .iter()
        .position(|s| *s == shard)
        .unwrap_or_else(|| panic!("the statement has no shard {shard:?}"))
}

/// Every shard of the statement `inputs` describes, proved with `cells`
/// applied; with `recommit` false, `honest` is reused for the global state and
/// for every shard no cell names.
fn prove_all(
    setup: &ProverSetup,
    archive: &TraceArchive,
    inputs: &StatementInputs,
    cells: &[Cell],
    recommit: bool,
    honest: Option<(GlobalCommitState, Vec<ShardProof>)>,
) -> (GlobalCommitState, Vec<ShardProof>, PublicInputs) {
    let (global, old) = match (recommit, honest) {
        (false, Some((global, proofs))) => (global, Some(proofs)),
        _ => (global_commit_phase(&setup.vk, &setup.srs, inputs), None),
    };
    let ctx = ProvingContext {
        setup,
        global: global.clone(),
    };
    let shards = statement_shards(&setup.vk.config, &inputs.shard_counts);
    let mut proofs = Vec::new();
    for (at, &(family, index)) in shards.iter().enumerate() {
        let mine: Vec<&Cell> = cells
            .iter()
            .filter(|c| (c.family, c.shard) == (family, index))
            .collect();
        if let (Some(old), true) = (&old, mine.is_empty()) {
            proofs.push(old[at].clone());
            continue;
        }
        let mut columns = shard_columns(setup, archive, family, index, &inputs.windows)
            .unwrap_or_else(|e| panic!("{e}"));
        for c in &mine {
            let column = columns
                .iter_mut()
                .find(|(a, _)| *a == c.address)
                .unwrap_or_else(|| panic!("shard ({family}, {index}) has no {}", c.address));
            column.1 = with_cell(&column.1, c.row, c.value);
        }
        let circuit = &setup
            .families
            .iter()
            .find(|f| f.family == family)
            .expect("a registered family")
            .circuit;
        // The honest prover's recount over the tampered columns, one channel at
        // a time: a channel whose counts are the tamper keeps them, and one
        // whose table does not hold a tampered tuple has no count and keeps its
        // honest one — neither stops another channel's recount.
        for spec in &circuit.channels {
            if mine.is_empty() || mine.iter().any(|c| c.address == spec.multiplicity) {
                continue;
            }
            let Ok(recount) =
                build_multiplicities(&circuit.artifact, &columns, slice::from_ref(spec))
            else {
                continue;
            };
            for (address, column) in recount {
                let slot = columns
                    .iter_mut()
                    .find(|(a, _)| *a == address)
                    .expect("a count");
                slot.1 = column;
            }
        }
        proofs.push(prove_shard_columns(&ctx, family, index, columns).0);
    }
    let public = public_inputs(&global, &proofs);
    (global, proofs, public)
}
