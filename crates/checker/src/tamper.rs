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
use verifier::{verify_block, verify_shard, PublicInputs, ShardProof, VerifyError};
use verifier_core::{statement_shards, BlockProof};

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
        let (proofs, public) = self.reprove(tamper);
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

    /// Prove the statement again with `tamper` applied and verify the whole
    /// **block**: the verdict of `verifier::verify_block`.
    ///
    /// S20's additive hook, and what a linkage twin needs that [`run`] cannot
    /// give it. `run` verifies one shard, so a tamper whose only symptom is
    /// the cross-shard read/write root product — one delegation invocation
    /// dropped, say — reaches no check there: step 10b is the statement's, not
    /// a shard's (`docs/spec/block-proof.md` §3). A block reads every shard's
    /// roots against the boundary at once, which is where such a tamper lands.
    ///
    /// [`run`]: TamperHarness::run
    pub fn run_block(&self, tamper: &Tamper) -> Result<(), VerifyError> {
        let (proofs, public) = self.reprove(tamper);
        let block = BlockProof {
            config: self.setup.vk.config.clone(),
            statement: public.clone(),
            shards: proofs,
        };
        block
            .shape()
            .unwrap_or_else(|e| panic!("the reassembled block is not a block: {e}"));
        verify_block(&self.setup.vk, &block, &public)
    }

    /// Assert [`run_block`] refuses with `expected`'s class.
    ///
    /// [`run_block`]: TamperHarness::run_block
    pub fn assert_block_rejects(&self, tamper: &Tamper, expected: VerifyError) {
        match self.run_block(tamper) {
            Err(e) if same_class(&e, &expected) => {}
            other => {
                panic!("expected a {expected:?}-class block refusal of {tamper:?}, got {other:?}")
            }
        }
    }

    /// Assert [`run_block`] still verifies.
    ///
    /// [`run_block`]: TamperHarness::run_block
    pub fn assert_block_verifies(&self, tamper: &Tamper) {
        if let Err(e) = self.run_block(tamper) {
            panic!("expected {tamper:?} to still verify as a block, got {e:?}");
        }
    }

    /// The statement re-proved with `tamper` applied: every shard's proof, in
    /// statement order, and the public inputs they were proved against.
    fn reprove(&self, tamper: &Tamper) -> (Vec<ShardProof>, PublicInputs) {
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
        (proofs, public)
    }
}

// ---------------------------------------------------------------------------
// The delegation anchor's twins
// ---------------------------------------------------------------------------

/// What one delegation family's anchor twins need to know: which shards, which
/// rows, and the columns the three request-side zeroings sit on.
///
/// Frozen at S21 for every delegation family (`docs/spec/delegation.md` §5.2);
/// S22 and S23 fill it with their own addresses and call
/// [`assert_anchor_twins_refused`]. Nothing here is keccak's: the anchor is one
/// mechanism, and a family that wrote its own would be a family whose pairing
/// nobody had argued.
#[derive(Clone, Copy, Debug)]
pub struct AnchorTwins {
    /// The family that owns ecall cycles, and the shard holding the requests.
    pub requester: (FamilyId, u32),
    /// The delegation family, and the shard holding its invocations.
    pub delegation: (FamilyId, u32),
    /// A live request row, and the invocation row that pairs with it — the one
    /// at the same cycle and the same frame base.
    pub request: usize,
    pub invocation: usize,
    /// A second live request row, whose mirror write the replay twin chains to.
    pub other_request: usize,
    /// `rd_selected`: the value the requesting row writes to `rd`, which a
    /// delegation request must not write. Zeroing one.
    pub rd_selected: PolyAddress,
    /// The requesting shard's cycle column, `M[0]`.
    pub cycle: PolyAddress,
    /// The mirror query's read timestamp. Zeroing two.
    pub mirror_read_ts: PolyAddress,
    /// The mirror query's read value. Zeroing three.
    pub mirror_read_value: PolyAddress,
    /// The mirror query's write value, which the invocation's teardown reads.
    pub mirror_write_value: PolyAddress,
    /// The delegation family's row mask, and the value its teardown consumes.
    pub live: PolyAddress,
    pub anchor_value: PolyAddress,
}

/// The four anchor twins and their control (S21 must-be-exact 3).
///
/// **Each twin is run at the level that names what refuses it**, and the two
/// levels answer differently on purpose. `verify_block` runs
/// `verify_global_memory` **before** any shard's own checks
/// (`docs/spec/block-proof.md` §3), so at block level a forgery that unbalances
/// the multiset is `MemoryArgument` whatever else is also wrong;
/// `verify_shard`'s order puts `Constraint` first, so at shard level the same
/// witness names the gate. A twin that asserted `Constraint` at block level
/// would be asserting something false — and did, until this run.
///
/// 1. **A request with no invocation**, at block level. The invocation's row is
///    switched off, so its answer tuple is not written and the request's read
///    of it matches nothing. `MemoryArgument`, and that check reads every
///    shard's roots at once, which is why this twin needs the block.
/// 2. **The same forgery with the anchor side repaired**, at block level: the
///    orphaned request's mirror chained onto another request's write, the way
///    it would chain if the timestamp zeroing were not there. Still
///    `MemoryArgument` — and *why* is the point. Switching an invocation off
///    drops its 50 RAM frame accesses with it, so the word at `base + 4j` loses
///    a write that the next invocation's `read_ts` still names. Repairing the
///    anchor does not repair that, and repairing *that* means re-pointing the
///    next invocation's 50 reads, re-deriving its 1,600 state bits and
///    re-running the permutation — which is proving the execution, not eliding
///    it. So in this family the chain cannot be mounted by editing cells at
///    all, and the multiset is what says so.
/// 3. **Each zeroing alone**, all three, at **shard** level so the gate is the
///    first failure and not the multiset: a request that writes a register, one
///    whose mirror read is stamped, and one whose mirror read carries a value,
///    each `Constraint`. This is the direct evidence that the gates are
///    load-bearing: they make the pairing 1:1 **locally**, without leaning on
///    the RAM side of twin 2. The third is the one an earlier rebuild dropped
///    while restoring the other two, because the headline defect named only the
///    timestamp.
///
/// The control is the pair the zeroings leave free — the mirror's write value
/// and the invocation's teardown value, moved **together** — which must still
/// verify as a block, or the twins above would prove nothing about *which*
/// cell matters.
pub fn assert_anchor_twins_refused(h: &TamperHarness, t: &AnchorTwins) {
    let (rf, rs) = t.requester;
    let (df, ds) = t.delegation;
    let cell = |address, row| h.cell(rf, rs, address, row);
    let drop_invocation = Cell {
        family: df,
        shard: ds,
        address: t.live,
        row: t.invocation,
        value: Fr::ZERO,
    };
    let request = |address, value| Cell {
        family: rf,
        shard: rs,
        address,
        row: t.request,
        value,
    };

    // 1: the request has no invocation to pair with.
    h.assert_block_rejects(
        &Tamper {
            cells: vec![drop_invocation],
            ..Tamper::default()
        },
        VerifyError::MemoryArgument(""),
    );

    // 2: and the orphan chains onto another request's write instead, which is
    // what a missing timestamp zeroing would let it do. The anchor side is then
    // consistent and the RAM side is not, so the multiset still refuses it.
    let other_ts = cell(t.cycle, t.other_request) * Fr::from_u64(constants::memory::TS_STEP)
        + Fr::from_u64(constants::delegation::ANCHOR_DELTA);
    h.assert_block_rejects(
        &Tamper {
            cells: vec![
                drop_invocation,
                request(t.mirror_read_ts, other_ts),
                request(
                    t.mirror_read_value,
                    cell(t.mirror_write_value, t.other_request),
                ),
            ],
            ..Tamper::default()
        },
        VerifyError::MemoryArgument(""),
    );

    // 3: each zeroing on its own, at shard level, where `Constraint` precedes
    // `MemoryArgument` and the gate is therefore the answer. Each of these
    // unbalances the multiset too — a stamped mirror read matches no write —
    // so at block level all three would read `MemoryArgument` and say nothing
    // about the gates.
    for (what, address) in [
        ("a request that writes a register", t.rd_selected),
        ("a mirror read with a timestamp", t.mirror_read_ts),
        ("a mirror read with a value", t.mirror_read_value),
    ] {
        let tamper = Tamper {
            cells: vec![request(address, Fr::ONE)],
            ..Tamper::default()
        };
        match h.run(&tamper, t.requester) {
            Err(VerifyError::Constraint { .. }) => {}
            other => panic!("{what} was not refused by a gate: {other:?}"),
        }
    }

    // The control: the one value the anchor leaves free, moved on both sides.
    let free = Fr::from_u64(0x5eed);
    h.assert_block_verifies(&Tamper {
        cells: vec![
            request(t.mirror_write_value, free),
            Cell {
                family: df,
                shard: ds,
                address: t.anchor_value,
                row: t.invocation,
                value: free,
            },
        ],
        ..Tamper::default()
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal's class is its variant, whatever its reason or layer, except
    /// that a `Lookup` must also name the channel.
    #[test]
    fn a_class_is_the_variant_and_a_lookups_channel() {
        use VerifyError::*;
        assert!(same_class(&Statement("a"), &Statement("b")));
        assert!(same_class(&MemoryArgument("a"), &MemoryArgument("b")));
        assert!(same_class(
            &Constraint { layer: 3 },
            &Constraint { layer: 0 }
        ));
        assert!(same_class(&Opening, &Opening));
        assert!(same_class(&Lookup { channel: 1 }, &Lookup { channel: 1 }));
        assert!(!same_class(&Lookup { channel: 0 }, &Lookup { channel: 3 }));
        assert!(!same_class(&Statement("a"), &Malformed("a")));
        assert!(!same_class(&Opening, &MemoryArgument("a")));
    }
}
