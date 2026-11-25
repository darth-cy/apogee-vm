//! The circuit check: an execution's witness held to its circuits before it is
//! proved, committing and proving nothing. `docs/spec/streaming.md` §7
//! specifies it.

use std::fmt;
use std::slice;
use std::time::Instant;

use checker::RowFailure;
use constants::memory::{READ_ROOT, TS_BITS, WRITE_ROOT};
use constants::{family, lookup_channel, transcript_tags};
use constraints::PolyAddress;
use emulator::{EmuError, GuestIo};
use field::{Fp, Fp2};
use gkr::{channel_holds, BaseLayer};
use program::FamilyId;
use prover::{ProverError, ProverSetup, ShardWitness, WitnessError};
use transcript::Transcript;
use verifier_core::{
    check_memory_windows, check_ts_windows, public_io_words, shard_challenges, statement_shards,
    verify_global_memory, GlobalChallenges, ShardRecord, VerifyError, MEMORY_CHALLENGES,
};

/// What a check that passed measured. All of it is a measurement; the
/// verdict is the `Ok`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckReport {
    /// Cycles the execution took.
    pub cycles: u64,
    /// How many shards the statement holds, each one checked.
    pub shards: usize,
    /// The journal, which a proof's statement would carry as its output.
    pub journal: Vec<u8>,
    /// The most shards held at once, at most `max_in_flight`.
    pub peak_in_flight: usize,
    /// The witness pass's wall clock: its execution, every shard's columns
    /// and their check.
    pub witness_ns: u64,
    /// The executor's time inside the witness pass, a part of `witness_ns`.
    pub execute_ns: u64,
    /// Wall clock of the whole call, the untraced run first included.
    pub wall_nanos: u64,
}

/// Why [`check`] refuses: the first thing a proof of the execution would fail
/// on, or the reason there is no execution to prove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckFailure {
    /// The executor stopped the guest: a fatal guest error, or
    /// `EmuError::CycleLimit` once the run passed `max_cycles`.
    Execution(EmuError),
    /// The guest exited with a nonzero status, which no proof covers.
    NonzeroExit { status: u32 },
    /// The prover cannot build the witness: a column, a trace it refuses.
    Prover(ProverError),
    /// A row of a shard breaks its family's circuit: the lowest such row, and
    /// the first relation it breaks there.
    Relation {
        family: FamilyId,
        shard: u32,
        row: usize,
        relation: String,
    },
    /// A LogUp channel of a shard does not balance, with the first tuple no
    /// table row holds — its row and lookup — where there is one; where there
    /// is none, the counts are what is wrong.
    Channel {
        family: FamilyId,
        shard: u32,
        channel: u32,
        unmatched: Option<(usize, String)>,
    },
    /// A public window's column is not the statement's bytes, from `row` on.
    PublicValue {
        family: FamilyId,
        shard: u32,
        row: usize,
    },
    /// The statement breaks a rule the verifier holds it to: its window list,
    /// a shard's time window.
    Statement(&'static str),
    /// The memory multiset does not reconcile with the boundary.
    Memory(&'static str),
    /// A circuit the evaluator cannot read as written: a defect of the core,
    /// never of the input.
    Unsupported { family: FamilyId, detail: String },
}

impl fmt::Display for CheckFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = program::family_name;
        match self {
            CheckFailure::Execution(e) => write!(f, "the execution stops: {e}"),
            CheckFailure::NonzeroExit { status } => write!(
                f,
                "the guest exited {}: only an execution that exits 0 is provable",
                *status as i32
            ),
            CheckFailure::Prover(e) => write!(f, "the prover refuses the execution: {e}"),
            CheckFailure::Relation {
                family,
                shard,
                row,
                relation,
            } => write!(
                f,
                "{} shard {shard}, row {row}: relation `{relation}` does not hold",
                name(*family)
            ),
            CheckFailure::Channel {
                family,
                shard,
                channel,
                unmatched,
            } => {
                let channel = lookup_channel::NAMES[*channel as usize];
                write!(
                    f,
                    "{} shard {shard}: channel `{channel}` does not balance",
                    name(*family)
                )?;
                match unmatched {
                    Some((row, lookup)) => {
                        write!(f, ": `{lookup}` at row {row} is in no table row")
                    }
                    None => write!(f, ": its multiplicities are not the lookups' counts"),
                }
            }
            CheckFailure::PublicValue { family, shard, row } => write!(
                f,
                "{} shard {shard}: the window's word {row} is not the statement's",
                name(*family)
            ),
            CheckFailure::Statement(why) => write!(f, "the statement: {why}"),
            CheckFailure::Memory(why) => write!(f, "the memory argument: {why}"),
            CheckFailure::Unsupported { family, detail } => {
                write!(f, "{}'s circuit cannot be checked: {detail}", name(*family))
            }
        }
    }
}

/// The values a check evaluates every circuit at, in place of the
/// challenges a proof draws after committing: the five memory challenges and
/// the LogUp pair, squeezed from a Poseidon2 transcript over the program
/// identity, the public input and the advice under
/// `transcript_tags::CIRCUIT_CHECK`. The witness is a function of exactly
/// those, so no input can be chosen against the values it is checked at.
struct Drawn {
    memory: [Fp2; MEMORY_CHALLENGES],
    g: Fp2,
    beta: Fp2,
}

impl Drawn {
    fn new(setup: &ProverSetup, io: &GuestIo) -> Drawn {
        let tag = transcript_tags::CIRCUIT_CHECK;
        let mut t = Transcript::new();
        t.append_bytes(tag, &setup.vk.identity.to_bytes());
        t.append_bytes(tag, &io.input);
        t.append_bytes(tag, &io.advice);
        let memory = std::array::from_fn(|_| t.challenge(tag));
        let g = t.challenge(tag);
        let beta = t.challenge(tag);
        Drawn { memory, g, beta }
    }
}

/// A shard checked: what the statement's checks read of it.
struct Checked {
    roots: [Fp2; 2],
    ts_window: [u64; 2],
}

/// Check the execution of `setup`'s program over `io` against every circuit a
/// proof of it would be verified by, without proving it.
///
/// A batch whose proof would fail is refused here, before any proving starts:
/// a run the executor accepts and the circuits reject is a completeness
/// defect of the core, and this is where it is caught. In order:
///
/// 1. the guest runs untraced, stopped past `max_cycles`
///    (`emulator::run_bounded`): a fatal run, a run that never exits and a
///    nonzero exit status are refused before any column exists;
/// 2. it runs again as `prover::prove_block_streaming`'s first pass runs it,
///    under the same cap, the same `max_in_flight` workers bounding the
///    shards held at once, and every shard's columns are filled by the
///    prover's own fills and multiplicities, as its proof would take them
///    (`prover::witness_block_streaming`);
/// 3. each shard as it fills: every row against its family's circuit
///    (`checker::evaluate_rows`), every channel's root pair holding, a public
///    window's column the statement's bytes, its time window in range;
/// 4. the statement: its window list, the shards' time windows, and the
///    memory multiset reconciling over every shard's roots with the register
///    and pc boundary (`verifier_core::verify_global_memory`).
///
/// The challenges are the check's own (`docs/spec/streaming.md` §7). What a
/// proof adds is the commitments and the openings, which an honest prover's
/// columns always pass.
///
/// `max_in_flight` must be at least 1; `prover::DEFAULT_MAX_IN_FLIGHT` is the
/// proving default, and a check holds no shard's inner layers, so the same
/// value costs it far less memory.
pub fn check(
    setup: &ProverSetup,
    io: &GuestIo,
    max_in_flight: usize,
    max_cycles: u64,
) -> Result<CheckReport, CheckFailure> {
    check_edited(setup, io, max_in_flight, max_cycles, &|_| {})
}

/// [`check`], with `edit` applied to every shard's columns before they are
/// checked: the seam the tamper twins below write a cell through.
fn check_edited(
    setup: &ProverSetup,
    io: &GuestIo,
    max_in_flight: usize,
    max_cycles: u64,
    edit: &(dyn Fn(&mut ShardWitness) + Sync),
) -> Result<CheckReport, CheckFailure> {
    let started = Instant::now();
    let execution = emulator::run_bounded(&setup.program.image, io, max_cycles)
        .map_err(CheckFailure::Execution)?;
    if execution.exit_code != 0 {
        return Err(CheckFailure::NonzeroExit {
            status: execution.exit_code as u32,
        });
    }
    let drawn = Drawn::new(setup, io);
    let block =
        prover::witness_block_streaming(setup, io, max_in_flight, max_cycles, |mut shard| {
            edit(&mut shard);
            check_shard(
                setup,
                &drawn,
                &execution.io.input,
                &execution.io.output,
                shard,
            )
        })
        .map_err(|e| match e {
            WitnessError::Execution(e) => CheckFailure::Execution(e),
            WitnessError::Prover(ProverError::NonzeroExit { status }) => {
                CheckFailure::NonzeroExit { status }
            }
            WitnessError::Prover(e) => CheckFailure::Prover(e),
            WitnessError::Work(failure) => failure,
        })?;
    let mut statement = block.statement;
    // One execution, run twice: the streams the shards were checked against
    // are the statement's.
    assert_eq!(
        (&statement.input, &statement.output),
        (&execution.io.input, &execution.io.output),
        "check: the two runs reached different public values"
    );

    let config = &setup.program.config;
    check_memory_windows(config, &statement.shard_counts, &statement.windows)
        .map_err(CheckFailure::Statement)?;
    let records: Vec<ShardRecord> = statement_shards(config, &statement.shard_counts)
        .into_iter()
        .zip(&block.shards)
        .map(|((family, shard_index), checked)| ShardRecord {
            family,
            shard_index,
            ts_window: checked.ts_window,
            roots: checked.roots,
        })
        .collect();
    check_ts_windows(&records).map_err(CheckFailure::Statement)?;
    statement.memory_roots = block.shards.iter().map(|c| c.roots).collect();
    let global = GlobalChallenges {
        memory: drawn.memory,
        digest: Fp2::ZERO,
    };
    verify_global_memory(&setup.vk, &global, &statement).map_err(|e| {
        CheckFailure::Memory(match e {
            VerifyError::MemoryArgument(why) => why,
            _ => "the statement's memory record is refused",
        })
    })?;
    Ok(CheckReport {
        cycles: block.report.cycles,
        shards: block.report.shards,
        journal: statement.output,
        peak_in_flight: block.report.peak_in_flight,
        witness_ns: block.report.pass1_ns,
        execute_ns: block.report.pass1_execute_ns,
        wall_nanos: started.elapsed().as_nanos() as u64,
    })
}

/// One shard against its circuit, `docs/spec/proof.md` §6's steps 4, 7–9 and
/// 10c over its columns rather than a proof of them.
fn check_shard(
    setup: &ProverSetup,
    drawn: &Drawn,
    input: &[u8],
    output: &[u8],
    shard: ShardWitness,
) -> Result<Checked, CheckFailure> {
    let ShardWitness {
        family,
        index,
        columns,
        windows,
    } = shard;
    let circuit = &setup
        .families
        .iter()
        .find(|f| f.family == family)
        .expect("the witness pass fills only registered families")
        .circuit;
    let artifact = &circuit.artifact;
    let unsupported = |detail: String| CheckFailure::Unsupported { family, detail };
    let base = BaseLayer::new(columns);
    let challenges = shard_challenges(circuit, index, &windows, &drawn.memory, drawn.g, drawn.beta);

    // Steps 7 and 8: every row against the circuit, and its outputs.
    let outputs = checker::evaluate_rows(artifact, &base, &challenges).map_err(|e| match e {
        RowFailure::Relation { row, relation } => CheckFailure::Relation {
            family,
            shard: index,
            row,
            relation,
        },
        RowFailure::Shape(detail) => unsupported(detail),
    })?;
    if outputs.len() != 2 + 2 * circuit.channels.len() {
        return Err(unsupported(format!(
            "{} outputs for two roots and {} channels",
            outputs.len(),
            circuit.channels.len()
        )));
    }

    // Step 9: each channel's root pair, after the two memory roots, in
    // channel order. One that does not hold is named by the independent
    // native sum, which finds the tuple no table row holds.
    for (j, spec) in circuit.channels.iter().enumerate() {
        if !channel_holds((outputs[2 + 2 * j], outputs[3 + 2 * j])) {
            let unmatched =
                checker::channel_sums(artifact, &base, slice::from_ref(spec), &challenges)
                    .ok()
                    .and_then(|sums| sums.into_iter().next())
                    .and_then(|sum| sum.unmatched.into_iter().next());
            return Err(CheckFailure::Channel {
                family,
                shard: index,
                channel: spec.channel,
                unmatched,
            });
        }
    }

    // Step 10c: a public window's value column is the statement's string,
    // word for word.
    let public = match family {
        family::PUBLIC_INPUT => Some((2, input)),
        family::PUBLIC_OUTPUT => Some((1, output)),
        _ => None,
    };
    if let Some((slot, bytes)) = public {
        let column = base
            .get(PolyAddress::Memory(slot))
            .ok_or_else(|| unsupported(format!("no value column M[{slot}]")))?;
        let words = public_io_words(bytes);
        if words.len() != column.len() {
            return Err(unsupported(format!(
                "{} words for a window of {} rows",
                words.len(),
                column.len()
            )));
        }
        if let Some(row) =
            (0..words.len()).find(|&y| column.get_base(y) != Fp::from_u64(words[y] as u64))
        {
            return Err(CheckFailure::PublicValue {
                family,
                shard: index,
                row,
            });
        }
    }

    // Step 4: the window the shard's proof would claim.
    let ts_window = prover::ts_window(family, &base);
    if ts_window[0] > ts_window[1] || ts_window[1] > 1 << TS_BITS {
        return Err(CheckFailure::Statement(
            "a shard's time window is not within the clock",
        ));
    }
    Ok(Checked {
        roots: [outputs[READ_ROOT], outputs[WRITE_ROOT]],
        ts_window,
    })
}

#[cfg(test)]
mod tests;
