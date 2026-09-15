//! The memory artifacts under the checker: `memory_roots`, the root self-check
//! hook of `docs/spec/memory.md` §1, agrees with a forwarded window and fails
//! when a row under a root changes; the three artifacts keep the laws, the
//! lookup rules and the padding contract, the frame its product-tree clause;
//! and an honest statement over a committed guest — its frame, its RAM windows
//! and its boundary, filled by `trace`'s builders from a real execution — keeps
//! every gate and every obligation, reconciles, and proves.

use checker::{
    check_laws, check_padding, check_padding_identity, memory_roots, violated_lookups, WitnessRow,
};
use constants::challenge_slot::{MEM_ALPHA_VAL, MEM_GAMMA};
use constants::{family, transcript_tags};
use constraints::memory::{
    frame, frame_artifact, image_window_artifact, zero_window_artifact, CYCLE, FRAME_QUERIES,
};
use constraints::{CircuitArtifact, PolyAddress};
use emulator::{trace_run, GuestIo};
use field::Fr;
use gkr::{
    boundary_factors, forward, prove, reconciles, self_check, verify, window_challenges, BaseLayer,
    ExternalChallenges, GkrError, LayerValues, OutputClaims,
};
use loader::{load_elf, ProgramImage};
use poly::{MultilinearPoly, PolyBacking};
use program::{check_memory_windows, decode_program, ProgramParams, VmConfig};
use sumcheck::{absorb_witness_digest, witness_digest};
use test_support::Rng;
use trace::{
    build_boundary_finals, build_frame_witness, build_init_teardown_columns, build_memory_columns,
    init_windows, plan_shards, CycleProfile, FamilyTraces, MemoryEventLog, ROLES,
};
use transcript::Transcript;

/// A forwarded artifact over random columns and random slots 1–4, plus slot 5
/// for window 9.
fn forwarded(a: &CircuitArtifact, seed: u64) -> LayerValues {
    let mut rng = Rng::new(seed);
    let rows = 1usize << a.trace_vars;
    let mut memory = ExternalChallenges::new();
    for slot in MEM_GAMMA..=MEM_ALPHA_VAL {
        memory.insert(slot, Fr::from_u64(rng.next_u64()));
    }
    let columns = a
        .committed()
        .into_iter()
        .map(|address| {
            let column = (0..rows).map(|_| Fr::from_u64(rng.next_u64())).collect();
            (address, MultilinearPoly::new(PolyBacking::Fr(column)))
        })
        .collect();
    let challenges = window_challenges(&memory, 9, a.trace_vars);
    forward(a, &BaseLayer::new(columns), &challenges)
}

type Constructor = fn(u32) -> CircuitArtifact;

/// Each artifact at `trace_vars` 4 beside the layer its first halving list
/// reads: layer 1 for a window, whose leaves it halves at once, and layer 4
/// for the frame, above its three row-wise lists.
const HALVING_INPUTS: [(&str, Constructor, usize); 2] = [
    ("zero window", zero_window_artifact, 1),
    ("frame", frame_artifact, 4),
];

/// On a forwarded artifact the roots are the top's two values and the
/// products of layer `k`'s columns 0 and 1, written out here. Kills a hook
/// that reads any layer but the first halving list's input.
#[test]
fn memory_roots_agrees_with_a_forwarded_artifact() {
    for (label, construct, k) in HALVING_INPUTS {
        let a = construct(4);
        let values = forwarded(&a, 0x5714_3201);
        let top = values.layers.last().expect("a top layer");
        let product =
            |j: usize| (0..16).fold(Fr::ONE, |acc, y| acc * values.layers[k - 1][j].get(y));
        assert_eq!(
            memory_roots(&a, &values),
            Ok((top[0].get(0), top[1].get(0))),
            "{label}"
        );
        assert_eq!(
            memory_roots(&a, &values),
            Ok((product(0), product(1))),
            "{label}"
        );
    }
}

/// One row under a root changed in `LayerValues`, the top left as it was:
/// refused. The same for the write side, on both artifacts. Kills a hook that
/// reads the roots off the top without recomputing them.
#[test]
fn memory_roots_refuses_a_changed_row_under_a_root() {
    for (label, construct, k) in HALVING_INPUTS {
        let a = construct(4);
        for j in 0..2 {
            let mut values = forwarded(&a, 0x5714_3202);
            let column = &values.layers[k - 1][j];
            let mut rows: Vec<Fr> = (0..column.len()).map(|y| column.get(y)).collect();
            rows[3] += Fr::ONE;
            values.layers[k - 1][j] = MultilinearPoly::new(PolyBacking::Fr(rows));
            let e = memory_roots(&a, &values).unwrap_err();
            assert!(
                e.contains(&format!("layer {k}'s column {j}")),
                "{label}: {e}"
            );
        }
    }
}

/// The halving input replaced by one-row columns holding the roots themselves,
/// whose products are the top: refused by height. A layer list of the wrong
/// depth is refused too. Kills a hook that takes the column heights from
/// `values` rather than from the artifact.
#[test]
fn memory_roots_refuses_a_layer_of_the_wrong_height_or_depth() {
    let a = zero_window_artifact(4);
    let mut values = forwarded(&a, 0x5714_3204);
    let top: Vec<Fr> = values
        .layers
        .last()
        .expect("a top")
        .iter()
        .map(|c| c.get(0))
        .collect();
    values.layers[0] = top
        .iter()
        .map(|root| MultilinearPoly::new(PolyBacking::Fr(vec![*root])))
        .collect();
    assert_eq!(
        memory_roots(&a, &values),
        Err("memory roots: layer 1's column 0 has 1 rows, not 16".to_string())
    );

    let mut values = forwarded(&a, 0x5714_3204);
    values.layers.remove(1);
    assert_eq!(
        memory_roots(&a, &values),
        Err("memory roots: 4 layers are materialized, and the artifact has 5".to_string())
    );
}

#[test]
fn memory_roots_refuses_an_artifact_with_no_halving_list() {
    let a = zero_window_artifact(4);
    let values = forwarded(&a, 0x5714_3203);
    let mut row_wise = a.clone();
    row_wise.layers.truncate(1);
    assert_eq!(
        memory_roots(&row_wise, &values),
        Err("memory roots: the artifact has no halving list".to_string())
    );
}

/// The checker's own laws, lookup rules and padding contract hold on all three
/// constructors — the `zero_row_valid` each computes included — and the
/// frame, an execution family's subtree whose shards have inactive rows, keeps
/// the product-tree clause.
#[test]
fn the_memory_artifacts_keep_the_laws_and_the_padding_contract() {
    for (label, a) in [
        ("frame", frame_artifact(6)),
        ("image window", image_window_artifact(6)),
        ("zero window", zero_window_artifact(6)),
    ] {
        assert_eq!(check_laws(&a), Ok(()), "{label}");
        assert_eq!(check_padding(&a), Ok(()), "{label}");
    }
    assert_eq!(check_padding_identity(&frame_artifact(6)), Ok(()));
}

// ---------------------------------------------------------------------------
// An honest statement over a committed guest
// ---------------------------------------------------------------------------

/// Every family's height: the init families' `h`, and tall enough for every
/// instruction table of every committed guest but `consistency`.
const HEIGHT: u32 = 1 << 16;

/// The guests, each on the input `crates/emulator/tests/common` runs it on:
/// fib's is `fib_io.txt`'s `n = 24`, heap's 40.
const GUESTS: [(&str, u32); 2] = [("fib", 24), ("heap", 40)];

/// One committed guest, decoded at `HEIGHT` and traced to its exit: what a
/// statement's memory shards are built from.
struct Traced {
    image: ProgramImage,
    config: VmConfig,
    traces: FamilyTraces,
    log: MemoryEventLog,
    profile: CycleProfile,
    /// `1..=n`, every cycle the execution ran.
    cycles: Vec<u64>,
}

/// The ELF is `crates/loader/tests/vectors`', pinned by digest in that crate's
/// suite.
fn traced(name: &str, input: u32) -> Traced {
    let path = format!(
        "{}/../loader/tests/vectors/{name}.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    let elf = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let image = load_elf(&elf).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let params = ProgramParams {
        heights: [HEIGHT; family::COUNT as usize],
        ..ProgramParams::defaults()
    };
    let (tables, config) =
        decode_program(&image, &params).unwrap_or_else(|e| panic!("{name}: {e}"));
    let io = GuestIo {
        input: input.to_le_bytes().to_vec(),
        hint: Vec::new(),
    };
    let (traces, log, profile, execution) =
        trace_run(&image, &io, &tables, &config).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(execution.exit_code, 0, "{name}");
    Traced {
        image,
        config,
        traces,
        log,
        profile,
        cycles: (1..=execution.cycle_count).collect(),
    }
}

/// Slots 1–4, drawn from a fresh transcript that binds nothing. S16's global
/// transcript owns the real schedule — the statement, every memory column's
/// commitment and the boundary absorbed before the squeeze
/// (`docs/spec/memory.md` §6.1). Here they are only values no trace was chosen
/// against.
fn memory_challenges() -> ExternalChallenges {
    let mut t = Transcript::new();
    let mut memory = ExternalChallenges::new();
    for slot in MEM_GAMMA..=MEM_ALPHA_VAL {
        memory.insert(
            slot,
            t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE),
        );
    }
    memory
}

/// One memory shard: its artifact, its base and the challenges its gates read.
struct Shard {
    label: String,
    artifact: CircuitArtifact,
    base: BaseLayer,
    challenges: ExternalChallenges,
}

/// A frame shard over `cycles`, in the order given, at `height` rows.
fn frame_shard(t: &Traced, cycles: &[u64], height: usize, memory: &ExternalChallenges) -> Shard {
    let mut columns = build_memory_columns(&t.log, cycles, height);
    columns.extend(build_frame_witness(&t.log, cycles, height));
    Shard {
        label: "frame".to_string(),
        artifact: frame_artifact(height.trailing_zeros()),
        base: BaseLayer::new(columns),
        challenges: memory.clone(),
    }
}

/// Every memory shard of `t`'s statement: the frame, one shard over every
/// cycle at the smallest power-of-two height holding them; then its windows.
fn shards(t: &Traced, memory: &ExternalChallenges) -> Vec<Shard> {
    let height = t.cycles.len().next_power_of_two();
    let mut out = vec![frame_shard(t, &t.cycles, height, memory)];
    out.extend(window_shards(t, memory));
    out
}

/// `t`'s window shards at `HEIGHT`: `INIT_TEARDOWN`, window 0, and one
/// `ZERO_WINDOWS` shard per id of `init_windows`.
fn window_shards(t: &Traced, memory: &ExternalChallenges) -> Vec<Shard> {
    let mut out = Vec::new();
    let vars = HEIGHT.trailing_zeros();
    let window = |w: u32, artifact: CircuitArtifact| Shard {
        label: format!("window {w}"),
        artifact,
        base: BaseLayer::new(build_init_teardown_columns(
            &t.log,
            &t.image,
            w,
            HEIGHT as usize,
        )),
        challenges: window_challenges(memory, w, vars),
    };
    out.push(window(0, image_window_artifact(vars)));
    let zero = zero_window_artifact(vars);
    for w in init_windows(&t.log, HEIGHT) {
        out.push(window(w, zero.clone()));
    }
    out
}

/// A shard's committed columns, in layout order.
fn committed(shard: &Shard) -> Vec<MultilinearPoly> {
    let columns = shard.artifact.committed().into_iter();
    let column = |a| shard.base.get(a).expect("a committed column").clone();
    columns.map(column).collect()
}

/// Prove `values` and verify the proof, each on a fresh transcript bound to
/// the committed columns' witness digest as S13's harness binds a base, then
/// discharge every base claim against its column.
fn prove_and_verify(shard: &Shard, values: &LayerValues) -> Result<(), GkrError> {
    let digest = witness_digest(&committed(shard));
    let bound = || {
        let mut t = Transcript::new();
        absorb_witness_digest(&mut t, digest);
        t
    };
    let a = &shard.artifact;
    let proof = prove(a, values, &shard.challenges, &mut bound());
    let top = values.layers.last().expect("a top layer");
    let tables = a.outputs.iter().map(|out| match *out {
        PolyAddress::Inner { offset, .. } => top[offset as usize].clone(),
        other => panic!("an output is an inner address, not {other}"),
    });
    let outputs = OutputClaims {
        tables: tables.collect(),
    };
    let claims = verify(a, &proof, &outputs, &shard.challenges, &mut bound())?;
    for claim in claims {
        let column = shard.base.get(claim.address).expect("a committed column");
        let label = &shard.label;
        assert_eq!(
            column.evaluate(&claim.point),
            claim.value,
            "{label}: {}",
            claim.address
        );
    }
    Ok(())
}

/// The honest statement of a committed guest: every shard's forward pass keeps
/// every gate, and its roots are what `memory_roots` recomputes; the frame
/// keeps every obligation on every row, live and padding, and the checker's
/// laws and padding contract; the window list keeps the verifier's rules; the
/// roots reconcile with the boundary `build_boundary_finals` fills at the
/// image's entry pc; and every window shard proves and verifies, and the frame
/// when `prove_frame` says so.
fn honest_statement(name: &str, input: u32, prove_frame: bool) {
    let t = traced(name, input);
    let memory = memory_challenges();
    let shards = shards(&t, &memory);
    let (mut reads, mut writes) = (Vec::new(), Vec::new());
    for (i, shard) in shards.iter().enumerate() {
        let (a, label) = (&shard.artifact, &shard.label);
        let values = forward(a, &shard.base, &shard.challenges);
        assert_eq!(
            self_check(a, &values, &shard.challenges),
            Ok(()),
            "{name} {label}"
        );
        let (read, write) =
            memory_roots(a, &values).unwrap_or_else(|e| panic!("{name} {label}: {e}"));
        reads.push(read);
        writes.push(write);
        if i > 0 || prove_frame {
            assert_eq!(prove_and_verify(shard, &values), Ok(()), "{name} {label}");
        }
    }

    let frame = &shards[0];
    assert_eq!(check_laws(&frame.artifact), Ok(()), "{name}");
    assert_eq!(check_padding(&frame.artifact), Ok(()), "{name}");
    assert_eq!(check_padding_identity(&frame.artifact), Ok(()), "{name}");
    let columns = committed(frame);
    let rows = columns[0].len();
    assert!(t.cycles.len() < rows, "{name}: the frame has a padding row");
    for row in 0..rows {
        let w = WitnessRow {
            committed: columns.iter().map(|c| c.get(row)).collect(),
            row,
            scratch: Vec::new(),
        };
        assert_eq!(
            violated_lookups(&frame.artifact, &w),
            Vec::<String>::new(),
            "{name}: frame row {row}"
        );
    }

    let windows = init_windows(&t.log, HEIGHT);
    let counts: Vec<u32> = plan_shards(&t.profile, &t.config)
        .shards
        .iter()
        .map(|(f, n)| match *f {
            family::INIT_TEARDOWN => 1,
            family::ZERO_WINDOWS => windows.len() as u32,
            _ => *n,
        })
        .collect();
    check_memory_windows(&t.config, &counts, &windows).unwrap_or_else(|e| panic!("{name}: {e}"));

    let factors = boundary_factors(&memory, t.image.entry, &build_boundary_finals(&t.log));
    assert!(reconciles(&reads, &writes, factors), "{name}");
}

/// fib's 2,117 cycles: a 2^12-row frame, window 0 and the stack window 8191,
/// every one proved.
#[test]
fn fib_honest_statement_reconciles_and_proves() {
    honest_statement("fib", 24, true);
}

/// heap's 141,832 cycles: a 2^18-row frame, forwarded and checked row by row
/// but not proved — its proof alone takes a minute in a debug build, and fib's
/// frame proves the same artifact — and its two windows, proved.
#[test]
fn heap_honest_statement_reconciles_and_proves_its_windows() {
    honest_statement("heap", 40, false);
}

/// The statement's frame split as execution-family shards split it: one frame
/// per family that ran, over that family's cycles — not contiguous — with the
/// first family's list reversed, each at the smallest power-of-two height of at
/// least 16. Row `i` holds `cycles[i]`, every shard keeps every gate, and the
/// roots of every frame with the windows' reconcile with the boundary. Kills a
/// builder that files a cycle's row by the cycle's number, or a list sorted,
/// rather than by its place in `cycles`.
#[test]
fn a_frame_per_family_in_any_order_reconciles() {
    for (name, input) in GUESTS {
        let t = traced(name, input);
        let memory = memory_challenges();
        let mut shards = Vec::new();
        for trace in t.traces.families.iter().filter(|f| !f.cycle.is_empty()) {
            let mut cycles = trace.cycle.clone();
            if shards.is_empty() {
                cycles.reverse();
            }
            let height = cycles.len().next_power_of_two().max(16);
            let mut shard = frame_shard(&t, &cycles, height, &memory);
            shard.label = format!("frame of family {}", trace.family);
            let column = shard.base.get(CYCLE).expect("the cycle column");
            for (i, &cycle) in cycles.iter().enumerate() {
                assert_eq!(column.get(i), Fr::from_u64(cycle), "{name}: row {i}");
            }
            shards.push(shard);
        }
        assert!(shards.len() > 1, "{name}: more than one family ran");
        shards.extend(window_shards(&t, &memory));
        let (mut reads, mut writes) = (Vec::new(), Vec::new());
        for shard in &shards {
            let (a, label) = (&shard.artifact, &shard.label);
            let values = forward(a, &shard.base, &shard.challenges);
            assert_eq!(
                self_check(a, &values, &shard.challenges),
                Ok(()),
                "{name} {label}"
            );
            let (read, write) =
                memory_roots(a, &values).unwrap_or_else(|e| panic!("{name} {label}: {e}"));
            reads.push(read);
            writes.push(write);
        }
        let factors = boundary_factors(&memory, t.image.entry, &build_boundary_finals(&t.log));
        assert!(reconciles(&reads, &writes, factors), "{name}");
    }
}

/// `build_memory_columns` against the family buffers, which file each query
/// under its role where the log files it by space and slot: on each guest the
/// row of cycle `c` holds `c`, its pc query `(1, 0, 4(c − 1), pc, next_pc)`,
/// and at query `1 + r` role `ROLES[r]`'s fields with mask 1, or zeros where
/// the cycle lacks it; and the first padding row is 0 in every column. Kills a
/// slot-2 register query filed under another role — which no gate of the frame
/// would notice, the three sharing a space and a slot — and a pc query or a
/// padding row filled otherwise.
#[test]
fn the_frame_columns_are_the_family_buffers() {
    for (name, input) in GUESTS {
        let t = traced(name, input);
        let height = t.cycles.len().next_power_of_two();
        let base = BaseLayer::new(build_memory_columns(&t.log, &t.cycles, height));
        let at = |address, y| base.get(address).expect("a frame column").get(y);
        let mut rows = 0;
        for trace in &t.traces.families {
            for i in 0..trace.len() {
                let row = trace.row(i);
                let pc = [1, 0, 4 * (row.cycle - 1), row.pc as u64, row.next_pc as u64];
                let mut expected = vec![(CYCLE, row.cycle)];
                expected.extend((0..5).map(|f| (frame(0, f), pc[f as usize])));
                for (r, role) in ROLES.iter().enumerate() {
                    let fields = row.query(*role).map_or([0; 5], |q| {
                        let (addr, read, write) = (q.addr, q.read_value, q.write_value);
                        [1, addr as u64, q.read_ts, read as u64, write as u64]
                    });
                    expected.extend((0..5).map(|f| (frame(1 + r, f), fields[f as usize])));
                }
                let y = (row.cycle - 1) as usize;
                for (address, value) in expected {
                    let cycle = row.cycle;
                    assert_eq!(
                        at(address, y),
                        Fr::from_u64(value),
                        "{name}: cycle {cycle}, {address}"
                    );
                }
                rows += 1;
            }
        }
        assert_eq!(rows, t.cycles.len(), "{name}: one family row per cycle");
        for m in 0..1 + 5 * FRAME_QUERIES as u32 {
            let padding = t.cycles.len();
            assert_eq!(
                at(PolyAddress::Memory(m), padding),
                Fr::ZERO,
                "{name}: M[{m}]"
            );
        }
    }
}
