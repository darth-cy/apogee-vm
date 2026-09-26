//! The memory artifacts under the checker: `memory_roots`, the root self-check
//! hook of `docs/spec/memory.md` §1, agrees with a forwarded window and fails
//! when a row under a root changes; every execution family's frame and both
//! window artifacts keep the laws, the lookup rules and the padding contract,
//! and each frame its product-tree clause; and an honest statement over a
//! committed guest — one frame per family that ran, its RAM windows and its
//! boundary, filled by `trace`'s builders from a real execution — keeps every
//! gate and every obligation, reconciles, and proves.

mod common;

use checker::{
    check_laws, check_padding, check_padding_identity, memory_roots, violated_lookups,
    violated_relations,
};
use common::{
    frame_height, frame_plan, frame_shard, memory_challenges, prove_and_verify, shards, traced,
    window_shards, witness_row, FAMILY_NAMES, GUESTS, HEIGHT,
};
use constants::challenge_slot::{MEM_ALPHA_VAL, MEM_GAMMA};
use constants::family;
use constraints::memory::{
    family_frame_artifact, frame, frame_queries, image_window_artifact, value_window_artifact,
    zero_window_artifact, CYCLE, PC,
};
use constraints::{CircuitArtifact, PolyAddress};
use field::Fr;
use gkr::{
    boundary_factors, forward, reconciles, self_check, window_challenges, BaseLayer,
    ExternalChallenges, LayerValues,
};
use poly::{MultilinearPoly, PolyBacking};
use program::check_memory_windows;
use test_support::Rng;
use trace::{
    build_boundary_finals, build_frame_witness, build_memory_columns, init_windows, plan_shards,
    RowSlice, ROLES,
};

/// The seven execution families, ascending: the frames a statement can carry.
/// The two init families run no cycles and have no frame.
const EXECUTION: [u32; 7] = [
    family::ADD_SUB_LUI_AUIPC,
    family::JUMP_BRANCH_SLT,
    family::SHIFT_BITWISE,
    family::MUL_DIV,
    family::MEM_WORD,
    family::MEM_SUBWORD,
    family::ATOMICS,
];

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

/// The widest frame, `ADD_SUB_LUI_AUIPC`'s seven queries: 8 leaves a side.
fn alu_frame(trace_vars: u32) -> CircuitArtifact {
    family_frame_artifact(family::ADD_SUB_LUI_AUIPC, trace_vars)
}

/// The narrowest, `JUMP_BRANCH_SLT`'s four: 4 leaves a side, and no pad leaf.
fn reg_frame(trace_vars: u32) -> CircuitArtifact {
    family_frame_artifact(family::JUMP_BRANCH_SLT, trace_vars)
}

/// Each artifact at `trace_vars` 4 beside the layer its first halving list
/// reads: layer 1 for a window, whose two leaves it halves at once; layer 4 for
/// a seven-query frame, whose 16 leaves take three row-wise lists; and layer 3
/// for a four-query frame, whose 8 leaves take two. The two frame widths are
/// here so the hook is held to a depth it cannot have hardcoded.
const HALVING_INPUTS: [(&str, Constructor, usize); 3] = [
    ("zero window", zero_window_artifact, 1),
    ("add_sub_lui_auipc frame", alu_frame, 4),
    ("jump_branch_slt frame", reg_frame, 3),
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
/// refused. The same for the write side, on all three artifacts. Kills a hook
/// that reads the roots off the top without recomputing them.
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

/// The checker's own laws, lookup rules and padding contract hold on every
/// execution family's frame and on both window artifacts — the `zero_row_valid`
/// each computes included — and each frame, an execution family's subtree whose
/// shards have inactive rows, keeps the product-tree clause. Every family is
/// built, so a width whose leaves need constant-1 padding is covered beside one
/// whose leaves are already a power of two.
#[test]
fn the_memory_artifacts_keep_the_laws_and_the_padding_contract() {
    let mut artifacts: Vec<(String, CircuitArtifact)> = EXECUTION
        .iter()
        .map(|&id| {
            let label = format!("{} frame", FAMILY_NAMES[id as usize]);
            (label, family_frame_artifact(id, 6))
        })
        .collect();
    for (label, a) in &artifacts {
        assert_eq!(check_padding_identity(a), Ok(()), "{label}");
    }
    artifacts.push(("image window".to_string(), image_window_artifact(6)));
    artifacts.push(("zero window".to_string(), zero_window_artifact(6)));
    artifacts.push(("value window".to_string(), value_window_artifact(6)));
    for (label, a) in &artifacts {
        assert_eq!(check_laws(a), Ok(()), "{label}");
        assert_eq!(check_padding(a), Ok(()), "{label}");
    }
}

// ---------------------------------------------------------------------------
// An honest statement over a committed guest
// ---------------------------------------------------------------------------

/// S14 acceptance 1, the honest statement of a committed guest: every shard's
/// forward pass keeps every gate, and its roots are what `memory_roots`
/// recomputes; every artifact keeps the checker's laws and padding contract,
/// and each frame the product-tree clause; the witness-row evaluator,
/// `violated_relations`, reports nothing on every row of every window and on
/// every live row and the first padding row of every frame, and the lookup
/// evaluator nothing on any row; the window list keeps the verifier's rules;
/// the roots reconcile with the boundary `build_boundary_finals` fills at the
/// image's entry pc; and every window shard proves and verifies, and the frames
/// when `prove_frames` says so. Fails on any gate, relation or obligation a
/// builder's honest column breaks, and on any imbalance between the builders.
///
/// The execution side is one frame per family that ran, each under that
/// family's `frame_queries`: a single frame cannot hold cycles of two families,
/// since an ecall row needs `arg1` and `arg2` and a load row needs `load`.
fn honest_statement(name: &str, input: u32, prove_frames: bool) {
    let t = traced(name, input);
    let memory = memory_challenges();
    let plan = frame_plan(&t);
    let shards = shards(&t, &memory);
    assert!(plan.len() > 1, "{name}: more than one family ran");
    assert_eq!(
        shards.len(),
        plan.len() + 3 + init_windows(t.log.state(), HEIGHT).len(),
        "{name}: one shard per frame, per RAM window and per public window"
    );
    assert!(
        plan.iter().any(|(_, c)| frame_height(c.len()) > c.len()),
        "{name}: some family's frame has a padding row"
    );
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
        assert_eq!(check_laws(a), Ok(()), "{name} {label}");
        assert_eq!(check_padding(a), Ok(()), "{name} {label}");

        let rows = 1usize << a.trace_vars;
        // A frame's live rows are its family's cycles; a window row is an
        // address, so a window has no inactive row at all.
        let live = match shard.family {
            Some(_) => {
                assert_eq!(check_padding_identity(a), Ok(()), "{name} {label}");
                plan[i].1.len()
            }
            None => rows,
        };
        for row in 0..rows {
            let w = witness_row(a, &values, row);
            if row <= live {
                assert_eq!(
                    violated_relations(a, &w, &shard.challenges),
                    Vec::<String>::new(),
                    "{name} {label}: row {row}"
                );
            }
            assert_eq!(
                violated_lookups(a, &w),
                Vec::<String>::new(),
                "{name} {label}: row {row}"
            );
        }
        if shard.family.is_none() || prove_frames {
            assert_eq!(prove_and_verify(shard, &values), Ok(()), "{name} {label}");
        }
    }

    let windows = init_windows(t.log.state(), HEIGHT);
    let counts: Vec<u32> = plan_shards(&t.profile, &t.config)
        .shards
        .iter()
        .map(|(f, n)| match *f {
            family::INIT_TEARDOWN => 1,
            family::ZERO_WINDOWS => windows.len() as u32,
            family::PUBLIC_INPUT | family::PUBLIC_OUTPUT => 1,
            family::ADVICE_WINDOWS => trace::advice_window_count(&t.advice, HEIGHT),
            _ => *n,
        })
        .collect();
    check_memory_windows(&t.config, &counts, &windows).unwrap_or_else(|e| panic!("{name}: {e}"));

    let factors = boundary_factors(
        &memory,
        t.image.entry,
        &build_boundary_finals(t.log.state()),
    );
    assert!(reconciles(&reads, &writes, factors), "{name}");
}

/// fib's 2,117 cycles, split across the families that ran: window 0 and the
/// stack window 8191 beside them, every shard proved.
#[test]
fn fib_honest_statement_reconciles_and_proves() {
    honest_statement("fib", 24, true);
}

/// heap's 141,832 cycles: its frames forwarded and checked row by row but not
/// proved — their proofs alone take minutes in a debug build, and fib's frames
/// prove the same artifacts — and its two windows, proved.
#[test]
fn heap_honest_statement_reconciles_and_proves_its_windows() {
    honest_statement("heap", 40, false);
}

/// The same statement built by hand, one frame per family that ran, over that
/// family's cycles — not contiguous — with the first family's list reversed,
/// each at the smallest power-of-two height of at least 16. Row `i` holds
/// `cycles[i]`, every shard keeps every gate, and the roots of every frame with
/// the windows' reconcile with the boundary. Kills a builder that files a
/// cycle's row by the cycle's number, or a list sorted, rather than by its
/// place in `cycles`.
#[test]
fn a_frame_per_family_in_any_order_reconciles() {
    for (name, input) in GUESTS {
        let t = traced(name, input);
        let memory = memory_challenges();
        let mut shards = Vec::new();
        for trace in t.traces.families.iter().filter(|f| !f.is_empty()) {
            let mut cycles = trace.cycle.clone();
            if shards.is_empty() {
                cycles.reverse();
            }
            let height = frame_height(cycles.len());
            let shard = frame_shard(&t.log, trace.family, &cycles, height, &memory);
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
        let factors = boundary_factors(
            &memory,
            t.image.entry,
            &build_boundary_finals(t.log.state()),
        );
        assert!(reconciles(&reads, &writes, factors), "{name}");
    }
}

/// `build_memory_columns` against the family buffers, which file each query
/// under its role where the log files it by space and slot: on each guest, in
/// each family's own frame under its own `frame_queries`, row `i` holds that
/// family's cycle `i`, its pc query `(1, 0, 4(c − 1), pc, next_pc)` at slot 0,
/// and role `ROLES[r]` — query `1 + r` of the table — at the slot the family's
/// list gives it, with mask 1, or zeros where the cycle lacks it; a role the
/// family's list has no slot for is a role no row of that family has; and the
/// first padding row is 0 in every column. Kills a slot-2 register query filed
/// under another role — which no gate of the frame would notice, the three
/// sharing a space and a slot — a query filed at a query id rather than at its
/// family's slot, a `frame_queries` narrower than the family that ran, and a pc
/// query or a padding row filled otherwise.
#[test]
fn the_frame_columns_are_the_family_buffers() {
    for (name, input) in GUESTS {
        let t = traced(name, input);
        let mut rows = 0;
        for trace in t.traces.families.iter().filter(|f| !f.is_empty()) {
            let queries = frame_queries(trace.family);
            let label = FAMILY_NAMES[trace.family as usize];
            assert_eq!(queries[0], PC, "{name} {label}: the pc query is slot 0");
            let height = frame_height(trace.len());
            let shard = RowSlice::shard(trace, 0, height);
            let columns = build_memory_columns(&shard, queries, height);
            let base = BaseLayer::new(columns);
            let at = |address, y| base.get(address).expect("a frame column").get(y);
            for i in 0..trace.len() {
                let row = trace.row(i);
                let pc = [1, 0, 4 * (row.cycle - 1), row.pc as u64, row.next_pc as u64];
                let mut expected = vec![(CYCLE, row.cycle)];
                expected.extend((0..5).map(|f| (frame(0, f), pc[f as usize])));
                for (r, role) in ROLES.iter().enumerate() {
                    let query = row.query(*role);
                    let Some(slot) = queries.iter().position(|&q| q == 1 + r) else {
                        assert!(
                            query.is_none(),
                            "{name} {label}: cycle {} has {role:?}, and the family's frame has \
                             no slot for it",
                            row.cycle
                        );
                        continue;
                    };
                    let fields = query.map_or([0; 5], |q| {
                        let (addr, read, write) = (q.addr, q.read_value, q.write_value);
                        [1, addr as u64, q.read_ts, read as u64, write as u64]
                    });
                    expected.extend((0..5).map(|f| (frame(slot, f), fields[f as usize])));
                }
                for (address, value) in expected {
                    let cycle = row.cycle;
                    assert_eq!(
                        at(address, i),
                        Fr::from_u64(value),
                        "{name} {label}: cycle {cycle}, {address}"
                    );
                }
                rows += 1;
            }
            let padding = trace.len();
            if padding < height {
                for m in 0..1 + 5 * queries.len() as u32 {
                    assert_eq!(
                        at(PolyAddress::Memory(m), padding),
                        Fr::ZERO,
                        "{name} {label}: M[{m}]"
                    );
                }
            }
        }
        assert_eq!(rows, t.cycles.len(), "{name}: one family row per cycle");
    }
}

/// **The frame builders' two readings agree, on every family of every guest.**
///
/// `trace::build_memory_columns` and `trace::build_frame_witness` read a shard's
/// **rows**, because that is all a streaming prover ever holds
/// (`docs/spec/streaming.md` §3); `checker::memory_columns_from_log` and
/// `checker::frame_witness_from_log` read the **memory event log**, which is
/// what those two read before the streaming stage. The two share no code, and
/// this is the check that they are one table computed twice: every column, every
/// row, over real executions.
///
/// It is the whole safety net under "a shard's columns are its execution's
/// memory queries". The row-based reading has to rebuild each row's events —
/// the pc query's read timestamp as `4·(cycle − 1)`, the roles in `ROLES` order,
/// and a delegation request's anchor space out of the row's own `a7`
/// (`trace::Row::delegation_space`) — and any of those got wrong is a column
/// that differs here.
///
/// `keccak-test` and `recursion-ops` are in the list for exactly that last one:
/// they are the committed guests that make delegation calls, so their add/sub
/// family carries live `deleg` queries and a `deleg_space` column with three
/// different tags in it.
#[test]
fn the_row_reading_and_the_log_reading_of_a_frame_agree() {
    let mut checked = (0, 0);
    for (name, input, status, height) in [
        ("fib", 24, 0, HEIGHT),
        ("heap", 40, 0, HEIGHT),
        ("keccak-test", 0, 6, HEIGHT),
        ("recursion-ops", 0, 9, HEIGHT),
        // S26's fixture, at `2^18` for the reason `deleg_space_tags` gives: its
        // `.text` reaches pc `0x2161a`. It is the third guest here that makes
        // delegation calls, and the only one that makes S26's.
        ("mod-mul-ops", 0, 12, 1 << 18),
        ("mem", 0, 50, HEIGHT),
        ("alu", 0, 96, HEIGHT),
        ("control", 0, 16, HEIGHT),
    ] {
        let t = common::traced_exiting_at(name, input, status, height);
        for trace in t.traces.families.iter().filter(|f| !f.is_empty()) {
            let queries = frame_queries(trace.family);
            let label = FAMILY_NAMES[trace.family as usize];
            // Every shard the family's rows are cut into, not just the first:
            // the cut is what a streaming executor reproduces, and a builder
            // that only agreed on shard 0 would agree by accident.
            let height = frame_height(trace.len().min(1 << 12));
            for index in 0..(trace.len().div_ceil(height) as u32) {
                let shard = RowSlice::shard(trace, index, height);
                let cycles = shard.cycles();
                let (rows, log) = (
                    build_memory_columns(&shard, queries, height),
                    checker::memory_columns_from_log(&t.log, queries, cycles, height),
                );
                assert_eq!(
                    rows.len(),
                    log.len(),
                    "{name} {label} {index}: column count"
                );
                for ((a, x), (b, y)) in rows.iter().zip(&log) {
                    assert_eq!(a, b, "{name} {label} {index}: column order");
                    assert!(
                        (0..height).all(|r| x.get(r) == y.get(r)),
                        "{name} {label} {index}: {a} differs"
                    );
                }
                let (rows, log) = (
                    build_frame_witness(&shard, queries, height),
                    checker::frame_witness_from_log(&t.log, queries, cycles, height),
                );
                assert_eq!(
                    rows.len(),
                    log.len(),
                    "{name} {label} {index}: witness count"
                );
                for ((a, x), (b, y)) in rows.iter().zip(&log) {
                    assert_eq!(a, b, "{name} {label} {index}: witness order");
                    assert!(
                        (0..height).all(|r| x.get(r) == y.get(r)),
                        "{name} {label} {index}: {a} differs"
                    );
                }
                checked = (checked.0 + 1, checked.1 + rows.len());
            }
        }
    }
    // A guard on the loop itself: a `GUESTS` list that stopped tracing, or a
    // family filter that excluded everything, would otherwise pass silently.
    assert!(
        checked.0 >= 40 && checked.1 >= 400,
        "the comparison covered {} shards and {} columns",
        checked.0,
        checked.1
    );
}

/// The `deleg_space` column is the thing the row reading recovers from `a7`
/// rather than from an event's own address space, so it gets its own check:
/// every live `deleg` query names the requested family's tag and no other row
/// does, and between the three guests all four tags appear.
///
/// `keccak-test` is S21's fixture and requests `KECCAK_F` alone;
/// `recursion-ops` is S23's and requests `POSEIDON2` and `FR_ARITH` through
/// ordinary `Fr` arithmetic; `mod-mul-ops` is S26's and requests `MOD_MUL`, both
/// by name and through `guests/vendor/k256`'s patched field multiply. No
/// committed guest requests all four, which is why this takes three.
#[test]
fn the_delegation_space_column_is_the_requested_family() {
    let seen: Vec<u64> = [
        ("keccak-test", 6, HEIGHT),
        ("recursion-ops", 9, HEIGHT),
        // `2^18`: its `.text` reaches pc `0x2161a` and a table's row `i` is pc `2i`.
        ("mod-mul-ops", 12, 1 << 18),
    ]
    .into_iter()
    .flat_map(|(name, status, height)| deleg_space_tags(name, status, height))
    .collect();
    let mut tags = seen.clone();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(
        tags,
        [
            constants::address_space::DELEGATION_KECCAK_F as u64,
            constants::address_space::DELEGATION_POSEIDON2 as u64,
            constants::address_space::DELEGATION_FR_ARITH as u64,
            constants::address_space::DELEGATION_MOD_MUL as u64,
        ],
        "the three guests request all four delegation families"
    );
}

/// `name`'s add/sub frame's `deleg_space` column, checked row by row against
/// the row's own requested family, and returned as the tags it held.
fn deleg_space_tags(name: &str, status: i32, height: u32) -> Vec<u64> {
    let t = common::traced_exiting_at(name, 0, status, height);
    let fam = family::ADD_SUB_LUI_AUIPC;
    let trace = t
        .traces
        .family(fam)
        .expect("the add/sub family owns every ecall row");
    let queries = frame_queries(fam);
    let at = queries
        .iter()
        .position(|&q| q == constraints::memory::DELEG)
        .expect("add/sub's frame has the deleg query");
    let height = trace.len().next_power_of_two();
    let shard = RowSlice::shard(trace, 0, height);
    let columns = build_memory_columns(&shard, queries, height);
    let space = &columns
        .iter()
        .find(|(a, _)| *a == constraints::memory::deleg_space(queries.len()))
        .expect("the deleg_space column")
        .1;
    let mask = &columns
        .iter()
        .find(|(a, _)| *a == frame(at, constraints::memory::FIELD_MASK))
        .expect("the deleg mask")
        .1;
    let mut tags: Vec<u64> = Vec::new();
    for r in 0..trace.len() {
        let row = trace.row(r);
        let live = row.query(trace::Role::Delegate).is_some();
        assert_eq!(
            mask.get(r),
            Fr::from_u64(live as u64),
            "{name} row {r}'s deleg mask"
        );
        match row.delegation_space() {
            Some(s) => {
                assert_eq!(space.get(r), Fr::from_u64(s.tag() as u64), "{name} row {r}");
                tags.push(s.tag() as u64);
            }
            None => assert_eq!(space.get(r), Fr::ZERO, "{name} row {r}"),
        }
    }
    assert!(!tags.is_empty(), "{name} makes a delegation call");
    tags
}
