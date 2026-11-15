//! The two precompiles over a real execution, `guests/precompiles` built from
//! source, in ordinary CI and without a proof (`docs/spec/precompiles.md`):
//!
//! - **the journal is the host's**: the Poseidon2 permutation of the
//!   generator's own input and of lanes at `2^64 − 1`, read mod `p`, and a
//!   Merkle root, each by `transcript`; and `mul_div` at edges whose answers
//!   are hand-derived or a `u128`'s;
//! - **every precompile circuit keeps every rule**, by `constraints` and, with
//!   no shared code, by this crate;
//! - **the fill holds**: every live row and the padding after it satisfy every
//!   row-local gate and lookup, `ADD_SUB_LUI_AUIPC`'s request rows among them;
//! - **no constraint is dead**: single-cell edits of `±1` and `+2^32` make
//!   every row-local gate and lookup refuse, and each written word one off is
//!   refused by its row alone;
//! - **the statement reconciles**: every shard forwarded, and the roots of all
//!   of them and the boundary multiply out, the anchors and the Poseidon2 state
//!   included. A round row moved to another call's key keeps every row-local
//!   relation and does not.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use checker::{
    check_laws, check_lookup_discharge, check_padding, check_padding_identity, memory_roots,
    violated_lookups, violated_relations, WitnessRow,
};
use constants::{challenge_slot, family, lookup_channel};
use constraints::lookup::check_discharge;
use constraints::memory::check_memory;
use constraints::{family_circuit, CircuitArtifact, PolyAddress};
use field::{Fp, Fp2};
use gkr::{
    boundary_factors, eval_gate, forward, gate_values, insert_lookup_challenges, reconciles,
    virtual_at_row, window_challenges, BaseLayer, ExternalChallenges,
};
use poly::{MultilinearPoly, PolyBacking};
use prover::{Program, ShardSource};
use trace::{IoStreams, PhaseTiming, TraceArchive};

const DELEGATIONS: [u32; 3] = [
    family::POSEIDON2,
    family::POSEIDON2_ROUNDS,
    family::MUL_DIV_U256,
];

fn f(v: u64) -> Fp {
    Fp::from_u64(v)
}

/// Lane `j` of leaf `i`: arbitrary, and the top lane at `2^64 − 1`, read mod p.
fn leaf(i: usize, j: usize) -> u64 {
    match j {
        7 => u64::MAX,
        _ => (i as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ j as u64,
    }
}

const LEAVES: usize = 8;

fn input() -> Vec<u8> {
    let mut out = (LEAVES as u32).to_le_bytes().to_vec();
    for i in 0..LEAVES {
        for j in 0..8 {
            out.extend(leaf(i, j).to_le_bytes());
        }
    }
    out
}

/// The guest, traced: the execution families at `2^20`, their floor, and every
/// window and delegation family at `2^16`.
fn traced() -> (Program, TraceArchive) {
    let image = loader::load_elf(&test_support::guest_elf("precompiles")).expect("it loads");
    let mut params = program::ProgramParams::defaults();
    params.heights[..=family::ATOMICS as usize].fill(1 << 20);
    for fam in [
        family::INIT_TEARDOWN,
        family::ZERO_WINDOWS,
        family::ADVICE_WINDOWS,
    ] {
        params.heights[fam as usize] = 1 << 16;
    }
    let (tables, config) = program::decode_program(&image, &params).expect("it decodes");
    for fam in DELEGATIONS {
        assert!(
            config.height(fam).is_some(),
            "the image declares family {fam}"
        );
    }
    let io = emulator::GuestIo {
        input: input(),
        advice: Vec::new(),
    };
    let (traces, log, profile, execution) =
        emulator::trace_run(&image, &io, &tables, &config).expect("it runs");
    assert_eq!(execution.exit_code, 0, "the guest exits 0");
    let initial = trace::InitialMemory {
        image: &image,
        public_input: &io.input,
        advice: &io.advice,
    };
    log.self_check(&initial)
        .expect("the trace's own memory check");
    let streams = IoStreams {
        input: execution.io.input,
        output: execution.io.output,
    };
    let archive = TraceArchive::from_execution(
        traces,
        log,
        profile,
        streams,
        Vec::new(),
        PhaseTiming { wall_nanos: 0 },
    );
    (
        Program {
            image,
            tables,
            config,
        },
        archive,
    )
}

// ---------------------------------------------------------------------------
// The journal
// ---------------------------------------------------------------------------

fn permute(lanes: [u64; 16]) -> [u64; 16] {
    let mut s = lanes.map(Fp::from_u64);
    transcript::poseidon2_permute(&mut s);
    s.map(Fp::to_u64)
}

/// `2^k` as 32 bytes, little-endian.
fn pow2(k: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[k / 8] = 1 << (k % 8);
    out
}

fn u128_le(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&v.to_le_bytes());
    out
}

#[test]
fn the_journal_is_the_hosts() {
    let (_, archive) = traced();
    let mut want: Vec<u8> = Vec::new();
    let lanes = |v: &[u64]| v.iter().flat_map(|l| l.to_le_bytes()).collect::<Vec<u8>>();
    want.extend(lanes(&permute(std::array::from_fn(|i| i as u64))));
    want.extend(lanes(&permute([u64::MAX; 16])));
    let mut level: Vec<[u64; 8]> = (0..LEAVES)
        .map(|i| std::array::from_fn(|j| leaf(i, j)))
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let mut s = [0u64; 16];
                s[..8].copy_from_slice(&pair[0]);
                s[8..].copy_from_slice(&pair[1]);
                std::array::from_fn(|j| permute(s)[j])
            })
            .collect();
    }
    want.extend(lanes(&level[0]));
    let mut chain = [0u64; 16];
    chain[..8].copy_from_slice(&level[0]);
    for _ in 0..300 {
        chain = permute(chain);
    }
    want.extend(lanes(&chain));
    let max = [0xffu8; 32];
    let mut max_less_1 = max;
    max_less_1[0] = 0xfe;
    let (a, b, d) = (
        0xffff_ffff_ffff_ffc5u128,
        0x1234_5678_9abc_def0u128,
        1_000_000_007u128,
    );
    let answered = [
        Some((pow2(240), [0; 32])),
        Some((max, [0; 32])),
        Some((u128_le(a * b / d), u128_le(a * b % d))),
        Some(([0x55; 32], [0; 32])),
        Some((max_less_1, [0; 32])),
        None,
        None,
    ];
    for case in answered {
        match case {
            Some((q, r)) => {
                want.push(1);
                want.extend(q);
                want.extend(r);
            }
            None => want.extend([0u8; 65]),
        }
    }
    assert_eq!(archive.io_streams().output, want);
}

// ---------------------------------------------------------------------------
// The circuits
// ---------------------------------------------------------------------------

#[test]
fn every_precompile_circuit_keeps_every_rule() {
    for fam in DELEGATIONS {
        let c = family_circuit(fam, 16).expect("the family's circuit");
        let a = &c.artifact;
        assert_eq!(CircuitArtifact::from_bytes(&a.to_bytes()).as_ref(), Ok(a));
        assert_eq!(a.validate(), Ok(()));
        assert_eq!(check_memory(a), Ok(()));
        assert_eq!(check_discharge(a, &c.channels), Ok(()));
        assert_eq!(check_laws(a), Ok(()));
        assert_eq!(check_padding(a), Ok(()));
        assert_eq!(check_padding_identity(a), Ok(()));
        assert_eq!(check_lookup_discharge(a, &c.channels), Ok(()));
        assert!(a.padding.zero_row_valid);
        // RANGE16's table needs 2^16 rows; the rounds read no lookup.
        let below = family_circuit(fam, 12);
        assert_eq!(
            below.is_some(),
            fam == family::POSEIDON2_ROUNDS,
            "family {fam} at 2^12"
        );
    }
}

// ---------------------------------------------------------------------------
// The fills, row by row
// ---------------------------------------------------------------------------

/// One family's filled shard 0, with what a row needs to be judged alone.
struct Shard {
    a: CircuitArtifact,
    columns: Vec<MultilinearPoly>,
    index: BTreeMap<PolyAddress, usize>,
    tables: BTreeMap<u32, HashSet<Vec<u64>>>,
    ch: ExternalChallenges,
    rows: usize,
    live: usize,
}

fn memory_slots() -> ExternalChallenges {
    let mut ch = ExternalChallenges::new();
    for (slot, v) in [
        (challenge_slot::MEM_GAMMA, 11),
        (challenge_slot::MEM_ALPHA_ADDR, 13),
        (challenge_slot::MEM_ALPHA_TS, 17),
        (challenge_slot::MEM_ALPHA_VAL, 19),
        (challenge_slot::MEM_ALPHA_HI, 23),
    ] {
        ch.insert(slot, f(v).into());
    }
    ch
}

/// Shard `index` of `fam`: its fill, multiplicities counted, in layout order.
fn filled(
    program: &Program,
    archive: &TraceArchive,
    fam: u32,
    index: u32,
    window: u32,
) -> (CircuitArtifact, Vec<(PolyAddress, MultilinearPoly)>) {
    let height = program.config.height(fam).expect("a config family");
    let circuit = family_circuit(fam, height.trailing_zeros()).expect("its circuit");
    let fill = prover::family_fill(fam).expect("its fill");
    let source =
        ShardSource::archived(program, archive, fam, index, height, window).expect("its rows");
    let mut columns = fill(&source).unwrap_or_else(|e| panic!("family {fam}: {e}"));
    let counts = trace::build_multiplicities(&circuit.artifact, &columns, &circuit.channels)
        .unwrap_or_else(|e| panic!("family {fam}: {e}"));
    columns.extend(counts);
    (circuit.artifact, columns)
}

impl Shard {
    fn new(program: &Program, archive: &TraceArchive, fam: u32) -> Shard {
        let (a, columns) = filled(program, archive, fam, 0, 0);
        let mut by: BTreeMap<PolyAddress, MultilinearPoly> = columns.into_iter().collect();
        let columns: Vec<MultilinearPoly> = a
            .committed()
            .iter()
            .map(|x| {
                by.remove(x)
                    .unwrap_or_else(|| panic!("the fill has no {x}"))
            })
            .collect();
        let index: BTreeMap<PolyAddress, usize> = a
            .committed()
            .into_iter()
            .enumerate()
            .map(|(i, x)| (x, i))
            .collect();
        let rows = 1usize << a.trace_vars;
        let circuit = family_circuit(fam, a.trace_vars).expect("its circuit");
        let mut tables = BTreeMap::new();
        for spec in circuit
            .channels
            .iter()
            .filter(|s| !lookup_channel::IS_RANGE[s.channel as usize])
        {
            let at: Vec<&MultilinearPoly> = spec.table.iter().map(|x| &columns[index[x]]).collect();
            let set = (0..rows).map(|r| at.iter().map(|c| c.get_base(r).to_u64()).collect());
            tables.insert(spec.channel, set.collect::<HashSet<Vec<u64>>>());
        }
        let mut ch = memory_slots();
        insert_lookup_challenges(&mut ch, f(29).into(), f(31).into(), &a);
        let traces = archive.family_traces();
        let live = match traces.delegation(fam) {
            Some(t) => t.rows() as usize,
            None => traces.family(fam).expect("its buffer").len(),
        };
        Shard {
            a,
            columns,
            index,
            tables,
            ch,
            rows: rows.min(1 << 16),
            live: live.min(rows),
        }
    }

    fn row(&self, r: usize) -> Vec<Fp> {
        self.columns.iter().map(|c| c.get_base(r)).collect()
    }

    fn at(&self, name: &str) -> usize {
        self.index[&self
            .a
            .column(name)
            .unwrap_or_else(|| panic!("no column `{name}`"))]
    }

    /// Every row-local relation, range obligation and table lookup `row`
    /// breaks at `r`, its scratch computed from it.
    fn refused(&self, row: &[Fp], r: usize) -> Vec<String> {
        let a = &self.a;
        let virtuals: Vec<Fp2> = a
            .virtuals
            .iter()
            .map(|(k, _)| virtual_at_row(*k, r).into())
            .collect();
        let mut scratch = vec![Fp2::ZERO; a.scratch.len()];
        let mut lower: Vec<Fp2> = row.iter().map(|v| (*v).into()).collect();
        for k in (0..a.depth()).take_while(|k| !a.layers[*k].halving) {
            let v: &[Fp2] = if k == 0 { &virtuals } else { &[] };
            let values = gate_values(a, k, &lower, &[], v, &self.ch);
            let produced = values[..a.layers[k].producing.len()].to_vec();
            for (j, value) in produced.iter().enumerate() {
                let address = PolyAddress::Inner {
                    layer: k as u32 + 1,
                    offset: j as u32,
                };
                let slot = a.scratch.iter().position(|s| s.address == address);
                scratch[slot.expect("every inner column has a scratch slot")] = *value;
            }
            lower = produced;
        }
        let w = WitnessRow {
            committed: row.to_vec(),
            row: r,
            scratch,
        };
        let mut out = violated_relations(a, &w, &self.ch);
        out.extend(violated_lookups(a, &w));
        for l in &a.lookups {
            let Some(table) = self.tables.get(&l.channel) else {
                continue;
            };
            let s = row[self.index[&l.selector]];
            let key: Vec<u64> = l
                .tuple
                .iter()
                .enumerate()
                .map(|(j, g)| {
                    let operands: Vec<Fp2> = g
                        .operands()
                        .iter()
                        .map(|x| match x {
                            PolyAddress::Virtual(k) => virtual_at_row(*k, r).into(),
                            x => row[self.index[x]].into(),
                        })
                        .collect();
                    let raw = eval_gate(g, &operands, &self.ch).c0;
                    match l.channel {
                        lookup_channel::GENERIC if j == 0 => s * (raw + Fp::ONE),
                        lookup_channel::DECODER => s * (raw + Fp::ONE) - Fp::ONE,
                        _ => s * raw,
                    }
                    .to_u64()
                })
                .collect();
            if !table.contains(&key) {
                out.push(l.name.clone());
            }
        }
        out
    }

    /// The row-local enforcing relations and every lookup, by name.
    fn constraints(&self) -> BTreeSet<String> {
        let a = &self.a;
        let gates = (0..a.depth())
            .take_while(|k| !a.layers[*k].halving)
            .flat_map(|k| &a.layers[k].enforcing)
            .map(|e| a.relations[e.relation as usize].name.clone());
        gates
            .chain(a.lookups.iter().map(|l| l.name.clone()))
            .collect()
    }
}

#[test]
fn every_row_holds_and_every_constraint_bites() {
    let (program, archive) = traced();
    let requests = Shard::new(&program, &archive, family::ADD_SUB_LUI_AUIPC);
    let delegates = requests.at("delegates");
    let mut seen = 0;
    for r in 0..requests.live + 2 {
        let row = requests.row(r);
        seen += (row[delegates] == Fp::ONE) as usize;
        let broken = requests.refused(&row, r);
        assert!(broken.is_empty(), "ADD_SUB row {r} breaks {broken:?}");
    }
    assert!(seen >= 3, "the guest's request rows are ADD_SUB's");

    for fam in DELEGATIONS {
        let label = program::family_name(fam);
        let s = Shard::new(&program, &archive, fam);
        assert!(s.live > 0, "{label} has a row");
        for r in (0..s.live + 2).chain([s.rows - 1]) {
            let broken = s.refused(&s.row(r), r);
            assert!(broken.is_empty(), "{label} row {r} breaks {broken:?}");
        }
        // Each kind of row once — a frame row, or a round row of each kind
        // and the idle one — and the first padding row.
        let samples: Vec<usize> = match fam {
            family::POSEIDON2_ROUNDS => (0..16).chain([s.live]).collect(),
            _ => vec![0, s.live],
        };
        let names: Vec<&String> = s.a.memory.iter().chain(&s.a.witness).collect();
        let mut refusing = BTreeSet::new();
        for r in samples {
            let honest = s.row(r);
            let edited = |i: usize, by: Fp| {
                let mut row = honest.clone();
                row[i] += by;
                s.refused(&row, r)
            };
            if r == 0 {
                for q in names.iter().filter(|n| n.ends_with("_write_value")) {
                    assert!(
                        !edited(s.at(q), Fp::ONE).is_empty(),
                        "{label}: {q} one off is accepted"
                    );
                }
            }
            for n in names.iter().filter(|n| !n.starts_with("mult_")) {
                for by in [Fp::ONE, -Fp::ONE, f(1 << 32)] {
                    refusing.extend(edited(s.at(n), by));
                }
            }
        }
        let dead: Vec<String> = s.constraints().difference(&refusing).cloned().collect();
        assert!(
            dead.is_empty(),
            "{label}: no single-cell edit makes {dead:?} refuse"
        );
    }
}

// ---------------------------------------------------------------------------
// The statement
// ---------------------------------------------------------------------------

/// A change to shard `(family, index)`'s committed columns.
type Edit<'a> = &'a dyn Fn(u32, u32, &mut [(PolyAddress, MultilinearPoly)]);

/// Every shard of the statement, forwarded: `(read_root, write_root)` each,
/// with `edit` applied to `(family, index)`'s columns first.
fn roots(program: &Program, archive: &TraceArchive, edit: Edit) -> Vec<(Fp2, Fp2)> {
    let config = &program.config;
    let state = archive.memory_log().state();
    let h = verifier_core::window_height(config).expect("one window height");
    let windows = trace::init_windows(state, h);
    let plan = trace::plan_shards(archive.cycle_profile(), config);
    let counts: Vec<u32> = plan
        .shards
        .iter()
        .map(|&(fam, n)| match fam {
            family::INIT_TEARDOWN | family::PUBLIC_INPUT | family::PUBLIC_OUTPUT => 1,
            family::ZERO_WINDOWS => windows.len() as u32,
            family::ADVICE_WINDOWS => 0,
            _ => n,
        })
        .collect();
    let memory = memory_slots();
    let mut out = Vec::new();
    for (fam, index) in verifier_core::statement_shards(config, &counts) {
        let vars = config
            .height(fam)
            .expect("a config family")
            .trailing_zeros();
        let window = verifier_core::shard_window(fam, index, &windows, vars);
        let (a, mut columns) = filled(program, archive, fam, index, window.unwrap_or(0));
        edit(fam, index, &mut columns);
        let mut ch = match window {
            Some(w) => window_challenges(&memory, w, vars),
            None => memory.clone(),
        };
        insert_lookup_challenges(&mut ch, f(29).into(), f(31).into(), &a);
        let values = forward(&a, &BaseLayer::new(columns), &ch);
        out.push(memory_roots(&a, &values).unwrap_or_else(|e| panic!("family {fam}: {e}")));
    }
    out
}

fn balances(program: &Program, archive: &TraceArchive, roots: &[(Fp2, Fp2)]) -> bool {
    let finals = trace::build_boundary_finals(archive.memory_log().state());
    let factors = boundary_factors(&memory_slots(), program.image.entry, &finals);
    let (reads, writes): (Vec<Fp2>, Vec<Fp2>) = roots.iter().copied().unzip();
    reconciles(&reads, &writes, factors)
}

#[test]
fn the_statement_reconciles_and_a_round_moved_to_another_call_does_not() {
    let (program, archive) = traced();
    assert!(balances(
        &program,
        &archive,
        &roots(&program, &archive, &|_, _, _| {})
    ));

    // Call 1's first round row, keyed to call 0: every row-local relation of
    // the row still holds — a key has no gate on a round row — and the
    // state it reads and writes is now call 0's twice and call 1's never.
    let s = Shard::new(&program, &archive, family::POSEIDON2_ROUNDS);
    let (key, row) = (s.at("key"), 16);
    let mut moved = s.row(row);
    moved[key] = s.row(0)[key];
    assert!(
        s.refused(&moved, row).is_empty(),
        "the moved row is a valid round"
    );
    let at = s.a.column("key").expect("a key column");
    let edit = |fam: u32, index: u32, columns: &mut [(PolyAddress, MultilinearPoly)]| {
        if (fam, index) != (family::POSEIDON2_ROUNDS, 0) {
            return;
        }
        let (_, c) = columns
            .iter_mut()
            .find(|(x, _)| *x == at)
            .expect("the key column");
        let mut values: Vec<Fp> = (0..c.len()).map(|i| c.get_base(i)).collect();
        values[row] = values[0];
        *c = MultilinearPoly::new(PolyBacking::Fp(values));
    };
    assert!(!balances(
        &program,
        &archive,
        &roots(&program, &archive, &edit)
    ));
}
