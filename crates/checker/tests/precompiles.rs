//! Five of the six precompiles over a real execution, `guests/precompiles`
//! built from source, in ordinary CI and without a proof
//! (`docs/spec/precompiles.md`); its input verifies no signature, so
//! `FALCON512_DECODE` is `crates/checker/tests/falcon_decode.rs`':
//!
//! - **the journal is the host's**: the Poseidon2 permutation of the
//!   generator's own input and of lanes at `2^64 − 1`, read mod `p`, and the
//!   leaves' root, each by `transcript`; `mul_div` at edges whose answers are
//!   hand-derived or a `u128`'s; Falcon-512's `‖s1‖²` of three arrays and of
//!   their rotations, each by the host's own negacyclic product; HashToPoint's
//!   sampler's digits of lanes at its edges, each by division; and the roots
//!   of seven trie programs, advised blocks read mod `p` among them, and of a
//!   long one of 4,100 hash ops, each by the trie's branch formula;
//! - **every precompile circuit keeps every rule**, by `constraints` and, with
//!   no shared code, by this crate;
//! - **the fill holds**: every live row and the padding after it satisfy every
//!   row-local gate and lookup, `ADD_SUB_LUI_AUIPC`'s request rows among them,
//!   and every trie call is past cycle `2^14`;
//! - **no constraint is dead**: single-cell edits of `±1` and `+2^32` make
//!   every row-local gate and lookup refuse, and each written word one off is
//!   refused by its row alone;
//! - **the statement reconciles**: every shard forwarded, and the roots of all
//!   of them and the boundary multiply out, the anchors and the Poseidon2,
//!   Falcon and trie state included. A round row moved to another call's
//!   cycle keeps every row-local relation and does not, nor does a trie
//!   program's continuation one off where it crosses a round shard, nor a JOIN
//!   taking a value no op parked, nor a Falcon product row claiming another
//!   residue, nor a split row another column;
//! - **a call crosses a shard**: the round shard a program continues into
//!   fills from its streamed chunk exactly as from the archive;
//! - **a block word is a word**: one no load could read is refused by its
//!   bound alone;
//! - **a sampled lane is below `T`**: one at `T` and one at `2^64 − 1`, each
//!   with digits that keep its identity, are refused by a bound alone.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::OnceLock;

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
use prover::{Program, ShardRows, ShardSource};
use trace::{IoStreams, PhaseTiming, TraceArchive};

const DELEGATIONS: [u32; 10] = [
    family::POSEIDON2,
    family::POSEIDON2_ROUNDS,
    family::MUL_DIV_U256,
    family::FALCON,
    family::FALCON_SPLIT,
    family::FALCON_PRODUCT,
    family::FALCON_SAMPLE,
    family::MPT,
    family::MPT_NODES,
    family::MPT_ROUNDS,
];

fn f(v: u64) -> Fp {
    Fp::from_u64(v)
}

/// Lane `j` of leaf `i`: arbitrary below `p`, and the top lane at `p − 1`, the
/// largest a digest holds.
fn leaf(i: usize, j: usize) -> u64 {
    match j {
        7 => field::A64_C5 - 1,
        _ => (i as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ j as u64,
    }
}

const LEAVES: usize = 8;

/// Coefficient `t` of the Falcon case's array `a`, `h`, `s2` and `c` in
/// turn: arbitrary halfwords, most of them at or above `q`, the first the
/// largest.
fn falcon_coefficient(a: usize, t: usize) -> u16 {
    match t {
        0 => u16::MAX,
        _ => ((t as u32 + 1).wrapping_mul(0x85eb_ca6b) >> 13 ^ (a as u32) << 9) as u16,
    }
}

/// The `s1_norm` calls after the first: the arrays rotated once, then twice.
const MORE: u32 = 2;

/// `q^4`, and HashToPoint's bound `T`, the largest multiple of it below `p`.
const Q4: u64 = 12289u64.pow(4);
const T: u64 = 808 * Q4;

/// The lanes the guest samples: at the edges of each digit and of `T`.
const SAMPLED: [u64; 8] = [
    0,
    1,
    Q4 - 1,
    Q4,
    T - 1,
    T / 3,
    T - Q4,
    0x0123_4567_89ab_cdef,
];

/// The long trie program's steps: after the 7 hash ops of the programs
/// before it, its 4,100 straddle the 4,096th, where `MPT_ROUNDS`' first shard
/// ends at `2^16`.
const STEPS: u32 = 4_100;

/// Lane `k` of the advice's blocks 0 and 1: arbitrary, lane 7 at `2^64 − 1`
/// and lane 11 at `p`, each read mod `p`.
fn start(k: usize) -> u64 {
    match k {
        7 => u64::MAX,
        11 => field::A64_C5,
        _ => (k as u64 + 1).wrapping_mul(0xd1b5_4a32_d192_ed03) ^ k as u64,
    }
}

/// The guest's advice and the long program's value, by the duplex
/// `guests/precompiles` defines: from [`start`]'s 16 lanes, step `s` permutes
/// and adds `s mod 512 + 1` to lane 0; each block past 1 is the last 8 lanes
/// of the step before its own, and the value the first 8 after the last.
fn duplex() -> (Vec<u8>, [u64; 8]) {
    let mut advice = STEPS.to_le_bytes().to_vec();
    advice.extend((0..16).flat_map(|k| start(k).to_le_bytes()));
    let mut state: [Fp; 16] = std::array::from_fn(|k| f(start(k)));
    for s in 1..=STEPS {
        transcript::poseidon2_permute(&mut state);
        state[0] += f(s as u64 % 512 + 1);
        if s < STEPS {
            advice.extend(state[8..].iter().flat_map(|x| x.to_u64().to_le_bytes()));
        }
    }
    // No trie scenario: `crates/emulator/tests/guests.rs` runs them.
    advice.extend(0u32.to_le_bytes());
    (advice, std::array::from_fn(|k| state[k].to_u64()))
}

fn input() -> Vec<u8> {
    let mut out = (LEAVES as u32).to_le_bytes().to_vec();
    for i in 0..LEAVES {
        for j in 0..8 {
            out.extend(leaf(i, j).to_le_bytes());
        }
    }
    for a in 0..3 {
        out.extend((0..512).flat_map(|t| falcon_coefficient(a, t).to_le_bytes()));
    }
    out.extend(MORE.to_le_bytes());
    // No Falcon-512 verification: `crates/emulator/tests/guests.rs` runs them.
    out.extend(0u32.to_le_bytes());
    out
}

/// The guest, traced once for every test here: the execution families at
/// `2^20`, their floor, and every window and delegation family at `2^16`. One
/// archive the tests share: at 1.7 million cycles one each is most of the
/// suite's peak.
fn traced() -> &'static (Program, TraceArchive) {
    static TRACED: OnceLock<(Program, TraceArchive)> = OnceLock::new();
    TRACED.get_or_init(trace)
}

fn trace() -> (Program, TraceArchive) {
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
        advice: duplex().0,
    };
    let (traces, log, profile, execution) =
        emulator::trace_run(&image, &io, &tables, &config).expect("it runs");
    assert_eq!(execution.exit_code, 0, "the guest exits 0");
    // Every trie call is past cycle `2^14`, so `4·cycle` passes `2^16` and a
    // masked-out access's gap takes a chunk above the low one.
    for fam in [family::MPT, family::MPT_NODES, family::MPT_ROUNDS] {
        let calls = traces.delegation(fam).expect("its buffer");
        assert!(
            calls.cycle.iter().all(|c| *c > 1 << 14),
            "a trie call before cycle 2^14"
        );
    }
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
        io.advice,
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

/// `‖s1‖²` of `s1 = (c − s2·h) mod (q, x^512 + 1)`, each coefficient of the
/// three read mod `q = 12289` and each of `s1` at its least absolute value:
/// coefficient `k` of the negacyclic product is `Σ_{i ≤ k} s2_i·h_{k−i}`
/// less `Σ_{i > k} s2_i·h_{k+512−i}`.
fn falcon_norm(h: &[u16; 512], s2: &[u16; 512], c: &[u16; 512]) -> u64 {
    let q = 12289i64;
    let m = |x: u16| x as i64 % q;
    (0..512)
        .map(|k| {
            let mut x = m(c[k]);
            for i in 0..512 {
                let t = m(s2[i]) * m(h[(k + 512 - i) % 512]);
                x += if i <= k { -t } else { t };
            }
            let x = x.rem_euclid(q);
            let s = x.min(q - x) as u64;
            s * s
        })
        .sum()
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
    let leaves: Vec<[u64; 8]> = (0..LEAVES)
        .map(|i| std::array::from_fn(|j| leaf(i, j)))
        .collect();
    let arrays: [[u16; 512]; 3] =
        std::array::from_fn(|a| std::array::from_fn(|t| falcon_coefficient(a, t)));
    let norm = |k: usize| {
        let p = |i: usize| &arrays[(i + k) % 3];
        falcon_norm(p(0), p(1), p(2))
    };
    assert!(norm(0) >> 32 != 0, "the norm has a high word");
    want.extend(norm(0).to_le_bytes());
    want.extend((1..=MORE as usize).map(norm).sum::<u64>().to_le_bytes());
    for x in SAMPLED {
        want.extend((0..4).flat_map(|j| ((x / 12289u64.pow(j) % 12289) as u16).to_le_bytes()));
    }
    // The trie programs: a branch at crit bit `c` is the first eight lanes of
    // the permutation of `l ‖ r` with `c + 1` added to lane 0, over leaves 0
    // to 3 and the advice's blocks 0 and 1 read mod `p`; then the duplex.
    let branch = |c: u64, l: [u64; 8], r: [u64; 8]| -> [u64; 8] {
        let mut s = [0u64; 16];
        s[..8].copy_from_slice(&l);
        s[8..].copy_from_slice(&r);
        let mut out: [u64; 8] = std::array::from_fn(|j| permute(s)[j]);
        out[0] = (f(out[0]) + f(c + 1)).to_u64();
        out
    };
    let block = |b: usize| -> [u64; 8] { std::array::from_fn(|k| f(start(8 * b + k)).to_u64()) };
    let [a, b, c, d] = [0, 1, 2, 3].map(|i| leaves[i]);
    for root in [
        a,
        branch(5, a, b),
        branch(5, b, a),
        branch(511, a, b),
        branch(1, branch(9, a, b), branch(3, d, c)),
        block(0),
        branch(7, block(1), a),
        duplex().1,
    ] {
        want.extend(lanes(&root));
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
        // RANGE16's table needs 2^16 rows; POSEIDON2's rounds read no lookup.
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
        let traces = archive.family_traces();
        let live = match traces.delegation(fam) {
            Some(t) => t.rows() as usize,
            None => traces.family(fam).expect("its buffer").len(),
        };
        Shard::of(fam, a, columns, live)
    }

    /// `fam`'s shard over `columns`, its first `live` rows live.
    fn of(
        fam: u32,
        a: CircuitArtifact,
        columns: Vec<(PolyAddress, MultilinearPoly)>,
        live: usize,
    ) -> Shard {
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
    let requests = Shard::new(program, archive, family::ADD_SUB_LUI_AUIPC);
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
        let s = Shard::new(program, archive, fam);
        assert!(s.live > 0, "{label} has a row");
        // A full shard, as `MPT_ROUNDS`' first is, has no padding row.
        let padding = (s.live < s.rows).then_some(s.live);
        for r in (0..(s.live + 2).min(s.rows)).chain([s.rows - 1]) {
            let broken = s.refused(&s.row(r), r);
            assert!(broken.is_empty(), "{label} row {r} breaks {broken:?}");
        }
        // Each kind of row once — a frame row, a round row of each kind and
        // the idle one, or a Falcon split row of chains `s2` and `c`, whose
        // `s` is 0 and is not — and the first padding row, where there is one.
        let samples: Vec<usize> = match fam {
            family::POSEIDON2_ROUNDS | family::MPT_ROUNDS => (0..16).chain(padding).collect(),
            family::FALCON_SPLIT => [0, 32].into_iter().chain(padding).collect(),
            // A LOAD's row, a SIB's, a park's and a JOIN's: the first
            // programs' ops 0, 2, 6 and 7.
            family::MPT_NODES => {
                let mask = |r: usize, name: &str| s.row(r)[s.at(name)];
                assert_eq!(
                    mask(2, "is_hash") - mask(2, "is_join"),
                    Fp::ONE,
                    "row 2 is a SIB"
                );
                assert_eq!(mask(6, "park"), Fp::ONE, "row 6 parks");
                assert_eq!(mask(7, "is_join"), Fp::ONE, "row 7 is a JOIN");
                [0, 2, 6, 7].into_iter().chain(padding).collect()
            }
            _ => [0].into_iter().chain(padding).collect(),
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

/// What an `MPT_NODES` row's `u` is over its own cells: `M_E` of the value it
/// enters with, its raw lanes with `pending` added to lane 0, and its other
/// child, the other on the left where `left` is 1.
fn node_u(s: &Shard, row: &[Fp]) -> [Fp; 16] {
    let cur: Vec<Fp> = (0..8)
        .map(|k| match k {
            0 => row[s.at("o0")] + row[s.at("pending")],
            _ => row[s.at(&format!("o{k}"))],
        })
        .collect();
    let other: Vec<Fp> = (0..8).map(|k| row[s.at(&format!("other{k}"))]).collect();
    let (left, right) = match row[s.at("left")] == Fp::ONE {
        true => (&other, &cur),
        false => (&cur, &other),
    };
    let mut x: [Fp; 16] = std::array::from_fn(|i| if i < 8 { left[i] } else { right[i - 8] });
    transcript::external(&mut x);
    x
}

/// The advice's malicious block word, in the row of the SIB whose block is
/// the advice's block 1, the first programs' op 15: a word pair whose low
/// word is 0 and whose high word is `2^−32`, so the hash would take the lane
/// 1 while a load of the low word sees 0. With the row's other child and `u`
/// recomputed over that lane every other row-local relation holds; the high
/// word's own bound refuses it, whatever halfword stands beside it.
#[test]
fn a_block_word_no_load_could_read_is_refused() {
    let (program, archive) = traced();
    let s = Shard::new(program, archive, family::MPT_NODES);
    let r = 15;
    let mut row = s.row(r);
    let advice = constants::guest_memory::ADVICE_ORIGIN as u64;
    assert!(
        row[s.at("arg_read_value")].to_u64() > advice && row[s.at("block")] == Fp::ONE,
        "row 15 reads a block in the advice"
    );
    let high = f(1 << 32).inverse().expect("a unit");
    for (cell, v) in [
        ("w0_read_value", Fp::ZERO),
        ("w0_h16", Fp::ZERO),
        ("w1_read_value", high),
        ("other0", Fp::ONE),
    ] {
        row[s.at(cell)] = v;
    }
    for (j, v) in node_u(&s, &row).iter().enumerate() {
        row[s.at(&format!("u{j}"))] = *v;
    }
    for h in [0, 1, 0xffff, (high.to_u64() >> 16) & 0xffff] {
        row[s.at("w1_h16")] = f(h);
        let broken = s.refused(&row, r);
        assert!(
            !broken.is_empty() && broken.iter().all(|n| n.starts_with("w1_")),
            "halfword {h:#x}: the forged word is refused by its bound alone, not {broken:?}"
        );
    }
}

/// A sampled lane at or above `T`, the call's lane 0 forged with its digits,
/// its rest and its writes recomputed from the lane's value mod `p`, so its
/// identity and every other row-local relation hold. At `T` the digits are 0
/// and the rest 808, refused by the rest's bound alone. At `2^64 − 1`, two
/// words that make 58 mod `p`, the digits are 58's, refused by the high
/// word's bound alone, whatever halfword stands beside it: without it a lane
/// at or above `p` would sample as its residue.
#[test]
fn a_sampled_lane_at_or_above_t_is_refused() {
    let (program, archive) = traced();
    let s = Shard::new(program, archive, family::FALCON_SAMPLE);
    let forged = |x: u64| {
        let mut row = s.row(0);
        let (lo, hi) = (x & 0xffff_ffff, x >> 32);
        let v = (f(lo) + f(hi) * f(1 << 32)).to_u64();
        let d = |j: u32| v / 12289u64.pow(j) % 12289;
        for (cell, value) in [
            ("w0_read_value", lo),
            ("w1_read_value", hi),
            ("w0_write_value", d(0) | d(1) << 16),
            ("w1_write_value", d(2) | d(3) << 16),
            ("d0_0", d(0)),
            ("d0_1", d(1)),
            ("d0_2", d(2)),
            ("d0_3", d(3)),
            ("e0", v / Q4),
        ] {
            row[s.at(cell)] = f(value);
        }
        (row, f((T - 1) >> 32) - f(hi))
    };
    let (mut row, gap) = forged(T);
    row[s.at("hb0_h16")] = f(gap.to_u64() >> 16);
    assert_eq!(s.refused(&row, 0), ["e0_high"], "a lane at T");
    let (mut row, gap) = forged(u64::MAX);
    for h in [0, 1, 0xffff, (gap.to_u64() >> 16) & 0xffff] {
        row[s.at("hb0_h16")] = f(h);
        let broken = s.refused(&row, 0);
        assert!(
            !broken.is_empty() && broken.iter().all(|n| n.starts_with("hb0_")),
            "halfword {h:#x}: a lane at 2^64 − 1 is refused by its high word's bound alone, \
             not {broken:?}"
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
            family::ADVICE_WINDOWS => trace::advice_window_count(archive.advice(), h),
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

/// An edit of `fam`'s shard 0: row `row` made `forged` where it is not
/// `honest`, `s`'s committed columns in order.
fn forge_row<'a>(
    fam: u32,
    row: usize,
    s: &'a Shard,
    honest: &'a [Fp],
    forged: &'a [Fp],
) -> impl Fn(u32, u32, &mut [(PolyAddress, MultilinearPoly)]) + 'a {
    let committed = s.a.committed();
    move |f, index, columns| {
        if (f, index) != (fam, 0) {
            return;
        }
        for (i, v) in forged.iter().enumerate().filter(|(i, v)| **v != honest[*i]) {
            let (_, c) = columns
                .iter_mut()
                .find(|(x, _)| *x == committed[i])
                .expect("a committed column");
            let mut values: Vec<Fp> = (0..c.len()).map(|r| c.get_base(r)).collect();
            values[row] = *v;
            *c = MultilinearPoly::new(PolyBacking::Fp(values));
        }
    }
}

#[test]
fn the_statement_reconciles_and_a_round_moved_to_another_call_does_not() {
    let (program, archive) = traced();
    assert!(balances(
        program,
        archive,
        &roots(program, archive, &|_, _, _| {})
    ));

    // Call 1's first round row, moved to call 0's cycle: every row-local
    // relation of the row still holds — a cycle has no gate on a round row —
    // and the state it reads and writes is now call 0's twice and call 1's
    // never.
    let s = Shard::new(program, archive, family::POSEIDON2_ROUNDS);
    let (cycle, row) = (s.at("cycle"), 16);
    let mut moved = s.row(row);
    moved[cycle] = s.row(0)[cycle];
    assert!(
        s.refused(&moved, row).is_empty(),
        "the moved row is a valid round"
    );
    let at = s.a.column("cycle").expect("a cycle column");
    let edit = |fam: u32, index: u32, columns: &mut [(PolyAddress, MultilinearPoly)]| {
        if (fam, index) != (family::POSEIDON2_ROUNDS, 0) {
            return;
        }
        let (_, c) = columns
            .iter_mut()
            .find(|(x, _)| *x == at)
            .expect("the cycle column");
        let mut values: Vec<Fp> = (0..c.len()).map(|i| c.get_base(i)).collect();
        values[row] = values[0];
        *c = MultilinearPoly::new(PolyBacking::Fp(values));
    };
    assert!(!balances(program, archive, &roots(program, archive, &edit)));

    // The long trie program's continuation across MPT_ROUNDS' shards, one
    // off: the parked lane 0 its op 6,135, the JOIN opening shard 1, takes,
    // which a SIB's or a LOAD's carry holds none of.
    assert!(!continuation_balances(
        program,
        archive,
        family::MPT_ROUNDS,
        CONTINUED,
        10
    ));

    // The first JOIN, the first programs' op 7, taking a value no op parked:
    // its other child's lane 0 one off and its `u` recomputed. Every row-local
    // relation holds — a JOIN reads no block, so nothing on its row holds the
    // value to one — and the park it receives is one no op sent, while its
    // op's park is sent and never received.
    let fam = family::MPT_NODES;
    let s = Shard::new(program, archive, fam);
    let row = 7;
    let honest = s.row(row);
    assert_eq!(honest[s.at("is_join")], Fp::ONE, "row 7 is a JOIN");
    let mut taken = honest.clone();
    taken[s.at("other0")] += Fp::ONE;
    for (j, v) in node_u(&s, &taken).iter().enumerate() {
        taken[s.at(&format!("u{j}"))] = *v;
    }
    assert!(
        s.refused(&taken, row).is_empty(),
        "the forged JOIN is a valid row"
    );
    let edit = forge_row(fam, row, &s, &honest, &taken);
    assert!(!balances(program, archive, &roots(program, archive, &edit)));

    // A Falcon product row claiming another residue: call 0's row of residue
    // 3, its one-hot and index moved to residue 5 and its 96 residues, its
    // wrapped products and its quotient chunks recomputed, residue 5's own.
    // Every row-local relation holds — a residue is nothing to a row but its
    // one-hot, its `β_r` and the pairs it reads — and the pairs it reads are
    // residue 5's, which residue 5's row reads too, while residue 3's are
    // written and never read.
    let fam = family::FALCON_PRODUCT;
    let s = Shard::new(program, archive, fam);
    let (row, to) = (3, 5);
    let honest = s.row(row);
    assert!(
        honest[s.at("o3")] == Fp::ONE && honest[s.at("r")] == f(3),
        "row 3 is residue 3's"
    );
    let theirs = s.row(to);
    let mut moved = honest.clone();
    moved[s.at("o3")] = Fp::ZERO;
    moved[s.at("o5")] = Fp::ONE;
    moved[s.at("r")] = f(5);
    let recomputed = (0..32)
        .flat_map(|i| ["a", "b", "d"].map(|x| format!("{x}{i}")))
        .chain((0..31).map(|k| format!("wrap{k}")))
        .chain((0..32).flat_map(|k| (0..3).map(move |c| format!("w{k}_c{c}"))));
    for name in recomputed {
        moved[s.at(&name)] = theirs[s.at(&name)];
    }
    assert!(
        s.refused(&moved, row).is_empty(),
        "the moved row is a valid product row"
    );
    let edit = forge_row(fam, row, &s, &honest, &moved);
    assert!(!balances(program, archive, &roots(program, archive, &edit)));

    // A Falcon split row claiming the next column: call 0's column 3 of chain
    // `c`, its stamp and its key one up. Every row-local relation holds — a
    // column is nothing to a row but its stamp and its key — and it reads a
    // control at column 4's stamp that no row sends, its pointer column 3's,
    // and sends its residues at column 4's place, while column 2's control is
    // sent and never read.
    let fam = family::FALCON_SPLIT;
    let s = Shard::new(program, archive, fam);
    let row = 32 + 3;
    let honest = s.row(row);
    assert!(
        honest[s.at("stamp")] == f(constraints::falcon::start(2) + 3),
        "row 35 is chain c's column 3"
    );
    let mut moved = honest.clone();
    for name in ["stamp", "key"] {
        moved[s.at(name)] += Fp::ONE;
    }
    assert!(
        s.refused(&moved, row).is_empty(),
        "the moved row is a valid split row"
    );
    let edit = forge_row(fam, row, &s, &honest, &moved);
    assert!(!balances(program, archive, &roots(program, archive, &edit)));
}

// ---------------------------------------------------------------------------
// A program across shards
// ---------------------------------------------------------------------------

/// The chunks a streaming run of the guest hands over that `keep` keeps, in
/// fill order, the rest dropped as they come.
fn stream(
    program: &Program,
    keep: impl Fn(&emulator::ShardChunk) -> bool,
) -> Vec<emulator::ShardChunk> {
    let io = emulator::GuestIo {
        input: input(),
        advice: duplex().0,
    };
    let mut run =
        emulator::StreamingRun::new(&program.image, &io, &program.tables, &program.config)
            .expect("it starts");
    let mut chunks = Vec::new();
    loop {
        let ready = run.next_shards().expect("it streams");
        if ready.is_empty() {
            break;
        }
        chunks.extend(ready.into_iter().filter(&keep));
    }
    let tail = run.finish().expect("it finishes").0;
    chunks.extend(tail.into_iter().filter(&keep));
    chunks
}

/// Shard `index` of `fam` filled from `calls` alone, as a streaming prover
/// fills a chunk, its multiplicities counted.
fn filled_from(
    program: &Program,
    archive: &TraceArchive,
    fam: u32,
    index: u32,
    calls: &trace::DelegationTrace,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let height = program.config.height(fam).expect("a config family");
    let circuit = family_circuit(fam, height.trailing_zeros()).expect("its circuit");
    let source = ShardSource {
        program,
        input: &archive.io_streams().input,
        advice: archive.advice(),
        rows: ShardRows::Invocations(trace::FrameSlice::shard(calls, 0, height as usize)),
        index,
        height: height as usize,
        window: 0,
    };
    let fill = prover::family_fill(fam).expect("its fill");
    let mut columns = fill(&source).unwrap_or_else(|e| panic!("family {fam}: {e}"));
    let counts = trace::build_multiplicities(&circuit.artifact, &columns, &circuit.channels)
        .unwrap_or_else(|e| panic!("family {fam}: {e}"));
    columns.extend(counts);
    columns
}

/// Every column's values by its address.
fn values(columns: &[(PolyAddress, MultilinearPoly)]) -> BTreeMap<PolyAddress, Vec<Fp>> {
    columns
        .iter()
        .map(|(x, c)| (*x, (0..c.len()).map(|r| c.get_base(r)).collect()))
        .collect()
}

/// Shard 1 of round family `fam` as a streaming run hands it over: a call's
/// last entries alone, the first at op `first`, their carries the
/// continuation.
fn continued(program: &Program, fam: u32, first: u64) -> trace::DelegationTrace {
    let chunk = stream(program, |c| c.family == fam && c.index == 1)
        .pop()
        .and_then(|c| c.calls)
        .expect("a second round shard");
    assert_eq!(
        chunk.carry[9].first(),
        Some(&first),
        "family {fam}'s shard 1 opens at its call's op {first}"
    );
    chunk
}

/// The op that opens `MPT_ROUNDS`' shard 1 at `2^16`: the guest's hash op
/// 4,096 from 0, past the 7 before the long program its step 4,090, an even
/// step, so its JOIN, op `3·4,090/2`.
const CONTINUED: u64 = 6_135;

/// Whether the statement reconciles with round family `fam`'s shard 1 filled
/// from its streamed continuation, the first entry's carry value `k` one off.
/// Every row of the forged shard holds, its rounds a permutation of what they
/// read; the round opening it reads a state no row sent.
fn continuation_balances(
    program: &Program,
    archive: &TraceArchive,
    fam: u32,
    first: u64,
    k: usize,
) -> bool {
    let mut forged = continued(program, fam, first);
    forged.carry[k][0] = (f(forged.carry[k][0]) + Fp::ONE).to_u64();
    let columns = filled_from(program, archive, fam, 1, &forged);
    let vars = program
        .config
        .height(fam)
        .expect("its height")
        .trailing_zeros();
    let circuit = family_circuit(fam, vars).expect("its circuit");
    let s = Shard::of(
        fam,
        circuit.artifact,
        columns.clone(),
        forged.rows() as usize,
    );
    for r in 0..s.live + 2 {
        let broken = s.refused(&s.row(r), r);
        assert!(
            broken.is_empty(),
            "the forged shard's row {r} breaks {broken:?}"
        );
    }
    let forged: BTreeMap<PolyAddress, MultilinearPoly> = columns.into_iter().collect();
    let edit = |f: u32, index: u32, columns: &mut [(PolyAddress, MultilinearPoly)]| {
        if (f, index) == (fam, 1) {
            for (x, c) in columns.iter_mut() {
                *c = forged[x].clone();
            }
        }
    };
    balances(program, archive, &roots(program, archive, &edit))
}

/// The guest's long trie program straddles `MPT_ROUNDS`' two shards, and the
/// second, streamed, holding only the call's last hash ops and their carries,
/// fills exactly as the archive's shard 1 does. The statement test forges its
/// continuation.
#[test]
fn a_call_across_a_round_shard_streams_as_its_archive() {
    let (program, archive) = traced();
    let fam = family::MPT_ROUNDS;
    let streamed = filled_from(
        program,
        archive,
        fam,
        1,
        &continued(program, fam, CONTINUED),
    );
    let (_, archived) = filled(program, archive, fam, 1, 0);
    assert_eq!(
        values(&streamed),
        values(&archived),
        "the streamed shard is the archived one"
    );
}
