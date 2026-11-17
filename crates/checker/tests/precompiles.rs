//! The five precompiles over a real execution, `guests/precompiles` built
//! from source, in ordinary CI and without a proof (`docs/spec/precompiles.md`):
//!
//! - **the journal is the host's**: the Poseidon2 permutation of the
//!   generator's own input and of lanes at `2^64 − 1`, read mod `p`, a Merkle
//!   root, and three `merkle_root` paths, the last after a run of 126, each by
//!   `transcript`; `mul_div` at edges whose answers are hand-derived or a
//!   `u128`'s; Keccak-f[1600] of a state, then of a chain, and SHAKE256 of
//!   a message of three rates, each by RustCrypto's `keccak` and `sha3`; and
//!   Falcon-512's `‖s1‖²` of three arrays and of their rotations, each by the
//!   host's own negacyclic product;
//! - **every precompile circuit keeps every rule**, by `constraints` and, with
//!   no shared code, by this crate;
//! - **the fill holds**: every live row and the padding after it satisfy every
//!   row-local gate and lookup, `ADD_SUB_LUI_AUIPC`'s request rows among them;
//! - **no constraint is dead**: single-cell edits of `±1` and `+2^32` make
//!   every row-local gate and lookup refuse, and each written word one off is
//!   refused by its row alone;
//! - **the statement reconciles**: every shard forwarded, and the roots of all
//!   of them and the boundary multiply out, the anchors and the Poseidon2 and
//!   Merkle, Keccak and Falcon state included. A round row moved to another
//!   call's cycle keeps every row-local relation and does not, nor does a
//!   level taking the other order, nor a path's continuation one off where it
//!   crosses a round shard, nor a chi row claiming the next round, nor a
//!   Falcon product row claiming another residue, nor a split row another
//!   column;
//! - **a path crosses a shard**: the round shard a path continues into fills
//!   from its streamed chunk exactly as from the archive;
//! - **a sibling word is a word**: one no load could read is refused by its
//!   bound alone.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use checker::{
    check_laws, check_lookup_discharge, check_padding, check_padding_identity, memory_roots,
    violated_lookups, violated_relations, WitnessRow,
};
use constants::{challenge_slot, delegation, family, lookup_channel};
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
use sha3::digest::{ExtendableOutput, Update, XofReader};
use trace::{IoStreams, PhaseTiming, TraceArchive};

const DELEGATIONS: [u32; 12] = [
    family::POSEIDON2,
    family::POSEIDON2_ROUNDS,
    family::MUL_DIV_U256,
    family::MERKLE_ROOT,
    family::MERKLE_LEVELS,
    family::MERKLE_ROUNDS,
    family::KECCAK,
    family::KECCAK_RHO,
    family::KECCAK_CHI,
    family::FALCON,
    family::FALCON_SPLIT,
    family::FALCON_PRODUCT,
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

/// The input's path: its slot, every bit of it taken, and its depth, the
/// least a path may have.
const SLOT: u32 = 0xb5a3;
const DEPTH: usize = 16;

/// The depth-32 paths before the guest's depth-20 one: its levels are then
/// 4,080 to 4,099, across level 4,096, where `MERKLE_ROUNDS`' first shard
/// ends at `2^16`.
const RUNS: u32 = 126;

/// Lane `j` of the input path's sibling `l`, the top lane at `p − 1`.
fn sibling(l: usize, j: usize) -> u64 {
    match j {
        7 => field::A64_C5 - 1,
        _ => (l as u64 + 1).wrapping_mul(0xd1b5_4a32_d192_ed03) ^ (j as u64) << 7,
    }
}

/// Lane `i` of the Keccak-f[1600] case's state: arbitrary, and the last at
/// `2^64 − 1`.
fn keccak_lane(i: usize) -> u64 {
    match i {
        24 => u64::MAX,
        _ => (i as u64 + 1).wrapping_mul(0xa076_1d64_78bd_642f) ^ (i as u64) << 3,
    }
}

/// The state's permutations after the first.
const CHAIN: u32 = 2;

/// SHAKE256's message, three rates: absorbed in halves, the first crosses a
/// rate and the second ends on one, so finalizing pads a rate of its own.
const MESSAGE: usize = 3 * 136;

/// The bytes SHAKE256 squeezes, in halves of 548, each crossing rates.
const SQUEEZE: usize = 1096;

/// Byte `i` of SHAKE256's message: arbitrary.
fn message(i: usize) -> u8 {
    (i as u8).wrapping_mul(0x3b) ^ 0x5c
}

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

fn input() -> Vec<u8> {
    let mut out = (LEAVES as u32).to_le_bytes().to_vec();
    for i in 0..LEAVES {
        for j in 0..8 {
            out.extend(leaf(i, j).to_le_bytes());
        }
    }
    out.extend(SLOT.to_le_bytes());
    out.extend((DEPTH as u32).to_le_bytes());
    for l in 0..DEPTH {
        for j in 0..8 {
            out.extend(sibling(l, j).to_le_bytes());
        }
    }
    out.extend(RUNS.to_le_bytes());
    for i in 0..25 {
        out.extend(keccak_lane(i).to_le_bytes());
    }
    out.extend(CHAIN.to_le_bytes());
    out.extend((MESSAGE as u32).to_le_bytes());
    out.extend((0..MESSAGE).map(message));
    out.extend((SQUEEZE as u32).to_le_bytes());
    for a in 0..3 {
        out.extend((0..512).flat_map(|t| falcon_coefficient(a, t).to_le_bytes()));
    }
    out.extend(MORE.to_le_bytes());
    // No Falcon-512 verification: `crates/emulator/tests/guests.rs` runs them.
    out.extend(0u32.to_le_bytes());
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

/// The root of `leaf` at `slot` up `path`: level `L`'s node the first eight
/// lanes of the permutation of the node below and its sibling, the node below
/// first where bit `L` of `slot` is 0.
fn fold(slot: u32, leaf: [u64; 8], path: &[[u64; 8]]) -> [u64; 8] {
    path.iter().enumerate().fold(leaf, |node, (level, sib)| {
        let (l, r) = match slot >> level & 1 {
            0 => (node, *sib),
            _ => (*sib, node),
        };
        let mut s = [0u64; 16];
        s[..8].copy_from_slice(&l);
        s[8..].copy_from_slice(&r);
        std::array::from_fn(|j| permute(s)[j])
    })
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
    let path: Vec<[u64; 8]> = (0..DEPTH)
        .map(|l| std::array::from_fn(|j| sibling(l, j)))
        .collect();
    want.extend(lanes(&fold(SLOT, leaves[0], &path)));
    let ram: Vec<[u64; 8]> = (0..32).map(|l| leaves[l % LEAVES]).collect();
    want.extend(lanes(&fold(u32::MAX, leaves[0], &ram)));
    let run = (0..RUNS).fold(leaves[0], |node, i| fold(i, node, &ram));
    want.extend(lanes(&fold(0x5a5a5, run, &ram[..20])));
    let mut state: [u64; 25] = std::array::from_fn(keccak_lane);
    keccak::f1600(&mut state);
    want.extend(lanes(&state));
    for _ in 0..CHAIN {
        keccak::f1600(&mut state);
    }
    want.extend(lanes(&state));
    let mut shake = sha3::Shake256::default();
    shake.update(&(0..MESSAGE).map(message).collect::<Vec<u8>>());
    let mut squeezed = vec![0u8; SQUEEZE];
    shake.finalize_xof().read(&mut squeezed);
    want.extend(squeezed);
    let arrays: [[u16; 512]; 3] =
        std::array::from_fn(|a| std::array::from_fn(|t| falcon_coefficient(a, t)));
    let norm = |k: usize| {
        let p = |i: usize| &arrays[(i + k) % 3];
        falcon_norm(p(0), p(1), p(2))
    };
    assert!(norm(0) >> 32 != 0, "the norm has a high word");
    want.extend(norm(0).to_le_bytes());
    want.extend((1..=MORE as usize).map(norm).sum::<u64>().to_le_bytes());
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
        // RANGE16's and XOR8's tables need 2^16 rows; POSEIDON2's rounds read
        // no lookup.
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
        // A table column is committed, or for XOR8 a closed form of the row.
        for spec in circuit
            .channels
            .iter()
            .filter(|s| !lookup_channel::IS_RANGE[s.channel as usize])
        {
            let value = |x: &PolyAddress, r: usize| match x {
                PolyAddress::Virtual(k) => virtual_at_row(*k, r).to_u64(),
                x => columns[index[x]].get_base(r).to_u64(),
            };
            let set = (0..rows).map(|r| spec.table.iter().map(|x| value(x, r)).collect());
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
        // A full shard, as `MERKLE_ROUNDS`' first is, has no padding row.
        let padding = (s.live < s.rows).then_some(s.live);
        for r in (0..(s.live + 2).min(s.rows)).chain([s.rows - 1]) {
            let broken = s.refused(&s.row(r), r);
            assert!(broken.is_empty(), "{label} row {r} breaks {broken:?}");
        }
        // Each kind of row once — a frame row, a round row of each kind and
        // the idle one, a Keccak row of planes 0 and 4, the two a selector
        // names, or a Falcon split row of chains `s2` and `c`, whose `s` is 0
        // and is not — and the first padding row, where there is one.
        let samples: Vec<usize> = match fam {
            family::POSEIDON2_ROUNDS | family::MERKLE_ROUNDS => (0..16).chain(padding).collect(),
            family::KECCAK | family::KECCAK_RHO | family::KECCAK_CHI => {
                [0, 4].into_iter().chain(padding).collect()
            }
            family::FALCON_SPLIT => [0, 32].into_iter().chain(padding).collect(),
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

/// What a `MERKLE_LEVELS` row's `u` is over its own cells: `M_E` of its node
/// and the sibling its words give, in its bit's order.
fn level_u(s: &Shard, row: &[Fp]) -> [Fp; 16] {
    let node: Vec<Fp> = (0..8).map(|i| row[s.at(&format!("n{i}"))]).collect();
    let word = |j: usize| row[s.at(&format!("w{j}_read_value"))];
    let sibling: Vec<Fp> = (0..8)
        .map(|k| word(2 * k) + word(2 * k + 1) * f(1 << 32))
        .collect();
    let (left, right) = match row[s.at("bit")] == Fp::ONE {
        true => (&sibling, &node),
        false => (&node, &sibling),
    };
    let mut x: [Fp; 16] = std::array::from_fn(|i| if i < 8 { left[i] } else { right[i - 8] });
    transcript::external(&mut x);
    x
}

/// The advice's malicious sibling: a word pair whose low word is 0 and whose
/// high word is `2^−32`, so the hash would take the lane 1 while a load of the
/// low word sees 0 — a lane no two words give. With the row's `u` recomputed
/// over that lane every other row-local relation holds, as the memory
/// argument would for a word only the advice initialized; the high word's own
/// bound refuses it, whatever halfword stands beside it.
#[test]
fn a_sibling_word_no_load_could_read_is_refused() {
    let (program, archive) = traced();
    let s = Shard::new(&program, &archive, family::MERKLE_LEVELS);
    let mut row = s.row(0);
    let high = f(1 << 32).inverse().expect("a unit");
    for (cell, v) in [
        ("w0_read_value", Fp::ZERO),
        ("w0_h16", Fp::ZERO),
        ("w1_read_value", high),
    ] {
        row[s.at(cell)] = v;
    }
    let u = level_u(&s, &row);
    for (j, v) in u.iter().enumerate() {
        row[s.at(&format!("u{j}"))] = *v;
    }
    for h in [0, 1, 0xffff, (high.to_u64() >> 16) & 0xffff] {
        row[s.at("w1_h16")] = f(h);
        let broken = s.refused(&row, 0);
        assert!(
            !broken.is_empty() && broken.iter().all(|n| n.starts_with("w1_")),
            "halfword {h:#x}: the forged word is refused by its bound alone, not {broken:?}"
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
        &program,
        &archive,
        &roots(&program, &archive, &|_, _, _| {})
    ));

    // Call 1's first round row, moved to call 0's cycle: every row-local
    // relation of the row still holds — a cycle has no gate on a round row —
    // and the state it reads and writes is now call 0's twice and call 1's
    // never.
    let s = Shard::new(&program, &archive, family::POSEIDON2_ROUNDS);
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
    assert!(!balances(
        &program,
        &archive,
        &roots(&program, &archive, &edit)
    ));

    // The input path's level 1 taking the other order, its row recomputed:
    // the bit flipped, the slot's rest halved from it, the node and the
    // sibling swapped through M_E. Every row-local relation holds, and the
    // state and the control it sends are not what the rows after it read.
    let s = Shard::new(&program, &archive, family::MERKLE_LEVELS);
    let row = 1;
    let honest = s.row(row);
    let mut swapped = honest.clone();
    let (bit, rest, next) = (s.at("bit"), s.at("rest"), s.at("rest_next"));
    swapped[bit] = Fp::ONE - honest[bit];
    swapped[next] = (honest[rest] - swapped[bit]) * f(2).inverse().expect("a unit");
    for (j, v) in level_u(&s, &swapped).iter().enumerate() {
        swapped[s.at(&format!("u{j}"))] = *v;
    }
    assert!(
        s.refused(&swapped, row).is_empty(),
        "the swapped level is a valid level"
    );
    let committed = s.a.committed();
    let edit = |fam: u32, index: u32, columns: &mut [(PolyAddress, MultilinearPoly)]| {
        if (fam, index) != (family::MERKLE_LEVELS, 0) {
            return;
        }
        for (i, v) in swapped
            .iter()
            .enumerate()
            .filter(|(i, v)| **v != honest[*i])
        {
            let (_, c) = columns
                .iter_mut()
                .find(|(x, _)| *x == committed[i])
                .expect("a committed column");
            let mut values: Vec<Fp> = (0..c.len()).map(|r| c.get_base(r)).collect();
            values[row] = *v;
            *c = MultilinearPoly::new(PolyBacking::Fp(values));
        }
    };
    assert!(!balances(
        &program,
        &archive,
        &roots(&program, &archive, &edit)
    ));

    // The depth-20 path's continuation across MERKLE_ROUNDS' shards, one off:
    // the node its level 16 starts from, carried into shard 1. Every row of
    // the forged shard holds, its rounds a permutation of what they read, and
    // the round opening it reads a state its level never sent.
    let fam = family::MERKLE_ROUNDS;
    let mut forged = continued(&program);
    forged.carry[0][0] = (f(forged.carry[0][0]) + Fp::ONE).to_u64();
    let columns = filled_from(&program, &archive, fam, 1, &forged);
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
    assert!(!balances(
        &program,
        &archive,
        &roots(&program, &archive, &edit)
    ));

    // A chi row claiming the next round: call 0's B-plane 2 of round 1, its
    // round one-hot moved to round 2 and its stamps recomputed. Every
    // row-local relation holds — a round is nothing to a row but its stamps
    // and, at planes 0 and 4, iota and the next round's D — and the planes it
    // reads and writes are round 2's, which round 2's own row reads and writes
    // too, while round 1's B-plane 2 is written and never read.
    let s = Shard::new(&program, &archive, family::KECCAK_CHI);
    let row = 5 + 2;
    let honest = s.row(row);
    assert!(
        honest[s.at("r1")] == Fp::ONE && honest[s.at("y2")] == Fp::ONE,
        "row 7 is round 1's B-plane 2"
    );
    let mut relabeled = honest.clone();
    relabeled[s.at("r1")] = Fp::ZERO;
    relabeled[s.at("r2")] = Fp::ONE;
    let stamps = ["st_b", "st_pin", "st_pout", "st_a"];
    for (name, stamp) in stamps.iter().zip(constraints::keccak::chi_stamps(2, 2)) {
        relabeled[s.at(name)] = f(stamp);
    }
    assert!(
        s.refused(&relabeled, row).is_empty(),
        "the relabeled row is a valid chi row"
    );
    let committed = s.a.committed();
    let edit = |fam: u32, index: u32, columns: &mut [(PolyAddress, MultilinearPoly)]| {
        if (fam, index) != (family::KECCAK_CHI, 0) {
            return;
        }
        for (i, v) in relabeled
            .iter()
            .enumerate()
            .filter(|(i, v)| **v != honest[*i])
        {
            let (_, c) = columns
                .iter_mut()
                .find(|(x, _)| *x == committed[i])
                .expect("a committed column");
            let mut values: Vec<Fp> = (0..c.len()).map(|r| c.get_base(r)).collect();
            values[row] = *v;
            *c = MultilinearPoly::new(PolyBacking::Fp(values));
        }
    };
    assert!(!balances(
        &program,
        &archive,
        &roots(&program, &archive, &edit)
    ));

    // A Falcon product row claiming another residue: call 0's row of residue
    // 3, its one-hot and index moved to residue 5 and its 96 residues, its
    // wrapped products and its quotient chunks recomputed, residue 5's own.
    // Every row-local relation holds — a residue is nothing to a row but its
    // one-hot, its `β_r` and the pairs it reads — and the pairs it reads are
    // residue 5's, which residue 5's row reads too, while residue 3's are
    // written and never read.
    let fam = family::FALCON_PRODUCT;
    let s = Shard::new(&program, &archive, fam);
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
    assert!(!balances(
        &program,
        &archive,
        &roots(&program, &archive, &edit)
    ));

    // A Falcon split row claiming the next column: call 0's column 3 of chain
    // `c`, its stamp and its key one up. Every row-local relation holds — a
    // column is nothing to a row but its stamp and its key — and it reads a
    // control at column 4's stamp that no row sends, its pointer column 3's,
    // and sends its residues at column 4's place, while column 2's control is
    // sent and never read.
    let fam = family::FALCON_SPLIT;
    let s = Shard::new(&program, &archive, fam);
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
    assert!(!balances(
        &program,
        &archive,
        &roots(&program, &archive, &edit)
    ));
}

// ---------------------------------------------------------------------------
// A path across shards
// ---------------------------------------------------------------------------

/// Every chunk a streaming run of the guest hands over, in fill order.
fn stream(program: &Program) -> Vec<emulator::ShardChunk> {
    let io = emulator::GuestIo {
        input: input(),
        advice: Vec::new(),
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
        chunks.extend(ready);
    }
    chunks.extend(run.finish().expect("it finishes").0);
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

/// `MERKLE_ROUNDS`' shard 1 as a streaming run hands it over: the guest's
/// depth-20 path's levels 16 to 19 alone, their carries the continuation.
fn continued(program: &Program) -> trace::DelegationTrace {
    let chunk = stream(program)
        .into_iter()
        .find(|c| c.family == family::MERKLE_ROUNDS && c.index == 1)
        .and_then(|c| c.calls)
        .expect("a second round shard");
    assert_eq!(
        chunk.carry[delegation::CARRY - 1].first(),
        Some(&16),
        "the shard opens at the depth-20 path's level 16"
    );
    chunk
}

/// The guest's depth-20 path straddles `MERKLE_ROUNDS`' two shards, and the
/// second, streamed, holding only the path's last four levels and their
/// carries, fills exactly as the archive's shard 1 does. The statement test
/// forges that continuation.
#[test]
fn a_path_across_a_round_shard_streams_as_its_archive() {
    let (program, archive) = traced();
    let fam = family::MERKLE_ROUNDS;
    let streamed = filled_from(&program, &archive, fam, 1, &continued(&program));
    let (_, archived) = filled(&program, &archive, fam, 1, 0);
    assert_eq!(
        values(&streamed),
        values(&archived),
        "the streamed shard is the archived one"
    );
}
