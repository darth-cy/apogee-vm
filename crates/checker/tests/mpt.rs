//! `MPT_ROOT`'s three circuits over entries written by hand as an executor
//! records them, without the emulator or a proof (`constraints::mpt`). The
//! program is four ops at a cycle whose `4·cycle` passes `2^32`: a LOAD, a
//! LOAD that parks, a JOIN of that park on the left at depth 511, and a SIB
//! of an advised block on the left. Its root is the trie's, `branch(6, S,
//! branch(511, A, B))`, by the hash formula alone:
//!
//! - **the fill holds**: every live row of `MPT`, `MPT_NODES` and
//!   `MPT_ROUNDS`, and the padding after them, satisfies every row-local gate
//!   and `RANGE16` obligation, the JOIN's row among them, whose masked-out
//!   block words still owe the gap chunks of `4·cycle`;
//! - **the call balances**: the space-10 tuples its rows read and write,
//!   decoded from the circuits' own leaves, are one multiset, and with the
//!   root one off they are not.

use std::collections::BTreeMap;

use checker::{violated_lookups, violated_relations, WitnessRow};
use constants::delegation::mpt::{DEPTH_SHIFT, FRAME, JOIN, LEFT, LOAD, OP_WORDS, PARK, ROOT, SIB};
use constants::{address_space, challenge_slot, ecall, family, guest_memory, memory};
use constraints::{family_circuit, CircuitArtifact, PolyAddress};
use field::{Fp, Fp2};
use gkr::{eval_gate, gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use loader::{ProgramImage, Segment, Slot};
use poly::MultilinearPoly;
use prover::{Program, ShardRows, ShardSource};
use trace::{DelegationTrace, FrameSlice, Query};

const HEIGHT: u32 = 1 << 16;
/// The call's cycle: `4·cycle` takes both gap chunks above the low one.
const CYCLE: u64 = 3 << 30 | 0x1234;
const FRAME_AT: u32 = guest_memory::RAM_ORIGIN + 0x1000;
const OPS_AT: u32 = guest_memory::RAM_ORIGIN + 0x2000;
const A_AT: u32 = guest_memory::RAM_ORIGIN + 0x3000;
const B_AT: u32 = guest_memory::RAM_ORIGIN + 0x3040;
const S_AT: u32 = guest_memory::ADVICE_ORIGIN + 0x100;
/// The JOIN's depth, the largest, and the SIB's.
const D_JOIN: u32 = 511;
const D_SIB: u32 = 6;

fn f(v: u64) -> Fp {
    Fp::from_u64(v)
}

/// `F(x)`: the permutation's first 8 lanes, no feed-forward.
fn compress(x: [Fp; 16]) -> [Fp; 8] {
    let mut s = x;
    transcript::poseidon2_permute(&mut s);
    std::array::from_fn(|i| s[i])
}

fn join(l: [Fp; 8], r: [Fp; 8]) -> [Fp; 16] {
    std::array::from_fn(|i| if i < 8 { l[i] } else { r[i - 8] })
}

/// A branch at crit bit `c`: `F(l ‖ r)` with `c + 1` added to lane 0.
fn branch(c: u32, l: [Fp; 8], r: [Fp; 8]) -> [Fp; 8] {
    let mut out = compress(join(l, r));
    out[0] += f(c as u64 + 1);
    out
}

/// Block `b`'s 16 words: arbitrary, and in `S`'s top lane all ones, a lane at
/// or above `p` that is read mod `p`.
fn block_words(b: u32) -> [u32; 16] {
    std::array::from_fn(|j| match (b, j) {
        (2, 14 | 15) => u32::MAX,
        _ => (b * 16 + j as u32 + 1).wrapping_mul(0x9e37_79b9) ^ (j as u32) << 9,
    })
}

/// A block's lanes, each two words read mod `p`.
fn lanes(words: &[u32; 16]) -> [Fp; 8] {
    std::array::from_fn(|k| f(words[2 * k] as u64 | (words[2 * k + 1] as u64) << 32))
}

/// A word read at the call's timestamp and written back: `j` sets how long
/// ago it was last written.
fn read(addr: u32, value: u32, j: u64) -> Query {
    Query {
        addr,
        read_ts: memory::TS_STEP * (CYCLE - 1000 - 37 * j) + j % 4,
        read_value: value as u64,
        write_value: value as u64,
    }
}

/// The three families' entries for the program, as `delegation::Per` says
/// an executor records them, with the root's lane 0 moved by `skew`.
fn entries(skew: u64) -> [DelegationTrace; 3] {
    let blocks = [A_AT, B_AT, S_AT];
    let words: Vec<[u32; 16]> = (0..3).map(block_words).collect();
    let info = |kind: u32, flags: u32, d: u32| kind | flags | d << DEPTH_SHIFT;
    let ops = [
        (info(LOAD, 0, 0), A_AT),
        (info(LOAD, PARK, 0), B_AT),
        (info(JOIN, LEFT, D_JOIN), 1),
        (info(SIB, LEFT, D_SIB), S_AT),
    ];
    let (a, b, s) = (lanes(&words[0]), lanes(&words[1]), lanes(&words[2]));
    let root = branch(D_SIB, s, branch(D_JOIN, a, b));

    let mut frame = DelegationTrace::new(family::MPT, HEIGHT, FRAME);
    let mut nodes = DelegationTrace::new(family::MPT_NODES, HEIGHT, OP_WORDS);
    let mut rounds = DelegationTrace::new(family::MPT_ROUNDS, HEIGHT, OP_WORDS);
    // The machine of `delegation::mpt`, op by op: the raw lanes, `pending`
    // and the parks.
    let (mut raw, mut pending) = ([Fp::ZERO; 8], 0u64);
    let mut parked: BTreeMap<u32, [Fp; 8]> = BTreeMap::new();
    for (i, &(info, arg)) in ops.iter().enumerate() {
        let i = i as u32;
        let at = OPS_AT + 8 * i;
        let mut cur = raw;
        cur[0] += f(pending);
        let kind = info & 3;
        let mut entry = vec![read(at, info, 0), read(at + 4, arg, 1)];
        let mut carry: Vec<u64> = raw.iter().map(|x| x.to_u64()).collect();
        carry.extend([pending, i as u64]);
        let other = match kind {
            JOIN => {
                let value = parked.remove(&arg).expect("an earlier park");
                entry.resize(OP_WORDS, Query::ABSENT);
                carry.extend(value.iter().map(|x| x.to_u64()));
                value
            }
            _ => {
                let at = blocks.iter().position(|b| *b == arg).expect("a block");
                let block = &words[at];
                for (j, w) in block.iter().enumerate() {
                    entry.push(read(arg + 4 * j as u32, *w, 2 + j as u64));
                }
                carry.extend([0; 8]);
                lanes(block)
            }
        };
        if info & PARK != 0 {
            parked.insert(i, cur);
        }
        nodes.push(CYCLE, at, &entry, &carry);
        (raw, pending) = match kind {
            LOAD => (other, 0),
            _ => {
                rounds.push(CYCLE, at, &entry, &carry);
                let (l, r) = match info & LEFT {
                    0 => (cur, other),
                    _ => (other, cur),
                };
                (compress(join(l, r)), (info >> DEPTH_SHIFT) as u64 + 1)
            }
        };
    }
    assert!(parked.is_empty(), "every park is consumed");
    let mut lane0 = raw;
    lane0[0] += f(pending);
    assert_eq!(lane0, root, "the machine computes the trie's root");

    let mut words: Vec<Query> = Vec::with_capacity(FRAME);
    let old = |j: usize| (j as u32).wrapping_mul(0x85eb_ca6b);
    words.push(read(FRAME_AT, OPS_AT, 40));
    words.push(read(FRAME_AT + 4, ops.len() as u32, 41));
    for (l, value) in root.iter().enumerate() {
        let lane = value.to_u64() + if l == 0 { skew } else { 0 };
        for (h, half) in [lane as u32, (lane >> 32) as u32].into_iter().enumerate() {
            let j = ROOT + 2 * l + h;
            let mut q = read(FRAME_AT + 4 * j as u32, old(j), 42 + j as u64);
            q.write_value = half as u64;
            words.push(q);
        }
    }
    frame.push(CYCLE, FRAME_AT, &words, &[pending]);
    [frame, nodes, rounds]
}

/// A program declaring `MPT_ROOT`, for the shard sources: `exit(0)`.
fn program() -> Program {
    let (a0, a7) = (10, 17);
    let addi = |rd: u32, rs1: u32, imm: u32| imm << 20 | rs1 << 15 | rd << 7 | 0x13;
    let code = [addi(a7, 0, ecall::EXIT), addi(a0, 0, 0), 0x73];
    let code_at = guest_memory::RAM_ORIGIN;
    let image = ProgramImage {
        entry: code_at,
        segments: vec![Segment {
            vaddr: code_at,
            mem_len: 4 * code.len() as u32,
            bytes: code.iter().flat_map(|w| w.to_le_bytes()).collect(),
        }],
        slot_base: code_at,
        slots: code
            .iter()
            .flat_map(|&word| {
                let first = Slot::Instruction {
                    word,
                    compressed: false,
                };
                [first, Slot::MidInstruction]
            })
            .collect(),
        delegations: vec![ecall::MPT_ROOT],
    };
    let params = program::ProgramParams::defaults();
    let (tables, config) = program::decode_program(&image, &params).expect("it decodes");
    for fam in [family::MPT, family::MPT_NODES, family::MPT_ROUNDS] {
        assert_eq!(config.height(fam), Some(HEIGHT), "family {fam}");
    }
    Program {
        image,
        tables,
        config,
    }
}

/// One family's filled shard 0, with what a row needs to be judged alone.
struct Shard {
    fam: u32,
    a: CircuitArtifact,
    columns: Vec<MultilinearPoly>,
    index: BTreeMap<PolyAddress, usize>,
    ch: ExternalChallenges,
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

impl Shard {
    /// `buffer`'s family filled, multiplicities counted, in layout order.
    fn new(program: &Program, buffer: &DelegationTrace) -> Shard {
        let fam = buffer.family;
        let circuit = family_circuit(fam, HEIGHT.trailing_zeros()).expect("its circuit");
        let source = ShardSource {
            program,
            input: &[],
            advice: &[],
            rows: ShardRows::Invocations(FrameSlice::shard(buffer, 0, HEIGHT as usize)),
            index: 0,
            height: HEIGHT as usize,
            window: 0,
        };
        let fill = prover::family_fill(fam).expect("its fill");
        let mut columns = fill(&source).unwrap_or_else(|e| panic!("family {fam}: {e}"));
        let counts = trace::build_multiplicities(&circuit.artifact, &columns, &circuit.channels)
            .unwrap_or_else(|e| panic!("family {fam}: {e}"));
        columns.extend(counts);
        let a = circuit.artifact;
        let mut by: BTreeMap<PolyAddress, MultilinearPoly> = columns.into_iter().collect();
        let committed = a.committed();
        let columns = committed
            .iter()
            .map(|x| {
                by.remove(x)
                    .unwrap_or_else(|| panic!("the fill has no {x}"))
            })
            .collect();
        let mut ch = memory_slots();
        insert_lookup_challenges(&mut ch, f(29).into(), f(31).into(), &a);
        Shard {
            fam,
            index: committed
                .into_iter()
                .enumerate()
                .map(|(i, x)| (x, i))
                .collect(),
            columns,
            ch,
            live: buffer.rows() as usize,
            a,
        }
    }

    fn row(&self, r: usize) -> Vec<Fp> {
        self.columns.iter().map(|c| c.get_base(r)).collect()
    }

    /// Every row-local relation and range obligation row `r` breaks, its
    /// scratch computed from it.
    fn refused(&self, r: usize) -> Vec<String> {
        let (a, row) = (&self.a, self.row(r));
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
            committed: row,
            row: r,
            scratch,
        };
        let mut out = violated_relations(a, &w, &self.ch);
        out.extend(violated_lookups(a, &w));
        out
    }

    /// Row `r`'s live memory leaves, decoded from the circuit's own gates:
    /// each with its side, a write or a read, and its tuple `(space, addr,
    /// ts, val, hi)`. A leaf is `1 + mask·(γ − 1 + space + Σ α·part)`, so
    /// with `γ = 1` and one `α` at 1 it gives its space and that part.
    fn leaves(&self, r: usize) -> Vec<(bool, [u64; 5])> {
        let slots = [
            challenge_slot::MEM_GAMMA,
            challenge_slot::MEM_ALPHA_ADDR,
            challenge_slot::MEM_ALPHA_TS,
            challenge_slot::MEM_ALPHA_VAL,
            challenge_slot::MEM_ALPHA_HI,
        ];
        let probes: Vec<ExternalChallenges> = (0..5)
            .map(|p| {
                let mut ch = ExternalChallenges::new();
                for (i, slot) in slots.iter().enumerate() {
                    ch.insert(*slot, f((i == 0 || i == p) as u64).into());
                }
                ch
            })
            .collect();
        let row = self.row(r);
        let mut out = Vec::new();
        for e in &self.a.layers[0].producing {
            let relation = &self.a.relations[e.relation as usize].name;
            let Some(name) = relation.strip_prefix("define_") else {
                continue;
            };
            let write = name.starts_with("write_") || name.starts_with("send_");
            if !write && !name.starts_with("read_") && !name.starts_with("receive_") {
                continue;
            }
            let operands: Vec<Fp2> = e
                .gate
                .operands()
                .iter()
                .map(|x| row[self.index[x]].into())
                .collect();
            let v: Vec<Fp> = probes
                .iter()
                .map(|ch| eval_gate(&e.gate, &operands, ch).c0 - Fp::ONE)
                .collect();
            if v[0] == Fp::ZERO {
                continue;
            }
            out.push((
                write,
                std::array::from_fn(|i| match i {
                    0 => v[0].to_u64(),
                    _ => (v[i] - v[0]).to_u64(),
                }),
            ));
        }
        out
    }
}

/// The space-10 tuples the three shards read and write, each sorted.
fn space(shards: &[Shard]) -> (Vec<[u64; 5]>, Vec<[u64; 5]>) {
    let (mut reads, mut writes) = (Vec::new(), Vec::new());
    for s in shards {
        for r in 0..s.live {
            for (write, t) in s.leaves(r) {
                if t[0] == address_space::MPT as u64 {
                    match write {
                        true => writes.push(t),
                        false => reads.push(t),
                    }
                }
            }
        }
    }
    reads.sort();
    writes.sort();
    (reads, writes)
}

#[test]
fn every_row_holds_and_the_call_balances() {
    let program = program();
    let buffers = entries(0);
    let shards: Vec<Shard> = buffers.iter().map(|b| Shard::new(&program, b)).collect();
    for s in &shards {
        let label = program::family_name(s.fam);
        assert!(s.live > 0, "{label} has a live row");
        let last = (1 << s.a.trace_vars) - 1;
        for r in (0..s.live + 2).chain([last]) {
            let broken = s.refused(r);
            assert!(broken.is_empty(), "{label} row {r} breaks {broken:?}");
        }
    }
    assert_eq!(
        shards.iter().map(|s| s.live).collect::<Vec<_>>(),
        [1, 4, 2 * 16],
        "a frame row, a row an op and sixteen a hash op"
    );
    let (reads, writes) = space(&shards);
    assert!(!reads.is_empty());
    assert_eq!(reads, writes, "the call's space-10 tuples balance");

    // The root's lane 0 one off: the frame row still holds alone, and the
    // raw lane it receives is no longer the one the last round wrote.
    let skewed = Shard::new(&program, &entries(1)[0]);
    assert!(
        skewed.refused(0).is_empty(),
        "a skewed root's row holds alone"
    );
    let shards = [
        skewed,
        Shard::new(&program, &buffers[1]),
        Shard::new(&program, &buffers[2]),
    ];
    let (reads, writes) = space(&shards);
    assert_ne!(reads, writes, "a root one off balances");
}
