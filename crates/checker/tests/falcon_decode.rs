//! `FALCON512_DECODE` over a real execution, without a proof
//! (`docs/spec/precompiles.md` §8, `constraints::falcon_decode`): a
//! hand-assembled guest decoding a public key's `h` and a signature's `s2`,
//! both compact and fresh from `apogee-falcon512`'s randomized signer, its
//! `FALCON_DECODE` shard filled from the run:
//!
//! - **the circuit keeps every rule**, by `constraints` and, with no shared
//!   code, by this crate, at every height it builds at;
//! - **the rows are the definitions'**: every row's slots, placed again from
//!   its in-state and its codewords by the encodings' definitions alone, are
//!   the fill's, and each row's in-state is the row before's out-state;
//! - **the fill holds**: every live row and the padding after it satisfy
//!   every row-local gate and lookup; and it refuses, by `Err`, an entry its
//!   call did not write;
//! - **no constraint is dead**: single-cell edits of `±1` and `+2^32` on each
//!   mode's frame row and a chain row and on the padding make every row-local
//!   gate and lookup refuse, and each written word one off is refused by its
//!   row alone;
//! - **the statement reconciles**: every shard forwarded, the roots and the
//!   boundary multiply out, the chain through space 9 among them; a row
//!   claiming the next row's stamp keeps every row-local relation and does
//!   not;
//! - **a forged row is refused by its one rule**: a key field at or above `q`,
//!   a `−0`, a codeword placed one bit late, a flushed limb that disagrees
//!   with its word, a flushed word with a bit set after the end, and a
//!   signature ending past 5,000 bits, each with every other cell the forgery
//!   moves recomputed.

use std::collections::{BTreeMap, BTreeSet};

use checker::{
    check_laws, check_lookup_discharge, check_padding, check_padding_identity, memory_roots,
    violated_lookups, violated_relations, WitnessRow,
};
use constants::delegation::falcon_decode::{
    END, FRAME, KEY, OUTPUT, ROWS, SIGNATURE, SIGNATURE_BITS, SOURCE,
};
use constants::{challenge_slot, ecall, family, guest_memory};
use constraints::lookup::check_discharge;
use constraints::memory::check_memory;
use constraints::{family_circuit, CircuitArtifact, PolyAddress};
use field::{Fp, Fp2};
use gkr::{
    boundary_factors, forward, gate_values, insert_lookup_challenges, reconciles, virtual_at_row,
    window_challenges, BaseLayer, ExternalChallenges,
};
use loader::{ProgramImage, Segment, Slot};
use poly::{MultilinearPoly, PolyBacking};
use prover::{Program, ShardRows, ShardSource};
use trace::{IoStreams, PhaseTiming, TraceArchive};

const FAM: u32 = family::FALCON_DECODE;
const Q: u64 = 12289;
/// The signature's call's first row: the key's call is rows `0..128`.
const SIGNED: usize = ROWS;

fn f(v: u64) -> Fp {
    Fp::from_u64(v)
}

/// `bytes` as RAM holds them: little-endian words, the last zero-padded.
fn le_words(bytes: &[u8]) -> Vec<u32> {
    let word = |c: &[u8]| {
        let mut w = [0; 4];
        w[..c.len()].copy_from_slice(c);
        u32::from_le_bytes(w)
    };
    bytes.chunks(4).map(word).collect()
}

/// The guest: a fresh key's `h` at one address and a signature's `s2` at
/// another, both compact in the image — the key's 224 words, the stream's
/// words through its last bit — and two calls, the key's and the
/// signature's, each into a polynomial of its own; then `exit(0)`. The
/// signature is drawn until its stream ends inside a word, so that its call
/// flushes: a key's never does. Traced with its execution families at
/// `2^20`, their floor, and every other at `2^16`.
fn traced() -> (Program, TraceArchive) {
    let (sk, pk) = apogee_falcon512::keygen([7; 32]);
    assert_eq!(pk[0], 0x09, "a v1.2 key");
    let stream = loop {
        let sig = apogee_falcon512::sign(&sk, b"a purchase", b"");
        let words = le_words(&sig[41..]);
        let d = emulator::falcon512_decode(SIGNATURE, &words).expect("a signature");
        if !d.end.is_multiple_of(32) {
            break words[..d.read].to_vec();
        }
    };
    let code_at = guest_memory::RAM_ORIGIN;
    let frames = code_at + 0x2000;
    let (dst0, dst1) = (frames + 0x1000, frames + 0x2000);
    let (key_at, sig_at) = (code_at + 0x8000, code_at + 0x9000);
    let data = [key_at, dst0, KEY, 0, sig_at, dst1, SIGNATURE, 0];
    // `lui a0, frames`, `li a7, FALCON512_DECODE`, a call, `a0 += 16`, a
    // call, then `exit(0)`.
    let (a0, a7) = (10, 17);
    let addi = |rd: u32, rs1: u32, imm: u32| imm << 20 | rs1 << 15 | rd << 7 | 0x13;
    let code = [
        frames | a0 << 7 | 0x37,
        addi(a7, 0, ecall::FALCON512_DECODE),
        0x73,
        addi(a0, a0, 16),
        0x73,
        addi(a7, 0, ecall::EXIT),
        addi(a0, 0, 0),
        0x73,
    ];
    let segment = |vaddr: u32, words: &[u32]| Segment {
        vaddr,
        mem_len: 4 * words.len() as u32,
        bytes: words.iter().flat_map(|w| w.to_le_bytes()).collect(),
    };
    let image = ProgramImage {
        entry: code_at,
        segments: vec![
            segment(code_at, &code),
            segment(frames, &data),
            segment(key_at, &le_words(&pk[1..])),
            segment(sig_at, &stream),
        ],
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
        delegations: vec![ecall::FALCON512_DECODE],
    };
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
    let io = emulator::GuestIo {
        input: Vec::new(),
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
    let program = Program {
        image,
        tables,
        config,
    };
    (program, archive)
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

/// Shard `index` of `fam`: its fill, multiplicities counted.
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

/// `FALCON_DECODE`'s shard 0, with what a row needs to be judged alone.
struct Shard {
    a: CircuitArtifact,
    columns: Vec<MultilinearPoly>,
    index: BTreeMap<PolyAddress, usize>,
    ch: ExternalChallenges,
    rows: usize,
    live: usize,
}

/// One slot's codeword: a key's field `x`, or a signature's sign `b`, low
/// bits and `k` zeros.
#[derive(Clone, Copy, Debug)]
struct Codeword {
    b: u64,
    low: u64,
    k: u64,
    x: u64,
}

impl Shard {
    fn new(program: &Program, archive: &TraceArchive) -> Shard {
        let (a, columns) = filled(program, archive, FAM, 0, 0);
        let calls = archive.family_traces().delegation(FAM).expect("its buffer");
        let mut by: BTreeMap<PolyAddress, MultilinearPoly> = columns.into_iter().collect();
        let committed = a.committed();
        let columns: Vec<MultilinearPoly> = committed
            .iter()
            .map(|x| {
                by.remove(x)
                    .unwrap_or_else(|| panic!("the fill has no {x}"))
            })
            .collect();
        let index = committed.into_iter().enumerate().map(|(i, x)| (x, i));
        let mut ch = memory_slots();
        insert_lookup_challenges(&mut ch, f(29).into(), f(31).into(), &a);
        let rows = 1usize << a.trace_vars;
        Shard {
            index: index.collect(),
            columns,
            ch,
            rows,
            live: calls.rows() as usize,
            a,
        }
    }

    fn row(&self, r: usize) -> Vec<Fp> {
        self.columns.iter().map(|c| c.get_base(r)).collect()
    }

    fn at(&self, name: &str) -> usize {
        let x = self.a.column(name);
        self.index[&x.unwrap_or_else(|| panic!("no column `{name}`"))]
    }

    fn get(&self, row: &[Fp], name: &str) -> u64 {
        row[self.at(name)].to_u64()
    }

    fn set(&self, row: &mut [Fp], name: &str, v: Fp) {
        row[self.at(name)] = v;
    }

    /// Every row-local relation and range obligation `row` breaks at `r`,
    /// its scratch computed from it.
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

    /// Slot `u`'s codeword as `row` holds it.
    fn codeword(&self, row: &[Fp], u: usize) -> Codeword {
        let k = (0..4).map(|i| self.get(row, &format!("k{u}_{i}")) << i);
        Codeword {
            b: self.get(row, &format!("b{u}")),
            low: self.get(row, &format!("low{u}")),
            k: k.sum(),
            x: self.get(row, &format!("x{u}")),
        }
    }

    /// `row`'s slots placed again from its in-state by the definitions alone,
    /// slot `u` the codeword `words[u]`: `L` bits at `o`, completing the limb
    /// where `o + L ≥ 32`, its `E` then `2^32·E/2^L` and else `E/2^L` — or
    /// half that at slot `late`, the codeword placed one bit later and every
    /// one after it with it. A completing slot's bytes are the limb's, the
    /// high word of `2^32·A + C·e`. Every cell the codewords determine is
    /// written: each slot's, the out-state and the output words; the frame,
    /// the ports' read timestamps and gaps and the in-state are left.
    fn place(&self, row: &mut [Fp], words: [Codeword; 4], late: Option<usize>) {
        let m = self.get(row, "m");
        let [mut o, mut e, mut a, mut sa, mut acc] =
            ["o_in", "e_in", "a_in", "sa_in", "acc_in"].map(|n| self.get(row, n));
        let mut v = [0u64; 4];
        for (u, w) in words.iter().enumerate() {
            let len = 9 + w.k;
            let c = (o + len >= 32) as u64;
            let mut e_out = ((e as u128) << (32 * c) >> len) as u64;
            if late == Some(u) {
                e_out /= 2;
            }
            let pow = 2u64 << w.k;
            let csig = (128 * w.b + w.low) * pow + 1;
            let cw = if m == 1 { csig } else { w.x };
            let mag = m * (w.low + 128 * w.k);
            let bs = w.b * mag;
            let z = cw as u128 * e_out as u128;
            let a_out = match c {
                0 => (a as u128 + z) as u64,
                _ => {
                    let total = ((a as u128) << 32) + z;
                    let be = (total >> 32) as u64;
                    let bytes = [be >> 24, be >> 16 & 0xff, be >> 8 & 0xff, be & 0xff];
                    for (j, byte) in bytes.iter().enumerate() {
                        self.set(row, &format!("p{u}_b{j}"), f(*byte));
                    }
                    let word: u64 = (0..4).map(|j| bytes[j] << (8 * j)).sum();
                    self.set(row, &format!("p{u}_read_value"), f(word));
                    total as u64 & 0xffff_ffff
                }
            };
            let k = |i: u64| w.k >> i & 1;
            for (name, value) in [
                ("b", w.b),
                ("low", w.low),
                ("p1_", 1 << (k(0) + 2 * k(1))),
                ("p2_", 1 << (4 * k(2) + 8 * k(3))),
                ("pow", pow),
                ("x", w.x),
                ("csig", csig),
                ("cw", cw),
                ("mag", mag),
                ("bs", bs),
                ("z", z as u64),
                ("c", c),
                ("e", e_out),
                ("a", a_out),
            ] {
                self.set(row, &format!("{name}{u}"), f(value));
            }
            for i in 0..4 {
                self.set(row, &format!("k{u}_{i}"), f(k(i)));
            }
            self.set(row, &format!("a{u}_h16"), f(a_out >> 16));
            let inv = f(bs).inverse().unwrap_or(Fp::ZERO);
            self.set(row, &format!("inv{u}"), inv);
            if u > 0 {
                self.set(row, &format!("sa{u}"), f(sa));
            }
            v[u] = w.x + mag + Q * w.b - 2 * bs;
            (o, e, a, sa, acc) = (o + len - 32 * c, e_out, a_out, sa + 4 * c, acc + mag * mag);
        }
        for (name, value) in [
            ("o_out", o),
            ("sa_out", sa),
            ("acc_out", acc),
            ("out0_write_value", v[0] | v[1] << 16),
            ("out1_write_value", v[2] | v[3] << 16),
        ] {
            self.set(row, name, f(value));
        }
    }
}

// ---------------------------------------------------------------------------
// The circuit and its rows
// ---------------------------------------------------------------------------

/// The circuit keeps every rule, by `constraints` and, with no shared code,
/// by this crate, at every height it builds at, and none below `2^16`, its
/// `RANGE16` table's.
#[test]
fn the_decode_circuit_keeps_every_rule() {
    for height in constants::family::HEIGHT_MENU {
        let vars = height.trailing_zeros();
        let Some(c) = family_circuit(FAM, vars) else {
            assert!(vars < 16, "no circuit at 2^{vars}");
            continue;
        };
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
    }
}

/// Each row's slots are its codewords placed by the definitions; each row's
/// in-state the row before's out-state, a call's first row's the start — the
/// limb empty at the source, in either mode — with stamps `4r` and outputs
/// `8r` past the destination; and every live row and the padding after it
/// hold every row-local rule.
#[test]
fn every_row_is_its_codewords_placed_and_holds() {
    let (program, archive) = traced();
    let s = Shard::new(&program, &archive);
    assert_eq!(s.live, 2 * ROWS, "two calls of 128 rows");
    let names = ["o", "e", "a", "sa", "acc"];
    for r in 0..s.live {
        let honest = s.row(r);
        let mut again = honest.clone();
        let words = std::array::from_fn(|u| s.codeword(&honest, u));
        s.place(&mut again, words, None);
        assert!(again == honest, "row {r} is not its codewords placed");
        let (call, at) = (r / ROWS, r % ROWS);
        let first = s.row(call * ROWS);
        let dst = s.get(&first, "w1_read_value");
        let stamp_da = [s.get(&honest, "stamp"), s.get(&honest, "da")];
        assert_eq!(stamp_da, [4 * at as u64, dst + 8 * at as u64], "row {r}");
        let state_in = names.map(|n| s.get(&honest, &format!("{n}_in")));
        let want = match at {
            0 => [0, 1 << 32, 0, s.get(&first, "w0_read_value"), 0],
            _ => {
                let before = s.row(r - 1);
                let out = ["o_out", "e3", "a3", "sa_out", "acc_out"];
                out.map(|n| s.get(&before, n))
            }
        };
        assert_eq!(state_in, want, "row {r}'s in-state");
    }
    for r in (0..(s.live + 2).min(s.rows)).chain([s.rows - 1]) {
        let broken = s.refused(&s.row(r), r);
        assert!(broken.is_empty(), "row {r} breaks {broken:?}");
    }
}

#[test]
fn no_decode_constraint_is_dead() {
    let (program, archive) = traced();
    let s = Shard::new(&program, &archive);
    let names: Vec<&String> = s.a.memory.iter().chain(&s.a.witness).collect();
    let mut refusing = BTreeSet::new();
    for r in [0, 1, SIGNED, SIGNED + 1, s.live] {
        let honest = s.row(r);
        let edited = |i: usize, by: Fp| {
            let mut row = honest.clone();
            row[i] += by;
            s.refused(&row, r)
        };
        if r % ROWS == 0 && r < s.live {
            for q in names.iter().filter(|n| n.ends_with("_write_value")) {
                assert!(
                    !edited(s.at(q), Fp::ONE).is_empty(),
                    "row {r}: {q} one off is accepted"
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
    assert!(dead.is_empty(), "no single-cell edit makes {dead:?} refuse");
}

/// A change to the decode's buffer.
type Change<'a> = &'a dyn Fn(&mut trace::DelegationTrace);

/// The fill refuses, by `Err`, an entry its call did not write: a source
/// word of the key's with a bit flipped, a coefficient one off, `END` one
/// off, the word after the signature's stream present, or its last word's
/// last bit, after its end, set.
#[test]
fn the_fill_refuses_an_entry_its_call_did_not_write() {
    let (program, archive) = traced();
    let honest = archive.family_traces().delegation(FAM).expect("its buffer");
    let height = program.config.height(FAM).expect("its height") as usize;
    let fill = prover::family_fill(FAM).expect("its fill");
    let attempt = |edit: Change| {
        let mut calls = honest.clone();
        edit(&mut calls);
        let source = ShardSource {
            program: &program,
            input: &[],
            advice: &[],
            rows: ShardRows::Invocations(trace::FrameSlice::shard(&calls, 0, height)),
            index: 0,
            height,
            window: 0,
        };
        fill(&source).map(|_| ())
    };
    assert_eq!(attempt(&|_| {}), Ok(()));
    let source = FRAME + OUTPUT;
    let flipped = |t: &mut trace::DelegationTrace| {
        let q = &mut t.words[source + 3];
        q.read_value[0] ^= 1 << 9;
        q.write_value[0] ^= 1 << 9;
    };
    let coefficient = |t: &mut trace::DelegationTrace| t.words[FRAME + 5].write_value[0] += 1;
    let end = |t: &mut trace::DelegationTrace| t.words[END].write_value[0] += 1;
    // The signature's source words, the slots before the first absent.
    let n = (0..SOURCE)
        .take_while(|i| honest.words[source + i].addr[1] != 0)
        .count();
    let past = |t: &mut trace::DelegationTrace| {
        let (at, ts) = (
            t.words[source + n - 1].addr[1] + 4,
            t.words[source].read_ts[1],
        );
        let q = &mut t.words[source + n];
        (q.addr[1], q.read_ts[1]) = (at, ts);
    };
    let after = |t: &mut trace::DelegationTrace| {
        let q = &mut t.words[source + n - 1];
        q.read_value[1] |= 1 << 24;
        q.write_value[1] |= 1 << 24;
    };
    let edits: [(&str, Change); 5] = [
        ("a flipped source bit", &flipped),
        ("a coefficient one off", &coefficient),
        ("END one off", &end),
        ("a word past the stream", &past),
        ("a bit set after the end", &after),
    ];
    for (what, edit) in edits {
        assert!(attempt(edit).is_err(), "{what} is filled");
    }
}

// ---------------------------------------------------------------------------
// The forgeries
// ---------------------------------------------------------------------------

/// The first chain row of the call at `from` and its slot whose codeword
/// `pick` accepts.
fn find(s: &Shard, from: usize, pick: impl Fn(Codeword) -> bool) -> (usize, usize) {
    (from + 1..from + ROWS)
        .flat_map(|r| (0..4).map(move |u| (r, u)))
        .find(|&(r, u)| pick(s.codeword(&s.row(r), u)))
        .expect("a slot to forge")
}

/// A key field at or above `q`, as 14 bits would hold it: its stream, its
/// placement and its coefficient all its own; the field's bound alone
/// refuses it.
#[test]
fn a_key_field_at_or_above_q_is_refused() {
    let (program, archive) = traced();
    let s = Shard::new(&program, &archive);
    let (r, u) = find(&s, 0, |w| w.x + Q < 1 << 14);
    let mut row = s.row(r);
    let mut words = std::array::from_fn(|i| s.codeword(&row, i));
    words[u].x += Q;
    s.place(&mut row, words, None);
    assert_eq!(s.refused(&row, r), [format!("x{u}_high")]);
}

/// A signature coefficient `−0`, sign 1 and size 0, in a codeword of a
/// small coefficient's length: refused by `mz` alone.
#[test]
fn a_minus_zero_is_refused() {
    let (program, archive) = traced();
    let s = Shard::new(&program, &archive);
    let (r, u) = find(&s, SIGNED, |w| w.k == 0);
    let mut row = s.row(r);
    let mut words = std::array::from_fn(|i| s.codeword(&row, i));
    words[u] = Codeword {
        b: 1,
        low: 0,
        k: 0,
        x: 0,
    };
    s.place(&mut row, words, None);
    assert_eq!(s.refused(&row, r), [format!("mz{u}")]);
}

/// A codeword placed one bit later than its offset says, every codeword
/// after it in the row with it, each limb's bytes and each next limb's bits
/// recomputed: the placement's own rule alone refuses it, in either mode.
#[test]
fn a_codeword_placed_one_bit_off_is_refused() {
    let (program, archive) = traced();
    let s = Shard::new(&program, &archive);
    for (r, u) in [(5, 1), (SIGNED + 7, 2)] {
        let mut row = s.row(r);
        let words = std::array::from_fn(|i| s.codeword(&row, i));
        s.place(&mut row, words, Some(u));
        assert_eq!(s.refused(&row, r), [format!("e_out{u}")], "row {r}");
    }
}

/// The signature's last word with a bit of the stream flipped, its bytes and
/// its word the flipped ones: the limb the chain placed disagrees with the
/// word the flush read, and the flush's rule alone refuses it. A key, ending
/// on a word, flushes nothing.
#[test]
fn a_flushed_limb_that_disagrees_with_its_word_is_refused() {
    let (program, archive) = traced();
    let s = Shard::new(&program, &archive);
    let key = s.row(0);
    let ended = (s.get(&key, "f"), s.get(&key, "o_e"));
    assert_eq!(ended, (0, 0), "a key flushes nothing");
    let mut row = s.row(SIGNED);
    let ended = (s.get(&row, "f"), s.get(&row, "o_e"));
    let end = s.get(&row, "w3_write_value");
    assert_eq!(ended, (1, end % 32), "the signature flushes");
    let (b0, w) = (s.get(&row, "flush_b0"), s.get(&row, "flush_read_value"));
    s.set(&mut row, "flush_b0", f(b0 ^ 0x80));
    s.set(&mut row, "flush_read_value", f(w ^ 0x80));
    assert_eq!(s.refused(&row, SIGNED), ["flush"]);
}

/// The signature's last word with the first bit after its end set, its bytes
/// and its word the set ones: the word is the stream's bits but not zeros
/// after them, and the flush's rule alone refuses it.
#[test]
fn a_flushed_word_with_a_bit_set_after_the_end_is_refused() {
    let (program, archive) = traced();
    let s = Shard::new(&program, &archive);
    let mut row = s.row(SIGNED);
    let o_e = s.get(&row, "o_e");
    assert_eq!(s.get(&row, "f"), 1, "the signature flushes");
    // Bit `o_e` of the limb, its first after the end: byte `o_e / 8`'s.
    let (j, bit) = (o_e / 8, 7 - o_e % 8);
    let name = format!("flush_b{j}");
    let (b, w) = (s.get(&row, &name), s.get(&row, "flush_read_value"));
    assert_eq!(b >> bit & 1, 0, "a zero after the end");
    s.set(&mut row, &name, f(b | 1 << bit));
    s.set(&mut row, "flush_read_value", f(w | 1 << (8 * j + bit)));
    assert_eq!(s.refused(&row, SIGNED), ["flush"]);
}

/// The signature's stream claimed to end past 5,000 bits: `END` and the end
/// state's limb moved on by whole words, `zz` recomputed, so every rule but
/// `zz`'s bound holds.
#[test]
fn a_signature_ending_past_5000_bits_is_refused() {
    let (program, archive) = traced();
    let s = Shard::new(&program, &archive);
    let mut row = s.row(SIGNED);
    let end = s.get(&row, "w3_write_value");
    let words = (SIGNATURE_BITS as u64 - end) / 32 + 1;
    let sa_e = s.get(&row, "sa_e");
    s.set(&mut row, "w3_write_value", f(end + 32 * words));
    s.set(&mut row, "sa_e", f(sa_e + 4 * words));
    s.set(
        &mut row,
        "zz",
        f(SIGNATURE_BITS as u64) - f(end + 32 * words),
    );
    assert_eq!(s.refused(&row, SIGNED), ["zz_range"]);
}

// ---------------------------------------------------------------------------
// The statement
// ---------------------------------------------------------------------------

/// Every shard of the statement forwarded, `(read_root, write_root)` each,
/// `FALCON_DECODE`'s shard 0's row `forged.0` made `forged.1` first.
fn roots(
    program: &Program,
    archive: &TraceArchive,
    forged: Option<(usize, &[Fp])>,
) -> Vec<(Fp2, Fp2)> {
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
        if let (Some((r, values)), true) = (forged, (fam, index) == (FAM, 0)) {
            let committed = a.committed();
            for (x, c) in columns.iter_mut() {
                let i = committed.iter().position(|y| y == x).expect("committed");
                let mut column: Vec<Fp> = (0..c.len()).map(|y| c.get_base(y)).collect();
                column[r] = values[i];
                *c = MultilinearPoly::new(PolyBacking::Fp(column));
            }
        }
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

/// The statement's memory multiplies out, the decode's frames, polynomials,
/// source words and its chain through space 9 among it. A signature row
/// claiming the next row's stamp keeps every row-local relation — a stamp is
/// nothing to a chain row but its tuples' timestamps — and receives a state
/// no row sends, while the state sent to it is never received.
#[test]
fn the_statement_reconciles_and_a_row_at_another_stamp_does_not() {
    let (program, archive) = traced();
    assert!(balances(
        &program,
        &archive,
        &roots(&program, &archive, None)
    ));
    let s = Shard::new(&program, &archive);
    let r = SIGNED + 5;
    let mut moved = s.row(r);
    let stamp = s.at("stamp");
    moved[stamp] += f(4);
    assert!(s.refused(&moved, r).is_empty(), "the moved row holds");
    let forged = roots(&program, &archive, Some((r, &moved)));
    assert!(!balances(&program, &archive, &forged));
}
