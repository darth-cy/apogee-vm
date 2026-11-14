//! The seven execution families' circuits against the prover's fill of real
//! guest traces, in ordinary CI and without a proof (`docs/spec/circuits.md`
//! §3).
//!
//! For each family, the guests that run it are traced and the family's first
//! shard filled by `prover::family_fill` at `2^20` rows. Then:
//!
//! - **the fill is honest**: its setup columns are the decoded table and the
//!   packed generic table, every gated tuple is a row of its table
//!   (`trace::build_multiplicities` refuses one that is not), and every live
//!   row, the two padding rows after them and the last row satisfy every gate
//!   and every lookup;
//! - **every kind runs**, so those rows cover the family;
//! - **every written word is pinned**: on one row of each kind, each word the
//!   row writes — the pc, `rd`'s two words, a RAM word — one off is refused by
//!   that row alone;
//! - **no constraint is dead**: over the same rows, single-cell edits of `±1`
//!   and `+2^32` make every row-local gate and every lookup refuse at least
//!   once.
//!
//! Two forgeries keep every identity and break only an inequality — a flipped
//! 64-bit comparison and a remainder past its divisor — and each is refused by
//! the range obligations on the gap it moved, and by nothing else. And
//! `MEM_SUBWORD`'s splice, at one bit to a byte, admits exactly one witness.
//! The proofs of tampered rows are `tests/tamper.rs`'.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use checker::{
    check_laws, check_lookup_discharge, check_padding, check_padding_identity, violated_lookups,
    violated_relations, WitnessRow,
};
use constants::{challenge_slot, family, lookup_channel};
use constraints::lookup::check_discharge;
use constraints::memory::check_memory;
use constraints::{family_circuit, mem_subword, CircuitArtifact, GateDef, PolyAddress};
use field::{Fp, Fp2};
use gkr::{eval_gate, gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use poly::MultilinearPoly;
use prover::Program;
use trace::{IoStreams, PhaseTiming, TraceArchive};

/// The height every execution family is filled at.
const VARS: u32 = 20;
const ROWS: usize = 1 << VARS;
const T32: u64 = 1 << 32;

fn f(v: u64) -> Fp {
    Fp::from_u64(v)
}

/// A signed integer as a field element.
fn fi(v: i64) -> Fp {
    if v < 0 {
        -f(v.unsigned_abs())
    } else {
        f(v as u64)
    }
}

// ---------------------------------------------------------------------------
// Guests and shards
// ---------------------------------------------------------------------------

/// What each guest reads: `atomics`' iteration count, `opcodes`' mode 0 and
/// the bytes its loads read, and four numbers for `cpp-primes` to test.
fn input(name: &str) -> Vec<u8> {
    match name {
        "atomics" => 37u32.to_le_bytes().to_vec(),
        "opcodes" => vec![0, 0, 0, 0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6],
        "cpp-primes" => [97u64, 561, 1_000_000_007, u64::MAX - 58]
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect(),
        _ => Vec::new(),
    }
}

/// Guest `name`, every execution family at `2^20`, traced into an archive.
fn traced(name: &str) -> (Program, TraceArchive) {
    let image = loader::load_elf(&test_support::guest_elf(name)).expect("the guest loads");
    let mut params = program::ProgramParams::defaults();
    params.heights[..=family::ATOMICS as usize].fill(1 << VARS);
    let (tables, config) = program::decode_program(&image, &params).expect("it decodes");
    let io = emulator::GuestIo {
        input: input(name),
        advice: Vec::new(),
    };
    let (traces, log, profile, execution) = emulator::trace_run(&image, &io, &tables, &config)
        .unwrap_or_else(|e| panic!("{name}: {e}"));
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

/// One family's filled shard 0, with what a row needs to be judged alone.
struct Shard {
    a: CircuitArtifact,
    /// The committed columns in layout order.
    columns: Vec<MultilinearPoly>,
    index: BTreeMap<PolyAddress, usize>,
    /// Each table channel's rows, as gated tuples.
    tables: BTreeMap<u32, HashSet<Vec<u64>>>,
    ch: ExternalChallenges,
    live: usize,
}

impl Shard {
    /// The family's fill of `archive`'s first shard, its setup columns held
    /// to the decoded table and the packed generic table, and every channel's
    /// multiplicities counted over it.
    fn new(program: &Program, archive: &TraceArchive, fam: u32) -> Shard {
        let circuit = family_circuit(fam, VARS).expect("the family's circuit");
        let fill = prover::family_fill(fam).expect("the family's fill");
        let source = prover::ShardSource::archived(program, archive, fam, 0, ROWS as u32, 0)
            .expect("the shard's rows");
        let filled = fill(&source).expect("the fill");
        let table = program.tables.family(fam).expect("the family's table");
        let generic = circuit
            .reads_generic_table()
            .then(|| program::lookup_tables::generic_table(VARS));
        let width = circuit.artifact.setup.len() - generic.as_ref().map_or(0, Vec::len);
        let counts = trace::build_multiplicities(&circuit.artifact, &filled, &circuit.channels)
            .unwrap_or_else(|e| panic!("family {fam}: {e}"));
        let n = filled.len() + counts.len();
        let mut filled: BTreeMap<PolyAddress, MultilinearPoly> =
            filled.into_iter().chain(counts).collect();
        assert_eq!(n, filled.len(), "the fill writes each column once");
        let missing: Vec<PolyAddress> = circuit
            .artifact
            .committed()
            .into_iter()
            .filter(|x| !filled.contains_key(x))
            .collect();
        assert!(missing.is_empty(), "the fill has no {missing:?}");
        let a = circuit.artifact;
        assert_eq!(
            filled.len(),
            a.committed().len(),
            "one column per committed address"
        );
        for j in 0..a.setup.len() {
            let want = match (j.checked_sub(width), &generic) {
                (Some(g), Some(packed)) => packed[g].clone(),
                _ => table.column_poly(j),
            };
            let got = &filled[&PolyAddress::Setup(j as u32)];
            assert!(
                (0..ROWS).all(|i| got.get(i) == want.get(i)),
                "S[{j}] is not its table"
            );
        }
        let columns: Vec<MultilinearPoly> = a
            .committed()
            .iter()
            .map(|x| {
                filled
                    .remove(x)
                    .unwrap_or_else(|| panic!("the fill has no {x}"))
            })
            .collect();
        let index: BTreeMap<PolyAddress, usize> = a
            .committed()
            .into_iter()
            .enumerate()
            .map(|(i, x)| (x, i))
            .collect();
        let mut tables = BTreeMap::new();
        for spec in circuit
            .channels
            .iter()
            .filter(|s| !lookup_channel::IS_RANGE[s.channel as usize])
        {
            let at: Vec<&MultilinearPoly> = spec.table.iter().map(|x| &columns[index[x]]).collect();
            let rows = (0..ROWS).map(|r| at.iter().map(|c| c.get_base(r).to_u64()).collect());
            tables.insert(spec.channel, rows.collect::<HashSet<Vec<u64>>>());
        }
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
        insert_lookup_challenges(&mut ch, f(29).into(), f(31).into(), &a);
        let live = archive
            .family_traces()
            .family(fam)
            .expect("the family's buffer")
            .len();
        Shard {
            a,
            columns,
            index,
            tables,
            ch,
            live,
        }
    }

    fn row(&self, r: usize) -> Vec<Fp> {
        self.columns.iter().map(|c| c.get_base(r)).collect()
    }

    /// The layout position of the column `name`.
    fn at(&self, name: &str) -> usize {
        let x = self
            .a
            .column(name)
            .unwrap_or_else(|| panic!("no column `{name}`"));
        self.index[&x]
    }

    fn value(&self, g: &GateDef, row: &[Fp], r: usize) -> Fp2 {
        let operands: Vec<Fp2> = g
            .operands()
            .iter()
            .map(|x| match x {
                PolyAddress::Virtual(k) => virtual_at_row(*k, r).into(),
                x => row[self.index[x]].into(),
            })
            .collect();
        eval_gate(g, &operands, &self.ch)
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
        // A table channel's tuple, gated as `docs/spec/lookup.md` §4 gates it.
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
                    let raw = self.value(g, row, r).c0;
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

    /// The row-local enforcing relations and every lookup, by name: what the
    /// edits of a dead-constraint search must make refuse.
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

    /// The kind column set on live row `r`.
    fn kind(&self, row: &[Fp]) -> String {
        let names = self.a.witness.iter().filter(|n| n.starts_with("kind_"));
        let set: Vec<&String> = names.filter(|n| row[self.at(n)] == Fp::ONE).collect();
        assert_eq!(set.len(), 1, "a live row has one kind");
        set[0].clone()
    }
}

// ---------------------------------------------------------------------------
// The generic suite
// ---------------------------------------------------------------------------

/// The suite of the module header for one family over `guests`.
fn holds(fam: u32, guests: &[&str]) {
    let label = program::family_name(fam);
    let mut kinds: BTreeSet<String> = BTreeSet::new();
    let (mut refusing, mut every) = (BTreeSet::new(), BTreeSet::new());
    for name in guests {
        let (program, archive) = traced(name);
        let s = Shard::new(&program, &archive, fam);
        assert!(s.live > 0, "{name} runs no {label} row");
        for r in (0..s.live + 2).chain([ROWS - 1]) {
            let broken = s.refused(&s.row(r), r);
            assert!(
                broken.is_empty(),
                "{label}: {name} row {r} breaks {broken:?}"
            );
        }
        every = s.constraints();

        // One row of each kind not yet sampled, and the first padding row.
        let mut samples = vec![s.live];
        for r in 0..s.live {
            if kinds.insert(s.kind(&s.row(r))) {
                samples.push(r);
            }
        }
        let names: Vec<&String> = s.a.memory.iter().chain(&s.a.witness).collect();
        for r in samples {
            let honest = s.row(r);
            let edited = |i: usize, by: Fp| {
                let mut row = honest.clone();
                row[i] += by;
                s.refused(&row, r)
            };
            if r < s.live {
                for q in names
                    .iter()
                    .filter(|n| n.ends_with("_write_value") || n.ends_with("_write_hi"))
                {
                    let query = q.split('_').next().expect("a query name");
                    if honest[s.at(&format!("{query}_mask"))] == Fp::ONE {
                        let what =
                            format!("{label}: {name} row {r} ({}): {q} one off", s.kind(&honest));
                        assert!(!edited(s.at(q), Fp::ONE).is_empty(), "{what} is accepted");
                    }
                }
            }
            for n in names.iter().filter(|n| !n.starts_with("mult_")) {
                for by in [Fp::ONE, -Fp::ONE, f(T32)] {
                    refusing.extend(edited(s.at(n), by));
                }
            }
        }
    }
    let all: BTreeSet<String> = every_kind(fam);
    assert_eq!(kinds, all, "{label}: the guests run every kind");
    let dead: Vec<&String> = every.difference(&refusing).collect();
    assert!(
        dead.is_empty(),
        "{label}: no single-cell edit makes {dead:?} refuse"
    );
}

/// The family's kind columns, read off its circuit.
fn every_kind(fam: u32) -> BTreeSet<String> {
    let a = family_circuit(fam, VARS)
        .expect("the family's circuit")
        .artifact;
    a.witness
        .iter()
        .filter(|n| n.starts_with("kind_"))
        .cloned()
        .collect()
}

#[test]
fn add_sub_lui_auipc() {
    // `opcodes` makes ecalls nobody answers, which no row of this family
    // proves: its one provable ecall is `exit`.
    holds(family::ADD_SUB_LUI_AUIPC, &["addsub", "cpp-primes"]);
}

#[test]
fn jump_branch_slt() {
    holds(
        family::JUMP_BRANCH_SLT,
        &["control", "opcodes", "cpp-primes"],
    );
}

#[test]
fn bitwise() {
    holds(family::BITWISE, &["alu", "opcodes"]);
}

#[test]
fn mul_div() {
    holds(family::MUL_DIV, &["alu", "opcodes", "cpp-primes"]);
}

#[test]
fn mem_word() {
    holds(family::MEM_WORD, &["mem", "opcodes"]);
}

#[test]
fn mem_subword() {
    holds(family::MEM_SUBWORD, &["mem", "opcodes"]);
}

#[test]
fn atomics() {
    holds(family::ATOMICS, &["atomics", "mem", "opcodes"]);
}

/// Every family's circuit round-trips through its wire form and keeps every
/// rule both enforcement points hold it to — the laws, the padding contract
/// and its product-tree clause, the memory rules and the discharge rule — by
/// `constraints` and, sharing no code, by this crate. Below `2^20` there is no
/// circuit: the timestamp channel's table is `2^19` rows of it.
#[test]
fn every_family_circuit_keeps_every_rule() {
    for fam in 0..=family::ATOMICS {
        let c = family_circuit(fam, VARS).expect("the family's circuit");
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
        assert!(family_circuit(fam, 18).is_none(), "family {fam} at 2^18");
    }
}

// ---------------------------------------------------------------------------
// Forgeries that keep every identity
// ---------------------------------------------------------------------------

/// `cells` written into `row` by name.
fn forge(s: &Shard, row: &[Fp], cells: &[(&str, Fp)]) -> Vec<Fp> {
    let mut row = row.to_vec();
    for (name, v) in cells {
        row[s.at(name)] = *v;
    }
    row
}

/// A comparison flipped against its operands: every `slt`, `sltu`, `slti` and
/// `sltiu` of `control` and `opcodes` that writes a register, with `lt`
/// negated and every column that follows it re-solved — the gap's high word
/// moved by `2^32`, so `cmp_hi` holds; `eq` and its inverse; `rd` — is refused
/// by the gap's range obligations and by nothing else. The comparison is
/// `crate::family::compare64`, which `ATOMICS` shares.
#[test]
fn a_flipped_comparison_is_refused_by_its_gap_alone() {
    let mut flipped = 0;
    for name in ["control", "opcodes"] {
        let (program, archive) = traced(name);
        let s = Shard::new(&program, &archive, family::JUMP_BRANCH_SLT);
        for r in 0..s.live {
            let row = s.row(r);
            let get = |n: &str| row[s.at(n)];
            let slt = ["slt", "sltu", "slti", "sltiu"]
                .iter()
                .any(|k| get(&format!("kind_{k}")) == Fp::ONE);
            if !slt || get("rd_addr") == Fp::ZERO {
                continue;
            }
            let lt = get("cmp_lt");
            let moved = if lt == Fp::ONE { -f(T32) } else { f(T32) };
            let x = get("cmp_gap_lo") + get("cmp_gap_hi") + moved;
            let forged = forge(
                &s,
                &row,
                &[
                    ("cmp_lt", Fp::ONE - lt),
                    ("cmp_gap_hi", get("cmp_gap_hi") + moved),
                    ("eq", f((x == Fp::ZERO) as u64)),
                    ("eq_inv", x.inverse().unwrap_or(Fp::ZERO)),
                    ("rd_selected", Fp::ONE - lt),
                    ("rd_write_value", Fp::ONE - lt),
                ],
            );
            let broken = s.refused(&forged, r);
            assert!(
                !broken.is_empty() && broken.iter().all(|b| b.starts_with("cmp_gap_hi")),
                "{name} row {r}: the flipped comparison breaks {broken:?}"
            );
            flipped += 1;
        }
    }
    assert!(flipped >= 8, "only {flipped} comparisons flipped");
}

/// A division whose quotient is one short, with the remainder grown by the
/// divisor so `q·B + r` is still the dividend and every chunk identity holds:
/// on each small unsigned division of `alu`, `opcodes` and `cpp-primes`, and
/// whichever carry the forger puts in the bound's range, the bound
/// `|B| − |r| − 1` is negative and the range obligations on its two words
/// refuse it, and nothing else does.
#[test]
fn a_remainder_past_its_divisor_is_refused_by_the_bound_alone() {
    let mut forged_rows = 0;
    for name in ["alu", "opcodes", "cpp-primes"] {
        let (program, archive) = traced(name);
        let s = Shard::new(&program, &archive, family::MUL_DIV);
        for r in 0..s.live {
            let row = s.row(r);
            let get = |n: &str| row[s.at(n)].to_u64();
            let kind = ["divu", "remu", "divuw", "remuw"].map(|k| get(&format!("kind_{k}")) == 1);
            let (q, rem, b) = (get("q_lo"), get("r_lo"), get("b_lo"));
            let high = get("q_hi") + get("r_hi") + get("b_hi") + get("rs1_read_hi");
            let small = high == 0
                && (2..1 << 15).contains(&b)
                && (1..1 << 16).contains(&q)
                && rem + b < 1 << 16;
            if !kind.contains(&true) || get("rd_addr") == 0 || !small {
                continue;
            }
            let rd = if kind[0] || kind[2] { q - 1 } else { rem + b };
            for carry in -3i64..=0 {
                let low = -(rem as i64 + 1) - carry * T32 as i64;
                let h16 = |v: i64| {
                    f(if (0..T32 as i64).contains(&v) {
                        v as u64 >> 16
                    } else {
                        0
                    })
                };
                let forged = forge(
                    &s,
                    &row,
                    &[
                        ("q_lo", f(q - 1)),
                        ("r_lo", f(rem + b)),
                        ("r_is_zero", Fp::ZERO),
                        ("r_inv", f(rem + b).inverse().expect("nonzero")),
                        ("bound_carry", fi(carry)),
                        ("bound_lo", fi(low)),
                        ("bound_lo_h16", h16(low)),
                        ("bound_hi", fi(carry)),
                        ("bound_hi_h16", h16(carry)),
                        ("rd_selected", f(rd)),
                        ("rd_write_value", f(rd)),
                    ],
                );
                let broken = s.refused(&forged, r);
                assert!(
                    !broken.is_empty() && broken.iter().all(|b| b.starts_with("bound_")),
                    "{name} row {r}, carry {carry}: the short quotient breaks {broken:?}"
                );
            }
            forged_rows += 1;
        }
    }
    assert!(
        forged_rows >= 2,
        "only {forged_rows} small unsigned divisions"
    );
}

// ---------------------------------------------------------------------------
// The splice at a reduced width
// ---------------------------------------------------------------------------

/// At one bit to a byte the splice admits exactly one witness.
///
/// `mem_subword::splice_gates` is the seam the family's own gates come from;
/// at **one bit to a byte** a word is 4 bits, a "byte" 1 and a "halfword" 2,
/// and every literal of the twelve gates is derived from that width by the
/// circuit, not transcribed here. For every `(word, offset, width)` a load
/// admits — all four offsets for a byte, the two even ones for a halfword —
/// every `(high, sub, low)` in `[0, 16)^3` is a candidate, and a candidate is a
/// witness when every gate holds **and** every column a bound covers is below
/// `2^4`, each scaled column solved from its own gate inside the bound.
#[test]
fn the_splice_admits_exactly_one_witness_at_a_reduced_width() {
    const B: u32 = 1;
    let full = 1u64 << (4 * B);
    let gates = mem_subword::splice_gates(B);
    assert_eq!(gates.len(), 12);
    let a = mem_subword::artifact(VARS);
    let x = |name: &str| {
        a.column(name)
            .unwrap_or_else(|| panic!("no column `{name}`"))
    };
    let eval = |g: &GateDef, v: &BTreeMap<PolyAddress, Fp>| {
        let operands: Vec<Fp2> = g.operands().iter().map(|o| v[o].into()).collect();
        eval_gate(g, &operands, &ExternalChallenges::new()).c0
    };
    // The one value below `window` zeroing gate `name` in `column`.
    let solve = |name: &str, column: &str, v: &mut BTreeMap<PolyAddress, Fp>, window: u64| {
        let g = &gates
            .iter()
            .find(|(n, _)| n == name)
            .expect("a seam gate")
            .1;
        let mut found = None;
        for c in 0..window {
            v.insert(x(column), f(c));
            if eval(g, v) == Fp::ZERO {
                assert!(found.is_none(), "`{name}` is solved twice below {window}");
                found = Some(c);
            }
        }
        v.insert(x(column), f(found.unwrap_or(0)));
        found
    };
    let mut cases = 0;
    for byte in [true, false] {
        let width = if byte { 1u64 << B } else { 1 << (2 * B) };
        for offset in (0..4u64).filter(|o| byte || o % 2 == 0) {
            let p = 1u64 << (B * offset as u32);
            for word in 0..full {
                cases += 1;
                let mut base: BTreeMap<PolyAddress, Fp> = BTreeMap::new();
                for k in mem_subword::KINDS {
                    base.insert(x(&format!("kind_{k}")), Fp::ZERO);
                }
                base.insert(x(if byte { "kind_lbu" } else { "kind_lhu" }), Fp::ONE);
                for (column, value) in [
                    ("pc_mask", 1),
                    ("bit0", offset & 1),
                    ("bit1", offset >> 1),
                    ("word", word),
                    // No RAM query, no source, no sign extension.
                    ("ram_mask", 0),
                    ("ram_write_value", 0),
                    ("rs2_read_value", 0),
                    ("p_ram", 0),
                    ("src_sub", 0),
                    ("src_high", 0),
                    ("src_sub_scaled", 0),
                    ("se", 0),
                ] {
                    base.insert(x(column), f(value));
                }
                for (gate, column) in [
                    ("p_rule", "p"),
                    ("pcopow_rule", "pcopow"),
                    ("wph_rule", "wph"),
                ] {
                    solve(gate, column, &mut base, 2 * full).expect("the offset's constants");
                }
                assert_eq!(base[&x("p")], f(p), "the offset's power");
                let partners = |part: &str, scaled: &str, gate: &str| -> Vec<Option<u64>> {
                    (0..full)
                        .map(|v| {
                            let mut b = base.clone();
                            b.insert(x(part), f(v));
                            solve(gate, scaled, &mut b, full)
                        })
                        .collect()
                };
                let highs = partners("high", "high_scaled", "high_scaled_rule");
                let subs = partners("sub", "sub_scaled", "sub_scaled_rule");
                let lows = partners("low", "low_scaled", "low_scaled_rule");
                let mut witnesses = Vec::new();
                for (high, hs) in highs.iter().enumerate() {
                    for (sub, ss) in subs.iter().enumerate() {
                        for (low, ls) in lows.iter().enumerate() {
                            let (Some(hs), Some(ss), Some(ls)) = (hs, ss, ls) else {
                                continue;
                            };
                            let mut v = base.clone();
                            for (column, value) in [
                                ("high", high as u64),
                                ("high_scaled", *hs),
                                ("sub", sub as u64),
                                ("sub_scaled", *ss),
                                ("low", low as u64),
                                ("low_scaled", *ls),
                            ] {
                                v.insert(x(column), f(value));
                            }
                            solve("sign_in_rule", "sign_in", &mut v, 2 * full).expect("sign_in");
                            solve("rd_value_rule", "rd_selected", &mut v, 2 * full).expect("rd");
                            if gates.iter().all(|(_, g)| eval(g, &v) == Fp::ZERO) {
                                witnesses.push((high as u64, sub as u64, low as u64));
                            }
                        }
                    }
                }
                assert_eq!(
                    witnesses,
                    [(word / (width * p), (word / p) % width, word % p)],
                    "word {word} at offset {offset}, byte {byte}"
                );
            }
        }
    }
    assert_eq!(cases, 96, "16 words at each of six offsets");
}
