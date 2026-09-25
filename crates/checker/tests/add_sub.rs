//! S16's `ADD_SUB_LUI_AUIPC` circuit (`docs/spec/shard-proof.md` §8), row by
//! row, in ordinary CI.
//!
//! No forward pass over `2^20` rows: each row is built by hand from what the
//! instruction computes — Rust's own `u32` arithmetic, not the circuit's — and
//! evaluated alone through `checker::violated_relations` and
//! `violated_lookups`, its row-local scratch computed by `gkr::gate_values`.
//! Every row kind the family proves satisfies every gate and every range
//! obligation; every gate refuses a row it exists to refuse, most of them as
//! the only gate that does; and the rows S16's negative controls are about
//! break exactly what those controls say. The proofs of the same rows are
//! `crates/checker/tests/tamper.rs`'.

use std::collections::BTreeMap;

use checker::{
    check_laws, check_lookup_discharge, check_padding, check_padding_identity, violated_lookups,
    violated_relations, WitnessRow,
};
use constants::extra_mask::add_sub_lui_auipc as kind;
use constants::{challenge_slot, ecall, family, guest_memory, lookup_channel};
use constraints::lookup::{check_discharge, ChannelSpec};
use constraints::memory::check_memory;
use constraints::{add_sub, family_circuit, CircuitArtifact, PolyAddress, VirtualKind};
use field::Fr;
use gkr::{gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use test_support::{sha256, to_hex};

const VARS: u32 = 20;
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/add_sub.bin"
);
const FIXTURE_SHA256: &str = "7198e023c78379d3e8ae40cc4006c8ebd6c91686b3eabdf6fbbd53a23ac6fde3";

fn artifact() -> CircuitArtifact {
    add_sub::artifact(VARS)
}

fn challenges(a: &CircuitArtifact) -> ExternalChallenges {
    let mut ch = ExternalChallenges::new();
    for (slot, v) in [
        (challenge_slot::MEM_GAMMA, 11),
        (challenge_slot::MEM_ALPHA_ADDR, 13),
        (challenge_slot::MEM_ALPHA_TS, 17),
        (challenge_slot::MEM_ALPHA_VAL, 19),
    ] {
        ch.insert(slot, Fr::from_u64(v));
    }
    insert_lookup_challenges(&mut ch, Fr::from_u64(23), Fr::from_u64(29), a);
    ch
}

fn f(v: u64) -> Fr {
    Fr::from_u64(v)
}

const TWO_32: u64 = 1 << 32;

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// A row by column name; a column not named is 0.
#[derive(Clone, Debug, Default)]
struct Row(BTreeMap<&'static str, Fr>);

impl Row {
    fn set(&mut self, name: &'static str, v: Fr) -> &mut Row {
        self.0.insert(name, v);
        self
    }

    fn get(&self, name: &str) -> Fr {
        self.0.get(name).copied().unwrap_or(Fr::ZERO)
    }

    /// Set the query `q`'s five columns and its gap chunk, reading a write
    /// made eight timestamps before its own.
    fn query(&mut self, q: &'static str, cycle: u64, delta: u64, addr: u64, read: u64, write: u64) {
        self.set(name(q, "mask"), Fr::ONE)
            .set(name(q, "addr"), f(addr))
            .set(name(q, "read_ts"), f(4 * cycle + delta - 8))
            .set(name(q, "read_value"), f(read))
            .set(name(q, "write_value"), f(write));
    }

    /// Drop query `q`: every one of its columns back to 0, as a row that lacks
    /// it carries.
    fn drop_query(&mut self, q: &'static str) {
        for field in ["mask", "addr", "read_ts", "read_value", "write_value"] {
            self.0.remove(name(q, field));
        }
    }

    /// The row as a witness row of `a`, its scratch computed row-locally.
    fn witness(&self, a: &CircuitArtifact, row: usize) -> WitnessRow {
        let names: Vec<&str> = a
            .memory
            .iter()
            .chain(&a.witness)
            .chain(&a.setup)
            .map(|s| s.as_str())
            .collect();
        for key in self.0.keys() {
            assert!(names.contains(key), "the circuit has no column `{key}`");
        }
        let committed: Vec<Fr> = names.iter().map(|n| self.get(n)).collect();
        let virtuals: Vec<Fr> = a
            .virtuals
            .iter()
            .map(|(k, _)| virtual_at_row(*k, row))
            .collect();
        let ch = challenges(a);
        let mut scratch = vec![Fr::ZERO; a.scratch.len()];
        let mut lower = committed.clone();
        for k in 0..a.depth() {
            if a.layers[k].halving {
                break;
            }
            let v: &[Fr] = if k == 0 { &virtuals } else { &[] };
            let values = gate_values(a, k, &lower, &[], v, &ch);
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
        WitnessRow {
            committed,
            row,
            scratch,
        }
    }
}

/// `<q>_<field>`, the frame's column names, leaked to `'static` for the map.
fn name(q: &str, field: &str) -> &'static str {
    Box::leak(format!("{q}_{field}").into_boxed_str())
}

/// One instruction of the family, as the decoded table holds it.
#[derive(Clone, Copy, Debug)]
struct Instr {
    bit: u32,
    pc: u32,
    compressed: bool,
    rs1: u32,
    rs2: u32,
    rd: u32,
    imm: u32,
}

impl Instr {
    fn new(bit: u32, rs1: u32, rs2: u32, rd: u32, imm: u32) -> Instr {
        Instr {
            bit,
            pc: 0x1_0010,
            compressed: false,
            rs1,
            rs2,
            rd,
            imm,
        }
    }
}

/// `(a + b) mod 2^32` and the carry.
fn add(a: u32, b: u32) -> (u32, u32) {
    let (s, c) = a.overflowing_add(b);
    (s, c as u32)
}

const CYCLE: u64 = 9;

/// The honest row of `i` on cycle 9, its reads seeing `rs1v`, `rs2v` and the
/// old `rd` value `rd_old` — an exit's status is `rs2v`, and its `rd` read sees
/// the same `a0`.
///
/// An ecall row whose `a7` is a **delegation** number rather than 93 is a
/// delegation request (`docs/spec/delegation.md` §2): it takes the same ecall
/// frame, carries its type's `is_deleg_t` beside `is_ecall`, makes the mirror query at the
/// `a0` it read, writes 0 into `a0`, and falls through rather than halting.
fn honest(i: Instr, rs1v: u32, rs2v: u32, rd_old: u32) -> Row {
    let system_ecall = i.bit == kind::SYSTEM && i.imm == 0;
    let delegation = system_ecall && rs1v == ecall::PRECOMPILE_KECCAK_F;
    // S25's two. Like a delegation request they are ecalls that fall through,
    // and like it their `a0` write is not what the instruction computes — it is
    // the byte count the executor answered with, which since S25a is pinned to
    // `a2` on a `write` and bounded to `[0, READ_WORD_BYTES]` on a `read`.
    let io = system_ecall && (rs1v == ecall::READ || rs1v == ecall::WRITE);
    let exit = system_ecall && !delegation && !io;
    let fence = i.bit == kind::SYSTEM && i.imm == 2;
    let (sel, wrap) = match i.bit {
        kind::ADD => add(rs1v, rs2v),
        kind::ADDI => add(rs1v, i.imm),
        kind::AUIPC => add(i.pc, i.imm),
        kind::SUB => (rs1v.wrapping_sub(rs2v), (rs1v < rs2v) as u32),
        kind::LUI => (i.imm, 0),
        _ if exit || io => (rd_old, 0),
        _ => (0, 0),
    };
    let fall = i.pc + if i.compressed { 2 } else { 4 };
    let next = if exit { 1 } else { fall };
    let uses_rs1 = matches!(i.bit, kind::ADD | kind::SUB | kind::ADDI) || system_ecall;
    let uses_rs2 = matches!(i.bit, kind::ADD | kind::SUB) || system_ecall;
    let uses_rd = !fence;
    let (rs1_addr, rs2_addr, rd_addr) = match system_ecall {
        true => (17, 10, 10),
        false => (i.rs1, i.rs2, i.rd),
    };

    let mut r = Row::default();
    r.set("cycle", f(CYCLE));
    r.set("pc_mask", Fr::ONE)
        .set("pc_read_ts", f(4 * (CYCLE - 1)))
        .set("pc_read_value", f(i.pc as u64))
        .set("pc_write_value", f(next as u64));
    if uses_rs1 {
        r.query("rs1", CYCLE, 1, rs1_addr as u64, rs1v as u64, rs1v as u64);
    }
    if uses_rs2 {
        r.query("rs2", CYCLE, 2, rs2_addr as u64, rs2v as u64, rs2v as u64);
    }
    if delegation {
        // The mirror query: address the frame base the request passed in `a0`,
        // reading the answer tuple an invocation wrote at timestamp 0, and
        // writing back a value nothing constrains — 0 in an honest fill
        // (`docs/spec/delegation.md` §5.2).
        r.set("deleg_mask", Fr::ONE)
            .set("deleg_addr", f(rs2v as u64));
    }
    if uses_rd {
        let write = if rd_addr == 0 { 0 } else { sel };
        r.query("rd", CYCLE, 3, rd_addr as u64, rd_old as u64, write as u64);
        match rd_addr {
            0 => r.set("rd_is_zero", Fr::ONE),
            a => r.set("rd_inv", f(a as u64).inverse().expect("nonzero")),
        };
    }
    r.set("rd_selected", f(sel as u64))
        .set("wrap", f(wrap as u64))
        .set("rd_hi", f(sel as u64 >> 16))
        .set("next_pc_hi", f(next as u64 >> 16));
    let table = [
        ("next_pc", fall),
        ("rs1", i.rs1),
        ("rs2", i.rs2),
        ("rd", i.rd),
        ("imm", i.imm),
    ];
    for (field, v) in table {
        r.set(name("decoded", field), f(v as u64));
        r.set(name("table", field), f(v as u64));
    }
    r.set("decoded_mask", f(1 << i.bit))
        .set("table_extra_mask", f(1 << i.bit))
        .set("table_pc", f(i.pc as u64));
    let kinds = ["system", "addi", "auipc", "add", "sub", "lui"];
    r.set(name("kind", kinds[i.bit as usize]), Fr::ONE);
    if system_ecall {
        r.set("is_ecall", Fr::ONE);
    }
    if delegation {
        r.set("is_deleg_9", Fr::ONE);
        // The mirror's leaf names the delegation type through this column, and
        // `deleg_space_rule` ties it to the selector above.
        r.set(
            "deleg_space",
            f(constants::address_space::DELEGATION_KECCAK_F as u64),
        );
    }
    if fence {
        r.set("is_fence", Fr::ONE);
    }
    // S25a: which of its call's two descriptors an I/O row names. fd 0 and
    // fd 1 are the committed streams and leave it 0; fd 3 and fd 2 are the
    // uncommitted ones and set it.
    if io && (rs2v == ecall::FD_HINT || rs2v == ecall::FD_STDERR) {
        r.set("fd_uncommitted", Fr::ONE);
    }
    r
}

/// Every row this file names, honest.
fn honest_rows() -> Vec<(&'static str, Row)> {
    let big = 0xffff_efff;
    let small = 0x1234_5678;
    let mut compressed = Instr::new(kind::ADD, 12, 29, 12, 0);
    compressed.compressed = true;
    vec![
        (
            "add, carrying",
            honest(Instr::new(kind::ADD, 5, 6, 7, 0), big, small, 3),
        ),
        (
            "add, not carrying",
            honest(Instr::new(kind::ADD, 6, 6, 28, 0), small, small, 0),
        ),
        (
            "sub, borrowing",
            honest(Instr::new(kind::SUB, 6, 5, 29, 0), small, big, 1),
        ),
        (
            "sub, not borrowing",
            honest(Instr::new(kind::SUB, 5, 6, 30, 0), big, small, 0),
        ),
        (
            "addi of -1, carrying",
            honest(
                Instr::new(kind::ADDI, 5, 0, 5, 0xffff_ffff),
                0xffff_f000,
                0,
                0xffff_f000,
            ),
        ),
        (
            "addi from x0, as c.li",
            honest(Instr::new(kind::ADDI, 0, 0, 11, 0xffff_fffd), 0, 0, 0),
        ),
        (
            "auipc, carrying",
            honest(Instr::new(kind::AUIPC, 0, 0, 31, 0xffff_f000), 0, 0, 0),
        ),
        (
            "auipc, not carrying",
            honest(Instr::new(kind::AUIPC, 0, 0, 9, 0), 0, 0, 0),
        ),
        (
            "lui",
            honest(Instr::new(kind::LUI, 0, 0, 6, 0x1234_5000), 0, 0, 0),
        ),
        (
            "add to x0, carrying",
            honest(Instr::new(kind::ADD, 5, 6, 0, 0), big, small, 0),
        ),
        (
            "sub to x0, borrowing",
            honest(Instr::new(kind::SUB, 6, 5, 0, 0), small, big, 0),
        ),
        ("nop", honest(Instr::new(kind::ADDI, 0, 0, 0, 0), 0, 0, 0)),
        ("c.add, two bytes", honest(compressed, 7, 9, 7)),
        (
            "fence",
            honest(Instr::new(kind::SYSTEM, 0, 0, 0, 2), 0, 0, 0),
        ),
        (
            "exit 42",
            honest(Instr::new(kind::SYSTEM, 0, 0, 0, 0), 93, 42, 42),
        ),
        // S21's row kind: `a7` is the keccak family's number, `a0` the frame
        // base — word-aligned and inside the RAM window, as every frame
        // pointer is (`docs/spec/delegation.md` §4) — and `a0` is written 0.
        (
            "keccak delegation request",
            honest(
                Instr::new(kind::SYSTEM, 0, 0, 0, 0),
                ecall::PRECOMPILE_KECCAK_F,
                guest_memory::RAM_ORIGIN + 0x400,
                7,
            ),
        ),
        // S25's two row kinds. A `read` asks for exactly one 4-aligned word
        // and carries the RAM query that delivers it, on this row; a `write`
        // carries no RAM query at all (`docs/spec/ecall-abi.md` §4).
        (
            "read of one word",
            read_row(
                guest_memory::RAM_ORIGIN + 0x200,
                4,
                0xdead_beef,
                0x0123_4567,
            ),
        ),
        (
            "read at end of stream",
            read_row(
                guest_memory::RAM_ORIGIN + 0x204,
                0,
                0x1111_2222,
                0x1111_2222,
            ),
        ),
        // A short read: fd 0 had one byte left, so `a0` answers 1 and the
        // other three bytes of the word are the old ones. It is a real answer
        // and stays provable — `read_count_gap_range` bounds the count, it
        // does not fix it (`docs/spec/ecall-abi.md` §4.1).
        (
            "short read of one byte",
            read_row(
                guest_memory::RAM_ORIGIN + 0x208,
                1,
                0x1111_2222,
                0x1111_2233,
            ),
        ),
        // The uncommitted descriptors, which stay provable and set
        // `fd_uncommitted`: fd 3 is prover advice and fd 2 is verifier-ignored,
        // and neither is in `io_digest`.
        (
            "read of one word from the hint stream",
            read_row_from(
                ecall::FD_HINT,
                guest_memory::RAM_ORIGIN + 0x20c,
                4,
                0x0000_0000,
                0x89ab_cdef,
            ),
        ),
        (
            "write of nine bytes",
            write_row(guest_memory::RAM_ORIGIN + 0x300, 9),
        ),
        (
            "write of three bytes to stderr",
            write_row_to(ecall::FD_STDERR, guest_memory::RAM_ORIGIN + 0x304, 3),
        ),
        ("padding", Row::default()),
    ]
}

/// A provable `read` of fd 0, the committed input stream.
fn read_row(buf: u32, delivered: u32, old: u32, new: u32) -> Row {
    read_row_from(ecall::FD_PUBLIC_INPUT, buf, delivered, old, new)
}

/// A provable `read`: `a7 = READ`, `fd` in `a0`, the buffer in `a1`, one word
/// in `a2`, the count delivered written back to `a0`, and the RAM query at the
/// buffer — all on this one row. `fd` is fd 0 or fd 3, the two descriptors
/// `read_descriptor` admits (S25a).
fn read_row_from(fd: u32, buf: u32, delivered: u32, old: u32, new: u32) -> Row {
    let mut r = honest(
        Instr::new(kind::SYSTEM, 0, 0, 0, 0),
        ecall::READ,
        fd,
        delivered,
    );
    r.set("is_read", Fr::ONE);
    r.query("arg1", CYCLE, 2, 11, buf as u64, buf as u64);
    r.query(
        "arg2",
        CYCLE,
        2,
        12,
        ecall::READ_WORD_BYTES as u64,
        ecall::READ_WORD_BYTES as u64,
    );
    r.query("ram", CYCLE, 3, buf as u64, old as u64, new as u64);
    r.set("ram_value_hi", f(new as u64 >> 16));
    r
}

/// A provable `write`: the same shell, and **no RAM query** — the bytes never
/// enter the memory argument, because the guest's own `io_digest` is what
/// binds fd 1 (`docs/spec/memory.md` §10).
fn write_row(buf: u32, count: u32) -> Row {
    write_row_to(ecall::FD_PUBLIC_OUTPUT, buf, count)
}

/// The same, to `fd` — fd 1 or fd 2, the two `write_descriptor` admits.
fn write_row_to(fd: u32, buf: u32, count: u32) -> Row {
    let mut r = honest(
        Instr::new(kind::SYSTEM, 0, 0, 0, 0),
        ecall::WRITE,
        fd,
        count,
    );
    r.set("is_write", Fr::ONE);
    r.query("arg1", CYCLE, 2, 11, buf as u64, buf as u64);
    r.query("arg2", CYCLE, 2, 12, count as u64, count as u64);
    r
}

fn violated(a: &CircuitArtifact, r: &Row) -> (Vec<String>, Vec<String>) {
    let w = r.witness(a, 1 << 15);
    (
        violated_relations(a, &w, &challenges(a)),
        violated_lookups(a, &w),
    )
}

/// A cell's value as an integer, where the row holds one below `2^64`.
fn small_int(v: Fr) -> u64 {
    let b = v.to_bytes();
    assert!(
        b[8..].iter().all(|x| *x == 0),
        "{v:?} is not a small integer"
    );
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

// ---------------------------------------------------------------------------
// The circuit
// ---------------------------------------------------------------------------

/// The committed fixture is the constructor at the family's default height,
/// and the circuit keeps every rule both enforcement points hold it to: the
/// laws, the padding contract and its product-tree clause, S14's memory rules,
/// and S15's discharge rule — by `constraints` and, sharing no code, by this
/// crate.
#[test]
fn the_circuit_is_the_fixture_and_keeps_every_rule() {
    let bytes = std::fs::read(FIXTURE).expect("the add/sub fixture");
    assert_eq!(to_hex(&sha256(&bytes)), FIXTURE_SHA256);
    assert_eq!(add_sub::artifact(22).to_bytes(), bytes);
    assert_eq!(
        CircuitArtifact::from_bytes(&bytes),
        Ok(add_sub::artifact(22))
    );

    let a = artifact();
    let specs = add_sub::channels();
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(check_memory(&a), Ok(()));
    assert_eq!(check_discharge(&a, &specs), Ok(()));
    assert_eq!(check_laws(&a), Ok(()));
    assert_eq!(check_padding(&a), Ok(()));
    assert_eq!(check_padding_identity(&a), Ok(()));
    assert_eq!(check_lookup_discharge(&a, &specs), Ok(()));
    assert!(
        a.padding.zero_row_valid,
        "every gate is 0 on the all-zero row"
    );
}

/// The layout is `docs/spec/shard-proof.md` §8.1's, and the gates, lookups and
/// channels are §8.2's and §8.3's, by name and in order.
#[test]
fn the_layout_and_the_gates_are_the_specs() {
    let a = artifact();
    assert_eq!(a.memory.len(), 42);
    let mut witness = names(&[
        "pc_gap_hi",
        "rs1_gap_hi",
        "rs2_gap_hi",
        "arg1_gap_hi",
        "arg2_gap_hi",
        "ram_gap_hi",
        "rd_gap_hi",
        "deleg_gap_hi",
        "rd_inv",
        "rd_is_zero",
        "rd_selected",
        "decoded_next_pc",
        "decoded_rs1",
        "decoded_rs2",
        "decoded_rd",
        "decoded_imm",
        "decoded_mask",
        "kind_system",
        "kind_addi",
        "kind_auipc",
        "kind_add",
        "kind_sub",
        "kind_lui",
        "is_ecall",
        "is_fence",
        "is_deleg_9",
        "is_deleg_10",
        "is_deleg_11",
        "is_read",
        "is_write",
        "fd_uncommitted",
        "ram_value_hi",
        "wrap",
        "rd_hi",
        "pc_wrap",
        "next_pc_hi",
    ]);
    witness.extend(names(&["mult_timestamp", "mult_range16", "mult_decoder"]));
    assert_eq!(a.witness, witness);
    assert_eq!(
        a.setup,
        names(&[
            "table_pc",
            "table_next_pc",
            "table_rs1",
            "table_rs2",
            "table_rd",
            "table_imm",
            "table_extra_mask"
        ])
    );
    assert_eq!(
        a.virtuals,
        vec![
            (VirtualKind::Range19, "range19".to_string()),
            (VirtualKind::Range16, "range16".to_string())
        ]
    );
    let enforcing: Vec<String> = a.layers[0]
        .enforcing
        .iter()
        .map(|e| a.relations[e.relation as usize].name.clone())
        .collect();
    let mut want = names(&[
        "pc_mask_boolean",
        "rs1_mask_boolean",
        "rs2_mask_boolean",
        "arg1_mask_boolean",
        "arg2_mask_boolean",
        "ram_mask_boolean",
        "rd_mask_boolean",
        "deleg_mask_boolean",
        "rs1_writes_back",
        "rs2_writes_back",
        "arg1_writes_back",
        "arg2_writes_back",
        "rd_is_zero_inverse",
        "rd_is_zero_at_nonzero",
        "rd_is_zero_boolean",
        "rd_write_masked",
    ]);
    want.extend(names(&[
        "kind_system_boolean",
        "kind_addi_boolean",
        "kind_auipc_boolean",
        "kind_add_boolean",
        "kind_sub_boolean",
        "kind_lui_boolean",
        "decoded_mask_bits",
        "is_ecall_boolean",
        "is_fence_boolean",
        "system_split",
        "ecall_code",
        "fence_code",
        "is_deleg_9_boolean",
        "deleg_9_is_an_ecall",
        "deleg_9_number",
        "is_deleg_10_boolean",
        "deleg_10_is_an_ecall",
        "deleg_10_number",
        "is_deleg_11_boolean",
        "deleg_11_is_an_ecall",
        "deleg_11_number",
        "is_read_boolean",
        "is_read_is_an_ecall",
        "read_number",
        "is_write_boolean",
        "is_write_is_an_ecall",
        "write_number",
        "fd_uncommitted_boolean",
        "read_descriptor",
        "write_descriptor",
        "ecall_is_exit",
        "rs1_mask_rule",
        "rs2_mask_rule",
        "arg1_mask_rule",
        "arg2_mask_rule",
        "ram_mask_rule",
        "rd_mask_rule",
        "deleg_mask_rule",
        "rs1_addr_rule",
        "rs2_addr_rule",
        "rd_addr_rule",
        "arg1_addr_rule",
        "arg2_addr_rule",
        "rs1_value_masked",
        "rs2_value_masked",
        "ram_addr_is_the_buffer",
        "read_count_is_one_word",
        "write_count_is_the_request",
        "add_addi_auipc",
        "sub",
        "lui",
        "exit_status",
        "deleg_writes_no_register",
        "deleg_read_ts_zero",
        "deleg_read_value_zero",
        "deleg_addr_rule",
        "deleg_space_rule",
        "wrap_boolean",
        "pc_wrap_boolean",
        "next_pc_rule",
    ]));
    assert_eq!(enforcing, want);

    let lookups: Vec<(String, u32)> = a
        .lookups
        .iter()
        .map(|l| (l.name.clone(), l.channel))
        .collect();
    assert_eq!(lookups.len(), 24);
    assert_eq!(
        lookups[16..],
        [
            ("rd_hi_range".to_string(), lookup_channel::RANGE16),
            ("rd_lo_range".to_string(), lookup_channel::RANGE16),
            ("next_pc_hi_range".to_string(), lookup_channel::RANGE16),
            ("next_pc_lo_range".to_string(), lookup_channel::RANGE16),
            ("ram_value_hi_range".to_string(), lookup_channel::RANGE16),
            ("ram_value_lo_range".to_string(), lookup_channel::RANGE16),
            ("read_count_gap_range".to_string(), lookup_channel::RANGE16),
            ("decode_row".to_string(), lookup_channel::DECODER),
        ]
    );
    assert!(lookups[..16]
        .iter()
        .all(|(_, c)| *c == lookup_channel::TIMESTAMP));
    // The frame's gap obligations are each under their own query's mask; the
    // family's seven are under the row's.
    let pc_mask = PolyAddress::Memory(1);
    for (at, l) in a.lookups[..16].iter().enumerate() {
        assert_eq!(
            l.selector,
            PolyAddress::Memory(1 + 5 * (at as u32 / 2)),
            "{}",
            l.name
        );
    }
    // Every family obligation is under the row's own mask but S25a's, whose
    // selector is `is_read`: off a `read` row a gated range key is 0, which is
    // a real and in-range entry, and `rd_selected` there is an arithmetic
    // result that no byte-count bound should touch.
    let read_count_gap = a
        .lookups
        .iter()
        .position(|l| l.name == "read_count_gap_range")
        .expect("S25a's obligation");
    assert_eq!(a.lookups[read_count_gap].selector, add_sub::IS_READ);
    assert!(
        a.lookups[16..]
            .iter()
            .enumerate()
            .all(|(at, l)| at + 16 == read_count_gap || l.selector == pc_mask),
        "every other new obligation is the row's"
    );

    let mult = |i: u32| PolyAddress::Witness(36 + i);
    assert_eq!(
        add_sub::channels(),
        vec![
            ChannelSpec {
                channel: lookup_channel::TIMESTAMP,
                table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
                multiplicity: mult(0),
            },
            ChannelSpec {
                channel: lookup_channel::RANGE16,
                table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
                multiplicity: mult(1),
            },
            ChannelSpec {
                channel: lookup_channel::DECODER,
                table: (0..7).map(PolyAddress::Setup).collect(),
                multiplicity: mult(2),
            },
        ]
    );
    // Four product-tree leaves a side beside the frame's, then one fraction
    // tree per channel. The frame is eight queries since S21, so its product
    // trees are 16 a side: 32 + 36 + 28 + 4.
    assert_eq!(a.layers[0].width, 100);
    assert_eq!(a.outputs.len(), 2 + 2 * 3);
}

/// The registry: this family at 20 variables and up, the two window families
/// at any menu height, each the constructor it names; and no execution circuit
/// at all below the timestamp channel's width — since S19 that guard covers
/// every one of the seven, so a key naming a menu height of `2^16` or `2^18`
/// gets `None` and not a panic. Each family's own circuit is its own suite's.
#[test]
fn the_registry_holds_the_three_families_s16_proves() {
    let c = family_circuit(family::ADD_SUB_LUI_AUIPC, 20).expect("add/sub at 2^20");
    assert_eq!(
        (c.family, c.artifact, c.channels),
        (0, artifact(), add_sub::channels())
    );
    assert_eq!(family_circuit(family::ADD_SUB_LUI_AUIPC, 18), None);
    for vars in [16, 22] {
        let init = family_circuit(family::INIT_TEARDOWN, vars).expect("the image window");
        assert_eq!(
            init.artifact,
            constraints::memory::image_window_artifact(vars)
        );
        assert!(init.channels.is_empty());
        let zero = family_circuit(family::ZERO_WINDOWS, vars).expect("a zero window");
        assert_eq!(
            zero.artifact,
            constraints::memory::zero_window_artifact(vars)
        );
    }
    for id in [
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::SHIFT_BITWISE,
        family::MUL_DIV,
        family::MEM_WORD,
        family::MEM_SUBWORD,
        family::ATOMICS,
    ] {
        for vars in [16, 18] {
            assert_eq!(family_circuit(id, vars), None, "family {id} at {vars}");
        }
        assert!(family_circuit(id, 20).is_some(), "family {id} at 20");
    }
    assert_eq!(family_circuit(family::COUNT, 20), None);
    assert_eq!(family_circuit(family::INIT_TEARDOWN, 31), None);
}

// ---------------------------------------------------------------------------
// Honest rows
// ---------------------------------------------------------------------------

/// Every row kind the family proves — each sum with and without its carry,
/// each difference with and without its borrow, `rd = x0` computing a nonzero
/// value it discards, an `x0` operand, a two-byte instruction, a fence, the
/// exit, S21's **delegation request**, and the all-zero padding row —
/// satisfies every gate and every range obligation.
#[test]
fn every_row_kind_satisfies_every_gate_and_every_bound() {
    let a = artifact();
    for (what, row) in honest_rows() {
        let (relations, lookups) = violated(&a, &row);
        assert!(relations.is_empty(), "{what}: {relations:?}");
        assert!(lookups.is_empty(), "{what}: {lookups:?}");
    }
    // The rows really are what their names say.
    let rows = honest_rows();
    let get = |what: &str, col: &str| rows.iter().find(|(w, _)| *w == what).unwrap().1.get(col);
    assert_eq!(get("add, carrying", "wrap"), Fr::ONE);
    assert_eq!(get("sub, borrowing", "wrap"), Fr::ONE);
    assert_eq!(get("auipc, carrying", "wrap"), Fr::ONE);
    assert_eq!(get("add to x0, carrying", "rd_write_value"), Fr::ZERO);
    assert_ne!(get("add to x0, carrying", "rd_selected"), Fr::ZERO);
    assert_eq!(get("c.add, two bytes", "decoded_next_pc"), f(0x1_0012));
    assert_eq!(get("exit 42", "pc_write_value"), Fr::ONE);
    // S21's row: an ecall that is not an exit. It carries both flags, makes
    // the mirror query at the `a0` it read, writes 0 into `a0`, and falls
    // through rather than halting (`docs/spec/delegation.md` §2, §5.1).
    let d = |col: &str| get("keccak delegation request", col);
    assert_eq!(d("is_ecall"), Fr::ONE);
    assert_eq!(d("is_deleg_9"), Fr::ONE);
    assert_eq!(d("rs1_read_value"), f(ecall::PRECOMPILE_KECCAK_F as u64));
    assert_eq!(d("deleg_mask"), Fr::ONE);
    assert_eq!(d("deleg_addr"), d("rs2_read_value"));
    assert_eq!(d("deleg_read_ts"), Fr::ZERO);
    assert_eq!(d("deleg_read_value"), Fr::ZERO);
    assert_eq!(d("rd_selected"), Fr::ZERO);
    assert_eq!(d("rd_write_value"), Fr::ZERO);
    assert_eq!(d("pc_write_value"), d("decoded_next_pc"));
    assert_ne!(
        d("pc_write_value"),
        Fr::ONE,
        "a delegation row does not halt"
    );
    // And the exit row is still the only one that halts: the two ecall kinds
    // differ in exactly the row's `is_deleg_t`.
    assert_eq!(get("exit 42", "is_deleg_9"), Fr::ZERO);
    // S25a's column really does split the four descriptors the way the two
    // gates read it, and the committed rows are the ones that leave it 0.
    for (what, fd) in [
        ("read of one word", ecall::FD_PUBLIC_INPUT),
        ("write of nine bytes", ecall::FD_PUBLIC_OUTPUT),
    ] {
        assert_eq!(get(what, "rs2_read_value"), f(fd as u64), "{what}");
        assert_eq!(get(what, "fd_uncommitted"), Fr::ZERO, "{what}");
    }
    for (what, fd) in [
        ("read of one word from the hint stream", ecall::FD_HINT),
        ("write of three bytes to stderr", ecall::FD_STDERR),
    ] {
        assert_eq!(get(what, "rs2_read_value"), f(fd as u64), "{what}");
        assert_eq!(get(what, "fd_uncommitted"), Fr::ONE, "{what}");
    }
    // A `write` answers the count it was asked for; a `read` answers at most
    // the one word it asked for, and a short read answers less.
    assert_eq!(
        get("write of nine bytes", "rd_selected"),
        get("write of nine bytes", "arg2_read_value")
    );
    assert_eq!(get("short read of one byte", "rd_selected"), Fr::ONE);
    assert_eq!(
        get("short read of one byte", "arg2_read_value"),
        f(ecall::READ_WORD_BYTES as u64)
    );
}

// ---------------------------------------------------------------------------
// Each gate refuses its row
// ---------------------------------------------------------------------------

fn row(what: &str) -> Row {
    honest_rows()
        .into_iter()
        .find(|(w, _)| *w == what)
        .unwrap_or_else(|| panic!("no row `{what}`"))
        .1
}

/// Set `rd`'s computed value to `sel` on a row whose `rd` is not `x0`, moving
/// its write and its high halfword with it, so only the semantic gate sees it.
fn with_sel(mut r: Row, sel: Fr) -> Row {
    r.set("rd_selected", sel).set("rd_write_value", sel);
    r
}

/// Each tamper beside the gates it must break, exactly: a single-cell or
/// small edit to an honest row that one gate, and only it, refuses. So every
/// gate here is load-bearing on the row shape it exists for.
#[test]
fn each_gate_is_the_one_that_refuses_its_row() {
    let a = artifact();
    let mut cases: Vec<(&str, Row, Vec<&str>)> = Vec::new();

    let mut r = row("add, carrying");
    r.set("wrap", Fr::ZERO);
    cases.push(("an add's carry dropped", r, vec!["add_addi_auipc"]));
    let r = row("add, not carrying");
    let sel = r.get("rd_selected") + Fr::ONE;
    cases.push((
        "an add's result moved",
        with_sel(r, sel),
        vec!["add_addi_auipc"],
    ));
    let r = row("addi of -1, carrying");
    let sel = r.get("rd_selected") + Fr::ONE;
    cases.push((
        "an addi's result moved",
        with_sel(r, sel),
        vec!["add_addi_auipc"],
    ));
    let r = row("auipc, carrying");
    let sel = r.get("rd_selected") - Fr::ONE;
    cases.push((
        "an auipc's result moved",
        with_sel(r, sel),
        vec!["add_addi_auipc"],
    ));
    let mut r = row("sub, borrowing");
    r.set("wrap", Fr::ZERO);
    cases.push(("a sub's borrow dropped", r, vec!["sub"]));
    let r = row("lui");
    let sel = r.get("rd_selected") + Fr::ONE;
    cases.push(("a lui's result moved", with_sel(r, sel), vec!["lui"]));
    let r = row("exit 42");
    cases.push((
        "the exit rewriting a0 to 43",
        with_sel(r, f(43)),
        vec!["exit_status"],
    ));

    let mut r = row("exit 42");
    r.set("rs1_read_value", f(64)).set("rs1_write_value", f(64));
    cases.push(("an ecall that is a write", r, vec!["ecall_is_exit"]));
    let mut r = row("exit 42");
    r.set("decoded_imm", f(1));
    cases.push(("an ecall row with ebreak's code", r, vec!["ecall_code"]));
    let mut r = row("fence");
    r.set("decoded_imm", Fr::ZERO);
    cases.push(("a fence row with ecall's code", r, vec!["fence_code"]));
    let mut r = row("fence");
    r.set("is_fence", Fr::ZERO);
    cases.push(("a system row that is neither", r, vec!["system_split"]));

    // A query the kind does not use, present: its mask rule and nothing else.
    let mut r = row("lui");
    r.query("rs1", CYCLE, 1, 0, 0, 0);
    cases.push(("a lui reading rs1", r, vec!["rs1_mask_rule"]));
    let mut r = row("addi of -1, carrying");
    r.query("rs2", CYCLE, 2, 0, 0, 0);
    cases.push(("an addi reading rs2", r, vec!["rs2_mask_rule"]));
    for q in ["arg1", "arg2"] {
        let mut r = row("exit 42");
        r.query(q, CYCLE, 2, if q == "arg1" { 11 } else { 12 }, 5, 5);
        let rule: &str = if q == "arg1" {
            "arg1_mask_rule"
        } else {
            "arg2_mask_rule"
        };
        cases.push(("an exit reading a1 or a2", r, vec![rule]));
    }
    // An exit row that stores a word breaks three gates, not one: it has no
    // RAM query to make, and the word it claims is neither at `a1` — which it
    // does not read — nor a one-word request.
    let mut r = row("exit 42");
    r.query("ram", CYCLE, 3, 0x7fff_fffc, 7, 9);
    r.set("ram_value_hi", f(0));
    cases.push((
        "the exit row storing a word",
        r,
        vec![
            "ram_mask_rule",
            "ram_addr_is_the_buffer",
            "read_count_is_one_word",
        ],
    ));

    // S25's two confinement gates, each on a row that breaks it alone.
    let base = guest_memory::RAM_ORIGIN + 0x200;
    let mut r = read_row(base, 4, 1, 2);
    r.query("ram", CYCLE, 3, (base + 4) as u64, 1, 2);
    cases.push((
        "a read writing the word after its buffer",
        r,
        vec!["ram_addr_is_the_buffer"],
    ));

    let mut r = read_row(base, 4, 1, 2);
    r.query("arg2", CYCLE, 2, 12, 8, 8);
    cases.push((
        "a read asking for two words",
        r,
        vec!["read_count_is_one_word"],
    ));

    // The shape a refused `read` would have: the ecall happened, the
    // descriptor was not one fd 0 or fd 3 names, so no word moved. The mask
    // rule refuses it, which is why `fill::add_sub` refuses such a cycle by
    // name rather than proving a shard that cannot verify
    // (`docs/spec/shard-proof.md` §8.5).
    let mut r = read_row(base, 4, 1, 2);
    r.drop_query("ram");
    r.set("ram_value_hi", Fr::ZERO);
    cases.push(("a read that moved no word", r, vec!["ram_mask_rule"]));

    // A `write` makes no RAM query, so claiming one is the mask rule's alone:
    // its `a1` and its count are whatever the call named, and the two
    // confinement gates are satisfied by naming them.
    let mut r = write_row(base, 4);
    r.query("ram", CYCLE, 3, base as u64, 1, 2);
    r.set("ram_value_hi", f(0));
    cases.push(("a write storing a word", r, vec!["ram_mask_rule"]));

    // The number pins, each the lone refusal of a row claiming the wrong one.
    let mut r = read_row(base, 4, 1, 2);
    r.query(
        "rs1",
        CYCLE,
        1,
        17,
        ecall::WRITE as u64,
        ecall::WRITE as u64,
    );
    cases.push(("a read row whose a7 says write", r, vec!["read_number"]));

    let mut r = write_row(base, 4);
    r.query("rs1", CYCLE, 1, 17, ecall::READ as u64, ecall::READ as u64);
    cases.push(("a write row whose a7 says read", r, vec!["write_number"]));

    // S25a's descriptor pins. `a0` is read as the fd and written as the count,
    // so a forged descriptor moves the read half of one query and nothing
    // else: the row still looks like a call, and until S25a it proved as one.
    // Each case is the lone refusal of the gate that owns that call's pair.
    let fd = |r: &mut Row, v: u32| {
        r.set("rs2_read_value", f(v as u64))
            .set("rs2_write_value", f(v as u64));
    };
    for (what, bad) in [
        // The other call's committed stream: a `read` of fd 1 would let a
        // prover pull bytes out of the *output* stream.
        ("a read from fd 1", ecall::FD_PUBLIC_OUTPUT),
        // The other call's uncommitted one, which `fd_uncommitted = 1` does
        // not reach either: fd 2 is not 3.
        ("a read from fd 2", ecall::FD_STDERR),
        ("a read from a descriptor the ABI gives no call", 7),
    ] {
        let mut r = read_row(base, 4, 1, 2);
        fd(&mut r, bad);
        cases.push((what, r, vec!["read_descriptor"]));
    }
    // The column and the descriptor disagreeing, each way round. Neither is a
    // forged *fd* — both name a legal one — and both are refused, which is
    // what makes `fd_uncommitted` decide rather than merely accompany.
    let mut r = read_row_from(ecall::FD_HINT, base, 4, 1, 2);
    r.set("fd_uncommitted", Fr::ZERO);
    cases.push((
        "a read of the hint stream claiming fd 0",
        r,
        vec!["read_descriptor"],
    ));
    let mut r = read_row(base, 4, 1, 2);
    r.set("fd_uncommitted", Fr::ONE);
    cases.push((
        "a read of fd 0 claiming the hint stream",
        r,
        vec!["read_descriptor"],
    ));
    for (what, bad) in [
        ("a write to fd 0", ecall::FD_PUBLIC_INPUT),
        ("a write to fd 3", ecall::FD_HINT),
        ("a write to a descriptor the ABI gives no call", 7),
    ] {
        let mut r = write_row(base, 4);
        fd(&mut r, bad);
        cases.push((what, r, vec!["write_descriptor"]));
    }
    let mut r = write_row_to(ecall::FD_STDERR, base, 4);
    r.set("fd_uncommitted", Fr::ZERO);
    cases.push((
        "a write to stderr claiming fd 1",
        r,
        vec!["write_descriptor"],
    ));
    let mut r = write_row(base, 4);
    r.set("fd_uncommitted", Fr::ONE);
    cases.push((
        "a write to fd 1 claiming stderr",
        r,
        vec!["write_descriptor"],
    ));

    // A `write` answering a count other than the one it was asked for. `a0`'s
    // write is the only cell that moves, and `exit_status` leaves it alone —
    // `is_ecall` and `is_write` cancel on this row — so the new gate is the
    // one refusal.
    let mut r = write_row(base, 4);
    r.set("rd_selected", f(3))
        .set("rd_write_value", f(3))
        .set("rd_hi", Fr::ZERO);
    cases.push((
        "a write claiming it moved fewer bytes than it was given",
        r,
        vec!["write_count_is_the_request"],
    ));
    let mut r = write_row(base, 4);
    r.set("rd_selected", f(5))
        .set("rd_write_value", f(5))
        .set("rd_hi", Fr::ZERO);
    cases.push((
        "a write claiming it moved more bytes than it was given",
        r,
        vec!["write_count_is_the_request"],
    ));
    let mut r = row("fence");
    r.query("rd", CYCLE, 3, 0, 0, 0);
    r.set("rd_is_zero", Fr::ONE);
    cases.push(("a fence writing x0", r, vec!["rd_mask_rule"]));
    // S14's control C8, first forgery: a padding row's rd query rewriting x10.
    let mut r = Row::default();
    r.query("rd", CYCLE, 3, 10, 42, 42);
    r.set("rd_inv", f(10).inverse().unwrap())
        .set("rd_selected", f(42));
    cases.push((
        "a padding row rewriting x10",
        r,
        vec!["rd_mask_rule", "rd_addr_rule"],
    ));
    // The same forgery with a free kind bit claiming addi — a padding row's
    // bits are no table's — which would make rs1 and rd present if a mask rule
    // forgot the row's liveness.
    let mut r = Row::default();
    r.set("kind_addi", Fr::ONE)
        .set("decoded_mask", f(2))
        .set("decoded_rd", f(10))
        .set("decoded_imm", f(43));
    r.query("rs1", CYCLE, 1, 0, 0, 0);
    r.query("rd", CYCLE, 3, 10, 42, 43);
    r.set("rd_inv", f(10).inverse().unwrap())
        .set("rd_selected", f(43));
    cases.push((
        "a padding row claiming addi and rewriting x10",
        r,
        vec!["rs1_mask_rule", "rd_mask_rule"],
    ));
    // A padding row storing into RAM. Three gates refuse it: a padding row
    // makes no RAM query, and the word it claims is neither at the `a1` it
    // does not read nor a one-word request.
    let mut r = Row::default();
    r.query("ram", CYCLE, 3, 0x7fff_fffc, 0, 7);
    cases.push((
        "a padding row storing a word",
        r,
        vec![
            "ram_mask_rule",
            "ram_addr_is_the_buffer",
            "read_count_is_one_word",
        ],
    ));
    // Its second: a live row's rd write masked off.
    let mut r = row("add, not carrying");
    r.drop_query("rd");
    r.set("rd_inv", Fr::ZERO).set("rd_selected", Fr::ZERO);
    let sel_gone = r.clone();
    cases.push((
        "an add whose write is masked off",
        sel_gone,
        vec!["rd_mask_rule", "add_addi_auipc"],
    ));

    // A present query at another address.
    for (q, rule) in [("rs1", "rs1_addr_rule"), ("rs2", "rs2_addr_rule")] {
        let mut r = row("add, carrying");
        let addr = r.get(name(q, "addr")) + Fr::ONE;
        r.set(name(q, "addr"), addr);
        cases.push(("a register query at the wrong register", r, vec![rule]));
    }
    let mut r = row("add, carrying");
    r.set("rd_addr", f(8))
        .set("rd_inv", f(8).inverse().unwrap());
    cases.push(("a write to the wrong register", r, vec!["rd_addr_rule"]));
    let mut r = row("exit 42");
    r.set("rs1_addr", f(10));
    cases.push((
        "an ecall reading its number from a0",
        r,
        vec!["rs1_addr_rule"],
    ));

    // An absent operand reading something.
    let mut r = row("lui");
    r.set("rs1_read_value", f(5)).set("rs1_write_value", f(5));
    cases.push(("a lui's absent rs1 reading 5", r, vec!["rs1_value_masked"]));
    let mut r = row("addi of -1, carrying");
    r.set("rs2_read_value", f(5)).set("rs2_write_value", f(5));
    cases.push((
        "an addi's absent rs2 reading 5",
        r,
        vec!["rs2_value_masked", "add_addi_auipc"],
    ));

    // next_pc.
    let mut r = row("add, carrying");
    let next = r.get("pc_write_value") + f(4);
    r.set("pc_write_value", next);
    cases.push(("an add jumping four ahead", r, vec!["next_pc_rule"]));
    // S14's truncation target: a row that is not the exit writing HALT_PC.
    let mut r = row("add, carrying");
    r.set("pc_write_value", Fr::ONE).set("next_pc_hi", Fr::ZERO);
    cases.push(("an add writing HALT_PC", r, vec!["next_pc_rule"]));
    let mut r = row("exit 42");
    r.set("pc_write_value", f(0x1_0014)).set("next_pc_hi", f(1));
    cases.push(("the exit falling through", r, vec!["next_pc_rule"]));

    // S21's eight gates, and the three S16 gates it amended
    // (`docs/spec/delegation.md` §5.2). Each case is one cell of the honest
    // delegation row, or of the honest exit row, moved.
    let deleg = || row("keccak delegation request");
    // The flag without the ecall it must accompany.
    let mut r = row("add, carrying");
    r.set("is_deleg_9", Fr::ONE);
    // A type selector without the `is_ecall` it must accompany makes the
    // amended gates' factor `is_ecall - Σ is_deleg_t` equal -1, so all of them
    // fire too: that is the price of subtracting rather than gating, and
    // `deleg_9_is_an_ecall` is what makes the factor 0 or 1 on any row that
    // passes. `deleg_space_rule` fires because the row names a type and its
    // `deleg_space` column is 0.
    cases.push((
        "an add claiming to be a delegation",
        r,
        vec![
            "deleg_9_is_an_ecall",
            "ecall_is_exit",
            "deleg_9_number",
            "deleg_mask_rule",
            "exit_status",
            "deleg_space_rule",
            "next_pc_rule",
        ],
    ));
    // A delegation whose a7 is another number: 130 and 131 partition the
    // ecalls this family proves, so a7 = 93 with the flag set breaks 131 and
    // a7 = 0x502 breaks both.
    let mut r = deleg();
    r.set("rs1_read_value", f(93)).set("rs1_write_value", f(93));
    cases.push((
        "a delegation row whose a7 is EXIT",
        r,
        vec!["deleg_9_number"],
    ));
    let mut r = deleg();
    let other = f(ecall::PRECOMPILE_KECCAK_F as u64 + 1);
    r.set("rs1_read_value", other).set("rs1_write_value", other);
    cases.push((
        "a delegation row calling an unregistered number",
        r,
        vec!["deleg_9_number"],
    ));
    // An exit row that claims the delegation flag is no longer held to 93 by
    // 130 — but 131 asks a7 for 0x501, and 138 for the mirror query.
    let mut r = row("exit 42");
    r.set("is_deleg_9", Fr::ONE);
    cases.push((
        "an exit row claiming the delegation flag",
        r,
        vec![
            "deleg_9_number",
            "deleg_mask_rule",
            "deleg_space_rule",
            "next_pc_rule",
        ],
    ));
    // The mirror query dropped: without it a request has no anchor and cannot
    // pair with an invocation, so the gate has to be the one that catches it.
    let mut r = deleg();
    r.drop_query("deleg");
    cases.push((
        "a delegation request without its mirror query",
        r,
        vec!["deleg_mask_rule"],
    ));
    // The mirror query at an address other than the a0 handed over.
    let mut r = deleg();
    let elsewhere = r.get("deleg_addr") + f(4);
    r.set("deleg_addr", elsewhere);
    cases.push((
        "a mirror query at another frame base",
        r,
        vec!["deleg_addr_rule"],
    ));
    // The three request-side zeroings, one at a time.
    let mut r = deleg();
    r.set("deleg_read_ts", f(4 * CYCLE + 1));
    cases.push((
        "a mirror query reading a stamped tuple",
        r,
        vec!["deleg_read_ts_zero"],
    ));
    let mut r = deleg();
    r.set("deleg_read_value", f(7));
    cases.push((
        "a mirror query reading a nonzero value",
        r,
        vec!["deleg_read_value_zero"],
    ));
    let mut r = deleg();
    r.set("rd_selected", f(7))
        .set("rd_write_value", f(7))
        .set("rd_hi", Fr::ZERO);
    cases.push((
        "a delegation answering something other than 0",
        r,
        vec!["deleg_writes_no_register"],
    ));
    // The mirror's leaf names the type through `deleg_space`, so a request
    // that claims keccak and stamps another family's tag is refused: without
    // this gate a poseidon2 invocation could answer a keccak request.
    let mut r = deleg();
    r.set(
        "deleg_space",
        f(constants::address_space::DELEGATION_POSEIDON2 as u64),
    );
    cases.push((
        "a request whose anchor names another delegation type",
        r,
        vec!["deleg_space_rule"],
    ));
    // And the amended pc rule: a delegation row that halts.
    let mut r = deleg();
    r.set("pc_write_value", Fr::ONE).set("next_pc_hi", Fr::ZERO);
    cases.push(("a delegation row halting", r, vec!["next_pc_rule"]));

    // The mask's bits. A lui row whose bits say add still sums — its result is
    // its immediate, and its absent operands read 0 — so what refuses it is the
    // recomposition, and the two operands an add reads and this row lacks.
    let mut r = row("lui");
    r.set("kind_lui", Fr::ZERO).set("kind_add", Fr::ONE);
    cases.push((
        "a lui whose bits say add",
        r,
        vec!["decoded_mask_bits", "rs1_mask_rule", "rs2_mask_rule"],
    ));

    for (what, r, want) in cases {
        let (relations, _) = violated(&a, &r);
        let mut want: Vec<String> = names(&want);
        let order: Vec<&str> = a.relations.iter().map(|r| r.name.as_str()).collect();
        want.sort_by_key(|n| order.iter().position(|o| o == n));
        assert_eq!(relations, want, "{what}");
    }
}

/// Every gate named in §8.2 is the lone or first refusal of at least one case
/// above, or one of the booleanity gates this test breaks — all nine of them:
/// nothing §8.2 adds is there without a row that needs it. The frame's own
/// booleanity gates are S14's, not §8.2's.
#[test]
fn every_booleanity_gate_refuses_a_value_of_two() {
    let a = artifact();
    let cases: [(&str, &str, &str); 6] = [
        ("add, carrying", "wrap", "wrap_boolean"),
        ("add, carrying", "pc_wrap", "pc_wrap_boolean"),
        ("exit 42", "is_ecall", "is_ecall_boolean"),
        ("fence", "is_fence", "is_fence_boolean"),
        (
            "keccak delegation request",
            "is_deleg_9",
            "is_deleg_9_boolean",
        ),
        (
            "read of one word",
            "fd_uncommitted",
            "fd_uncommitted_boolean",
        ),
    ];
    for (base, column, gate) in cases {
        let mut r = row(base);
        r.set(column, f(2));
        let (relations, _) = violated(&a, &r);
        assert!(
            relations.contains(&gate.to_string()),
            "{column} = 2: {relations:?}"
        );
    }
    for k in ["system", "addi", "auipc", "add", "sub", "lui"] {
        let mut r = Row::default();
        r.set(name("kind", k), f(2));
        let (relations, _) = violated(&a, &r);
        let gate = format!("kind_{k}_boolean");
        assert!(relations.contains(&gate), "kind_{k} = 2: {relations:?}");
    }
}

// ---------------------------------------------------------------------------
// S16's negative controls, row by row
// ---------------------------------------------------------------------------

/// Acceptance 7, as rows. An unreduced sum — wrap 0 and `rd` holding the whole
/// `a + b ≥ 2^32` — breaks no gate and only the range channel sees it, on an
/// add, an addi and a sub alike; a wrap of 2 is refused by its booleanity; a
/// `next_pc` outside 32 bits, reached through a wrap of 1, breaks no gate and
/// only the range channel sees it, through its low halfword or, with the high
/// one solved in the field, through the high one; an
/// all-zero mask breaks no gate and no range, so the decoder channel's domain
/// is the only thing left to refuse it, which `tests/tamper.rs` proves.
#[test]
fn the_negative_controls_break_what_they_say_they_break() {
    let a = artifact();

    let r = row("add to x0, carrying");
    let (big, small) = (0xffff_efffu64, 0x1234_5678u64);
    let mut unreduced = r.clone();
    unreduced
        .set("wrap", Fr::ZERO)
        .set("rd_selected", f(big + small))
        .set("rd_hi", f((big + small) >> 16));
    assert_eq!(violated(&a, &unreduced), (vec![], names(&["rd_hi_range"])));

    let mut two = r.clone();
    let sel = f(big + small) - f(2 * TWO_32);
    two.set("wrap", f(2))
        .set("rd_selected", sel)
        .set("rd_hi", f(0));
    let (relations, lookups) = violated(&a, &two);
    assert_eq!(relations, names(&["wrap_boolean"]));
    assert!(lookups.contains(&"rd_lo_range".to_string()), "{lookups:?}");

    let mut far = row("add, carrying");
    let next = far.get("decoded_next_pc") - f(TWO_32);
    far.set("pc_wrap", Fr::ONE)
        .set("pc_write_value", next)
        .set("next_pc_hi", f(0));
    let (relations, lookups) = violated(&a, &far);
    assert_eq!(relations, Vec::<String>::new());
    assert_eq!(lookups, names(&["next_pc_lo_range"]));

    // The unreduced result from the other row kinds that compute one: every
    // row writing rd is range-checked, not only add's.
    let value = |r: &Row, column: &str| small_int(r.get(column));
    let mut addi = row("addi of -1, carrying");
    let sum = f(value(&addi, "rs1_read_value") + value(&addi, "decoded_imm"));
    addi.set("wrap", Fr::ZERO)
        .set("rd_selected", sum)
        .set("rd_write_value", sum)
        .set("rd_hi", f(0xffff));
    assert_eq!(violated(&a, &addi), (vec![], names(&["rd_lo_range"])));
    let mut sub = row("sub, borrowing");
    let difference = f(value(&sub, "rs1_read_value")) - f(value(&sub, "rs2_read_value"));
    sub.set("wrap", Fr::ZERO)
        .set("rd_selected", difference)
        .set("rd_write_value", difference)
        .set("rd_hi", Fr::ZERO);
    assert_eq!(violated(&a, &sub), (vec![], names(&["rd_lo_range"])));

    // A next_pc outside 32 bits whose high halfword is solved in the field so
    // that its low halfword is in range: the high halfword's own check is the
    // one that refuses it.
    let mut solved = row("add, carrying");
    let next = solved.get("decoded_next_pc") - f(TWO_32);
    let low = f(value(&solved, "decoded_next_pc") & 0xffff);
    let high = (next - low) * f(1 << 16).inverse().unwrap();
    solved
        .set("pc_wrap", Fr::ONE)
        .set("pc_write_value", next)
        .set("next_pc_hi", high);
    assert_eq!(
        violated(&a, &solved),
        (vec![], names(&["next_pc_hi_range"]))
    );

    let mut zero = row("lui");
    zero.set("decoded_mask", Fr::ZERO)
        .set("kind_lui", Fr::ZERO)
        .set("rd_selected", Fr::ZERO)
        .set("rd_hi", Fr::ZERO);
    zero.drop_query("rd");
    zero.set("rd_inv", Fr::ZERO);
    assert_eq!(violated(&a, &zero), (vec![], vec![]));
}

/// S25a's bound on what a `read` answers: `[0, READ_WORD_BYTES]`, and the
/// range channel is the whole of it.
///
/// A short read is a real answer — fd 0's cursor lives in the executor and no
/// row holds it — so the count is bounded and not fixed
/// (`docs/spec/ecall-abi.md` §4.1). What the bound buys is the other side: a
/// count above the one word the call asked for is a count the guest's own loop
/// would run past the buffer on, and the `-EBADF` a refused `read` answers is
/// a 32-bit word whose two halfwords are both in range, so `rd_hi_range` and
/// `rd_lo_range` admit it and only this obligation does not.
#[test]
fn a_read_answers_at_most_the_word_it_asked_for() {
    let a = artifact();
    let base = guest_memory::RAM_ORIGIN + 0x200;

    // Every legal answer, the empty one and the full one included.
    for n in 0..=ecall::READ_WORD_BYTES {
        let r = read_row(base, n, 0x1111_2222, 0x3333_4444);
        assert_eq!(violated(&a, &r), (vec![], vec![]), "a read of {n} bytes");
    }

    // One byte past it, and nothing else on the row moved: `rd_hi` and the low
    // halfword still pair, so the two `rd` obligations pass.
    let mut r = read_row(base, 0, 0x1111_2222, 0x3333_4444);
    r.set("rd_selected", f(u64::from(ecall::READ_WORD_BYTES) + 1))
        .set("rd_write_value", f(u64::from(ecall::READ_WORD_BYTES) + 1));
    assert_eq!(violated(&a, &r), (vec![], names(&["read_count_gap_range"])));

    // The shape that made this obligation worth its leaf: `-EBADF` in `a0`,
    // which is what the executor answers a `read` on a descriptor the call
    // does not name. `read_descriptor` refuses the descriptor; this refuses
    // the answer, so a row forging both is refused twice over.
    let ebadf = u64::from(ecall::EBADF.wrapping_neg());
    let mut r = read_row(base, 0, 0x1111_2222, 0x3333_4444);
    r.set("rd_selected", f(ebadf))
        .set("rd_write_value", f(ebadf))
        .set("rd_hi", f(ebadf >> 16));
    assert_eq!(violated(&a, &r), (vec![], names(&["read_count_gap_range"])));

    // And it is a `read`'s alone: the selector is `is_read`, so an ordinary
    // sum whose result is nowhere near a byte count discharges it on the
    // switched-off row's key of 0.
    let big = row("add, carrying");
    assert!(small_int(big.get("rd_selected")) > u64::from(ecall::READ_WORD_BYTES));
    assert_eq!(violated(&a, &big), (vec![], vec![]));
}
