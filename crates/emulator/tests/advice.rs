//! The **advice** region in the executor: what a load reads, what chains, and
//! the three things that are fatal.
//!
//! `docs/spec/advice.md` is the page. The programs here are hand-encoded
//! rather than compiled, because the property under test is the address map —
//! a guest reaching `0x8000_0000` with an ordinary `lw` — and no committed
//! guest does that yet.
//!
//! **These guests would fault under `qemu-riscv32`** and are not in any
//! cross-executor suite (`docs/spec/advice.md` §9): a host loader maps the
//! `PT_LOAD`s the image declares, and advice is by definition not in the
//! image.

mod common;

use common::preprocess;
use constants::{ecall, guest_memory};
use emulator::{run, trace_run, EmuError, GuestIo};
use loader::{ProgramImage, Segment, Slot};
use trace::AddressSpace;

// ---------------------------------------------------------------------------
// Hand-encoded programs
// ---------------------------------------------------------------------------

const OP_LOAD: u32 = 0x03;
const OP_STORE: u32 = 0x23;
const OP_OP_IMM: u32 = 0x13;
const OP_LUI: u32 = 0x37;
const OP_AMO: u32 = 0x2f;
const OP_SYSTEM: u32 = 0x73;

fn i_type(op: u32, funct3: u32, rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | op
}

fn s_type(op: u32, funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let imm = imm as u32;
    ((imm >> 5 & 0x7f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((imm & 0x1f) << 7)
        | op
}

fn lui(rd: u32, imm20: u32) -> u32 {
    (imm20 << 12) | (rd << 7) | OP_LUI
}

fn amo(funct5: u32, rd: u32, rs1: u32, rs2: u32) -> u32 {
    (funct5 << 27) | (rs2 << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | OP_AMO
}

/// `x1 = ADVICE_ORIGIN`, which is one `lui`: the region's base is a power of
/// two with nothing in its low twelve bits, which is the same fact that makes
/// the circuit's selector one bit (`docs/spec/advice.md` §3.1).
fn advice_base(rd: u32) -> u32 {
    assert_eq!(guest_memory::ADVICE_ORIGIN & 0xfff, 0);
    lui(rd, guest_memory::ADVICE_ORIGIN >> 12)
}

/// `exit(a0)`: the status is whatever `x10` holds.
fn exit_words() -> [u32; 2] {
    [
        i_type(OP_OP_IMM, 0, 17, 0, ecall::EXIT as i32),
        OP_SYSTEM, // ecall
    ]
}

/// A one-segment image of 32-bit `words` entered at `RAM_ORIGIN`.
fn image_of(words: &[u32]) -> ProgramImage {
    let at = guest_memory::RAM_ORIGIN;
    let mut slots = Vec::new();
    for word in words {
        isa::decode(*word).unwrap_or_else(|e| panic!("{word:#010x} decodes: {e:?}"));
        slots.push(Slot::Instruction {
            word: *word,
            compressed: false,
        });
        slots.push(Slot::MidInstruction);
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    ProgramImage {
        entry: at,
        segments: vec![Segment {
            vaddr: at,
            mem_len: bytes.len() as u32,
            bytes,
        }],
        slot_base: at,
        slots,
    }
}

fn with_advice(advice: Vec<u8>) -> GuestIo {
    GuestIo {
        advice,
        ..GuestIo::default()
    }
}

/// Four little-endian words.
fn words(v: [u32; 4]) -> Vec<u8> {
    v.iter().flat_map(|w| w.to_le_bytes()).collect()
}

// ---------------------------------------------------------------------------
// What a load reads
// ---------------------------------------------------------------------------

/// A load at `ADVICE_ORIGIN` reads the bytes the prover supplied, and a load
/// four bytes up reads the next word: the region is addressed, not streamed.
#[test]
fn a_load_reads_the_advice_the_prover_supplied() {
    for (offset, want) in [(0, 7), (4, 9), (8, 11)] {
        let program = image_of(&[
            advice_base(1),
            i_type(OP_LOAD, 2, 10, 1, offset), // lw x10, offset(x1)
            exit_words()[0],
            exit_words()[1],
        ]);
        let run = run(&program, &with_advice(words([7, 9, 11, 13]))).expect("it runs");
        assert_eq!(run.exit_code, want, "advice word at offset {offset}");
    }
}

/// The last word may be partial: a region whose length is not a multiple of
/// four reads zero-padded, and the padding is not a way past the extent —
/// `a_load_past_the_advice_is_fatal` is the check that stops there.
#[test]
fn a_partial_final_advice_word_is_zero_padded() {
    let program = image_of(&[
        advice_base(1),
        i_type(OP_LOAD, 2, 10, 1, 0),
        exit_words()[0],
        exit_words()[1],
    ]);
    let run = run(&program, &with_advice(vec![5, 0])).expect("it runs");
    assert_eq!(run.exit_code, 5);
}

/// **Repeated reads agree, and that is the memory argument's doing.** The
/// second load's read timestamp is the first's write timestamp, so the two
/// sit on one chain at one address: a prover cannot answer one address with
/// two values (`docs/spec/advice.md` §1).
#[test]
fn a_second_read_of_one_advice_word_chains_to_the_first() {
    let program = image_of(&[
        advice_base(1),
        i_type(OP_LOAD, 2, 10, 1, 0),
        i_type(OP_LOAD, 2, 11, 1, 0),
        exit_words()[0],
        exit_words()[1],
    ]);
    let io = with_advice(words([42, 0, 0, 0]));
    let (tables, config) = preprocess(&program);
    let (_, log, _, execution) = trace_run(&program, &io, &tables, &config).expect("it traces");
    assert_eq!(execution.exit_code, 42);
    log.self_check(&program).expect("the log balances");

    let reads: Vec<_> = log
        .events()
        .iter()
        .filter(|e| e.space == AddressSpace::Advice)
        .collect();
    assert_eq!(reads.len(), 2, "two loads, two advice queries");
    assert_eq!(reads[0].addr, guest_memory::ADVICE_ORIGIN);
    assert_eq!(reads[1].addr, reads[0].addr);
    assert_eq!(
        reads[1].read_ts, reads[0].ts,
        "the second read is chained to the first's write-back"
    );
    for e in &reads {
        assert_eq!(e.read_value, 42);
        assert_eq!(
            e.write_value, e.read_value,
            "a load writes back what it read, which is what read-only means"
        );
    }
}

/// `run` and `trace_run` agree over the advice path, as they do everywhere
/// else (`crates/emulator/tests/consistency.rs`).
#[test]
fn the_traced_and_plain_paths_agree_over_advice() {
    let program = image_of(&[
        advice_base(1),
        i_type(OP_LOAD, 2, 10, 1, 4),
        exit_words()[0],
        exit_words()[1],
    ]);
    let io = with_advice(words([1, 23, 4, 5]));
    let (tables, config) = preprocess(&program);
    let plain = run(&program, &io).expect("it runs");
    let (_, _, _, traced) = trace_run(&program, &io, &tables, &config).expect("it traces");
    assert_eq!(plain, traced);
    assert_eq!(plain.exit_code, 23);
}

// ---------------------------------------------------------------------------
// The three fatal ones
// ---------------------------------------------------------------------------

/// **A store into the advice region is fatal.** Read-only is not advice's own
/// gate: a store's RAM query carries the literal `RAM` tag and could not name
/// the advice space whatever its address, so the executor refuses here what
/// the circuit refuses there (`docs/spec/advice.md` §4).
#[test]
fn a_store_into_advice_is_fatal() {
    let program = image_of(&[
        advice_base(1),
        s_type(OP_STORE, 2, 1, 0, 0), // sw x0, 0(x1)
        exit_words()[0],
        exit_words()[1],
    ]);
    let err = run(&program, &with_advice(words([1, 2, 3, 4]))).expect_err("a write is refused");
    assert!(
        matches!(
            err,
            EmuError::AdviceWrite {
                addr: guest_memory::ADVICE_ORIGIN,
                ..
            }
        ),
        "{err}"
    );
}

/// So is a sub-word store, which is a different family and the same rule.
#[test]
fn a_byte_store_into_advice_is_fatal() {
    let program = image_of(&[
        advice_base(1),
        s_type(OP_STORE, 0, 1, 0, 2), // sb x0, 2(x1)
        exit_words()[0],
        exit_words()[1],
    ]);
    let err = run(&program, &with_advice(words([1, 2, 3, 4]))).expect_err("a write is refused");
    assert!(matches!(err, EmuError::AdviceWrite { .. }), "{err}");
}

/// **An atomic may not even read it.** Every atomic stages one
/// read-and-write query, so admitting `lr.w` would mean admitting the write
/// half too; refusing the family outright costs nothing, since a
/// read-modify-write on a region nothing may write has no meaning.
#[test]
fn an_atomic_on_advice_is_fatal() {
    for (funct5, what) in [(0x00, "amoadd.w"), (0x02, "lr.w")] {
        let program = image_of(&[
            advice_base(1),
            amo(funct5, 10, 1, 0),
            exit_words()[0],
            exit_words()[1],
        ]);
        let err = run(&program, &with_advice(words([1, 2, 3, 4]))).expect_err("refused");
        assert!(matches!(err, EmuError::AdviceWrite { .. }), "{what}: {err}");
    }
}

/// A load past what the prover supplied is fatal, and it is **its own** error:
/// `OutOfBounds` says "outside the RAM window", which would be a lie about an
/// address that is squarely in the advice space.
#[test]
fn a_load_past_the_advice_is_fatal() {
    let program = image_of(&[
        advice_base(1),
        i_type(OP_LOAD, 2, 10, 1, 16), // lw x10, 16(x1): past four words
        exit_words()[0],
        exit_words()[1],
    ]);
    let err = run(&program, &with_advice(words([1, 2, 3, 4]))).expect_err("past the end");
    assert!(
        matches!(err, EmuError::AdviceOutOfBounds { len: 16, .. }),
        "{err}"
    );
}

/// An empty advice region has no readable word at all, so the very first load
/// is refused: a guest given no advice cannot silently read zeros.
#[test]
fn a_load_with_no_advice_supplied_is_fatal() {
    let program = image_of(&[
        advice_base(1),
        i_type(OP_LOAD, 2, 10, 1, 0),
        exit_words()[0],
        exit_words()[1],
    ]);
    let err = run(&program, &GuestIo::default()).expect_err("nothing was supplied");
    assert!(
        matches!(err, EmuError::AdviceOutOfBounds { len: 0, .. }),
        "{err}"
    );
}

/// Misalignment is checked first and unchanged, so an unaligned advice load is
/// `Misaligned` and not one of the advice errors.
#[test]
fn a_misaligned_advice_load_is_misaligned() {
    let program = image_of(&[
        advice_base(1),
        i_type(OP_LOAD, 2, 10, 1, 1), // lw x10, 1(x1)
        exit_words()[0],
        exit_words()[1],
    ]);
    let err = run(&program, &with_advice(words([1, 2, 3, 4]))).expect_err("misaligned");
    assert!(
        matches!(err, EmuError::Misaligned { width: 4, .. }),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// Aliasing
// ---------------------------------------------------------------------------

/// **Advice cannot alias RAM, and the ranges are why.** Distinct tags already
/// keep the tuples apart; what they do not do is stop a guest pointer walking
/// from one region into the other, because `p + n` is arithmetic and not a
/// tuple. The two spaces hold disjoint address sets, and neither holds an
/// address of the other (`docs/spec/advice.md` §1.1).
#[test]
fn the_two_memory_spaces_hold_disjoint_addresses() {
    assert!(!AddressSpace::Ram.holds(guest_memory::ADVICE_ORIGIN));
    assert!(!AddressSpace::Ram.holds(0xffff_fffc));
    assert!(!AddressSpace::Advice.holds(guest_memory::RAM_ORIGIN));
    assert!(!AddressSpace::Advice.holds(guest_memory::ADVICE_ORIGIN - 4));
    assert!(AddressSpace::Advice.holds(guest_memory::ADVICE_ORIGIN));
    // RAM's window ends exactly where advice begins, which is what leaves no
    // address in both and no address in neither.
    assert_eq!(
        guest_memory::RAM_ORIGIN + guest_memory::RAM_LENGTH,
        guest_memory::ADVICE_ORIGIN
    );
    assert!(AddressSpace::Ram.holds(guest_memory::ADVICE_ORIGIN - 4));
}

/// A run that touches both spaces logs them apart: no event of one is an
/// event of the other, at any address.
#[test]
fn a_run_touching_both_spaces_keeps_their_events_apart() {
    let program = image_of(&[
        advice_base(1),
        i_type(OP_LOAD, 2, 10, 1, 0),  // advice word 0 -> x10
        lui(2, 0x11),                  // x2 = 0x11000, RAM above this code
        s_type(OP_STORE, 2, 2, 10, 0), // sw x10, 0(x2): RAM
        i_type(OP_LOAD, 2, 11, 2, 0),  // lw x11, 0(x2): RAM again
        exit_words()[0],
        exit_words()[1],
    ]);
    let io = with_advice(words([77, 0, 0, 0]));
    let (tables, config) = preprocess(&program);
    let (_, log, _, execution) = trace_run(&program, &io, &tables, &config).expect("it traces");
    assert_eq!(execution.exit_code, 77);
    log.self_check(&program).expect("the log balances");

    let advice: Vec<_> = log
        .events()
        .iter()
        .filter(|e| e.space == AddressSpace::Advice)
        .map(|e| e.addr)
        .collect();
    let ram: Vec<_> = log
        .events()
        .iter()
        .filter(|e| e.space == AddressSpace::Ram)
        .map(|e| e.addr)
        .collect();
    assert!(!advice.is_empty() && !ram.is_empty(), "both were touched");
    for a in &advice {
        assert!(!ram.contains(a), "address {a:#010x} is in both spaces");
        assert!(*a >= guest_memory::ADVICE_ORIGIN);
    }
    for r in &ram {
        assert!(*r < guest_memory::ADVICE_ORIGIN);
    }
}
