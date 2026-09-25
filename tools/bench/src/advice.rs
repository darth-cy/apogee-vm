//! The **advice** region against the fd 0 `read` path, per word of witness
//! consumed. `docs/spec/advice.md` §7 is the cost table this routine measures.
//!
//! Two hand-encoded programs sum `n` 32-bit words and exit with the low byte
//! of the sum. They differ in where the words come from and in nothing else:
//!
//! - **fd 0**: one `read` ecall per word into a fixed one-word buffer, then an
//!   `lw` from that buffer. This is what `docs/spec/ecall-abi.md` §4 makes
//!   provable — a `read` moves exactly one 4-aligned word — so the ecall count
//!   is the witness size in words and is not a tunable.
//! - **advice**: one `lw` straight out of the region. No ecall, no buffer, no
//!   RAM write.
//!
//! **What this measures and what it does not.** It measures the per-word
//! mechanism: cycles, the shard plan, and the memory rows each path stages. It
//! is a *lower bound* on the fd 0 path, because a real guest reads through
//! `guest_sdk::read_input`, which also appends every byte to the public-input
//! stream — and because the dominant term, the exit-time `io_digest` over the
//! whole of fd 0, is not here at all: these programs exit through a bare
//! `EXIT` ecall with no SDK. The handoff note carries the end-to-end number
//! for `guests/revm-block`, where both of those are present.

use constants::{ecall, family, guest_memory};
use emulator::{trace_run, GuestIo};
use loader::{ProgramImage, Segment, Slot};
use program::{decode_program, ProgramParams};
use trace::plan_shards;

/// Witness sizes, in 32-bit words. The top one is 1 MiB, which is 1.3 million
/// cycles on the advice side and 1.8 million on fd 0's; above that the
/// emulator's own run time dominates the routine rather than the comparison.
const SIZES: [u32; 5] = [256, 4 * 1024, 16 * 1024, 64 * 1024, 256 * 1024];

const OP_LOAD: u32 = 0x03;
const OP_OP_IMM: u32 = 0x13;
const OP_OP: u32 = 0x33;
const OP_BRANCH: u32 = 0x63;
const OP_LUI: u32 = 0x37;
const OP_SYSTEM: u32 = 0x73;

fn i_type(op: u32, funct3: u32, rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | op
}

fn r_type(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | OP_OP
}

/// `bne rs1, rs2, imm` — `imm` is the signed byte offset from this
/// instruction, and B-type scatters its bits.
fn b_type(funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let i = imm as u32;
    ((i >> 12 & 1) << 31)
        | ((i >> 5 & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((i >> 1 & 0xf) << 8)
        | ((i >> 11 & 1) << 7)
        | OP_BRANCH
}

fn lui(rd: u32, imm20: u32) -> u32 {
    (imm20 << 12) | (rd << 7) | OP_LUI
}

/// `rd = value`, in one or two instructions: `lui` of the high twenty bits
/// then `addi` of the low twelve, sign-corrected.
fn load_imm(rd: u32, value: u32) -> Vec<u32> {
    let lo = value & 0xfff;
    let hi = (value >> 12) + u32::from(lo >= 0x800);
    let mut out = Vec::new();
    if hi != 0 {
        out.push(lui(rd, hi & 0xf_ffff));
    }
    if lo != 0 || hi == 0 {
        out.push(i_type(
            OP_OP_IMM,
            0,
            rd,
            if hi == 0 { 0 } else { rd },
            lo as i32,
        ));
    }
    out
}

/// A one-segment image of 32-bit `words`, entered at `RAM_ORIGIN`, with
/// `scratch` bytes of zero-initialized space after the code for the fd 0
/// buffer.
fn image_of(words: &[u32], scratch: u32) -> ProgramImage {
    let at = guest_memory::RAM_ORIGIN;
    let mut slots = Vec::new();
    for word in words {
        slots.push(Slot::Instruction {
            word: *word,
            compressed: false,
        });
        slots.push(Slot::MidInstruction);
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mem_len = bytes.len() as u32 + scratch;
    ProgramImage {
        entry: at,
        segments: vec![Segment {
            vaddr: at,
            mem_len,
            bytes,
        }],
        slot_base: at,
        slots,
    }
}

/// The advice program: `x1` walks the region, `x3` accumulates, `x2` counts
/// down. Five instructions a word — `lw`, `add`, two `addi`, `bne` — and the
/// loop is what the other three are measured against.
fn advice_program(n: u32) -> ProgramImage {
    let mut words = Vec::new();
    words.push(lui(1, guest_memory::ADVICE_ORIGIN >> 12)); // x1 = ADVICE_ORIGIN
    words.extend(load_imm(2, n)); // x2 = n
    words.push(i_type(OP_OP_IMM, 0, 3, 0, 0)); // x3 = 0
    let loop_start = words.len();
    words.push(i_type(OP_LOAD, 2, 5, 1, 0)); // lw x5, 0(x1)
    words.push(r_type(0, 5, 3, 0, 3)); // add x3, x3, x5
    words.push(i_type(OP_OP_IMM, 0, 1, 1, 4)); // addi x1, x1, 4
    words.push(i_type(OP_OP_IMM, 0, 2, 2, -1)); // addi x2, x2, -1
    let back = -4 * (words.len() - loop_start) as i32;
    words.push(b_type(1, 2, 0, back)); // bne x2, x0, loop
    words.push(i_type(OP_OP_IMM, 7, 10, 3, 0xff)); // andi a0, x3, 255
    words.push(i_type(OP_OP_IMM, 0, 17, 0, ecall::EXIT as i32));
    words.push(OP_SYSTEM);
    image_of(&words, 0)
}

/// The fd 0 program: the same loop with a `read` ecall in front of the load,
/// and `a0` reset each pass because the call writes its byte count there.
/// Seven instructions a word, one of them an ecall that moves one word.
fn fd0_program(n: u32) -> ProgramImage {
    let mut words = Vec::new();
    words.extend(load_imm(2, n)); // x2 = n
    words.push(i_type(OP_OP_IMM, 0, 3, 0, 0)); // x3 = 0
    words.push(i_type(OP_OP_IMM, 0, 17, 0, ecall::READ as i32)); // a7 = read
    words.push(i_type(OP_OP_IMM, 0, 12, 0, 4)); // a2 = 4 bytes
                                                // a1 = the buffer, one word past the end of the code. The image reserves
                                                // `scratch` bytes there and the loop reads into the same word every pass:
                                                // what is measured is the transfer, not where it lands.
    let buffer_at = guest_memory::RAM_ORIGIN + 4 * (words.len() as u32 + 8);
    words.extend(load_imm(11, buffer_at));
    let loop_start = words.len();
    words.push(i_type(OP_OP_IMM, 0, 10, 0, 0)); // a0 = fd 0
    words.push(OP_SYSTEM); // ecall: read one word
    words.push(i_type(OP_LOAD, 2, 5, 11, 0)); // lw x5, 0(a1)
    words.push(r_type(0, 5, 3, 0, 3)); // add x3, x3, x5
    words.push(i_type(OP_OP_IMM, 0, 2, 2, -1)); // addi x2, x2, -1
    let back = -4 * (words.len() - loop_start) as i32;
    words.push(b_type(1, 2, 0, back)); // bne x2, x0, loop
    words.push(i_type(OP_OP_IMM, 7, 10, 3, 0xff)); // andi a0, x3, 255
    words.push(i_type(OP_OP_IMM, 0, 17, 0, ecall::EXIT as i32));
    words.push(OP_SYSTEM);
    // The buffer sits where `a1` was computed to point; the code may not reach
    // it, so pad the instruction list out to that address first.
    while guest_memory::RAM_ORIGIN + 4 * words.len() as u32 <= buffer_at {
        words.push(i_type(OP_OP_IMM, 0, 0, 0, 0)); // nop
    }
    image_of(&words, 16)
}

/// One measured run: cycles and the shard plan. **Not** wall clock: what this
/// routine compares is what a proof would cost, and the emulator's own speed is
/// not that.
struct Run {
    cycles: u64,
    shards: Vec<(u32, u32)>,
}

fn measure(image: &ProgramImage, io: &GuestIo) -> Run {
    let mut params = ProgramParams::defaults();
    // One height for everything: the programs are a handful of instructions,
    // and the shard plan is what the witness size moves, not the code size.
    params.heights = [1 << 20; family::COUNT as usize];
    for f in [family::KECCAK_F, family::POSEIDON2, family::FR_ARITH] {
        params.heights[f as usize] = 1 << 8;
    }
    let (tables, config) = decode_program(image, &params).expect("the program decodes");
    let (_, log, profile, execution) =
        trace_run(image, io, &tables, &config).expect("the program runs");
    let h = 1 << 20;
    let windows = trace::init_windows(&log, h);
    let advice = trace::advice_windows(&log, h);
    let shards: Vec<(u32, u32)> = plan_shards(&profile, &config)
        .shards
        .iter()
        .map(|&(f, n)| match f {
            family::INIT_TEARDOWN => (f, 1),
            family::ZERO_WINDOWS => (f, windows.len() as u32),
            family::ADVICE_WINDOWS => (f, advice),
            _ => (f, n),
        })
        .filter(|(_, n)| *n > 0)
        .collect();
    assert_eq!(execution.exit_code & !0xff, 0, "the program exits cleanly");
    Run {
        cycles: profile.total(),
        shards,
    }
}

fn shard_list(shards: &[(u32, u32)]) -> String {
    shards
        .iter()
        .map(|(f, n)| format!("{}x{n}", program::family_name(*f)))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn run() {
    println!("S25b: the advice region against the fd 0 `read` path, per word of witness");
    println!("  A word is 4 bytes. `cycles/word` is the whole run divided by the words read,");
    println!("  so it carries the loop's own overhead as a real guest's would.\n");
    println!(
        "  {:>9} {:>9} {:>12} {:>11} {:>12} {:>11} {:>8}",
        "words", "bytes", "fd0 cycles", "fd0 c/word", "adv cycles", "adv c/word", "saved"
    );
    let mut plans: Vec<(u32, String, String)> = Vec::new();
    for n in SIZES {
        let bytes = 4 * n as usize;
        let blob: Vec<u8> = (0..bytes).map(|i| (i * 7 + 1) as u8).collect();
        let fd0 = measure(
            &fd0_program(n),
            &GuestIo {
                input: blob.clone(),
                ..GuestIo::default()
            },
        );
        let adv = measure(
            &advice_program(n),
            &GuestIo {
                advice: blob,
                ..GuestIo::default()
            },
        );
        println!(
            "  {:>9} {:>9} {:>12} {:>11.2} {:>12} {:>11.2} {:>7.2}x",
            n,
            bytes,
            fd0.cycles,
            fd0.cycles as f64 / n as f64,
            adv.cycles,
            adv.cycles as f64 / n as f64,
            fd0.cycles as f64 / adv.cycles as f64
        );
        plans.push((n, shard_list(&fd0.shards), shard_list(&adv.shards)));
    }
    println!("\n  The shard plan each path produces:");
    for (n, fd0, adv) in plans {
        println!("  {n:>9} words");
        println!("    fd 0   {fd0}");
        println!("    advice {adv}");
    }
    println!(
        "\n  Neither number includes the exit-time `io_digest`, which the fd 0 path pays over"
    );
    println!("  every byte it read and the advice path does not pay at all. That term is what");
    println!("  `docs/spec/advice.md` §7 calls dominant, and the handoff note measures it on");
    println!("  `guests/revm-block`, where the SDK and the digest are both present.");
}
