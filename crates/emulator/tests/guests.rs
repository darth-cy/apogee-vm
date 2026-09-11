//! The committed guests, executed by the emulator, against what the host
//! computes — the checks `crates/loader/tests/qemu.rs` makes under QEMU, made
//! here without an emulator of anybody else's, so they run everywhere.
//!
//! Acceptance 10 (a precompile answers `-ENOSYS` and the fallback completes)
//! and 11 (a misaligned access is a named fatal error in both paths) are
//! here, and so is the check that `opcodes` really executes every
//! instruction it claims to.

mod common;

use std::collections::BTreeSet;

use common::{image, instr_at, io, preprocess, traced, TRACED};
use emulator::{run, trace_run, EmuError, GuestIo};
use field::Fr;
use loader::Slot;
use test_support::to_hex;

#[test]
fn fib_commits_the_recorded_value() {
    let (input, output) = common::fib_record();
    let execution = run(&image("fib"), &io(&input)).unwrap();
    assert_eq!(execution.exit_code, 0);
    assert_eq!(execution.io.input, input, "fib consumes its whole input");
    assert_eq!(to_hex(&execution.io.output), to_hex(&output));
}

/// Must-be-exact 12: one core. The tracing path is the plain path plus a
/// recorder, so both report the same execution, bit for bit.
#[test]
fn run_and_trace_run_are_one_execution() {
    for name in TRACED {
        let t = traced(name);
        let plain = run(&t.image, &io(&common::input_of(name))).unwrap();
        assert_eq!(plain, t.execution, "{name}");
    }
}

#[test]
fn heap_churns_the_allocator_and_commits_the_host_values() {
    let n = 40u32;
    let squares: Vec<u32> = (0..n).map(|i| i.wrapping_mul(i)).collect();
    let rows: Vec<Vec<u8>> = (0..n)
        .map(|i| (0..(i % 13) as u8).collect::<Vec<u8>>())
        .filter(|r| r.len().is_multiple_of(2))
        .collect();
    let want: Vec<u8> = [
        squares.iter().fold(0u32, |a, s| a.wrapping_add(*s)),
        squares.iter().fold(0u32, |a, s| a.wrapping_add(s ^ 0x5555)),
        rows.iter().map(|r| r.len() as u32).sum(),
        rows.iter()
            .flatten()
            .fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(*b as u32)),
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();

    let execution = run(&image("heap"), &io(&n.to_le_bytes())).unwrap();
    assert_eq!(execution.exit_code, 0);
    assert_eq!(to_hex(&execution.io.output), to_hex(&want));
}

/// The host recomputation `tests/qemu.rs::atomics_computes_its_cells` makes,
/// against the emulator: every AMO's write and every value it returns.
#[test]
fn atomics_computes_its_cells() {
    let n: u32 = 37;
    let fold = |acc: u32, value: u32| acc.wrapping_mul(31).wrapping_add(value);
    let (mut sum, mut last, mut mixed, mut masked, mut flags) = (0u32, 0u32, 0u32, u32::MAX, 0u32);
    let (mut low, mut high, mut steps) = (i32::MAX, 0u32, 1u32);
    let (mut signed_high, mut unsigned_low) = (i32::MIN, u32::MAX);
    let mut old = 0u32;
    for i in 0..n {
        let x = i.wrapping_mul(0x9e37_79b9);
        old = fold(old, sum);
        sum = sum.wrapping_add(x);
        old = fold(old, last);
        last = x;
        old = fold(old, mixed);
        mixed ^= x;
        old = fold(old, masked);
        masked &= !(1 << (i % 32));
        old = fold(old, flags);
        flags |= 1 << (x >> 27);
        old = fold(old, low as u32);
        low = low.min(x as i32);
        old = fold(old, signed_high as u32);
        signed_high = signed_high.max(x as i32);
        old = fold(old, high);
        high = high.max(x);
        old = fold(old, unsigned_low);
        unsigned_low = unsigned_low.min(x ^ 0x5555_5555);
        steps = steps.wrapping_mul(3).wrapping_add(1);
    }
    high ^= signed_high as u32;
    sum = sum.wrapping_add(unsigned_low);
    let want: Vec<u8> = [
        sum, last, mixed, masked, flags, low as u32, high, steps, old,
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();

    let execution = run(&image("atomics"), &io(&n.to_le_bytes())).unwrap();
    assert_eq!(execution.exit_code, 0);
    assert_eq!(to_hex(&execution.io.output), to_hex(&want));
}

#[test]
fn the_rvc_fixture_runs() {
    let execution = run(&image("rvc-dense"), &io(&7u32.to_le_bytes())).unwrap();
    assert_eq!(execution.exit_code, 0);
    let word =
        |i: usize| u32::from_le_bytes(execution.io.output[4 * i..4 * i + 4].try_into().unwrap());
    assert_eq!(word(0), 46, "rvc_exec(7) and norvc_exec(7) agree on 46");
    assert_eq!(word(2), 2 * word(1));
}

/// Acceptance 10: the precompile number answers `-ENOSYS`, the guest takes
/// its software path, and that path computes the real S02 permutation —
/// with fd 1 an exact echo and the hint kept off it, as under QEMU.
#[test]
fn a_precompile_answers_enosys_and_the_fallback_completes() {
    let input: Vec<u8> = (0..100u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    let guest = GuestIo {
        input: input.clone(),
        hint: b"private-advice".to_vec(),
    };
    let execution = run(&image("echo"), &guest).unwrap();
    assert_eq!(execution.exit_code, 0);
    assert_eq!(to_hex(&execution.io.output), to_hex(&input));
    let stderr = String::from_utf8_lossy(&execution.stderr);
    assert!(stderr.contains("hint=private-advice"), "{stderr}");
    assert!(stderr.contains("precompile=software"), "{stderr}");
    let mut state = [Fr::from_u64(1), Fr::from_u64(2), Fr::from_u64(3)];
    transcript::poseidon2_permute(&mut state);
    assert!(
        stderr.contains(&format!("state0={}", to_hex(&state[0].to_bytes()))),
        "the software fallback did not produce the S02 permutation: {stderr}"
    );
}

/// `orderbook` commits the same bytes under a sorting permutation, a
/// transposed one and no advice at all: fd 3 binds nothing, in this executor
/// as in QEMU.
#[test]
fn orderbook_ignores_advice_it_cannot_verify() {
    let mut input = 4u32.to_le_bytes().to_vec();
    for (side, price, qty) in [(0u32, 100u64, 10u64), (1, 90, 6), (0, 95, 5), (1, 100, 3)] {
        input.extend_from_slice(&side.to_le_bytes());
        input.extend_from_slice(&price.to_le_bytes());
        input.extend_from_slice(&qty.to_le_bytes());
    }
    let advice = |perm: &[u32]| {
        let mut bytes = (perm.len() as u32).to_le_bytes().to_vec();
        for i in perm {
            bytes.extend_from_slice(&i.to_le_bytes());
        }
        bytes
    };
    let image = image("orderbook");
    let outputs: Vec<(Vec<u8>, String)> =
        [advice(&[0, 2, 1, 3]), advice(&[0, 2, 3, 1]), Vec::new()]
            .into_iter()
            .map(|hint| {
                let e = run(
                    &image,
                    &GuestIo {
                        input: input.clone(),
                        hint,
                    },
                )
                .unwrap();
                assert_eq!(e.exit_code, 0);
                (e.io.output, String::from_utf8_lossy(&e.stderr).into_owned())
            })
            .collect();
    assert_eq!(outputs[0].0.len(), 28);
    assert_eq!(outputs[0].0, outputs[1].0);
    assert_eq!(outputs[0].0, outputs[2].0);
    assert!(outputs[0].1.contains("advice=verified"), "{}", outputs[0].1);
    assert!(outputs[1].1.contains("advice=rejected"), "{}", outputs[1].1);
    assert!(outputs[2].1.contains("advice=rejected"), "{}", outputs[2].1);
}

/// The 59 RV32IMA mnemonics, from the ISA manual's tables rather than from
/// `crates/isa`.
const MNEMONICS: [&str; 59] = [
    "lui",
    "auipc",
    "jal",
    "jalr",
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",
    "lb",
    "lh",
    "lw",
    "lbu",
    "lhu",
    "sb",
    "sh",
    "sw",
    "addi",
    "slti",
    "sltiu",
    "xori",
    "ori",
    "andi",
    "slli",
    "srli",
    "srai",
    "add",
    "sub",
    "sll",
    "slt",
    "sltu",
    "xor",
    "srl",
    "sra",
    "or",
    "and",
    "fence",
    "ecall",
    "ebreak",
    "mul",
    "mulh",
    "mulhsu",
    "mulhu",
    "div",
    "divu",
    "rem",
    "remu",
    "lr.w",
    "sc.w",
    "amoswap.w",
    "amoadd.w",
    "amoxor.w",
    "amoand.w",
    "amoor.w",
    "amomin.w",
    "amomax.w",
    "amominu.w",
    "amomaxu.w",
];

/// `opcodes` executes every instruction but `ebreak` in mode 0 — and
/// `ebreak` in mode 1 — and every instruction of its compressed block, all
/// of them compressed.
#[test]
fn opcodes_executes_every_instruction() {
    let t = traced("opcodes");
    let mut executed = BTreeSet::new();
    let mut pcs = BTreeSet::new();
    for trace in &t.traces.families {
        for pc in &trace.pc {
            executed.insert(instr_at(&t.image, *pc).mnemonic());
            pcs.insert(*pc);
        }
    }
    let missing: Vec<&str> = MNEMONICS
        .iter()
        .filter(|m| **m != "ebreak" && !executed.contains(*m))
        .copied()
        .collect();
    assert!(missing.is_empty(), "opcodes never executes {missing:?}");
    assert_eq!(executed.len(), 58, "{executed:?}");

    let out = &t.execution.io.output;
    assert_eq!(
        &out[..6],
        &common::opcodes_input()[4..],
        "cover_ecall echoes its payload"
    );
    let word = |i: usize| u32::from_le_bytes(out[6 + 4 * i..10 + 4 * i].try_into().unwrap());
    let (begin, end) = (word(5), word(6));
    assert!(
        end > begin + 60,
        "the compressed block is {} bytes",
        end - begin
    );
    let mut pc = begin;
    let mut count = 0;
    while pc < end {
        match t.image.slot_at(pc) {
            Some(Slot::Instruction {
                compressed: true, ..
            }) => {}
            other => panic!("{pc:#x} in the compressed block is {other:?}"),
        }
        assert!(
            pcs.contains(&pc),
            "the compressed instruction at {pc:#x} never ran"
        );
        pc += 2;
        count += 1;
    }
    assert!(count >= 40, "only {count} compressed instructions");

    let e = run(&t.image, &io(&1u32.to_le_bytes())).unwrap_err();
    let EmuError::Ebreak { pc } = e else {
        panic!("mode 1 stopped with {e:?}")
    };
    assert_eq!(instr_at(&t.image, pc).mnemonic(), "ebreak");
}

/// Acceptance 11: each misaligned access — `lw`, `sw`, `lh`, `sh`, `lr.w`,
/// `sc.w`, `amoadd.w` — is the named fatal error in `run` and in
/// `trace_run`, at the instruction that made it, and `trace_run` hands back
/// no trace.
#[test]
fn a_misaligned_access_is_a_named_fatal_error_in_both_paths() {
    let image = image("opcodes");
    let (tables, config) = preprocess(&image);
    for (mode, mnemonic, width) in [
        (2u32, "lw", 4),
        (3, "sw", 4),
        (4, "lh", 2),
        (5, "sh", 2),
        (6, "lr.w", 4),
        (7, "sc.w", 4),
        (8, "amoadd.w", 4),
    ] {
        let guest = io(&mode.to_le_bytes());
        let plain = run(&image, &guest).unwrap_err();
        let traced = trace_run(&image, &guest, &tables, &config).unwrap_err();
        assert_eq!(plain, traced, "{mnemonic}: the two paths disagree");
        let EmuError::Misaligned { pc, addr, width: w } = plain else {
            panic!("{mnemonic}: stopped with {plain:?}, not a misaligned access")
        };
        assert_eq!(instr_at(&image, pc).mnemonic(), mnemonic);
        assert_eq!(w, width, "{mnemonic}");
        assert_ne!(addr % width, 0, "{mnemonic}: {addr:#x} is aligned");
        assert!(plain.to_string().contains("misaligned"), "{plain}");
    }
}
