//! The committed guests, executed by the emulator, against what the host
//! computes: each guest's journal recomputed here from its inputs, so every
//! check runs everywhere with no second executor to install.
//!
//! The check that a misaligned access is a named fatal error in both paths is
//! here, and so is the check that `opcodes` really executes every instruction
//! it claims to.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{image, instr_at, io, preprocess, traced, TRACED};
use emulator::{run, trace_run, EmuError};
use loader::Slot;
use test_support::{to_hex, Rng};

/// `fib` reads its `n` out of the public input window and leaves its term in
/// the journal, so the committed record is both of its public values and a
/// proof binds the pair (`docs/spec/public-values.md` §1).
#[test]
fn fib_commits_the_recorded_value() {
    let (input, output) = common::fib_record();
    let execution = run(&image("fib"), &io(&input)).unwrap();
    assert_eq!(execution.exit_code, 0);
    assert_eq!(to_hex(&execution.io.output), to_hex(&output));
    assert_eq!(
        to_hex(&execution.io.input),
        to_hex(&input),
        "the window's contents are the statement's public input"
    );
}

/// `cpp-primes`, the C++ guest, built by CMake against the C/C++ SDK
/// (`docs/guest-program-manual.md` §11), decides primality of 64-bit integers
/// whose answers are number theory, not this repository: the first primes and
/// non-primes, the Carmichael number 561, the Mersenne prime `2^61 − 1`, the
/// largest 64-bit prime `2^64 − 59`, `2^64 − 1`, and 3215031751, the least
/// strong pseudoprime to the bases 2, 3, 5 and 7.
#[test]
fn cpp_primes_decides_each_integer() {
    let cases: [(u64, u8); 10] = [
        (0, 0),
        (1, 0),
        (2, 1),
        (97, 1),
        (561, 0),
        (1_000_000_007, 1),
        ((1 << 61) - 1, 1),
        (u64::MAX - 58, 1),
        (u64::MAX, 0),
        (3_215_031_751, 0),
    ];
    let input: Vec<u8> = cases.iter().flat_map(|(n, _)| n.to_le_bytes()).collect();
    let execution = run(&image("cpp-primes"), &io(&input)).unwrap();
    assert_eq!(execution.exit_code, 0);
    let mut journal = 10u32.to_le_bytes().to_vec();
    journal.extend(5u32.to_le_bytes());
    journal.extend(cases.map(|(_, prime)| prime));
    assert_eq!(to_hex(&execution.io.output), to_hex(&journal));
}

// ---------------------------------------------------------------------------
// The public values and the advice region, executed
// ---------------------------------------------------------------------------

/// The public input `guests/public-io` reads for `advice`: the advice's length
/// and the checksum it must have (`guests/public-io/src/main.rs`).
fn public_io_input(advice: &[u8]) -> Vec<u8> {
    let mut sum = 0u32;
    for (i, byte) in advice.iter().enumerate() {
        sum = sum.wrapping_add((*byte as u32).wrapping_mul(i as u32 + 1));
    }
    let mut input = (advice.len() as u32).to_le_bytes().to_vec();
    input.extend_from_slice(&sum.to_le_bytes());
    input
}

fn sample_advice() -> Vec<u8> {
    (0..20u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect()
}

/// The whole mechanism, executed: the guest reads its public input with
/// ordinary loads, checks its advice against it, and leaves its result in the
/// journal — which the executor reads back out of the window at exit
/// (`docs/spec/public-values.md`).
#[test]
fn public_io_reads_its_windows_and_commits_a_journal() {
    let advice = sample_advice();
    let guest = common::with_advice(&public_io_input(&advice), &advice);
    let execution = run(&image("public-io"), &guest).unwrap();
    assert_eq!(execution.exit_code, 0, "the guest accepted its advice");

    // The journal is the checksum, then the first eight advice bytes; its
    // byte length is what word 0 of the window carries, so a journal of 12
    // bytes reads back as 12 bytes and not as three zero-padded words.
    let mut want = public_io_input(&advice)[4..].to_vec();
    want.extend_from_slice(&advice[..8]);
    assert_eq!(to_hex(&execution.io.output), to_hex(&want));
    assert_eq!(execution.io.output.len(), 12);

    // The statement's public input is the window's payload, whether or not the
    // guest looked — here it did.
    assert_eq!(execution.io.input, public_io_input(&advice));
}

/// Advice is unbound, so the guest is what stands in for the binding: a run
/// whose advice does not check against its public input publishes nothing.
#[test]
fn public_io_refuses_advice_its_public_input_does_not_commit_to() {
    let advice = sample_advice();
    let input = public_io_input(&advice);

    let mut swapped = advice.clone();
    swapped[0] ^= 0xFF;
    let execution = run(&image("public-io"), &common::with_advice(&input, &swapped)).unwrap();
    assert_eq!(execution.exit_code, 62, "the checksum did not match");
    assert!(
        execution.io.output.is_empty(),
        "a refused run published a journal"
    );

    // A permutation is refused too: the checksum is position-dependent.
    let mut rotated = advice.clone();
    rotated.swap(0, 1);
    let execution = run(&image("public-io"), &common::with_advice(&input, &rotated)).unwrap();
    assert_eq!(execution.exit_code, 62);

    // And a different length is refused before the checksum is even taken.
    let short = &advice[..advice.len() - 1];
    let execution = run(&image("public-io"), &common::with_advice(&input, short)).unwrap();
    assert_eq!(execution.exit_code, 61);
}

/// **No advice means no advice region**, so a guest that asks for advice it
/// was not given takes the fatal `OutOfBounds` rather than reading zeros
/// (`docs/spec/public-values.md` §6). A prover that supplies nothing loses its
/// own trace, which is the right cost.
#[test]
fn asking_for_advice_that_was_not_supplied_is_fatal() {
    let guest = common::with_advice(&public_io_input(&[]), &[]);
    match run(&image("public-io"), &guest) {
        Err(EmuError::OutOfBounds { addr, .. }) => assert_eq!(
            addr,
            constants::guest_memory::ADVICE_ORIGIN as u64,
            "the fatal read is the region's length word"
        ),
        other => panic!("a run with no advice gave {other:?}"),
    }
}

/// A public input longer than the window that would carry it is refused before
/// the first cycle, by name: no statement could hold it
/// (`docs/spec/public-values.md` §3).
#[test]
fn a_public_input_too_long_for_its_window_is_refused_by_name() {
    let payload = constants::guest_memory::PUBLIC_PAYLOAD_BYTES as usize;
    // The ceiling itself runs; one byte more does not.
    let guest = common::with_advice(&vec![7u8; payload], &[]);
    assert!(matches!(
        run(&image("public-io"), &guest),
        Ok(_) | Err(EmuError::OutOfBounds { .. })
    ));
    let guest = common::with_advice(&vec![7u8; payload + 1], &[]);
    assert_eq!(
        run(&image("public-io"), &guest),
        Err(EmuError::PublicInputTooLong { len: payload + 1 })
    );
}

/// One core: the tracing path is the plain path plus a recorder, so both
/// report the same execution, bit for bit.
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

/// The host's own recomputation of `atomics`' cells, against the emulator's:
/// every AMO's write and every value it returns, in the journal's order.
#[test]
fn atomics_computes_its_cells() {
    let n: u32 = 37;
    let fold = |acc: u32, value: u32| acc.wrapping_mul(31).wrapping_add(value);
    let (mut sum, mut last, mut mixed, mut masked, mut flags) = (0u32, 0u32, 0u32, u32::MAX, 0u32);
    let (mut low, mut high, mut steps) = (i32::MAX, 0u32, 1u32);
    let (mut signed_high, mut unsigned_low) = (i32::MIN, u32::MAX);
    let mut old = 0u32;
    let fold64 = |acc: u64, value: u64| acc.wrapping_mul(31).wrapping_add(value);
    let mut wide = [0u64, 0, 0, u64::MAX, 0, 1];
    let (mut wide_low, mut wide_high) = (i64::MAX, i64::MIN);
    let (mut wide_ulow, mut wide_uhigh) = (u64::MAX, 0u64);
    let mut wide_old = 0u64;
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
        let y = (x as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ i as u64;
        let returned = [
            wide[0],
            wide[1],
            wide[2],
            wide[3],
            wide[4],
            wide_low as u64,
            wide_high as u64,
            wide_ulow,
            wide_uhigh,
        ];
        for v in returned {
            wide_old = fold64(wide_old, v);
        }
        wide[0] = wide[0].wrapping_add(y);
        wide[1] = y;
        wide[2] ^= y;
        wide[3] &= !(1 << (i % 64));
        wide[4] |= 1 << (y >> 58);
        wide_low = wide_low.min(y as i64);
        wide_high = wide_high.max(y as i64);
        wide_ulow = wide_ulow.min(y);
        wide_uhigh = wide_uhigh.max(y);
        wide[5] = wide[5].wrapping_mul(3).wrapping_add(1);
    }
    high ^= signed_high as u32;
    sum = sum.wrapping_add(unsigned_low);
    let mut want: Vec<u8> = [
        sum, last, mixed, masked, flags, low as u32, high, steps, old,
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let cells =
        wide.iter()
            .copied()
            .chain([wide_low as u64, wide_high as u64, wide_ulow, wide_uhigh]);
    want.extend(cells.fold(0, fold64).to_le_bytes());
    want.extend(wide_old.to_le_bytes());

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

/// `echo` is the bump allocator's fixture, and this is the allocator running:
/// the advice region reaches the journal 64 bytes at a time through a
/// heap-allocated buffer, so a real allocation and a real copy stand between
/// the two regions.
///
/// Nothing binds advice, so this journal is a byte string the prover chose —
/// the one shape `docs/spec/public-values.md` §6 tells a real program not to
/// have, and exactly why this guest is a fixture and not a program.
///
/// Exit 0 carries the guest's own assertions besides, the four-byte-aligned
/// allocation among them: a panicking guest exits 101 and keeps whatever it
/// had already committed, so the pair — the status and the journal — is what
/// says the run finished.
#[test]
fn echo_copies_its_advice_into_the_journal_through_the_heap() {
    let advice: Vec<u8> = (0..100u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    let execution = run(&image("echo"), &common::with_advice(&[], &advice)).unwrap();
    assert_eq!(execution.exit_code, 0);
    assert_eq!(to_hex(&execution.io.output), to_hex(&advice));
}

/// `orderbook` commits the same bytes under a sorting permutation, a
/// transposed one and a region carrying no permutation at all.
///
/// Advice binds nothing, so which path ran — the checked permutation or the
/// guest's own sort — is a fact about the prover and not about the auction, and
/// the journal is where that shows: it is the same 28 bytes three times, with
/// nothing anywhere saying which (`docs/spec/public-values.md` §6).
///
/// The third case supplies a *region* rather than nothing, because asking for
/// advice a run was not given is a fatal executor error: "no permutation to
/// offer" is a length word of 0, not an absent region.
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
    let journals: Vec<Vec<u8>> = [advice(&[0, 2, 1, 3]), advice(&[0, 2, 3, 1]), advice(&[])]
        .into_iter()
        .map(|region| {
            let e = run(&image, &common::with_advice(&input, &region)).unwrap();
            assert_eq!(e.exit_code, 0);
            e.io.output
        })
        .collect();
    assert_eq!(journals[0].len(), 28);
    assert_eq!(journals[0], journals[1]);
    assert_eq!(journals[0], journals[2]);
}

/// The 87 RV64IMA mnemonics, from the ISA manual's tables rather than from
/// `crates/isa`.
const MNEMONICS: [&str; 87] = [
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
    "ld",
    "lwu",
    "sd",
    "addiw",
    "slliw",
    "srliw",
    "sraiw",
    "addw",
    "subw",
    "sllw",
    "srlw",
    "sraw",
    "mulw",
    "divw",
    "divuw",
    "remw",
    "remuw",
    "lr.d",
    "sc.d",
    "amoswap.d",
    "amoadd.d",
    "amoxor.d",
    "amoand.d",
    "amoor.d",
    "amomin.d",
    "amomax.d",
    "amominu.d",
    "amomaxu.d",
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
    assert_eq!(executed.len(), 86, "{executed:?}");

    let out = &t.execution.io.output;
    assert_eq!(
        out.len(),
        32,
        "the journal is the six blocks' folds and the compressed block's bounds"
    );
    let word = |i: usize| u32::from_le_bytes(out[4 * i..4 * i + 4].try_into().unwrap());
    let (begin, end) = (word(6), word(7));
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

/// Each misaligned access — `lw`, `sw`, `lh`, `sh`, `lr.w`,
/// `sc.w`, `amoadd.w`, `ld`, `amoadd.d` — is the named fatal error in `run` and in
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
        (9, "ld", 8),
        (10, "amoadd.d", 8),
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
        assert_ne!(addr % width as u64, 0, "{mnemonic}: {addr:#x} is aligned");
        assert!(plain.to_string().contains("misaligned"), "{plain}");
    }
}

/// **The recorded public input is what the host supplied, not what the guest
/// read.**
///
/// `heap` takes its four-byte `n` out of the window and never the four after
/// it, and both runs record all eight. The statement's public input is the
/// *window's* contents: the binding is that the window held those bytes, not
/// that anybody read them (`docs/spec/public-values.md` §9). A window is not a
/// cursor, and how far a guest got is guest state the statement has no room
/// for.
#[test]
fn the_recorded_public_input_is_what_the_host_supplied() {
    let mut window = 40u32.to_le_bytes().to_vec();
    window.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let guest = io(&window);
    let image = image("heap");
    let plain = run(&image, &guest).unwrap();
    assert_eq!(plain.io.input, window);
    let (tables, config) = preprocess(&image);
    let (.., traced) = trace_run(&image, &guest, &tables, &config).unwrap();
    assert_eq!(traced.io.input, window);
}

// ---------------------------------------------------------------------------
// Falcon-512 verification, executed
// ---------------------------------------------------------------------------

/// A Falcon-512 case in the SDK's advised forms: a key, a message, a context
/// and a signature.
type Case = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// The case of v1.2's encodings `pk` and `sig`, converted as a host converts
/// them, or the conversion's refusal of a key's or a signature's length or
/// header.
fn advised(pk: &[u8], msg: &[u8], context: &[u8], sig: &[u8]) -> Result<Case, &'static str> {
    let key = apogee_falcon512::key_advice(pk)?.to_vec();
    let signature = apogee_falcon512::signature_advice(sig)?;
    Ok((key, msg.to_vec(), context.to_vec(), signature))
}

/// The bit after the last one in `stream`, its bytes MSB first: where a
/// stream of codewords, each ending in a one, ends.
fn stream_end(stream: &[u8]) -> usize {
    let i = stream.iter().rposition(|&b| b != 0).expect("a one");
    8 * i + 8 - stream[i].trailing_zeros() as usize
}

/// `guests/precompiles` over `cases` and the trie scenarios `tries`, after its
/// other calls at their fewest: a zero leaf, the zero arrays' norm once, and a
/// long trie program of one step. Each case's key and signature, then each
/// one's message and context. Eight cases of short messages and contexts fill
/// the public input window.
fn precompiles_run(cases: &[Case], tries: &[Vec<u8>]) -> Result<emulator::Execution, EmuError> {
    let mut input = [
        1u32.to_le_bytes().as_slice(),
        &[0u8; 64],
        &[0u8; 3 * 1024],
        &0u32.to_le_bytes(),
    ]
    .concat();
    input.extend((cases.len() as u32).to_le_bytes());
    for (key, _, _, signature) in cases {
        input.extend(key);
        input.extend((signature.len() as u32).to_le_bytes());
        input.extend(signature);
    }
    for (_, message, context, _) in cases {
        for field in [message, context] {
            input.extend((field.len() as u32).to_le_bytes());
            input.extend(field);
        }
    }
    let advice = common::precompiles_advice(1, tries);
    run(&image("precompiles"), &common::with_advice(&input, &advice))
}

/// Every one of `cases` verifies: the guest exits 0, a 1 journaled a case.
fn falcon_verifies(cases: &[Case]) {
    let execution = precompiles_run(cases, &[]).unwrap();
    assert_eq!(execution.exit_code, 0);
    let journal = execution.io.output;
    assert_eq!(journal[journal.len() - cases.len()..], vec![1; cases.len()]);
}

/// How a Falcon-512 case ends its execution: a panic, exit 101, or the
/// decode call's refusal of a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Panic,
    Refused,
}

/// How `case`, run alone, ends the execution; a panic if it does not.
fn falcon_failure(case: Case) -> Failure {
    match precompiles_run(&[case], &[]) {
        Ok(e) if e.exit_code == 101 => Failure::Panic,
        Err(EmuError::DelegationFrame { detail, .. }) if detail.starts_with("falcon512_decode") => {
            Failure::Refused
        }
        other => panic!("the case does not end the execution: {other:?}"),
    }
}

/// The host library's signatures, under keys from two fixed seeds, over
/// messages of 0, 64 and 200 bytes under contexts of 0, 25 and 255 bytes,
/// verify: new ones each run, its signing randomized.
#[test]
fn falcon512_verifies_apogee_falcon512_signatures() {
    let mut cases = Vec::new();
    for seed in [[0x5a; 32], [0xc3; 32]] {
        let (sk, pk) = apogee_falcon512::keygen(seed);
        for (len, context) in [(0, 0), (64, 25), (200, 255)] {
            let bytes = |len: usize, k: u8| -> Vec<u8> {
                (0..len)
                    .map(|i| (i as u8).wrapping_mul(k) ^ seed[0])
                    .collect()
            };
            let (msg, context) = (bytes(len, 29), bytes(context, 53));
            let sig = apogee_falcon512::sign(&sk, &msg, &context);
            cases.push(advised(&pk, &msg, &context, &sig).unwrap());
        }
    }
    falcon_verifies(&cases);
}

/// A host library signature of a 64-byte message under a 25-byte context,
/// drawn until its stream ends inside a word, altered one way a case, each
/// ending its own execution: a bit of the message, of the salt and of the
/// context flipped, the key another seed's, which K and so HashToPoint hash
/// too, and the signature a word longer, its last byte 1, which verifies but
/// is not the length the input gives, all panics; the key's first
/// coefficient `2^14 − 1`, at least `q`, `s2`'s stream all zeros, no
/// coefficient ending within 16 zeros, a one just after the stream's end, in
/// its last word, and 512 coefficients of size 2047, 24 bits each, past 5,000
/// bits, the decode call's refusals; and a bit of the stream flipped, or the
/// signature a word short, either, as the stream can decode to other
/// coefficients or to none, or end elsewhere. The header of a key or a
/// signature changed, or either a byte short, the host's conversion refuses.
#[test]
fn falcon512_refuses_each_alteration() {
    use apogee_falcon512::{key_advice, signature_advice};
    use Failure::{Panic, Refused};
    let (sk, pk) = apogee_falcon512::keygen([0x5a; 32]);
    let (_, other) = apogee_falcon512::keygen([0xc3; 32]);
    let msg: Vec<u8> = (0..64).map(|i| (i as u8).wrapping_mul(29)).collect();
    let context = b"apogee/amazon/purchase/v1".to_vec();
    let (sig, end) = loop {
        let sig = apogee_falcon512::sign(&sk, &msg, &context);
        let end = stream_end(&sig[41..]);
        if !end.is_multiple_of(32) {
            break (sig, end);
        }
    };
    let flip = |bytes: &[u8], at: usize, bit: u32| {
        let mut bytes = bytes.to_vec();
        bytes[at] ^= 1 << bit;
        bytes
    };
    assert_eq!(
        key_advice(&flip(&pk, 0, 1)),
        Err("a public key's header is 0x09")
    );
    assert_eq!(key_advice(&pk[..896]), Err("a public key is 897 bytes"));
    assert_eq!(
        signature_advice(&flip(&sig, 0, 4)),
        Err("a signature's header is 0x39")
    );
    assert_eq!(
        signature_advice(&sig[..665]),
        Err("a signature is 666 bytes")
    );

    let case = advised(&pk, &msg, &context, &sig).unwrap();
    let altered = |alter: &dyn Fn(&mut Case)| {
        let mut case = case.clone();
        alter(&mut case);
        case
    };
    let cases = [
        (altered(&|c| c.1[16] ^= 1), Some(Panic)),
        (altered(&|c| c.3[17] ^= 1 << 3), Some(Panic)),
        (altered(&|c| c.2[24] ^= 1), Some(Panic)),
        (
            altered(&|c| c.0 = key_advice(&other).unwrap().to_vec()),
            Some(Panic),
        ),
        (altered(&|c| c.3.extend([0, 0, 0, 1])), Some(Panic)),
        (
            altered(&|c| {
                c.0[0] = 0xff;
                c.0[1] |= 0xfc;
            }),
            Some(Refused),
        ),
        (altered(&|c| c.3[40..].fill(0)), Some(Refused)),
        (
            altered(&|c| c.3[40 + end / 8] |= 0x80 >> (end % 8)),
            Some(Refused),
        ),
        (
            altered(&|c| {
                c.3.truncate(40);
                c.3.extend([0x7f, 0, 1].repeat(512));
            }),
            Some(Refused),
        ),
        (altered(&|c| c.3[140] ^= 1 << 5), None),
        (altered(&|c| c.3.truncate(c.3.len() - 4)), None),
    ];
    for (k, (case, want)) in cases.into_iter().enumerate() {
        let failure = falcon_failure(case);
        assert!(
            want.is_none_or(|want| failure == want),
            "case {k}: {failure:?}"
        );
    }
}

/// The SDK's verifier agrees with the other implementations on
/// `tools/falcon512/vectors.json`, each key and signature converted as a host
/// converts them. Every signature there verifies under its context: two each
/// from the Rust, JavaScript and Python libraries. The conversion refuses the
/// malformed signature under `0x29` and the one a byte short; every other
/// malformed case ends its own execution, including the two a lenient
/// decoder would pass: negative zero, and a one bit after the last
/// coefficient, inside its byte. The decode call refuses those and the key's
/// coefficient `2^14 − 1`. The guest panics at `padding_byte_bit`, whose one
/// is in the stream's byte 620, the first of the word after the one holding
/// its last bit, 4,954: the signature verifies, but is a word shorter than
/// the advice. The SDK panics at the rest.
#[test]
fn falcon512_agrees_with_every_implementation() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../../tools/falcon512/vectors.json"))
            .expect("the vectors are JSON");
    let section = |name: &str| vectors[name].as_array().expect("a section").clone();
    let case = |v: &serde_json::Value| {
        let field = |k: &str| test_support::hex_to_bytes(v[k].as_str().expect("hex")).expect("hex");
        advised(
            &field("pk"),
            &field("msg"),
            &field("context"),
            &field("sig"),
        )
    };
    let signatures = section("signatures");
    assert_eq!(signatures.len(), 6);
    let cases: Vec<Case> = signatures.iter().map(|v| case(v).unwrap()).collect();
    falcon_verifies(&cases);
    let malformed = section("malformed");
    assert_eq!(malformed.len(), 8);
    for v in &malformed {
        let name = v["case"].as_str().expect("a name");
        let want = match name {
            "header_0x29" | "one_byte_short" => {
                assert!(case(v).is_err(), "{name}");
                continue;
            }
            "negative_zero" | "last_byte_bit" | "key_coefficient_16383" => Failure::Refused,
            _ => Failure::Panic,
        };
        assert_eq!(falcon_failure(case(v).unwrap()), want, "{name}");
    }
}

// ---------------------------------------------------------------------------
// The SDK's trie, executed
// ---------------------------------------------------------------------------

/// A table of `k`-byte keys and `v`-byte values, and a batch over it.
struct Batch {
    k: usize,
    v: usize,
    table: Vec<(Vec<u8>, Vec<u8>)>,
    inserts: Vec<(Vec<u8>, Vec<u8>)>,
    sets: Vec<(Vec<u8>, Vec<u8>)>,
    removes: Vec<Vec<u8>>,
}

impl Batch {
    /// `table` of `k`-byte keys, each with a value of `v` random bytes, and a
    /// batch inserting `inserts`, setting the next `sets` keys of `table` to
    /// new values and removing the `removes` after them.
    fn new(
        rng: &mut Rng,
        (k, v): (usize, usize),
        table: &[Vec<u8>],
        inserts: &[Vec<u8>],
        (sets, removes): (usize, usize),
    ) -> Batch {
        let mut valued = |keys: &[Vec<u8>]| -> Vec<(Vec<u8>, Vec<u8>)> {
            keys.iter()
                .map(|key| (key.clone(), rng.next_bytes(v)))
                .collect()
        };
        Batch {
            k,
            v,
            table: valued(table),
            inserts: valued(inserts),
            sets: valued(&table[..sets]),
            removes: table[sets..sets + removes].to_vec(),
        }
    }

    /// The batch as `guests/precompiles` reads a trie scenario, where its
    /// proof begins, and the root `tools/mpt` gives the table after it. The
    /// guest opens every key the batch sets or removes and each insert's
    /// witness, all on the table before the batch.
    fn scenario(&self) -> (Vec<u8>, usize, apogee_mpt::Digest) {
        let mut trie = apogee_mpt::Trie::new(self.k);
        for (key, value) in &self.table {
            trie.insert(key, apogee_mpt::leaf(key, value));
        }
        let mut opened: BTreeSet<Vec<u8>> = self.removes.iter().cloned().collect();
        opened.extend(self.sets.iter().map(|(key, _)| key.clone()));
        if !trie.is_empty() {
            opened.extend(self.inserts.iter().map(|(key, _)| trie.witness(key)));
        }
        let opened: Vec<Vec<u8>> = opened.into_iter().collect();
        let values: BTreeMap<&Vec<u8>, &Vec<u8>> =
            self.table.iter().map(|(key, value)| (key, value)).collect();
        let word = |n: usize| (n as u32).to_le_bytes();
        let mut out = [word(self.k), word(self.v), word(opened.len())].concat();
        for key in &opened {
            out.extend(key);
            out.extend(values[key]);
        }
        let proof = out.len();
        out.extend(trie.proof(&opened));
        out.extend(trie.root().iter().flat_map(|lane| lane.to_le_bytes()));
        for edits in [&self.inserts, &self.sets] {
            out.extend(word(edits.len()));
            for (key, value) in edits {
                out.extend(key);
                out.extend(value);
                trie.insert(key, apogee_mpt::leaf(key, value));
            }
        }
        out.extend(word(self.removes.len()));
        for key in &self.removes {
            out.extend(key);
            trie.remove(key);
        }
        (out, proof, trie.root())
    }
}

/// `n` distinct keys by `draw`.
fn keys(rng: &mut Rng, n: usize, draw: impl Fn(&mut Rng) -> Vec<u8>) -> Vec<Vec<u8>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    while out.len() < n {
        let key = draw(rng);
        if seen.insert(key.clone()) {
            out.push(key);
        }
    }
    out
}

/// A table of 40 four-byte keys, 36 with the top bit set and `0x10` to
/// `0x13`, and a batch inserting four keys, setting five and removing three
/// and then `0x10`: the one key it touches under the branch over `0x10` to
/// `0x13`, which the remove leaves with two opaque children.
fn four_byte_batch(rng: &mut Rng) -> Batch {
    let drawn = keys(rng, 40, |rng| {
        let mut key = rng.next_bytes(4);
        key[0] |= 0x80;
        key
    });
    let mut table = drawn[..36].to_vec();
    table.splice(8..8, (0x10..0x14).map(|b| vec![0, 0, 0, b]));
    Batch::new(rng, (4, 8), &table, &drawn[36..], (5, 4))
}

/// `guests/precompiles` streamed on `input`, its public input, and the trie
/// scenarios `tries`, each shard dropped as it fills: the execution, and its
/// `MPT_ROOT` calls, its profile's `MPT` rows, one a call.
fn trie_calls(input: &[u8], tries: &[Vec<u8>]) -> (emulator::Execution, u64) {
    let image = image("precompiles");
    let (tables, config) = preprocess(&image);
    let io = common::with_advice(input, &common::precompiles_advice(1, tries));
    let mut run = emulator::StreamingRun::new(&image, &io, &tables, &config).unwrap();
    while !run.next_shards().unwrap().is_empty() {}
    let (_, streamed) = run.finish().unwrap();
    let (_, calls) = streamed
        .profile
        .counts
        .into_iter()
        .find(|&(family, _)| family == constants::family::MPT)
        .expect("the profile counts every family");
    (streamed.execution, calls)
}

/// Each trie scenario's root in `guests/precompiles`' journal is the root
/// `tools/mpt` gives its table after its batch: an empty table taking
/// inserts; a table the batch does not touch, its proof the root alone; four-
/// and forty-byte keys, the longer ones sharing their first 32 bytes in three
/// groups so their crit bits pass 256, each table a few dozen keys under
/// inserts, sets and removes; every key of a table removed, its proof no
/// sibling; one key of two removed, the other an opaque root; and 2,100
/// four-byte keys, each opened and set, whose program of 4,199 ops is over
/// the 4,096 a call may have. `Trie::root` splits that one at its root branch,
/// its halves some 2,100 ops each, so each of its two roots is three calls:
/// its halves' and one hashing the two.
#[test]
fn the_sdk_trie_opens_and_edits_tables_as_tools_mpt_does() {
    let mut rng = Rng::new(0x0517);
    let prefixes: Vec<Vec<u8>> = (0..3).map(|_| rng.next_bytes(32)).collect();
    let forty = keys(&mut rng, 34, |rng| {
        let prefix = &prefixes[rng.next_u64() as usize % 3];
        [prefix.as_slice(), &rng.next_bytes(8)].concat()
    });
    let small = keys(&mut rng, 10, |rng| rng.next_bytes(4));
    let wide = keys(&mut rng, 2_100, |rng| rng.next_bytes(4));
    let batches = [
        Batch::new(&mut rng, (4, 8), &[], &small[..5], (0, 0)),
        Batch::new(&mut rng, (4, 4), &small[..6], &[], (0, 0)),
        four_byte_batch(&mut rng),
        Batch::new(&mut rng, (40, 24), &forty[..30], &forty[30..], (4, 4)),
        Batch::new(&mut rng, (4, 4), &small[..6], &[], (0, 6)),
        Batch::new(&mut rng, (4, 8), &small[6..8], &[], (0, 1)),
        Batch::new(&mut rng, (4, 4), &wide, &[], (wide.len(), 0)),
    ];
    let (tries, roots): (Vec<Vec<u8>>, Vec<apogee_mpt::Digest>) = batches
        .iter()
        .map(|batch| {
            let (bytes, _, root) = batch.scenario();
            (bytes, root)
        })
        .unzip();
    // The public input `precompiles_run` lays out, with no Falcon-512 case.
    let input = precompiles_run(&[], &[]).unwrap().io.input;
    let (e, calls) = trie_calls(&input, &tries);
    assert_eq!(e.exit_code, 0);
    let (_, others) = trie_calls(&input, &tries[..tries.len() - 1]);
    assert_eq!(calls - others, 2 * 3, "the 2,100 keys' two roots");
    let journaled = &e.io.output[e.io.output.len() - 64 * roots.len()..];
    for (i, root) in roots.iter().enumerate() {
        let want: Vec<u8> = root.iter().flat_map(|lane| lane.to_le_bytes()).collect();
        assert_eq!(
            to_hex(&journaled[64 * i..64 * i + 64]),
            to_hex(&want),
            "scenario {i}"
        );
    }
}

/// A proof altered is refused, the guest panicking where the proof as made
/// opens: a sibling's digest a bit off opens to another root, and the first
/// sibling's word owned past the last key is never taken.
#[test]
fn a_trie_proof_altered_does_not_open() {
    let mut rng = Rng::new(0x0517);
    let batch = four_byte_batch(&mut rng);
    let (bytes, proof, _) = batch.scenario();
    let s = u32::from_le_bytes(bytes[proof..proof + 4].try_into().unwrap()) as usize;
    let m = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    assert!(s > 1, "the batch has siblings");
    let mut digest = bytes.clone();
    digest[proof + 4 + 4 * s + 64 + 9] ^= 0x10;
    let mut word = bytes.clone();
    let at = proof + 4;
    let w = u32::from_le_bytes(word[at..at + 4].try_into().unwrap());
    word[at..at + 4].copy_from_slice(&(w % 512 + 512 * m).to_le_bytes());
    for (scenario, exit, what) in [
        (bytes, 0, "the proof as made"),
        (digest, 101, "a sibling's digest"),
        (word, 101, "a sibling's word"),
    ] {
        let e = precompiles_run(&[], &[scenario]).unwrap();
        assert_eq!(e.exit_code, exit, "{what}");
    }
}

// ---------------------------------------------------------------------------
// guests/amazon: signed purchases against two tables
// ---------------------------------------------------------------------------

/// The host's side of `guests/amazon`: its two tables as `tools/mpt`'s tries,
/// the users keyed by address and the listings by id big-endian, a record's
/// leaf its key's and its value's, and the snapshot the two roots compressed;
/// and the store's rules, read apart from the guest's, over `u128` amounts.
mod amazon {
    use std::collections::{BTreeMap, BTreeSet};

    use apogee_mpt::{leaf, Trie};
    use field::Fp;

    pub use apogee_mpt::Digest;

    /// A user's name, its key in the users table: K's first 32 bytes, K the
    /// key digest of its key.
    pub type Address = [u8; 32];

    /// The first 8 lanes of the permutation of `l ‖ r`, with no feed-forward.
    pub fn compress(l: &Digest, r: &Digest) -> Digest {
        let mut s: [Fp; 16] =
            std::array::from_fn(|i| Fp::from_u64(if i < 8 { l[i] } else { r[i - 8] }));
        transcript::poseidon2_permute(&mut s);
        std::array::from_fn(|i| s[i].to_u64())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct User {
        pub address: Address,
        pub balance: u128,
        pub nonce: u64,
    }

    impl User {
        /// The record, 56 bytes: the address, its key, then its value, the
        /// balance and the nonce.
        pub fn record(&self) -> Vec<u8> {
            let mut b = self.address.to_vec();
            b.extend(self.balance.to_le_bytes());
            b.extend(self.nonce.to_le_bytes());
            b
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Listing {
        pub item: u32,
        pub seller: Address,
        pub price: u128,
        pub stock: u64,
    }

    impl Listing {
        /// The record of the listing at `id`, 64 bytes: the id big-endian,
        /// its key, then its value, the item, the seller, the price and the
        /// stock.
        pub fn record(&self, id: u32) -> Vec<u8> {
            let mut b = id.to_be_bytes().to_vec();
            b.extend(self.item.to_le_bytes());
            b.extend(self.seller);
            b.extend(self.price.to_le_bytes());
            b.extend(self.stock.to_le_bytes());
            b
        }
    }

    /// The tables' tries: each user's leaf at its address, and each listing's
    /// at its id big-endian, each its record's key and value.
    pub fn tables(
        users: &BTreeMap<Address, User>,
        listings: &BTreeMap<u32, Listing>,
    ) -> (Trie, Trie) {
        let mut user_trie = Trie::new(32);
        for (a, u) in users {
            user_trie.insert(a, leaf(a, &u.record()[32..]));
        }
        let mut listing_trie = Trie::new(4);
        for (id, l) in listings {
            let key = id.to_be_bytes();
            listing_trie.insert(&key, leaf(&key, &l.record(*id)[4..]));
        }
        (user_trie, listing_trie)
    }

    /// The tables' snapshot: the users root and the listings root, compressed.
    pub fn snapshot(users: &BTreeMap<Address, User>, listings: &BTreeMap<u32, Listing>) -> Digest {
        let (user_trie, listing_trie) = tables(users, listings);
        compress(&user_trie.root(), &listing_trie.root())
    }

    /// A request: the 76 bytes its buyer signs, its listing by its key.
    #[derive(Clone, Copy, Debug)]
    pub struct Request {
        pub buyer: Address,
        pub max_price: u128,
        pub quantity: u64,
        pub nonce: u64,
        pub market: u64,
        pub listing: u32,
    }

    impl Request {
        pub fn signed(&self) -> Vec<u8> {
            let mut b = self.buyer.to_vec();
            b.extend(self.max_price.to_le_bytes());
            b.extend(self.quantity.to_le_bytes());
            b.extend(self.nonce.to_le_bytes());
            b.extend(self.market.to_le_bytes());
            b.extend(self.listing.to_be_bytes());
            b
        }
    }

    /// The store as the host reads its rules: the users by address and the
    /// listings by id, the volume, and the users and the listings the
    /// requests have read.
    pub struct Model {
        pub users: BTreeMap<Address, User>,
        pub listings: BTreeMap<u32, Listing>,
        pub volume: u128,
        pub read_users: BTreeSet<Address>,
        pub read_listings: BTreeSet<u32>,
    }

    impl Model {
        /// `r` applied, its nonce spent and the tables moved; or, for a request
        /// that is not valid or does not apply, a panic, as the guest's.
        pub fn settle(&mut self, r: &Request, market: u64) {
            assert!(r.market == market, "a request for another market");
            self.read_users.insert(r.buyer);
            let buyer = self.users[&r.buyer];
            assert!(r.nonce != u64::MAX, "a request at the last nonce");
            assert!(r.nonce == buyer.nonce, "a request not at its buyer's nonce");
            self.users.get_mut(&r.buyer).expect("a user").nonce += 1;
            self.purchase(r, buyer);
        }

        /// `r`'s purchase by `buyer`, its nonce spent: applied, the tables
        /// moved, or a panic.
        fn purchase(&mut self, r: &Request, buyer: User) {
            self.read_listings.insert(r.listing);
            let listing = self.listings[&r.listing];
            assert!(
                r.quantity != 0 && r.quantity <= listing.stock,
                "a quantity of 0 or more than the stock"
            );
            assert!(listing.price <= r.max_price, "a price above the max price");
            assert!(
                listing.seller != r.buyer,
                "a purchase of the buyer's own listing"
            );
            let cost = listing
                .price
                .checked_mul(r.quantity as u128)
                .expect("a cost past 2^128");
            assert!(cost <= buyer.balance, "a cost above the buyer's balance");
            self.read_users.insert(listing.seller);
            let seller = self.users[&listing.seller];
            let paid = seller
                .balance
                .checked_add(cost)
                .expect("the seller's balance past 2^128");
            let volume = self
                .volume
                .checked_add(cost)
                .expect("the volume past 2^128");
            self.users.get_mut(&r.buyer).expect("a user").balance = buyer.balance - cost;
            self.users.get_mut(&listing.seller).expect("a user").balance = paid;
            self.listings.get_mut(&r.listing).expect("a listing").stock -= r.quantity;
            self.volume = volume;
        }
    }
}

/// `guests/amazon` settles a batch of Falcon-512-signed purchases against its
/// users and listings by their snapshot.
///
/// Forty users, each keyed by its key's address and each with a key from a
/// seed of its own; and 22 listings at ids apart, fourteen of 30 units and up
/// sold by users who also buy; then 77 requests, ordered by listing as a
/// backend gathering each listing's requests would, each buyer's nonces in
/// the batch's order. Each applies: seventy-one purchases of one to three
/// units, the last unit of a listing of one, both of a listing of two, a
/// seller's purchase paid for by a sale earlier in the batch, and a purchase at
/// `2^127`. Every request is signed by its buyer, new signatures each run, as
/// signing is randomized. The advice holds what the batch reads and nothing
/// else: the counts, the records it reads, each request's signed bytes and
/// its buyer's, listing's and seller's places among those records, each
/// table's proof of them, `tools/mpt`'s, then each request's buyer's key at
/// the buyer's first and its signature, the key and the signature in the
/// SDK's advised forms, converted as a host converts them. The journal is
/// both snapshots, the count of purchases and the volume. The execution
/// panics with a byte past the public input's market; with the first request
/// from an address no user has, and, signed again by its signer, for another
/// market, from a user the advice does not hold, or at the nonce after its
/// buyer's; with the first request's buyer's, listing's or seller's place
/// naming the next record, or its buyer's past the users; with a request at
/// the last nonce, its buyer's record advised; with a request that does not
/// apply, signed by its buyer and last in the batch: a unit of the listing of
/// one once sold, a max price one below the price, the buyer's own listing, a
/// seller no user is, a cost past `2^128`, a cost past the balance, or a
/// seller's balance or the volume past `2^128`; and with a byte after the
/// advice's last signature, a user no request reads, the first key another
/// user's, the first signature one bit of its salt off, or its buyer's over
/// another of its requests, and a user's balance one off. The decode call
/// refuses the first key with its first coefficient at least `q`, the first
/// signature with its `s2` all zeros, and a signature with a one just after
/// its end, in its last word. The first key left out, and the first signature
/// a word longer, its last byte 1, put every read after them off, a panic or
/// the decode call's refusal. Each is its own execution.
#[test]
fn amazon_settles_signed_purchases_by_its_snapshot() {
    use std::collections::{BTreeMap, BTreeSet};

    use amazon::{snapshot, tables, Address, Listing, Model, Request, User};
    use apogee_falcon512::{address, key_advice, keygen, sign, signature_advice};

    const E18: u128 = 1_000_000_000_000_000_000;
    const MARKET: u64 = 0x0a3a_5017;
    const CONTEXT: &[u8] = b"apogee/amazon/purchase/v2";
    // The bytes of a request its buyer signs, before its three places.
    const SIGNED: usize = 76;
    // Users 0..32 buy, the odd ones of them selling the plain listings too.
    const POOR: usize = 32;
    const RICH: [usize; 2] = [33, 34];
    const ALMOST_FULL: usize = 35;
    const EXHAUSTED: usize = 36;
    const IDLE: usize = 37;
    const EARNER: usize = 38;
    const BIG_SELLER: usize = 39;
    // Listings 0..14 are plain; the rest are each a case.
    const SINGLE: usize = 14;
    const PAIR: usize = 15;
    const EARNS: usize = 16;
    const SPENDS: usize = 17;
    const OVERFILLS: usize = 18;
    const BIG: usize = 19;
    const BIG_TOO: usize = 20;
    const UNPAYABLE: usize = 21;
    let listing = |j: usize| (7 + j * 40_009) as u32;
    let half: u128 = 1 << 127;
    // An address no user has.
    let stranger = address(b"no user's key");

    // Each user's key, by its address.
    let mut secret = BTreeMap::new();
    let mut keys = BTreeMap::new();
    let mut users = BTreeMap::new();
    let mut addresses: Vec<Address> = Vec::new();
    for i in 0..40 {
        let (sk, key) = keygen([i as u8 + 1; 32]);
        let a = address(&key);
        secret.insert(a, sk);
        let balance = match i {
            POOR => E18,
            r if RICH.contains(&r) => half + 1000 * E18,
            ALMOST_FULL => u128::MAX - 5 * E18 + 1,
            EARNER => 0,
            _ => (10_000 + i as u128) * E18,
        };
        let nonce = if i == EXHAUSTED {
            u64::MAX
        } else {
            i as u64 % 3
        };
        users.insert(
            a,
            User {
                address: a,
                balance,
                nonce,
            },
        );
        keys.insert(a, key);
        addresses.push(a);
    }
    let user = |i: usize| addresses[i];
    let mut listings = BTreeMap::new();
    for j in 0..=UNPAYABLE {
        let (seller, price, stock) = match j {
            SINGLE => (user(4), 7 * E18, 1),
            PAIR => (user(10), 3 * E18, 2),
            EARNS => (user(EARNER), 20 * E18, 5),
            SPENDS => (user(22), 30 * E18, 5),
            OVERFILLS => (user(ALMOST_FULL), 10 * E18, 5),
            BIG => (user(BIG_SELLER), half, 3),
            BIG_TOO => (user(9), half, 1),
            UNPAYABLE => (stranger, E18, 5),
            _ => (
                user(2 * j + 1),
                (j as u128 + 1) * E18 + j as u128 * E18 / 10,
                30 + 5 * j as u64,
            ),
        };
        listings.insert(
            listing(j),
            Listing {
                item: 1000 + j as u32,
                seller,
                price,
                stock,
            },
        );
    }
    let price = |j: usize| listings[&listing(j)].price;

    let mut batch: Vec<(Address, usize, u64, u128)> = (0..70)
        .map(|k| {
            let j = k % 14;
            let b = match (k * 11 + 3) % 32 {
                b if b == 2 * j + 1 => (b + 2) % 32,
                b => b,
            };
            (user(b), j, 1 + k as u64 % 3, price(j))
        })
        .collect();
    batch.extend([
        (user(6), SINGLE, 1, price(SINGLE)),
        (user(12), PAIR, 1, price(PAIR)),
        (user(14), PAIR, 1, price(PAIR)),
        (user(20), EARNS, 2, price(EARNS)),
        (user(EARNER), SPENDS, 1, price(SPENDS)),
        (user(RICH[0]), BIG, 1, half),
        (user(15), 6, 1, price(6)),
    ]);
    // The backend's order: each listing's requests together, in the order
    // they came.
    batch.sort_by_key(|&(_, j, ..)| listing(j));

    let (user_trie, listing_trie) = tables(&users, &listings);
    let before = snapshot(&users, &listings);

    let mut model = Model {
        users: users.clone(),
        listings: listings.clone(),
        volume: 0,
        read_users: BTreeSet::new(),
        read_listings: BTreeSet::new(),
    };
    let mut input: Vec<u8> = before.iter().flat_map(|l| l.to_le_bytes()).collect();
    input.extend(MARKET.to_le_bytes());
    // The requests, in the batch's order, and the stream: each request's
    // buyer's key at the buyer's first, and its signature, the key and the
    // signature in their advised forms; and where each request's signature
    // starts in the stream.
    let mut requests = Vec::new();
    let mut stream = Vec::new();
    let mut signed_at = Vec::new();
    let mut signers = BTreeSet::new();
    let mut signatures = Vec::new();
    for &(buyer, j, quantity, max_price) in &batch {
        let request = Request {
            buyer,
            max_price,
            quantity,
            nonce: model.users[&buyer].nonce,
            market: MARKET,
            listing: listing(j),
        };
        let signature = sign(&secret[&buyer], &request.signed(), CONTEXT);
        assert_eq!(signature.len(), 666);
        model.settle(&request, MARKET);
        if signers.insert(buyer) {
            stream.extend(key_advice(&keys[&buyer]).unwrap());
        }
        signed_at.push(stream.len());
        stream.extend(signature_advice(&signature).unwrap());
        requests.push(request);
        signatures.push(signature);
    }
    // The model panics at a request that does not apply.
    assert_eq!(batch.len(), 77, "the batch is each case it claims");

    // The advice for the users `held`, the listings at the ids `listed`, the
    // `requests`, each with its buyer's, listing's and seller's places among
    // those records, and the `stream`: the three counts; each user's record as
    // the snapshot holds it, by address, and each listing's, by id; each
    // request's signed bytes and then its places; each table's proof of those
    // keys; then the stream. And where the requests start, and where the
    // stream does.
    let advice_of = |held: &BTreeSet<Address>,
                     listed: &BTreeSet<u32>,
                     requests: &[(Request, [u32; 3])],
                     stream: &[u8]| {
        let mut advice = (requests.len() as u32).to_le_bytes().to_vec();
        advice.extend((held.len() as u32).to_le_bytes());
        advice.extend((listed.len() as u32).to_le_bytes());
        for a in held {
            advice.extend(users[a].record());
        }
        for id in listed {
            advice.extend(listings[id].record(*id));
        }
        let requests_at = advice.len();
        for (r, places) in requests {
            advice.extend(r.signed());
            advice.extend(places.iter().flat_map(|p| p.to_le_bytes()));
        }
        advice.extend(user_trie.proof(&held.iter().collect::<Vec<_>>()));
        let ids: Vec<[u8; 4]> = listed.iter().map(|id| id.to_be_bytes()).collect();
        advice.extend(listing_trie.proof(&ids));
        let stream_at = advice.len();
        advice.extend(stream);
        (advice, requests_at, stream_at)
    };
    // A user's place among `held`, the first's where it holds none, and a
    // listing's among `listed`.
    let user_at = |held: &BTreeSet<Address>, a: &Address| {
        held.iter().position(|h| h == a).unwrap_or(0) as u32
    };
    let listing_at =
        |listed: &BTreeSet<u32>, id: u32| listed.iter().position(|&x| x == id).unwrap_or(0) as u32;
    // The advice as the backend writes it: each request's places where the
    // records its buyer, its listing and the listing's seller are lie.
    let advice_for =
        |held: &BTreeSet<Address>, listed: &BTreeSet<u32>, requests: &[Request], stream: &[u8]| {
            let placed: Vec<(Request, [u32; 3])> = requests
                .iter()
                .map(|r| {
                    let seller = listings[&r.listing].seller;
                    let places = [
                        user_at(held, &r.buyer),
                        listing_at(listed, r.listing),
                        user_at(held, &seller),
                    ];
                    (*r, places)
                })
                .collect();
            advice_of(held, listed, &placed, stream)
        };
    let (advice, requests_at, stream_at) =
        advice_for(&model.read_users, &model.read_listings, &requests, &stream);
    // The advice region's bytes start 4 bytes in, so past the counts every
    // record and request, a whole number of u64s, is on 8 bytes; every proof,
    // key and signature is a whole number of words, so the stream starts and
    // ends on a word.
    assert!(
        (4 + 12usize).is_multiple_of(8)
            && (4 + requests_at).is_multiple_of(8)
            && stream_at.is_multiple_of(4)
            && stream.len().is_multiple_of(4),
        "every record and request on 8 bytes, the stream on a word"
    );

    let after = snapshot(&model.users, &model.listings);
    let mut journal: Vec<u8> = before
        .iter()
        .chain(&after)
        .flat_map(|l| l.to_le_bytes())
        .collect();
    journal.extend((batch.len() as u32).to_le_bytes());
    journal.extend(model.volume.to_le_bytes());
    let image = image("amazon");
    let e = run(&image, &common::with_advice(&input, &advice)).unwrap();
    assert_eq!(e.exit_code, 0);
    assert_eq!(to_hex(&e.io.output), to_hex(&journal));

    // Each alteration below ends its own execution: a panic, exit 101, or the
    // decode call's refusal of a stream; `ends` is either.
    let panics = |input: &[u8], advice: &[u8]| {
        run(&image, &common::with_advice(input, advice))
            .unwrap()
            .exit_code
            == 101
    };
    let refused = |advice: &[u8]| {
        matches!(
            run(&image, &common::with_advice(&input, advice)),
            Err(EmuError::DelegationFrame { detail, .. }) if detail.starts_with("falcon512_decode")
        )
    };
    let ends = |advice: &[u8]| match run(&image, &common::with_advice(&input, advice)) {
        Ok(e) => e.exit_code == 101,
        Err(EmuError::DelegationFrame { detail, .. }) => detail.starts_with("falcon512_decode"),
        Err(_) => false,
    };
    // The advice with `bytes` put in at `at`.
    let spliced = |at: usize, bytes: &[u8]| {
        let mut spliced = advice.clone();
        spliced.splice(at..at, bytes.iter().copied());
        spliced
    };

    let mut surplus = input.clone();
    surplus.push(0);
    assert!(
        panics(&surplus, &advice),
        "a byte past the market is a public input of another length"
    );

    // The first request, from a user who signed it, now from an address no
    // user has: its buyer's place names a user of another address.
    let buyer = requests[0].buyer;
    let mut strange = advice.clone();
    strange[requests_at..requests_at + 32].copy_from_slice(&stranger);
    assert!(
        panics(&input, &strange),
        "a request from an address the advice does not hold is a malformed batch"
    );

    // The first request's buyer's place past the users.
    let mut past = advice.clone();
    let held = model.read_users.len() as u32;
    past[requests_at + SIGNED..][..4].copy_from_slice(&held.to_le_bytes());
    assert!(panics(&input, &past), "a buyer's place past the users");

    // User 0's purchase of a unit of listing 5, user 11's, alone in a batch,
    // its buyer's first request, signed, the advice holding the users `held`
    // and the listings `listed`, its places those of the users `buyer` and
    // `seller` and the listing `listed[0]`. Each case below is one a guest
    // that did not check its places would settle, exit 0, against the records
    // they name: user 3, at user 0's nonce, paying in user 0's place; listing
    // 3, cheaper and user 7's, sold in listing 5's place; and user 13 paid in
    // user 11's place. Each is a malformed batch.
    let alone = |held: &[usize], listed: &[usize], buyer: usize, seller: usize| {
        let r = Request {
            buyer: user(0),
            max_price: price(5),
            quantity: 1,
            nonce: users[&user(0)].nonce,
            market: MARKET,
            listing: listing(5),
        };
        let held: BTreeSet<Address> = held.iter().map(|&i| user(i)).collect();
        let listed: BTreeSet<u32> = listed.iter().map(|&j| listing(j)).collect();
        let first = *listed.first().expect("a listing");
        let places = [
            user_at(&held, &user(buyer)),
            listing_at(&listed, first),
            user_at(&held, &user(seller)),
        ];
        let mut streamed = key_advice(&keys[&r.buyer]).unwrap().to_vec();
        streamed.extend(signature_advice(&sign(&secret[&r.buyer], &r.signed(), CONTEXT)).unwrap());
        advice_of(&held, &listed, &[(r, places)], &streamed).0
    };
    assert_eq!(users[&user(3)].nonce, users[&user(0)].nonce);
    assert_eq!(listings[&listing(5)].seller, user(11));
    assert_eq!(listings[&listing(3)].seller, user(7));
    assert!(price(3) <= price(5));
    for (advice, what) in [
        (
            alone(&[3, 11], &[5], 3, 11),
            "a buyer's place naming another user",
        ),
        (
            alone(&[0, 7], &[3], 0, 7),
            "a listing's place naming another listing",
        ),
        (
            alone(&[0, 13], &[5], 0, 13),
            "a seller's place naming another user",
        ),
    ] {
        assert!(panics(&input, &advice), "{what}");
    }

    assert!(
        panics(&input, &spliced(advice.len(), &[0])),
        "a byte after the last signature"
    );

    // The idle user's record, and the users proof of it with the rest: it
    // opens the users table, and the batch does not read it.
    let mut idle = model.read_users.clone();
    assert!(idle.insert(user(IDLE)), "no request reads it");
    assert!(
        panics(
            &input,
            &advice_for(&idle, &model.read_listings, &requests, &stream).0
        ),
        "a record the batch does not read"
    );

    // The first request is its buyer's first: the stream starts with the
    // buyer's key, then the request's signature.
    let first = signature_advice(&signatures[0]).unwrap();
    assert_eq!(signed_at[0], 896);
    let key_at = stream_at;
    let signature_at = key_at + 896;

    // That key, its first coefficient `2^14 − 1`, at least `q`: the key does
    // not decode.
    let mut undecodable = advice.clone();
    undecodable[key_at] = 0xff;
    undecodable[key_at + 1] |= 0xfc;
    assert!(refused(&undecodable), "an advised key that does not decode");

    // That key, another user's: its address is not the buyer's.
    let other = user(if buyer == user(0) { 1 } else { 0 });
    let mut swapped = advice.clone();
    swapped[key_at..][..896].copy_from_slice(&key_advice(&keys[&other]).unwrap());
    assert!(
        panics(&input, &swapped),
        "an advised key that is not its buyer's"
    );

    // That key left out: the signature, and what follows it, is read as the
    // key.
    let mut keyless = advice.clone();
    keyless.drain(key_at..key_at + 896);
    assert!(ends(&keyless), "a key the stream lacks");

    // The first request, one field changed, signed again by its signer: for
    // another market, from the idle user, whom the advice does not hold, or at
    // the nonce after its buyer's. None is valid, so each is a malformed
    // batch.
    let resigned = |at: usize, bytes: &[u8]| {
        let mut request = advice[requests_at..requests_at + SIGNED].to_vec();
        request[at..at + bytes.len()].copy_from_slice(bytes);
        let signature = sign(&secret[&buyer], &request, CONTEXT);
        let mut resigned = advice.clone();
        resigned.splice(
            signature_at..signature_at + first.len(),
            signature_advice(&signature).unwrap(),
        );
        resigned[requests_at..requests_at + SIGNED].copy_from_slice(&request);
        resigned
    };
    assert!(
        panics(&input, &resigned(64, &(MARKET + 1).to_le_bytes())),
        "a request for another market"
    );
    assert!(
        panics(&input, &resigned(0, &user(IDLE))),
        "a request from a user the advice does not hold"
    );
    let skipped = users[&buyer].nonce + 1;
    assert!(
        panics(&input, &resigned(56, &skipped.to_le_bytes())),
        "a request at a nonce skipped"
    );

    // The exhausted user's request at its nonce, `2^64 − 1`, the last,
    // signed, first in the batch, with the user's record advised.
    let last = Request {
        buyer: user(EXHAUSTED),
        max_price: price(10),
        quantity: 1,
        nonce: u64::MAX,
        market: MARKET,
        listing: listing(10),
    };
    let mut advised = model.read_users.clone();
    assert!(advised.insert(last.buyer), "no request reads it");
    let mut first_last = vec![last];
    first_last.extend(&requests);
    let mut streamed = key_advice(&keys[&last.buyer]).unwrap().to_vec();
    streamed
        .extend(signature_advice(&sign(&secret[&last.buyer], &last.signed(), CONTEXT)).unwrap());
    streamed.extend(&stream);
    assert!(
        panics(
            &input,
            &advice_for(&advised, &model.read_listings, &first_last, &streamed).0
        ),
        "a request at the last nonce"
    );

    // A request that does not apply, its buyer's at the buyer's nonce after
    // the batch, signed, last in the batch, its buyer's key with it where the
    // buyer has no request before it, and the records it reads advised where
    // the tables hold them: one for each reason a purchase cannot apply, a
    // unit of a listing of one once sold, a max price one below the price, the
    // buyer's own listing, a seller no user is, a cost past `2^128`, a cost
    // past the balance, and a seller's balance and the volume past `2^128`.
    // Each is a malformed batch.
    let appended = |(buyer, j, quantity, max_price): (Address, usize, u64, u128)| {
        let r = Request {
            buyer,
            max_price,
            quantity,
            nonce: model.users[&buyer].nonce,
            market: MARKET,
            listing: listing(j),
        };
        let mut appended = requests.clone();
        appended.push(r);
        let mut streamed = stream.clone();
        if !signers.contains(&buyer) {
            streamed.extend(key_advice(&keys[&buyer]).unwrap());
        }
        streamed.extend(signature_advice(&sign(&secret[&buyer], &r.signed(), CONTEXT)).unwrap());
        let mut advised = model.read_users.clone();
        let seller = listings[&r.listing].seller;
        advised.extend(
            [buyer, seller]
                .into_iter()
                .filter(|a| users.contains_key(a)),
        );
        let mut advised_listings = model.read_listings.clone();
        advised_listings.insert(r.listing);
        advice_for(&advised, &advised_listings, &appended, &streamed).0
    };
    for request in [
        (user(8), SINGLE, 1, price(SINGLE)),
        (user(11), 2, 1, price(2) - 1),
        (user(7), 3, 1, price(3)),
        (user(28), UNPAYABLE, 1, price(UNPAYABLE)),
        (user(26), BIG, 2, half),
        (user(POOR), 13, 1, price(13)),
        (user(24), OVERFILLS, 1, price(OVERFILLS)),
        (user(RICH[1]), BIG_TOO, 1, half),
    ] {
        assert!(
            panics(&input, &appended(request)),
            "a request for listing {} that does not apply",
            request.1
        );
    }

    // The first request's signature, one bit of its salt flipped.
    let mut flipped = advice.clone();
    flipped[signature_at + 19] ^= 0x04;
    assert!(
        panics(&input, &flipped),
        "a signature that does not verify is a malformed batch"
    );

    // The first request's signature, its `s2` all zeros: no coefficient
    // ends within 16 zeros.
    let mut zeroed = advice.clone();
    zeroed[signature_at + 40..signature_at + first.len()].fill(0);
    assert!(refused(&zeroed), "a signature that does not decode");

    // The first signature whose stream ends inside a word, with a one just
    // after its end.
    let k = (0..batch.len())
        .find(|&k| !stream_end(&signatures[k][41..]).is_multiple_of(32))
        .expect("a stream ending inside a word");
    let end = stream_end(&signatures[k][41..]);
    let mut trailing = advice.clone();
    trailing[stream_at + signed_at[k] + 40 + end / 8] |= 0x80 >> (end % 8);
    assert!(refused(&trailing), "a one after a signature's end");

    // The first request's signature a word longer, its last byte 1, as the
    // conversion keeps a one past the end: verified, it moves the cursor to
    // that word, and every read after it is off.
    assert!(
        ends(&spliced(signature_at + first.len(), &[0, 0, 0, 1])),
        "a signature advised with a word it does not hold"
    );

    // The first request's signature, its buyer's over another of its
    // requests.
    let k = (1..batch.len())
        .find(|&k| batch[k].0 == buyer)
        .expect("the buyer signs another request");
    let mut reused = advice.clone();
    reused.splice(
        signature_at..signature_at + first.len(),
        signature_advice(&signatures[k]).unwrap(),
    );
    assert!(
        panics(&input, &reused),
        "another request's signature is a malformed batch"
    );

    // The first user's balance, one off: its leaf is not the users table's,
    // and the roots are not the snapshot.
    let mut unopened = advice.clone();
    unopened[12 + 32] ^= 1;
    assert!(
        panics(&input, &unopened),
        "a balance the table does not hold"
    );
}
