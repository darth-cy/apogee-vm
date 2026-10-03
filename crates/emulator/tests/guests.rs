//! The committed guests, executed by the emulator, against what the host
//! computes: each guest's journal recomputed here from its inputs, so every
//! check runs everywhere with no second executor to install.
//!
//! Acceptance 11 (a misaligned access is a named fatal error in both paths) is
//! here, and so is the check that `opcodes` really executes every instruction
//! it claims to.

mod common;

use std::collections::BTreeSet;

use common::{image, instr_at, io, preprocess, traced, TRACED};
use emulator::{run, trace_run, EmuError};
use loader::Slot;
use test_support::to_hex;

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

// ---------------------------------------------------------------------------
// S-IO: the public values and the advice region, executed
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
            constants::guest_memory::ADVICE_ORIGIN,
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
        out.len(),
        28,
        "the journal is the five blocks' folds and the compressed block's bounds"
    );
    let word = |i: usize| u32::from_le_bytes(out[4 * i..4 * i + 4].try_into().unwrap());
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
// S21: the keccak corpus
// ---------------------------------------------------------------------------

/// `guests/keccak-test`'s corpus source: byte `i` is `(31i + 7) mod 256`.
fn keccak_corpus_source() -> Vec<u8> {
    (0..400usize)
        .map(|i| (31u32.wrapping_mul(i as u32).wrapping_add(7)) as u8)
        .collect()
}

/// The `[[u32; 8]; 6]` literal in `guests/keccak-test/src/main.rs`, read out
/// of the source file.
///
/// Reading the guest's source rather than restating its table is the whole
/// point: a digest table restated in a test is a second literal, and two
/// stale literals agree. `guests/` is not a workspace member and the constant
/// is `no_std` guest code, so there is no way to link it.
fn keccak_guest_digests() -> Vec<[u8; 32]> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../guests/keccak-test/src/main.rs");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let head = "const DIGESTS: [[u32; 8]; 6] = [";
    let start = text.find(head).expect("keccak-test declares DIGESTS") + head.len();
    let body = &text[start..start + text[start..].find("\n];").expect("DIGESTS ends")];
    let mut words: Vec<u32> = Vec::new();
    let mut rest = body;
    while let Some(at) = rest.find("0x") {
        let digits = &rest[at + 2..];
        let end = digits
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(digits.len());
        assert_eq!(
            end,
            8,
            "a digest word is eight hex digits: {}",
            &digits[..end]
        );
        words.push(u32::from_str_radix(&digits[..end], 16).expect("hex"));
        rest = &digits[end..];
    }
    assert_eq!(words.len(), 6 * 8, "six digests of eight words");
    words
        .chunks(8)
        .map(|c| {
            let mut out = [0u8; 32];
            for (w, word) in c.iter().enumerate() {
                out[4 * w..4 * w + 4].copy_from_slice(&word.to_le_bytes());
            }
            out
        })
        .collect()
}

/// Acceptance 3, the host half: every digest `guests/keccak-test` checks
/// itself against is `tiny-keccak`'s, re-derived here from the reference
/// rather than copied.
///
/// The guest compares in-guest and exits 6, so a wrong literal would make the
/// guest fail — but only if the emulator's keccak-f and the SDK's sponge were
/// both right. Re-deriving from the reference is what closes that: this test
/// fixes the *answer*, and the two tests below fix the two paths to it.
#[test]
fn the_keccak_corpus_digests_are_the_references() {
    use tiny_keccak::Hasher;

    let source = keccak_corpus_source();
    let pinned = keccak_guest_digests();
    for (i, len) in [0usize, 1, 135, 136, 137, 400].iter().enumerate() {
        let mut hasher = tiny_keccak::Keccak::v256();
        hasher.update(&source[..*len]);
        let mut want = [0u8; 32];
        hasher.finalize(&mut want);
        assert_eq!(
            to_hex(&pinned[i]),
            to_hex(&want),
            "keccak-test's digest of the first {len} bytes is stale"
        );
    }
}

/// Acceptance 3, the delegation half: the guest runs on the emulator, whose
/// ecall performs the permutation, and exits 6 — one per corpus entry.
///
/// `guests/keccak-unused` links the shim and never calls it, so it makes no
/// invocation and exits 7; that it still *declares* the family is
/// `crates/program/tests/delegation.rs`'.
#[test]
fn keccak_test_checks_its_corpus_under_the_delegation_ecall() {
    for (name, status) in [("keccak-test", 6), ("keccak-unused", 7)] {
        let execution = run(&image(name), &io(&[])).unwrap();
        assert_eq!(
            execution.exit_code, status,
            "{name} exited {}, and 200 + i would name the corpus entry that failed",
            execution.exit_code
        );
        assert!(execution.io.output.is_empty(), "{name} commits nothing");
    }
}

// ---------------------------------------------------------------------------
// S23: the two recursion delegations
// ---------------------------------------------------------------------------

/// The `KAT_OUT` literal in `guests/recursion-ops/src/main.rs`, read out of
/// the source file.
///
/// Reading the guest's source rather than restating its table is the whole
/// point, as it is for `keccak_guest_digests`: two stale literals agree.
fn recursion_guest_kat() -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../guests/recursion-ops/src/main.rs");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let head = "const KAT_OUT: [&str; 3] = [";
    let start = text.find(head).expect("recursion-ops declares KAT_OUT") + head.len();
    let body = &text[start..start + text[start..].find("\n];").expect("KAT_OUT ends")];
    let out: Vec<String> = body
        .split('"')
        .filter(|s| s.starts_with("0x"))
        .map(str::to_string)
        .collect();
    assert_eq!(out.len(), 3, "three lanes");
    out
}

/// Acceptance 2's pin: the state `guests/recursion-ops` checks itself against
/// is `transcript::poseidon2_permute`'s, re-derived here rather than copied.
///
/// The guest compares in-guest and exits 9, so a wrong literal would make the
/// guest fail — but only if the emulator's delegation were right. Re-deriving
/// from the crate is what closes that: this test fixes the *answer*, and the
/// one below fixes the path to it.
#[test]
fn the_recursion_guests_kat_is_the_transcripts() {
    let mut state = [
        field::Fr::ZERO,
        field::Fr::from_u64(1),
        field::Fr::from_u64(2),
    ];
    transcript::poseidon2_permute(&mut state);
    for (lane, want) in state.iter().zip(recursion_guest_kat()) {
        assert_eq!(
            *lane,
            field::Fr::from_hex(&want).expect("a pinned lane is canonical hex"),
            "recursion-ops' known-answer state is stale"
        );
    }
}

/// Acceptances 1 and 2, the delegated half: the guest runs on the emulator,
/// whose two ecalls perform the arithmetic and the permutation, and exits 9 —
/// one per check.
///
/// `guests/recursion-unused` links both backends and reaches neither, so it
/// makes no invocation and exits 11; that it still *declares* both families is
/// `crates/program/tests/delegation.rs`'.
#[test]
fn recursion_ops_checks_itself_under_both_delegation_ecalls() {
    for (name, status) in [("recursion-ops", 9), ("recursion-unused", 11)] {
        let execution = run(&image(name), &io(&[])).unwrap();
        assert_eq!(
            execution.exit_code, status,
            "{name} exited {}, and 200 + i would name the check that failed",
            execution.exit_code
        );
        assert!(execution.io.output.is_empty(), "{name} commits nothing");
    }
}

/// The `MOD_MUL` fixture: the delegation over all four selectors by name and
/// against a software oracle of the guest's own, then `k256`'s group and
/// scalar arithmetic and `ark-bn254`'s two fields, none of which names a shim
/// at all. Exit 28, one per check.
///
/// **This is the only test of the three vendored patches' marshalling.** Each
/// routes a library's multiply through the ecall over a representation that is
/// not the frame's — `k256`'s ten 26-bit field limbs, its `U256` scalar,
/// arkworks' Montgomery `Fp256` — so an executor or a patch that got the
/// packing wrong would fail one of the guest's own checks and exit `200 + i`.
/// A disagreement between the delegation and the guest's own long division
/// exits 251.
#[test]
fn mod_mul_ops_checks_itself_under_the_delegation_ecall() {
    let execution = run(&image("mod-mul-ops"), &io(&[])).unwrap();
    assert_eq!(
        execution.exit_code, 28,
        "mod-mul-ops exited {}, and 200 + i would name the check that failed",
        execution.exit_code
    );
    assert!(execution.io.output.is_empty(), "it commits nothing");
}

/// The `MOD_MUL` invocation count, and **the only thing in the repository that
/// can see whether a vendored patch still routes**.
///
/// A delegated multiply and a software one agree on the value, so no check
/// inside the guest can tell them apart; what changes is how many invocations
/// the execution makes. If `guests/vendor/k256`'s field or scalar patch or
/// `guests/vendor/ark-ff`'s Montgomery patch stopped reaching the ecall — a
/// refreshed vendor copy with the change dropped, a `cfg` that stopped
/// matching — every guest check would still pass and this number would fall.
///
/// It is a pin over a build, so it moves when the guest or a vendored crate
/// changes; when it does, re-derive it rather than accepting it, and check the
/// three lower bounds below still hold for the reason each states.
#[test]
fn mod_mul_ops_routes_every_vendored_patch_through_the_ecall() {
    let image = image("mod-mul-ops");
    let (tables, config) = preprocess(&image);
    let (traces, ..) = trace_run(&image, &io(&[]), &tables, &config).expect("it traces");
    let trace = traces
        .delegation(constants::family::MOD_MUL)
        .expect("MOD_MUL has a buffer");
    // The ABI half is 13 calls the guest makes by name, so anything above
    // that is a library seam.
    assert!(
        trace.len() > 13,
        "only {} invocations: no vendored patch is routing",
        trace.len()
    );
    // Above one `2^8` shard, which is what makes the `MOD_MUL` fixture in
    // `crates/prover/tests/common` multi-shard — the only coverage this
    // family's anchor pairing and last-shard padding rows have.
    assert!(
        trace.len() > 256,
        "{} invocations, so the 2^8 fixture would be one shard",
        trace.len()
    );
    // The equality is the part that separates the three seams: each
    // contributes a different amount, so any one of them falling back moves
    // this number and nothing else in the suite would notice.
    // 1,567 until S26c, when `guests/vendor/k256`'s `ProjectivePoint` patch
    // moved this guest's group arithmetic — twelve field multiplies an
    // addition — out of `MOD_MUL` and into `EC_ADD`.
    assert_eq!(trace.len(), 1_443, "the pinned invocation count");

    // And the other side of that same move, on the trace already in hand.
    //
    // **This assertion lives here because it is free here.** It belongs with
    // the `EC_ADD` counts in `the_new_families_are_invoked_the_pinned_number_of_times`,
    // which is `#[ignore]`d for memory — and it is the one of those counts that
    // cannot be given up, because `mod-mul-ops` names **neither** shim and
    // reaches `EC_ADD` through the patched `ProjectivePoint` alone. It is
    // therefore the only thing in ordinary CI that can see that patch still
    // routing: 13 point operations at three invocations each. Tracing this
    // guest costs what it already cost; tracing `ec-ops` is what does not fit.
    let ec = traces
        .delegation(constants::family::EC_ADD)
        .expect("EC_ADD has a buffer");
    assert_eq!(ec.len(), 39, "the pinned projective-patch invocation count");
}

/// The invocation counts the two delegation families actually see, which is
/// what a shard plan divides by the height.
///
/// `run` has no `VmConfig` and records nothing; `trace_run` does both, so this
/// is also the test that the families are in the config at all.
#[test]
fn recursion_ops_invokes_both_families() {
    let image = image("recursion-ops");
    let (tables, config) = preprocess(&image);
    let (traces, ..) = trace_run(&image, &io(&[]), &tables, &config).expect("it traces");
    for family in [constants::family::POSEIDON2, constants::family::FR_ARITH] {
        let trace = traces
            .delegation(family)
            .unwrap_or_else(|| panic!("{} has no buffer", program::family_name(family)));
        assert!(
            !trace.is_empty(),
            "{} is invoked at least once",
            program::family_name(family)
        );
        assert!(
            trace.len() <= 256,
            "{} makes {} invocations, past one 2^8 shard",
            program::family_name(family),
            trace.len()
        );
    }
    // The permutation runs twice, which is what the guest's second call is
    // for: one row would not show a shard holding more than one invocation.
    assert_eq!(
        traces
            .delegation(constants::family::POSEIDON2)
            .expect("a buffer")
            .len(),
        2,
        "the guest permutes twice"
    );
}

// ---------------------------------------------------------------------------
// S26c's two fixtures
// ---------------------------------------------------------------------------

/// `sha256-ops` checks itself: the `SHA256_COMP` frame ABI against FIPS
/// 180-4's own `"abc"` vector, and `guest_sdk::sha256` against published
/// digests at every length that moves the Merkle-Damgård padding — each of
/// those also against `sha2`, an unpatched crates.io implementation and the
/// only one in that comparison which is not this repository's. Exit 13, one
/// per check but the first: since S26e the ABI is checked by one raw
/// four-round call against FIPS 180-4's appendix, its window, and a whole
/// sixteen-call compression.
#[test]
fn sha256_ops_checks_itself_under_the_delegation_ecall() {
    let execution = run(&image("sha256-ops"), &io(&[])).unwrap();
    assert_eq!(
        execution.exit_code, 13,
        "sha256-ops exited {}, and 200 + i would name the check that failed",
        execution.exit_code
    );
    assert!(execution.io.output.is_empty(), "it commits nothing");
}

/// `ec-ops` checks itself: every delegated addition against its own Algorithm
/// 7 over its own long division, limb for limb, and the resulting point
/// against `k256` and `ark-bn254` by cross-multiplication. A disagreement
/// between the two implementations exits 251. Exit 20.
///
/// **The completeness cases are the ones worth having.** `P + P`, `P + O`,
/// `O + O` and `P + (-P)` are what an incomplete formula gets wrong, and they
/// are why this delegation is one addition rather than an addition and a
/// doubling.
#[test]
fn ec_ops_checks_itself_under_the_delegation_ecall() {
    let execution = run(&image("ec-ops"), &io(&[])).unwrap();
    assert_eq!(
        execution.exit_code, 20,
        "ec-ops exited {}, and 200 + i would name the check that failed",
        execution.exit_code
    );
    assert!(execution.io.output.is_empty(), "it commits nothing");
}

/// The invocation counts of S26c's two families, and — for `EC_ADD` — the one
/// thing that can see whether the `k256` projective patch still routes.
///
/// `ec-ops` names the `EC_ADD` shim itself, so its count cannot distinguish a
/// live patch from a dead one; `mod-mul-ops` names neither shim and reaches
/// both through `k256` alone, which is what makes its two counts the seam's
/// test. Every number here is a pin over a build: when the guest or a vendored
/// crate changes, re-derive it rather than accepting it.
#[test]
#[ignore = "DEFERRED: four traced executions, two of them `ec-ops`, peak 23.9 GiB             and 118 s -- above what a GitHub runner has, so it reclaims the job"]
fn the_new_families_are_invoked_the_pinned_number_of_times() {
    let counts: Vec<(&str, &str, usize)> = [
        ("sha256-ops", constants::family::SHA256_COMP),
        ("ec-ops", constants::family::EC_ADD),
        ("ec-ops", constants::family::MOD_MUL),
        ("mod-mul-ops", constants::family::EC_ADD),
    ]
    .into_iter()
    .map(|(name, family)| {
        let image = image(name);
        let (tables, config) = preprocess(&image);
        let (traces, ..) = trace_run(&image, &io(&[]), &tables, &config).expect("it traces");
        let trace = traces.delegation(family).expect("the family has a buffer");
        (name, program::family_name(family), trace.len())
    })
    .collect();
    // Every one of these is derivable by hand from the guest's source, which
    // is what makes it a pin and not a recording:
    //
    // - `sha256-ops` makes 529 calls since S26e, a compression being sixteen:
    //   one raw call and two whole compressions by name through the frame ABI,
    //   33, and 31 blocks through `guest_sdk::sha256`, 496 — 11 for the seven
    //   padding-boundary lengths, 2 for the two-block vector, 16 for the
    //   1,000-byte message and 2 for the last one-byte-difference check.
    // - `ec-ops` performs 27 point operations: 20 of its own additions and 7
    //   inside its `k256` oracle, which since S26c is itself delegated. Three
    //   invocations each.
    // - `mod-mul-ops` performs 13, all of them inside `k256` — its own source
    //   names no shim at all, which is what makes its count the projective
    //   patch's only test.
    assert_eq!(
        counts,
        vec![
            ("sha256-ops", "SHA256_COMP", 529),
            ("ec-ops", "EC_ADD", 81),
            ("ec-ops", "MOD_MUL", 2_084),
            ("mod-mul-ops", "EC_ADD", 39),
        ]
    );
}
