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

/// `fib` reads fd 0 and writes fd 1, the compatibility path: a proof binds
/// neither, and its public values are empty
/// (`docs/spec/public-values.md` §1).
#[test]
fn fib_commits_the_recorded_value() {
    let (input, output) = common::fib_record();
    let execution = run(&image("fib"), &io(&input)).unwrap();
    assert_eq!(execution.exit_code, 0);
    assert_eq!(to_hex(&execution.stdout), to_hex(&output));
    assert!(
        execution.io.input.is_empty() && execution.io.output.is_empty(),
        "fd 0 and fd 1 are not the public values"
    );
}

// ---------------------------------------------------------------------------
// S25: the public values and the advice region, executed
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

    // And it issued no ecall but EXIT, which is what makes it provable: fd 1
    // and fd 2 are untouched.
    assert!(execution.stdout.is_empty() && execution.stderr.is_empty());

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
    assert_eq!(to_hex(&execution.stdout), to_hex(&want));
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
    assert_eq!(to_hex(&execution.stdout), to_hex(&want));
}

#[test]
fn the_rvc_fixture_runs() {
    let execution = run(&image("rvc-dense"), &io(&7u32.to_le_bytes())).unwrap();
    assert_eq!(execution.exit_code, 0);
    let word =
        |i: usize| u32::from_le_bytes(execution.stdout[4 * i..4 * i + 4].try_into().unwrap());
    assert_eq!(word(0), 46, "rvc_exec(7) and norvc_exec(7) agree on 46");
    assert_eq!(word(2), 2 * word(1));
}

/// Acceptance 10: the precompile number answers `-ENOSYS`, the guest takes
/// its software path, and that path computes the real S02 permutation —
/// with fd 1 an exact echo and the hint kept off it, as under QEMU.
#[test]
fn a_precompile_runs_and_its_state_is_the_s02_permutation() {
    let input: Vec<u8> = (0..100u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    let guest = GuestIo {
        input: Vec::new(),
        advice: Vec::new(),
        stdin: input.clone(),
        hint: b"private-advice".to_vec(),
    };
    let execution = run(&image("echo"), &guest).unwrap();
    assert_eq!(execution.exit_code, 0);
    assert_eq!(to_hex(&execution.stdout), to_hex(&input));
    let stderr = String::from_utf8_lossy(&execution.stderr);
    assert!(stderr.contains("hint=private-advice"), "{stderr}");
    // Since S23 the number has a circuit, so this executor answers it: what
    // used to be the fallback's branch is now the delegated one. Under
    // `qemu-riscv32` the same binary still takes the software branch, which is
    // `crates/loader/tests/qemu.rs`'.
    assert!(stderr.contains("precompile=accelerated"), "{stderr}");
    let mut state = [Fr::from_u64(1), Fr::from_u64(2), Fr::from_u64(3)];
    transcript::poseidon2_permute(&mut state);
    assert!(
        stderr.contains(&format!("state0={}", to_hex(&state[0].to_bytes()))),
        "the delegated permutation is not the S02 one: {stderr}"
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
                        input: Vec::new(),
                        advice: Vec::new(),
                        stdin: input.clone(),
                        hint,
                    },
                )
                .unwrap();
                assert_eq!(e.exit_code, 0);
                (e.stdout, String::from_utf8_lossy(&e.stderr).into_owned())
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

    let out = &t.execution.stdout;
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

/// **The recorded public input is what the host supplied, not what the guest
/// read — and fd 0 is a different thing entirely.**
///
/// `heap` takes its four-byte `n` off fd 0 and never the four after it. The
/// statement's public input is the *window's* contents, which this run fills
/// independently and the guest never looks at: the binding is that the window
/// held those bytes, not that anybody read them
/// (`docs/spec/public-values.md` §9).
///
/// Until S25 this recorded the consumed prefix of fd 0, which was the right
/// answer for a stream and is the wrong one for a window: a cursor is guest
/// state, and the statement is not.
#[test]
fn the_recorded_public_input_is_what_the_host_supplied() {
    let mut offered = 40u32.to_le_bytes().to_vec();
    offered.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let window = b"bytes the guest never reads".to_vec();
    let guest = GuestIo {
        input: window.clone(),
        advice: Vec::new(),
        stdin: offered.clone(),
        hint: Vec::new(),
    };
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
        assert!(execution.stdout.is_empty(), "{name} writes nothing");
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
        assert!(execution.stdout.is_empty(), "{name} writes nothing");
    }
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
