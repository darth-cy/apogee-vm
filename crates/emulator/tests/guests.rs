//! The committed guests, executed by the emulator, against what the host
//! computes: each guest's journal recomputed here from its inputs, so every
//! check runs everywhere with no second executor to install.
//!
//! The check that a misaligned access is a named fatal error in both paths is
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

/// The host's side of `guests/marketplace`: a sparse table of listings as the
/// guest commits to it, each node `transcript`'s permutation of two digests,
/// truncated, each leaf a listing's 76 bytes packed seven to a lane beside four
/// zeros and a tag lane of 1.
mod market {
    use std::collections::BTreeMap;

    use field::Fp;

    pub const DEPTH: usize = 20;
    pub const LISTING: usize = 76;
    pub type Digest = [u64; 8];
    pub type Listing = [u8; LISTING];

    pub fn compress(l: &Digest, r: &Digest) -> Digest {
        let mut s: [Fp; 16] =
            std::array::from_fn(|i| Fp::from_u64(if i < 8 { l[i] } else { r[i - 8] }));
        transcript::poseidon2_permute(&mut s);
        std::array::from_fn(|i| s[i].to_u64())
    }

    /// Eleven lanes of seven bytes, four zeros and the tag 1, permuted once.
    pub fn leaf(listing: &Listing) -> Digest {
        let mut bytes = [0u8; 77];
        bytes[..LISTING].copy_from_slice(listing);
        let mut lanes = [0u64; 16];
        for (i, lane) in lanes.iter_mut().take(11).enumerate() {
            let mut b = [0u8; 8];
            b[..7].copy_from_slice(&bytes[7 * i..7 * i + 7]);
            *lane = u64::from_le_bytes(b);
        }
        lanes[15] = 1;
        compress(
            lanes[..8].try_into().expect("8 lanes"),
            lanes[8..].try_into().expect("8 lanes"),
        )
    }

    pub fn listing(seller: u64, item: u64, price: u128, stock: u64, currency: [u8; 20]) -> Listing {
        let mut b = [0u8; LISTING];
        b[..8].copy_from_slice(&seller.to_le_bytes());
        b[8..16].copy_from_slice(&item.to_le_bytes());
        b[16..32].copy_from_slice(&price.to_le_bytes());
        b[48..56].copy_from_slice(&stock.to_le_bytes());
        b[56..].copy_from_slice(&currency);
        b
    }

    /// The listed slots; every other slot holds the all-zero listing.
    pub struct Table(pub BTreeMap<u32, Listing>);

    impl Table {
        fn node(&self, level: usize, index: u32, empty: &[Digest]) -> Digest {
            let slots = index << level..(index + 1) << level;
            match (self.0.range(slots).next(), level) {
                (None, _) => empty[level],
                (Some((_, l)), 0) => leaf(l),
                _ => compress(
                    &self.node(level - 1, 2 * index, empty),
                    &self.node(level - 1, 2 * index + 1, empty),
                ),
            }
        }

        fn empty() -> Vec<Digest> {
            let mut out = vec![leaf(&[0; LISTING])];
            for l in 0..DEPTH {
                out.push(compress(&out[l], &out[l]));
            }
            out
        }

        pub fn root(&self) -> Digest {
            self.node(DEPTH, 0, &Table::empty())
        }

        /// `slot`'s listing and its siblings from the leaf up: its proof.
        pub fn proof(&self, slot: u32) -> Vec<u8> {
            let empty = Table::empty();
            let mut out = self.0.get(&slot).copied().unwrap_or([0; LISTING]).to_vec();
            for level in 0..DEPTH {
                let sibling = self.node(level, (slot >> level) ^ 1, &empty);
                out.extend(sibling.iter().flat_map(|l| l.to_le_bytes()));
            }
            out
        }
    }
}

/// `guests/marketplace` follows its listings table by its Merkle root.
///
/// Two listings, one in a token and one in the native currency, then eleven
/// operations whose outcomes are this table's own reading of the rules: buy 4
/// of 10 at 25 in the token (cost 100, fee 0.3 at 30 bps), buy past the stock,
/// reprice by the seller into a second token, reprice by another account, list
/// over a listing, list an empty slot in the first token, buy the repriced
/// listing's last unit at 4 (fee 0.012), buy from oneself, delist, an op that
/// does not exist, and buy 1 of the new listing at 1 (fee 0.003); amounts in
/// units of `10^18`. Six apply and five are refused, and the journal is both
/// roots and a tally per currency bought in, in first-purchase order, the first
/// token's two purchases summed. The advice is a proof for each run of
/// consecutive ops on one slot, under the table the runs before it left: the
/// eleven ops are seven runs of up to three, slot 5's ops in three of them. The
/// batch with a record past its `n_ops` panics, and so does the same advice one
/// sibling off.
#[test]
fn marketplace_follows_its_table_by_its_root() {
    use market::{listing, Table};
    const E18: u128 = 1_000_000_000_000_000_000;
    const NATIVE: [u8; 20] = [0; 20];
    const TOKEN: [u8; 20] = [0xa0; 20];
    const OTHER: [u8; 20] = [0xb7; 20];
    let mut table = Table(
        [
            (5, listing(1, 100, 25 * E18, 10, TOKEN)),
            (77_777, listing(2, 200, 3 * E18, 1, NATIVE)),
        ]
        .into_iter()
        .collect(),
    );
    let before = table.root();
    let last = (1 << market::DEPTH) - 1;
    // (kind, slot, account, item, price, quantity, currency), and the slot's
    // listing after the op where it applies: `Some(None)` empties it.
    type Op = (u32, u32, u64, u64, u128, u64, [u8; 20]);
    let ops: [(Op, Option<Option<market::Listing>>); 11] = [
        (
            (2, 5, 9, 0, 0, 4, NATIVE),
            Some(Some(listing(1, 100, 25 * E18, 6, TOKEN))),
        ),
        ((2, 5, 9, 0, 0, 7, NATIVE), None),
        (
            (1, 77_777, 2, 0, 4 * E18, 0, OTHER),
            Some(Some(listing(2, 200, 4 * E18, 1, OTHER))),
        ),
        ((1, 77_777, 3, 0, 5 * E18, 0, TOKEN), None),
        ((0, 5, 4, 300, E18, 1, TOKEN), None),
        (
            (0, last, 4, 300, E18, 1000, TOKEN),
            Some(Some(listing(4, 300, E18, 1000, TOKEN))),
        ),
        (
            (2, 77_777, 9, 0, 0, 1, NATIVE),
            Some(Some(listing(2, 200, 4 * E18, 0, OTHER))),
        ),
        ((2, 5, 1, 0, 0, 1, NATIVE), None),
        ((3, 5, 1, 0, 0, 0, NATIVE), Some(None)),
        ((9, 5, 1, 0, 0, 0, NATIVE), None),
        (
            (2, last, 9, 0, 0, 1, NATIVE),
            Some(Some(listing(4, 300, E18, 999, TOKEN))),
        ),
    ];
    let mut input: Vec<u8> = before.iter().flat_map(|l| l.to_le_bytes()).collect();
    input.extend(30u32.to_le_bytes());
    input.extend((ops.len() as u32).to_le_bytes());
    let mut advice = Vec::new();
    let mut run_slot = None;
    for ((kind, slot, account, item, price, quantity, currency), after) in ops {
        input.extend(kind.to_le_bytes());
        input.extend(slot.to_le_bytes());
        input.extend(account.to_le_bytes());
        input.extend(item.to_le_bytes());
        input.extend(price.to_le_bytes());
        input.extend([0u8; 16]);
        input.extend(quantity.to_le_bytes());
        input.extend(currency);
        if run_slot != Some(slot) {
            advice.extend(table.proof(slot));
            run_slot = Some(slot);
        }
        match after {
            Some(Some(l)) => {
                table.0.insert(slot, l);
            }
            Some(None) => {
                table.0.remove(&slot);
            }
            None => {}
        }
    }
    let mut journal: Vec<u8> = before
        .iter()
        .chain(&table.root())
        .flat_map(|l| l.to_le_bytes())
        .collect();
    journal.extend(6u32.to_le_bytes());
    journal.extend(5u32.to_le_bytes());
    journal.extend(2u32.to_le_bytes());
    for (currency, volume, fees) in [
        (TOKEN, 101 * E18, 303 * E18 / 1000),
        (OTHER, 4 * E18, 12 * E18 / 1000),
    ] {
        journal.extend(currency);
        for total in [volume, fees] {
            journal.extend(total.to_le_bytes());
            journal.extend([0u8; 16]);
        }
    }
    let image = image("marketplace");
    let e = run(&image, &common::with_advice(&input, &advice)).unwrap();
    assert_eq!(e.exit_code, 0);
    assert_eq!(to_hex(&e.io.output), to_hex(&journal));

    let mut surplus = input.clone();
    surplus.extend([0u8; 84]);
    let e = run(&image, &common::with_advice(&surplus, &advice)).unwrap();
    assert_eq!(e.exit_code, 101, "a record past n_ops is a malformed batch");

    advice[market::LISTING] ^= 1;
    let e = run(&image, &common::with_advice(&input, &advice)).unwrap();
    assert_eq!(
        e.exit_code, 101,
        "a proof one sibling off does not open the table"
    );
}

// ---------------------------------------------------------------------------
// Falcon-512 verification, executed
// ---------------------------------------------------------------------------

/// A Falcon-512 case: a key, a message, a context and a signature.
type Case = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// What `guests/precompiles` journals for each of `cases` — 1 the signature
/// verifies under the context, 0 it does not, 2 the key does not decode — run
/// after its other calls at their fewest: a zero leaf up sixteen zero
/// siblings, no runs, and the zero arrays' norm once. Seven cases of short
/// messages and contexts fill the public input window.
fn falcon_verdicts(cases: &[Case]) -> Vec<u8> {
    let mut input = [
        1u32.to_le_bytes().as_slice(),
        &[0u8; 64],
        &0u32.to_le_bytes(),
        &16u32.to_le_bytes(),
        &[0u8; 64 * 16],
        &0u32.to_le_bytes(),
        &[0u8; 3 * 1024],
        &0u32.to_le_bytes(),
    ]
    .concat();
    input.extend((cases.len() as u32).to_le_bytes());
    for (key, message, context, signature) in cases {
        for field in [key, message, context, signature] {
            input.extend((field.len() as u32).to_le_bytes());
            input.extend(field);
        }
    }
    let execution = run(&image("precompiles"), &io(&input)).unwrap();
    assert_eq!(execution.exit_code, 0);
    let journal = execution.io.output;
    journal[journal.len() - cases.len()..].to_vec()
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
            cases.push((pk.clone(), msg, context, sig));
        }
    }
    assert_eq!(falcon_verdicts(&cases), [1; 6]);
}

/// A host library signature of a 64-byte message under a 25-byte context
/// altered one way a case: a bit of the message, of the salt, of `s2` and of
/// the padding flipped, the header `0x29`, the signature a byte short, the key
/// another seed's, which K and so HashToPoint hash too, and a bit of the
/// context flipped, none of which verifies; and the key's first coefficient
/// `2^14 − 1`, at least `q`, which does not decode. Two runs, as seven cases
/// fill the public input window.
#[test]
fn falcon512_refuses_each_alteration() {
    let (sk, pk) = apogee_falcon512::keygen([0x5a; 32]);
    let (_, other) = apogee_falcon512::keygen([0xc3; 32]);
    let msg: Vec<u8> = (0..64).map(|i| (i as u8).wrapping_mul(29)).collect();
    let context = b"apogee/amazon/purchase/v1".to_vec();
    let sig = apogee_falcon512::sign(&sk, &msg, &context);
    let flip = |bytes: &[u8], at: usize, bit: u32| {
        let mut bytes = bytes.to_vec();
        bytes[at] ^= 1 << bit;
        bytes
    };
    let mut key = pk.clone();
    key[1] = 0xff;
    key[2] |= 0xfc;
    let case = |pk: &[u8], msg: &[u8], context: &[u8], sig: &[u8]| {
        (pk.to_vec(), msg.to_vec(), context.to_vec(), sig.to_vec())
    };
    let cases = [
        case(&pk, &flip(&msg, 16, 0), &context, &sig),
        case(&pk, &msg, &context, &flip(&sig, 18, 3)),
        case(&pk, &msg, &context, &flip(&sig, 141, 5)),
        case(&pk, &msg, &context, &flip(&sig, 665, 0)),
        case(&pk, &msg, &context, &flip(&sig, 0, 4)),
        case(&pk, &msg, &context, &sig[..665]),
        case(&other, &msg, &context, &sig),
        case(&pk, &msg, &flip(&context, 24, 0), &sig),
        case(&key, &msg, &context, &sig),
    ];
    let verdicts = [&cases[..4], &cases[4..]].map(falcon_verdicts).concat();
    assert_eq!(verdicts, [0, 0, 0, 0, 0, 0, 0, 0, 2]);
}

/// The SDK's verifier agrees with the other implementations on
/// `tools/falcon512/vectors.json`. Every signature there verifies under its
/// context: two each from the Rust, JavaScript and Python libraries. Every
/// malformed case is refused, including the two a lenient decoder would pass
/// (negative zero, and a one bit after the last coefficient), a context
/// altered, and one of 256 bytes. A key that does not decode is 2. The
/// malformed cases are two runs, as seven cases fill the public input window.
#[test]
fn falcon512_agrees_with_every_implementation() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../../tools/falcon512/vectors.json"))
            .expect("the vectors are JSON");
    let section = |name: &str| vectors[name].as_array().expect("a section").clone();
    let cases = |entries: &[serde_json::Value]| -> Vec<Case> {
        let bytes = |v: &serde_json::Value, k: &str| {
            test_support::hex_to_bytes(v[k].as_str().expect("hex")).expect("hex")
        };
        entries
            .iter()
            .map(|v| {
                let field = |k| bytes(v, k);
                (field("pk"), field("msg"), field("context"), field("sig"))
            })
            .collect()
    };
    let signatures = section("signatures");
    assert_eq!(signatures.len(), 6);
    assert_eq!(falcon_verdicts(&cases(&signatures)), [1; 6]);
    let malformed = section("malformed");
    assert_eq!(malformed.len(), 8);
    let verdicts = [&malformed[..4], &malformed[4..]].map(|half| falcon_verdicts(&cases(half)));
    for (v, verdict) in malformed.iter().zip(verdicts.concat()) {
        let case = v["case"].as_str().expect("a name");
        let refused = if case.starts_with("key_") { 2 } else { 0 };
        assert_eq!(verdict, refused, "{case}");
    }
}

// ---------------------------------------------------------------------------
// guests/amazon: signed purchases against two tables
// ---------------------------------------------------------------------------

/// The host's side of `guests/amazon`: its two tables as sparse trees over
/// `market`'s node, a record's leaf its address's four lanes, the rest of its
/// bytes packed seven to a lane, and its table's tag, 1 for a user and 2 for a
/// listing, in lane 15; and the store's rules, read apart from the guest's,
/// over a `U256` of two `u128` halves.
mod amazon {
    use std::collections::{BTreeMap, BTreeSet};

    pub use super::market::{compress, Digest};

    pub const DEPTH: usize = 20;

    /// A user's name: K's first 32 bytes, K the key digest of its key.
    pub type Address = [u8; 32];

    /// The zero address, which names no account.
    pub const NO_ACCOUNT: Address = [0; 32];

    /// `hi · 2^128 + lo`: a balance, a price, the volume.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
    pub struct U256 {
        pub hi: u128,
        pub lo: u128,
    }

    impl U256 {
        pub const fn small(lo: u128) -> U256 {
            U256 { hi: 0, lo }
        }

        pub fn checked_add(self, other: U256) -> Option<U256> {
            let (lo, carry) = self.lo.overflowing_add(other.lo);
            let hi = self.hi.checked_add(other.hi)?.checked_add(carry as u128)?;
            Some(U256 { hi, lo })
        }

        /// `self − other`, which is at most `self`.
        pub fn minus(self, other: U256) -> U256 {
            let (lo, borrow) = self.lo.overflowing_sub(other.lo);
            U256 {
                hi: self.hi - other.hi - borrow as u128,
                lo,
            }
        }

        /// `self · q`, or `None` from `2^256` up.
        pub fn checked_mul(self, q: u64) -> Option<U256> {
            let q = q as u128;
            let low = (self.lo as u64 as u128) * q;
            let high = (self.lo >> 64) * q + (low >> 64);
            let hi = self.hi.checked_mul(q)?.checked_add(high >> 64)?;
            Some(U256 {
                hi,
                lo: (low as u64 as u128) | high << 64,
            })
        }

        pub fn le_bytes(self) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[..16].copy_from_slice(&self.lo.to_le_bytes());
            b[16..].copy_from_slice(&self.hi.to_le_bytes());
            b
        }
    }

    /// `bytes` seven to a lane, little-endian.
    fn pack(bytes: &[u8]) -> Vec<u64> {
        bytes
            .chunks(7)
            .map(|seven| {
                let mut b = [0u8; 8];
                b[..seven.len()].copy_from_slice(seven);
                u64::from_le_bytes(b)
            })
            .collect()
    }

    /// A record's leaf: `address`'s four lanes, then `rest` seven bytes to a
    /// lane, zeros, and `tag` in lane 15, permuted once.
    fn leaf(address: &Address, rest: &[u8], tag: u64) -> Digest {
        let mut lanes = [0u64; 16];
        for (lane, eight) in lanes.iter_mut().zip(address.chunks(8)) {
            *lane = u64::from_le_bytes(eight.try_into().expect("8 bytes"));
        }
        let rest = pack(rest);
        lanes[4..4 + rest.len()].copy_from_slice(&rest);
        lanes[15] = tag;
        compress(
            lanes[..8].try_into().expect("8 lanes"),
            lanes[8..].try_into().expect("8 lanes"),
        )
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct User {
        pub address: Address,
        pub balance: U256,
        pub nonce: u64,
    }

    impl User {
        pub fn bytes(&self) -> Vec<u8> {
            let mut b = self.address.to_vec();
            b.extend(self.balance.le_bytes());
            b.extend(self.nonce.to_le_bytes());
            b
        }

        /// The address, then the balance and the nonce in six lanes, and the
        /// tag 1.
        pub fn leaf(&self) -> Digest {
            leaf(&self.address, &self.bytes()[32..], 1)
        }
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Listing {
        pub seller: Address,
        pub item: u64,
        pub price: U256,
        pub stock: u64,
    }

    impl Listing {
        pub fn bytes(&self) -> Vec<u8> {
            let mut b = self.seller.to_vec();
            b.extend(self.item.to_le_bytes());
            b.extend(self.price.le_bytes());
            b.extend(self.stock.to_le_bytes());
            b
        }

        /// The seller's address, then the item, the price and the stock in
        /// seven lanes, and the tag 2.
        pub fn leaf(&self) -> Digest {
            leaf(&self.seller, &self.bytes()[32..], 2)
        }
    }

    /// A table: each slot's leaf, every slot not listed holding `empty[0]`.
    pub struct Tree {
        leaves: BTreeMap<u32, Digest>,
        empty: Vec<Digest>,
    }

    impl Tree {
        pub fn new(empty: Digest, leaves: impl IntoIterator<Item = (u32, Digest)>) -> Tree {
            let mut levels = vec![empty];
            for l in 0..DEPTH {
                levels.push(compress(&levels[l], &levels[l]));
            }
            Tree {
                leaves: leaves.into_iter().collect(),
                empty: levels,
            }
        }

        fn node(&self, level: usize, index: u32) -> Digest {
            let slots = index << level..(index + 1) << level;
            match (self.leaves.range(slots).next(), level) {
                (None, _) => self.empty[level],
                (Some((_, leaf)), 0) => *leaf,
                _ => compress(
                    &self.node(level - 1, 2 * index),
                    &self.node(level - 1, 2 * index + 1),
                ),
            }
        }

        pub fn root(&self) -> Digest {
            self.node(DEPTH, 0)
        }

        /// `slot`'s siblings from the leaf up, 64 bytes each.
        pub fn path(&self, slot: u32) -> Vec<u8> {
            (0..DEPTH)
                .flat_map(|level| self.node(level, (slot >> level) ^ 1))
                .flat_map(|lane| lane.to_le_bytes())
                .collect()
        }

        pub fn set(&mut self, slot: u32, leaf: Digest) {
            self.leaves.insert(slot, leaf);
        }
    }

    /// A request: the 92 bytes its buyer signs.
    #[derive(Clone, Copy, Debug)]
    pub struct Request {
        pub buyer: Address,
        pub listing: u32,
        pub quantity: u64,
        pub max_price: U256,
        pub nonce: u64,
        pub market: u64,
    }

    impl Request {
        pub fn bytes(&self) -> Vec<u8> {
            let mut b = self.buyer.to_vec();
            b.extend(self.listing.to_le_bytes());
            b.extend(self.quantity.to_le_bytes());
            b.extend(self.max_price.le_bytes());
            b.extend(self.nonce.to_le_bytes());
            b.extend(self.market.to_le_bytes());
            b
        }
    }

    /// The store as the host reads its rules: the users by address and the
    /// listings by slot, the volume, and the users and the listings the
    /// requests have read.
    pub struct Model {
        pub users: BTreeMap<Address, User>,
        pub listings: BTreeMap<u32, Listing>,
        pub volume: U256,
        pub read_users: BTreeSet<Address>,
        pub read_listings: BTreeSet<u32>,
    }

    impl Model {
        /// `r`'s outcome and why, the tables moved where it applies; `signed`
        /// is whether its signature is its buyer's, over it.
        pub fn settle(&mut self, r: &Request, market: u64, signed: bool) -> &'static str {
            if r.market != market {
                return "rejected: another market";
            }
            if r.buyer == NO_ACCOUNT {
                return "rejected: no account";
            }
            self.read_users.insert(r.buyer);
            let buyer = self.users[&r.buyer];
            if r.nonce == u64::MAX {
                return "rejected: the last nonce";
            }
            if r.nonce != buyer.nonce {
                return "rejected: not the nonce";
            }
            if !signed {
                return "rejected: not signed";
            }
            self.users.get_mut(&r.buyer).expect("an account").nonce += 1;
            self.read_listings.insert(r.listing);
            let listing = self.listings.get(&r.listing).copied().unwrap_or_default();
            if r.quantity == 0 || r.quantity > listing.stock {
                return "declined: not in stock";
            }
            if listing.price > r.max_price {
                return "declined: above the max price";
            }
            if listing.seller == r.buyer {
                return "declined: the buyer's own";
            }
            if listing.seller == NO_ACCOUNT {
                return "declined: a seller with no account";
            }
            let Some(cost) = listing.price.checked_mul(r.quantity) else {
                return "declined: a cost past 2^256";
            };
            if cost > buyer.balance {
                return "declined: above the balance";
            }
            self.read_users.insert(listing.seller);
            let seller = self.users[&listing.seller];
            let Some(paid) = seller.balance.checked_add(cost) else {
                return "declined: the seller's balance past 2^256";
            };
            let Some(volume) = self.volume.checked_add(cost) else {
                return "declined: the volume past 2^256";
            };
            self.users.get_mut(&r.buyer).expect("an account").balance = buyer.balance.minus(cost);
            self.users
                .get_mut(&listing.seller)
                .expect("an account")
                .balance = paid;
            self.listings.get_mut(&r.listing).expect("in stock").stock -= r.quantity;
            self.volume = volume;
            "applied"
        }
    }
}

/// `guests/amazon` settles a batch of Falcon-512-signed purchases against its
/// users and listings by their snapshot.
///
/// Forty users, each named by its key's address and each but one with a key
/// from a seed of its own, the one a key that does not decode, in slots apart
/// whose order is not their addresses'; and 22 listings, fourteen of 30 units
/// and up sold by users who also buy; then 98 requests, sequenced by listing
/// as a sequencer gathering each listing's requests would, each buyer's
/// nonces in the batch's order. Seventy purchases of one to three units apply,
/// and so do the last unit of a listing of one, both of a listing of two, a
/// seller's purchase paid for by a sale earlier in the batch, and a purchase
/// at `2^255`. Twelve are declined, each its nonce spent: none asked for, more
/// than the stock, the listings of one and of two once sold out, a vacant
/// listing, a max price one below the price, the buyer's own listing, a
/// seller with no account, the zero address, a cost past `2^256`, a cost past
/// the balance, a seller's balance and the volume past `2^256`. Eight are
/// rejected: another market, the zero address as the buyer, a request again,
/// a nonce skipped, a signature tampered with, a signature under another
/// user's key, the last nonce, and a key that does not decode; the tampered
/// request's buyer then applies with the same nonce. Signatures are new each
/// run, as signing is randomized. The journal is both snapshots, the three
/// counts and the volume. The batch panics with a byte past its requests, and
/// with a request from an address the advice does not hold; and so does the
/// advice with a user's balance one off, and with a user's key another's.
#[test]
fn amazon_settles_signed_purchases_by_its_snapshot() {
    use std::collections::{BTreeMap, BTreeSet};

    use amazon::{compress, Address, Listing, Model, Request, Tree, User, NO_ACCOUNT, U256};
    use apogee_falcon512::{address, keygen, sign};

    const E18: u128 = 1_000_000_000_000_000_000;
    const MARKET: u64 = 0x0a3a_5017;
    const CONTEXT: &[u8] = b"apogee/amazon/purchase/v1";
    // Users 0..32 buy, the odd ones of them selling the plain listings too.
    const POOR: usize = 32;
    const RICH: [usize; 2] = [33, 34];
    const ALMOST_FULL: usize = 35;
    const EXHAUSTED: usize = 36;
    const MALFORMED: usize = 37;
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
    const VACANT: usize = 22;
    let slot = |i: usize| (i * 26_800) as u32;
    let listing = |j: usize| (7 + j * 40_009) as u32;
    let half = U256 {
        hi: 1 << 127,
        lo: 0,
    };

    // Each user's key, by its address, and the slot its record is in.
    let mut secret = BTreeMap::new();
    let mut keys = BTreeMap::new();
    let mut slots = BTreeMap::new();
    let mut users = BTreeMap::new();
    let mut addresses: Vec<Address> = Vec::new();
    for i in 0..40 {
        let (sk, key) = if i == MALFORMED {
            // The first coefficient `2^14 − 1`, at least `q`.
            let mut key = vec![0u8; 897];
            key[..3].copy_from_slice(&[0x09, 0xff, 0xfc]);
            (None, key)
        } else {
            let (sk, pk) = keygen([i as u8 + 1; 32]);
            (Some(sk), pk)
        };
        let a = address(&key);
        if let Some(sk) = sk {
            secret.insert(a, sk);
        }
        let balance = match i {
            POOR => U256::small(E18),
            r if RICH.contains(&r) => U256 {
                hi: 1 << 127,
                lo: 1000 * E18,
            },
            ALMOST_FULL => U256 {
                hi: u128::MAX,
                lo: u128::MAX - 5 * E18 + 1,
            },
            EARNER => U256::default(),
            _ => U256::small((10_000 + i as u128) * E18),
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
        slots.insert(a, slot(i));
        addresses.push(a);
    }
    let user = |i: usize| addresses[i];
    let mut listings = BTreeMap::new();
    for j in 0..VACANT {
        let (seller, price, stock) = match j {
            SINGLE => (user(4), U256::small(7 * E18), 1),
            PAIR => (user(10), U256::small(3 * E18), 2),
            EARNS => (user(EARNER), U256::small(20 * E18), 5),
            SPENDS => (user(22), U256::small(30 * E18), 5),
            OVERFILLS => (user(ALMOST_FULL), U256::small(10 * E18), 5),
            BIG => (user(BIG_SELLER), half, 3),
            BIG_TOO => (user(9), half, 1),
            UNPAYABLE => (NO_ACCOUNT, U256::small(E18), 5),
            _ => (
                user(2 * j + 1),
                U256::small((j as u128 + 1) * E18 + j as u128 * E18 / 10),
                30 + 5 * j as u64,
            ),
        };
        let item = 1000 + j as u64;
        listings.insert(
            listing(j),
            Listing {
                seller,
                item,
                price,
                stock,
            },
        );
    }
    let price = |j: usize| listings.get(&listing(j)).copied().unwrap_or_default().price;

    // How a request is made: signed by its buyer at its nonce, by another
    // user, tampered with, at the nonce after its buyer's, the request before
    // it again, or for another market.
    #[derive(Clone, Copy, PartialEq)]
    enum How {
        Signed,
        By(usize),
        Tampered,
        Skipped,
        Again,
        Elsewhere,
    }
    use How::*;
    let mut batch: Vec<(Address, usize, u64, U256, How)> = (0..70)
        .map(|k| {
            let j = k % 14;
            let b = match (k * 11 + 3) % 32 {
                b if b == 2 * j + 1 => (b + 2) % 32,
                b => b,
            };
            (user(b), j, 1 + k as u64 % 3, price(j), Signed)
        })
        .collect();
    batch.extend([
        (user(5), 0, 0, price(0), Signed),
        (user(7), 1, 1000, price(1), Signed),
        (user(11), 2, 1, price(2).minus(U256::small(1)), Signed),
        (user(7), 3, 1, price(3), Signed),
        (user(6), SINGLE, 1, price(SINGLE), Signed),
        (user(8), SINGLE, 1, price(SINGLE), Signed),
        (user(12), PAIR, 1, price(PAIR), Signed),
        (user(14), PAIR, 1, price(PAIR), Signed),
        (user(16), PAIR, 1, price(PAIR), Signed),
        (user(20), EARNS, 2, price(EARNS), Signed),
        (user(EARNER), SPENDS, 1, price(SPENDS), Signed),
        (user(24), OVERFILLS, 1, price(OVERFILLS), Signed),
        (user(26), BIG, 2, half, Signed),
        (user(RICH[0]), BIG, 1, half, Signed),
        (user(RICH[1]), BIG_TOO, 1, half, Signed),
        (user(28), UNPAYABLE, 1, price(UNPAYABLE), Signed),
        (user(2), VACANT, 1, price(VACANT), Signed),
        (user(POOR), 13, 1, price(13), Signed),
        (user(13), 4, 1, price(4), Elsewhere),
        (NO_ACCOUNT, 5, 1, price(5), By(0)),
        (user(15), 6, 1, price(6), Signed),
        (user(15), 6, 1, price(6), Again),
        (user(17), 7, 1, price(7), Skipped),
        (user(19), 8, 1, price(8), Tampered),
        (user(19), 8, 1, price(8), Signed),
        (user(21), 9, 1, price(9), By(23)),
        (user(EXHAUSTED), 10, 1, price(10), Signed),
        (user(MALFORMED), 11, 1, price(11), By(0)),
    ]);
    // The sequencer's order: each listing's requests together, in the order
    // they came. A stable sort, so a request and its repeat stay adjacent.
    batch.sort_by_key(|&(_, j, ..)| listing(j));

    let tables = |users: &BTreeMap<Address, User>, listings: &BTreeMap<u32, Listing>| {
        (
            Tree::new(
                User::default().leaf(),
                users.iter().map(|(a, u)| (slots[a], u.leaf())),
            ),
            Tree::new(
                Listing::default().leaf(),
                listings.iter().map(|(&s, l)| (s, l.leaf())),
            ),
        )
    };
    let (mut user_tree, mut listing_tree) = tables(&users, &listings);
    let roots = [user_tree.root(), listing_tree.root()];
    let before = compress(&roots[0], &roots[1]);

    let mut model = Model {
        users: users.clone(),
        listings: listings.clone(),
        volume: U256::default(),
        read_users: BTreeSet::new(),
        read_listings: BTreeSet::new(),
    };
    let mut input: Vec<u8> = before.iter().flat_map(|l| l.to_le_bytes()).collect();
    input.extend(MARKET.to_le_bytes());
    input.extend((batch.len() as u32).to_le_bytes());
    let mut signatures = Vec::new();
    let mut outcomes: BTreeMap<&str, u32> = BTreeMap::new();
    let mut previous: Option<(Request, Vec<u8>)> = None;
    for &(buyer, j, quantity, max_price, how) in &batch {
        let (request, signature, signed) = match how {
            Again => {
                let (request, signature) = previous.clone().expect("a request to repeat");
                (request, signature, true)
            }
            _ => {
                let request = Request {
                    buyer,
                    listing: listing(j),
                    quantity,
                    max_price,
                    nonce: model.users.get(&buyer).map_or(0, |u| u.nonce) + (how == Skipped) as u64,
                    market: MARKET + (how == Elsewhere) as u64,
                };
                let signer = match how {
                    By(i) => user(i),
                    _ => buyer,
                };
                let mut signature = sign(&secret[&signer], &request.bytes(), CONTEXT);
                if how == Tampered {
                    signature[200] ^= 0x04;
                }
                (request, signature, signer == buyer && how != Tampered)
            }
        };
        assert_eq!(signature.len(), 666);
        input.extend(request.bytes());
        signatures.push(signature.clone());
        *outcomes
            .entry(model.settle(&request, MARKET, signed))
            .or_default() += 1;
        previous = Some((request, signature));
    }
    assert_eq!(
        outcomes,
        BTreeMap::from([
            ("applied", 78),
            ("declined: a cost past 2^256", 1),
            ("declined: a seller with no account", 1),
            ("declined: above the balance", 1),
            ("declined: above the max price", 1),
            ("declined: not in stock", 5),
            ("declined: the buyer's own", 1),
            ("declined: the seller's balance past 2^256", 1),
            ("declined: the volume past 2^256", 1),
            ("rejected: another market", 1),
            ("rejected: no account", 1),
            ("rejected: not signed", 3),
            ("rejected: not the nonce", 2),
            ("rejected: the last nonce", 1),
        ]),
        "the batch is each case it claims"
    );

    // The advice: the roots, each record read as the snapshot holds it, the
    // users by address, each an account and its key beside it, the
    // signatures, and a path a record, each under its table as the records
    // before it left it.
    let mut advice: Vec<u8> = roots
        .iter()
        .flatten()
        .flat_map(|l| l.to_le_bytes())
        .collect();
    advice.extend((model.read_users.len() as u32).to_le_bytes());
    let mut key_at = BTreeMap::new();
    for a in &model.read_users {
        advice.extend(slots[a].to_le_bytes());
        advice.extend(users[a].bytes());
        key_at.insert(*a, advice.len());
        advice.extend(&keys[a]);
    }
    advice.extend((model.read_listings.len() as u32).to_le_bytes());
    for slot in &model.read_listings {
        advice.extend(slot.to_le_bytes());
        advice.extend(listings.get(slot).copied().unwrap_or_default().bytes());
    }
    advice.extend(signatures.concat());
    advice.resize(advice.len().next_multiple_of(4), 0);
    for a in &model.read_users {
        advice.extend(user_tree.path(slots[a]));
        user_tree.set(slots[a], model.users[a].leaf());
    }
    for slot in &model.read_listings {
        advice.extend(listing_tree.path(*slot));
        let l = model.listings.get(slot).copied().unwrap_or_default();
        listing_tree.set(*slot, l.leaf());
    }
    let after = compress(&user_tree.root(), &listing_tree.root());
    let (users_after, listings_after) = tables(&model.users, &model.listings);
    assert_eq!(
        after,
        compress(&users_after.root(), &listings_after.root()),
        "the paths write the tables the batch leaves"
    );

    let mut journal: Vec<u8> = before
        .iter()
        .chain(&after)
        .flat_map(|l| l.to_le_bytes())
        .collect();
    for outcome in ["applied", "declined", "rejected"] {
        let count: u32 = outcomes
            .iter()
            .filter(|(why, _)| why.starts_with(outcome))
            .map(|(_, n)| n)
            .sum();
        journal.extend(count.to_le_bytes());
    }
    journal.extend(model.volume.le_bytes());
    let image = image("amazon");
    let e = run(&image, &common::with_advice(&input, &advice)).unwrap();
    assert_eq!(e.exit_code, 0);
    assert_eq!(to_hex(&e.io.output), to_hex(&journal));

    let mut surplus = input.clone();
    surplus.push(0);
    let e = run(&image, &common::with_advice(&surplus, &advice)).unwrap();
    assert_eq!(
        e.exit_code, 101,
        "a byte past the requests is a malformed batch"
    );

    // The first request, from a user who signed it, now from an address no
    // user has: the advice cannot hold it, and nothing proves it absent.
    let (buyer, .., how) = batch[0];
    assert!(how == Signed && buyer != NO_ACCOUNT);
    let mut stranger = input.clone();
    stranger[76..108].copy_from_slice(&address(b"no user's key"));
    let e = run(&image, &common::with_advice(&stranger, &advice)).unwrap();
    assert_eq!(
        e.exit_code, 101,
        "a request from an address the advice does not hold is a malformed batch"
    );

    // That buyer's key, another user's: its address is not the record's.
    let other = user(if buyer == user(0) { 1 } else { 0 });
    let mut swapped = advice.clone();
    swapped[key_at[&buyer]..][..897].copy_from_slice(&keys[&other]);
    let e = run(&image, &common::with_advice(&input, &swapped)).unwrap();
    assert_eq!(e.exit_code, 101, "an advised key that is not its user's");

    // The first user's balance, one off: its record no longer opens the
    // users table.
    advice[128 + 4 + 4 + 32] ^= 1;
    let e = run(&image, &common::with_advice(&input, &advice)).unwrap();
    assert_eq!(e.exit_code, 101, "a balance the table does not hold");
}
