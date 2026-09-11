//! What the dump promises, held to `crates/loader`.
//!
//! The tool's whole claim is that the file it writes is the frozen wire form
//! and that the page it prints describes that file. Both are checked here
//! against the loader itself rather than against a recorded expectation, so a
//! change to either side has to agree with the other to pass.

use std::collections::BTreeMap;
use std::path::PathBuf;

use artifact_dump::{dump, wire_form};
use loader::{load_elf, ProgramImage, Slot};

/// The committed guest ELFs, plus the smallest synthetic one.
const FIXTURES: [&str; 8] = [
    "fib",
    "echo",
    "rvc-dense",
    "amm",
    "orderbook",
    "vault",
    "atomics",
    "minimal",
];

fn elf(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/loader/tests/vectors")
        .join(format!("{name}.elf"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The artifact is the wire form, and nothing of this tool's own is in it.
#[test]
fn the_artifact_is_exactly_the_loaders_wire_form() {
    for name in FIXTURES {
        let bytes = elf(name);
        let image = load_elf(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let dumped = dump(&bytes, name, "x.img").unwrap_or_else(|e| panic!("{name}: {e}"));

        assert_eq!(
            dumped.artifact,
            wire_form(&image),
            "{name}: the exported bytes are not the frozen wire form"
        );
        let back: ProgramImage = postcard::from_bytes(&dumped.artifact)
            .unwrap_or_else(|e| panic!("{name}: the artifact does not parse: {e}"));
        assert_eq!(
            back, image,
            "{name}: the artifact reads back as a different image"
        );
    }
}

/// A dump is a function of the ELF bytes, like the load it wraps.
#[test]
fn two_dumps_of_one_elf_agree_byte_for_byte() {
    for name in FIXTURES {
        let bytes = elf(name);
        let a = dump(&bytes, name, "x.img").unwrap_or_else(|e| panic!("{name}: {e}"));
        let b = dump(&bytes, name, "x.img").unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(a.artifact, b.artifact, "{name}: the artifact moved");
        assert_eq!(a.report, b.report, "{name}: the report moved");
    }
}

/// The printed listing IS the instruction stream: same addresses, same
/// encodings, same lengths, nothing extra and nothing dropped.
///
/// This is the check that makes the report examinable rather than decorative.
/// A renderer that skipped a slot, or printed an address twice, or disagreed
/// with the artifact about a length, fails here.
#[test]
fn the_listing_is_the_instruction_stream() {
    for name in FIXTURES {
        let bytes = elf(name);
        let image = load_elf(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let report = dump(&bytes, name, "x.img")
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .report;

        let listed = parse_listing(&report);
        let expected: BTreeMap<u32, (u32, u32)> = image
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| match slot {
                Slot::Instruction { word, compressed } => Some((
                    image.slot_base + 2 * i as u32,
                    (if *compressed { 2 } else { 4 }, *word),
                )),
                _ => None,
            })
            .collect();

        assert!(!expected.is_empty(), "{name}: no instructions to list");
        assert_eq!(
            listed, expected,
            "{name}: the listing and the image disagree"
        );
    }
}

/// Every slot is accounted for: an instruction line, the mid-instruction slot
/// its length implies, or a folded `not code` run.
#[test]
fn every_slot_is_accounted_for() {
    for name in FIXTURES {
        let bytes = elf(name);
        let image = load_elf(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let report = dump(&bytes, name, "x.img")
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .report;

        let from_lines: usize = parse_listing(&report)
            .values()
            .map(|(len, _)| *len as usize / 2)
            .sum::<usize>()
            + parse_not_code_runs(&report)
                .iter()
                .map(|(_, _, n)| n)
                .sum::<usize>();
        assert_eq!(
            from_lines,
            image.slots.len(),
            "{name}: the listing covers {from_lines} of {} slots",
            image.slots.len()
        );
    }
}

/// The entry line carries the symbol the linker put there.
#[test]
fn the_entry_is_annotated_with_its_symbol() {
    let bytes = elf("fib");
    let report = dump(&bytes, "fib", "x.img").expect("fib dumps").report;
    let entry = report
        .lines()
        .find(|line| line.starts_with("entry  "))
        .expect("the report names the entry");
    assert!(
        entry.contains("_start"),
        "the entry line lost its symbol: {entry}"
    );
}

/// A file the loader refuses is an error, not a written artifact.
#[test]
fn a_refused_elf_produces_no_artifact() {
    for name in ["et_dyn", "elf64", "not_riscv"] {
        // `Dump` carries a whole report, so a `Debug` bound on it would put the
        // page in the failure message; matching says the same thing quietly.
        match dump(&elf(name), name, "x.img") {
            Ok(_) => panic!("{name} was accepted"),
            Err(err) => assert!(err.contains(name), "{name}: unnamed error: {err}"),
        }
    }
}

/// Slots that are not code are folded into one line, and the fold is exact.
///
/// No committed guest reaches this path — with the frozen linker script `.text`
/// is the lowest loaded segment, so the slot span is all code — so the fixture
/// is built here: a read-only segment below an executable one leaves a gap of
/// slots that are addresses in the image and not instructions.
#[test]
fn runs_that_are_not_code_are_folded_exactly() {
    // `c.nop`, `c.jr ra`: two halfwords that decode.
    let text = [0x01u8, 0x00, 0x82, 0x80];
    let bytes = two_segment_elf(0x0001_0000, &[0xaa; 0x40], 0x0001_0100, &text);

    let image = load_elf(&bytes).expect("the synthetic ELF loads");
    let dumped = dump(&bytes, "gap", "gap.img").expect("it dumps");

    let runs = parse_not_code_runs(&dumped.report);
    assert_eq!(
        runs,
        vec![(0x0001_0000, 0x0001_0100, 128)],
        "the gap below .text was not folded into one line"
    );
    assert_eq!(
        parse_listing(&dumped.report)
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![0x0001_0100, 0x0001_0102],
        "only the two instructions above the gap should be listed"
    );
    assert_eq!(image.slot_base, 0x0001_0000);
}

// ---------------------------------------------------------------------------
// Reading the report back
// ---------------------------------------------------------------------------

/// `address -> (len, expanded word)` for every instruction line.
fn parse_listing(report: &str) -> BTreeMap<u32, (u32, u32)> {
    let body = report
        .split_once("address     len  in memory  expanded  symbol\n")
        .expect("the report has a listing")
        .1;
    let mut out = BTreeMap::new();
    for line in body.lines() {
        let Some(rest) = line.strip_prefix("0x") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let address = u32::from_str_radix(fields.next().expect("an address"), 16)
            .expect("the address is hex");
        let len: u32 = fields.next().expect("a length").parse().expect("a number");
        let _in_memory = fields.next().expect("the memory encoding");
        let word = u32::from_str_radix(fields.next().expect("the expanded word"), 16)
            .expect("the word is hex");
        assert!(
            out.insert(address, (len, word)).is_none(),
            "{address:#010x} is listed twice"
        );
    }
    out
}

/// `(start, end, halfwords)` for every folded run.
fn parse_not_code_runs(report: &str) -> Vec<(u32, u32, usize)> {
    report
        .lines()
        .filter_map(|line| line.strip_prefix("---- not code: "))
        .map(|rest| {
            let mut fields = rest.split_whitespace();
            let start = hex(fields.next().expect("a start"));
            let _dots = fields.next();
            let end = hex(fields.next().expect("an end").trim_end_matches(','));
            let count: usize = fields
                .next()
                .expect("a count")
                .parse()
                .expect("the count is a number");
            (start, end, count)
        })
        .collect()
}

fn hex(s: &str) -> u32 {
    u32::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex")
}

// ---------------------------------------------------------------------------
// A synthetic ELF, for the one case no guest produces
// ---------------------------------------------------------------------------

/// A static RV32 executable with a read-only segment below an executable one.
///
/// The same 52-byte header and 32-byte program headers `tools/kat-gen` writes
/// for the loader's negative controls; entry is the first byte of the text.
fn two_segment_elf(data_at: u32, data: &[u8], text_at: u32, text: &[u8]) -> Vec<u8> {
    const EHDR: usize = 52;
    const PHDR: usize = 32;
    let body_at = EHDR + 2 * PHDR;

    let mut out = Vec::new();
    out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0]);
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
    out.extend_from_slice(&243u16.to_le_bytes()); // e_machine: EM_RISCV
    out.extend_from_slice(&1u32.to_le_bytes()); // e_version
    out.extend_from_slice(&text_at.to_le_bytes()); // e_entry
    out.extend_from_slice(&(EHDR as u32).to_le_bytes()); // e_phoff
    out.extend_from_slice(&0u32.to_le_bytes()); // e_shoff: no sections
    out.extend_from_slice(&1u32.to_le_bytes()); // e_flags: EF_RISCV_RVC
    out.extend_from_slice(&(EHDR as u16).to_le_bytes());
    out.extend_from_slice(&(PHDR as u16).to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes()); // e_phnum
    out.extend_from_slice(&40u16.to_le_bytes()); // e_shentsize
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    let mut offset = body_at;
    for (vaddr, bytes, flags) in [(data_at, data, 4u32), (text_at, text, 5u32)] {
        out.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        out.extend_from_slice(&vaddr.to_le_bytes());
        out.extend_from_slice(&vaddr.to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&4u32.to_le_bytes());
        offset += bytes.len();
    }
    out.extend_from_slice(data);
    out.extend_from_slice(text);
    out
}
