//! A guest ELF in, the frozen `ProgramImage` artifact out, plus a report of
//! that artifact a person can read.
//!
//! # What the artifact is
//!
//! Exactly the wire form S10 froze: `postcard` over `entry`, `segments`,
//! `slot_base` and `slots` in declaration order, with **no header, no magic
//! and no framing of this tool's own**. A later stage reads one back with
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let bytes = std::fs::read("fib.img")?;
//! let image: loader::ProgramImage = postcard::from_bytes(&bytes)?;
//! # Ok(()) }
//! ```
//!
//! and gets the value `loader::load_elf` gives for the same ELF, because that
//! is what was written. Inventing a container here would have made the file a
//! second format to freeze, and the point of the exercise is that there is
//! only one.
//!
//! # Why the report is rendered from the artifact and not from the image
//!
//! [`dump`] serializes the loaded image, reads it back — through the reader
//! that re-checks every invariant, because a wire form is untrusted input —
//! compares it equal to what the loader produced, and renders the report from
//! **that** value. A report rendered from the in-memory image would describe
//! something the file might not contain. This way the printed thing and the
//! exported thing cannot disagree: if they could, the round trip fails first
//! and nothing is written.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use constants::guest_memory;
use loader::{load_elf, ProgramImage, Slot};
use test_support::{sha256, to_hex};

pub mod symbols;

/// One dump: the artifact, the report of it, and the image both describe.
pub struct Dump {
    /// The frozen wire form. This is the file to keep.
    pub artifact: Vec<u8>,
    /// The report of that artifact, ready to write or print.
    pub report: String,
    /// The image, as it came back off the wire.
    pub image: ProgramImage,
}

/// Load an ELF, export it, and render the report.
///
/// `source_label` is how the ELF is named in the report — a path, usually.
/// `artifact_name` is the file name the artifact will be written under; it
/// appears in the report so a printed page says which file it describes.
pub fn dump(elf: &[u8], source_label: &str, artifact_name: &str) -> Result<Dump, String> {
    let image =
        load_elf(elf).map_err(|e| format!("{source_label}: the loader refused it: {e:?}"))?;

    let artifact = wire_form(&image);
    let back: ProgramImage = postcard::from_bytes(&artifact)
        .map_err(|e| format!("{source_label}: the artifact does not read back: {e}"))?;
    if back != image {
        // Unreachable unless the serialization and its reader have drifted
        // apart, which is exactly the thing worth refusing to write over.
        return Err(format!(
            "{source_label}: the artifact does not round-trip; refusing to write \
             a file whose contents are not the image the loader produced"
        ));
    }

    let report = render(&back, &artifact, elf, source_label, artifact_name);
    Ok(Dump {
        artifact,
        report,
        image: back,
    })
}

/// The frozen wire form: `postcard` over the image.
///
/// `postcard` is taken with no features, so there is no `to_allocvec`; the
/// buffer is a heap `Vec` sized from the image and `to_slice` writes into it.
/// This is `crates/loader/tests/common`'s helper, deliberately: the bytes this
/// tool exports are the bytes that suite exercises.
pub fn wire_form(image: &ProgramImage) -> Vec<u8> {
    let bound = 64
        + image.slots.len() * 8
        + image
            .segments
            .iter()
            .map(|s| s.bytes.len() + 32)
            .sum::<usize>();
    let mut buf = vec![0u8; bound];
    let used = postcard::to_slice(image, &mut buf).expect("the buffer bound holds");
    used.to_vec()
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

fn render(
    image: &ProgramImage,
    artifact: &[u8],
    elf: &[u8],
    source_label: &str,
    artifact_name: &str,
) -> String {
    let names = symbols::read(elf);
    let mut out = String::with_capacity(64 * image.slots.len());

    header(&mut out, artifact, elf, source_label, artifact_name);
    entry_and_memory(&mut out, image, &names);
    segments(&mut out, image);
    let counts = instruction_stream(&mut out, image);
    symbol_index(&mut out, &names);
    listing(&mut out, image, &names, counts);
    out
}

fn header(out: &mut String, artifact: &[u8], elf: &[u8], source_label: &str, artifact_name: &str) {
    let _ = write!(
        out,
        "apogee-vm program image\n\
         =======================\n\
         \n\
         artifact          {artifact_name}\n\
         artifact bytes    {}\n\
         artifact sha256   {}\n\
         source ELF        {source_label}\n\
         source bytes      {}\n\
         source sha256     {}\n\
         \n\
         Everything below is rendered from the artifact: the loaded image was\n\
         serialized, read back through the reader that re-checks every invariant,\n\
         and compared equal to what `loader::load_elf` produced. Each number here\n\
         is one that survived the wire form.\n\
         \n\
         The artifact IS that wire form -- `postcard` over `entry`, `segments`,\n\
         `slot_base` and `slots` in declaration order, with no header and no\n\
         framing of its own. A later stage reads it back with\n\
         \n\
         \x20   let bytes = std::fs::read({artifact_name:?})?;\n\
         \x20   let image: loader::ProgramImage = postcard::from_bytes(&bytes)?;\n\
         \n\
         and gets the value `load_elf` gives for the same ELF.\n\
         \n\
         The sha256 above pins these bytes so a rebuild can be compared against\n\
         them. It is **not** program identity: that is S11's, computed over the\n\
         decoded per-family tables and the `VmConfig`, and it is a different\n\
         value in a different field.\n\
         \n\
         Symbol names below come from the ELF's own symbol table. They make the\n\
         listing navigable and are NOT part of the artifact -- nothing downstream\n\
         sees them, and two ELFs differing only in their symbols export the same\n\
         artifact bytes.\n",
        artifact.len(),
        to_hex(&sha256(artifact)),
        elf.len(),
        to_hex(&sha256(elf)),
    );
}

fn entry_and_memory(out: &mut String, image: &ProgramImage, names: &Names) {
    let span_end = image.slot_base as u64 + 2 * image.slots.len() as u64;
    let ram_lo = guest_memory::RAM_ORIGIN as u64;
    let ram_hi = ram_lo + guest_memory::RAM_LENGTH as u64;
    let _ = write!(
        out,
        "\nentry and memory\n\
         ----------------\n\
         entry             {:#010x}{}\n\
         RAM window        {ram_lo:#010x} .. {ram_hi:#010x}    constants::guest_memory\n\
         slot_base         {:#010x}\n\
         slot span         {:#010x} .. {span_end:#010x}    {} halfwords\n\
         \n\
         The slot vector stops at the top of the highest executable segment: no\n\
         pc above the last executable byte can be an instruction, so a slot there\n\
         would say nothing, and `slot_at` answers `None`.\n",
        image.entry,
        annotation(names, image.entry),
        image.slot_base,
        image.slot_base,
        image.slots.len(),
    );
}

fn segments(out: &mut String, image: &ProgramImage) {
    let _ = write!(
        out,
        "\nsegments\n\
         --------\n\
         {} of them, sorted by vaddr and pairwise disjoint. `zero fill` is\n\
         `mem_len` less the file-backed bytes: memory the loader supplies as\n\
         zeroes, which is `.bss` and the heap-and-stack reservation above it.\n\
         `instructions` counts the instruction slots inside the segment, so a\n\
         nonzero count is what makes a segment executable as far as the image is\n\
         concerned -- the artifact carries no permission bits.\n\
         \n\
         \x20 #  vaddr       end          mem_len      file bytes    zero fill  instructions\n",
        image.segments.len(),
    );
    for (i, segment) in image.segments.iter().enumerate() {
        let end = segment.vaddr as u64 + segment.mem_len as u64;
        let instructions = (0..segment.mem_len as u64)
            .step_by(2)
            .filter(|off| {
                matches!(
                    image.slot_at((segment.vaddr as u64 + off) as u32),
                    Some(Slot::Instruction { .. })
                )
            })
            .count();
        let _ = writeln!(
            out,
            "  {i:>1}  {:#010x}  {end:#010x}   {:#010x}  {:>12}  {:>11}  {instructions:>12}",
            segment.vaddr,
            segment.mem_len,
            segment.bytes.len(),
            segment.mem_len as u64 - segment.bytes.len() as u64,
        );
    }
}

/// `(wide, compressed, mid, non)`.
type Counts = (usize, usize, usize, usize);

fn instruction_stream(out: &mut String, image: &ProgramImage) -> Counts {
    let mut wide = 0usize;
    let mut compressed = 0usize;
    let mut mid = 0usize;
    let mut non = 0usize;
    for slot in &image.slots {
        match slot {
            Slot::Instruction {
                compressed: false, ..
            } => wide += 1,
            Slot::Instruction {
                compressed: true, ..
            } => compressed += 1,
            Slot::MidInstruction => mid += 1,
            Slot::NonInstruction => non += 1,
        }
    }
    let _ = write!(
        out,
        "\ninstruction stream\n\
         ------------------\n\
         instructions      {:<10} {wide} four-byte, {compressed} two-byte\n\
         mid-instruction   {mid:<10} the second halfword of each four-byte instruction\n\
         not code          {non:<10} data below the code, gaps, bytes above a segment's\n\
         \x20                            file length, and tails no instruction fit in\n\
         total slots       {:<10} {} + {mid} + {non}, and the slot span is {} bytes\n\
         instruction bytes {:<10} 4*{wide} + 2*{compressed}\n",
        wide + compressed,
        image.slots.len(),
        wide + compressed,
        2 * image.slots.len(),
        4 * wide + 2 * compressed,
    );
    (wide, compressed, mid, non)
}

fn symbol_index(out: &mut String, names: &Names) {
    if names.is_empty() {
        let _ = write!(
            out,
            "\nsymbols\n\
             -------\n\
             None: this ELF carries no symbol table, or none that could be read.\n\
             The listing below has no symbol column. The artifact is unaffected.\n"
        );
        return;
    }
    let total: usize = names.values().map(|set| set.len()).sum();
    let _ = write!(
        out,
        "\nsymbols\n\
         -------\n\
         {total} names at {} addresses, read from the ELF and not from the artifact.\n\
         Assembler-local labels (`.L*`) and mapping symbols (`$*`) are dropped;\n\
         everything else the linker defined is here, mangled names included.\n\
         \n",
        names.len(),
    );
    for (addr, set) in names {
        let _ = writeln!(out, "  {addr:#010x}  {}", joined(set));
    }
}

fn listing(out: &mut String, image: &ProgramImage, names: &Names, counts: Counts) {
    let (wide, compressed, _, _) = counts;
    let _ = write!(
        out,
        "\nlisting\n\
         -------\n\
         Every slot that starts an instruction, in address order: {} lines.\n\
         \n\
         `len` is the instruction's length in memory, in bytes. It is the only\n\
         thing that says whether the next pc is +2 or +4 -- the expanded word\n\
         cannot say, because a compressed instruction expands to a full 32-bit\n\
         encoding while still occupying two bytes. Addresses are never compacted.\n\
         \n\
         `in memory` is the halfword or word as the ELF stores it at that address.\n\
         `expanded` is what the artifact carries: the same word for a four-byte\n\
         instruction, and for a two-byte one the exact 32-bit instruction it\n\
         abbreviates.\n\
         \n\
         The halfword after a four-byte instruction is a mid-instruction slot and\n\
         is not listed. Its position is implied by `len`, and the artifact's reader\n\
         rejects an image where one is missing or stands alone. Runs of slots that\n\
         are not code are folded into a single line.\n\
         \n\
         For mnemonics, disassemble the same ELF with the pinned toolchain:\n\
         \n\
         \x20   llvm-objdump --disassemble --no-print-imm-hex -M no-aliases <elf>\n\
         \n\
         `crates/loader/tests/differential.rs` holds this listing to that\n\
         disassembler's, address for address and encoding for encoding, in both\n\
         directions -- so a sweep that had lost synchronisation would fail there\n\
         rather than be printed here.\n\
         \n\
         address     len  in memory  expanded  symbol\n",
        wide + compressed,
    );

    let mut i = 0usize;
    while i < image.slots.len() {
        let pc = image.slot_base + 2 * i as u32;
        match image.slots[i] {
            Slot::Instruction { word, compressed } => {
                let len = if compressed { 2 } else { 4 };
                let raw = match in_memory(image, pc, len) {
                    // Four hex digits for a halfword, eight for a word, so the
                    // column says the length as well as the `len` column does.
                    Some(bytes) if compressed => format!("{:>8}", format!("{:04x}", u16le(&bytes))),
                    Some(bytes) => format!("{:08x}", u32le(&bytes)),
                    // Above a segment's file length there are no bytes to show,
                    // and the sweep leaves those slots non-instruction anyway.
                    None => "       ?".to_string(),
                };
                let _ = writeln!(
                    out,
                    "{pc:#010x}  {len:>3}   {raw}  {word:08x}{}",
                    annotation(names, pc)
                );
                i += if compressed { 1 } else { 2 };
            }
            // Validated to follow a four-byte instruction, which consumed it.
            Slot::MidInstruction => i += 1,
            Slot::NonInstruction => {
                let start = i;
                while matches!(image.slots.get(i), Some(Slot::NonInstruction)) {
                    i += 1;
                }
                let run = i - start;
                let end = image.slot_base as u64 + 2 * i as u64;
                let _ = writeln!(
                    out,
                    "---- not code: {pc:#010x} .. {end:#010x}, {run} halfword{} ----",
                    if run == 1 { "" } else { "s" }
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

type Names = BTreeMap<u32, BTreeSet<String>>;

/// `"  name, other"`, or the empty string when nothing is defined at `addr`.
fn annotation(names: &Names, addr: u32) -> String {
    match names.get(&addr) {
        Some(set) => format!("  {}", joined(set)),
        None => String::new(),
    }
}

fn joined(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join(", ")
}

/// The `len` file-backed bytes at `pc`, if a segment supplies them.
fn in_memory(image: &ProgramImage, pc: u32, len: usize) -> Option<Vec<u8>> {
    let segment = image
        .segments
        .iter()
        .find(|s| pc >= s.vaddr && (pc as u64) < s.vaddr as u64 + s.mem_len as u64)?;
    let at = (pc - segment.vaddr) as usize;
    segment.bytes.get(at..at.checked_add(len)?).map(Vec::from)
}

fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
