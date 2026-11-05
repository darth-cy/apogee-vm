//! `crates/loader`'s fixtures: the synthetic ELFs and the fib public-I/O
//! record.
//!
//! Everything here is a deterministic function of nothing at all, which is what
//! lets CI regenerate it and diff. No guest ELF is a fixture: a suite that runs
//! one builds it from `guests/` (`test_support::guest_elf`), and lists it with
//! the pinned toolchain's `llvm-objdump` and `llvm-nm` there.

use crate::write_vectors;

pub fn generate() {
    synthetic_elfs();
    fib_io();
}

// ---------------------------------------------------------------------------
// Synthetic ELFs
// ---------------------------------------------------------------------------

/// A hand-built ELF: 52-byte header, program headers, then the segment bodies.
///
/// Small enough to read, which is the point — every negative control is a
/// named deviation from this one shape, and no toolchain will produce most of
/// them for RV32.
pub(crate) struct ElfBuilder {
    pub(crate) e_type: u16,
    e_machine: u16,
    ei_class: u8,
    entry: u32,
    /// `(p_type, p_flags, vaddr, filesz_bytes, memsz)`.
    segments: Vec<(u32, u32, u32, Vec<u8>, u32)>,
}

impl ElfBuilder {
    /// A minimal, valid, static RV32 executable with one `R|X` segment.
    pub(crate) fn rv32_exec(text: &[u8]) -> ElfBuilder {
        ElfBuilder {
            e_type: 2,
            e_machine: 243,
            ei_class: 1,
            entry: 0x0001_0000,
            segments: vec![(1, 5, 0x0001_0000, text.to_vec(), text.len() as u32)],
        }
    }

    pub(crate) fn build(&self) -> Vec<u8> {
        const EHDR: usize = 52;
        const PHDR: usize = 32;
        let body_at = EHDR + PHDR * self.segments.len();

        let mut out = Vec::new();
        out.extend_from_slice(&[0x7f, b'E', b'L', b'F', self.ei_class, 1, 1, 0]);
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&self.e_type.to_le_bytes());
        out.extend_from_slice(&self.e_machine.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // e_version
        out.extend_from_slice(&self.entry.to_le_bytes());
        out.extend_from_slice(&(EHDR as u32).to_le_bytes()); // e_phoff
        out.extend_from_slice(&0u32.to_le_bytes()); // e_shoff
        out.extend_from_slice(&1u32.to_le_bytes()); // e_flags: EF_RISCV_RVC
        out.extend_from_slice(&(EHDR as u16).to_le_bytes());
        out.extend_from_slice(&(PHDR as u16).to_le_bytes());
        out.extend_from_slice(&(self.segments.len() as u16).to_le_bytes());
        out.extend_from_slice(&40u16.to_le_bytes()); // e_shentsize
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert_eq!(out.len(), EHDR);

        let mut offset = body_at;
        for (p_type, p_flags, vaddr, bytes, memsz) in &self.segments {
            out.extend_from_slice(&p_type.to_le_bytes());
            out.extend_from_slice(&(offset as u32).to_le_bytes());
            out.extend_from_slice(&vaddr.to_le_bytes());
            out.extend_from_slice(&vaddr.to_le_bytes()); // p_paddr
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&memsz.to_le_bytes());
            out.extend_from_slice(&p_flags.to_le_bytes());
            out.extend_from_slice(&4u32.to_le_bytes()); // p_align
            offset += bytes.len();
        }
        assert_eq!(out.len(), body_at);

        for (_, _, _, bytes, _) in &self.segments {
            out.extend_from_slice(bytes);
        }
        out
    }
}

/// `c.nop`, then `c.jr ra`: two halfwords that decode, so a fixture's failure
/// is always the thing it is named after.
const GOOD_TEXT: [u8; 4] = [0x01, 0x00, 0x82, 0x80];

fn synthetic_elfs() {
    // Each entry: file name, the bytes.
    //
    // A valid one-segment RV32 executable: the positive control for every
    // negative below, and proof that the builder itself is right.
    let mut cases: Vec<(&str, Vec<u8>)> =
        vec![("minimal", ElfBuilder::rv32_exec(&GOOD_TEXT).build())];

    // -- the RVC negatives -------------------------------------------------
    // An all-zero halfword after a c.nop: RVC's defined-illegal encoding, which
    // the sweep records as not code rather than refusing -- this one is a
    // positive fixture, not a negative.
    cases.push((
        "zero_halfword",
        ElfBuilder::rv32_exec(&[0x01, 0x00, 0x00, 0x00]).build(),
    ));
    // c.nop, two all-zero halfwords, c.jr ra, one more, c.nop: the sweep must
    // resynchronise on the far side of padding rather than swallow what follows
    // it. The lone halfword is the load-bearing one -- after a pair, a sweep
    // that over-advanced by two bytes would land on the second and look correct,
    // because an unswept slot is already NonInstruction.
    cases.push((
        "zero_halfword_run",
        ElfBuilder::rv32_exec(&[
            0x01, 0x00, // c.nop
            0x00, 0x00, // padding
            0x00, 0x00, // padding
            0x82, 0x80, // c.jr ra
            0x00, 0x00, // padding, alone this time
            0x01, 0x00, // c.nop -- only a correctly resynchronised sweep finds it
        ])
        .build(),
    ));
    // c.addi4spn a0, sp, 0 (0x0008): nzuimm = 0 is reserved.
    cases.push((
        "reserved_addi4spn",
        ElfBuilder::rv32_exec(&[0x01, 0x00, 0x08, 0x00]).build(),
    ));
    // 0xb872, a cm.push-shaped halfword in quadrant 2 funct3 = 101: the Zcmp
    // encoding space, which RV32IMAC does not have.
    cases.push((
        "zcmp",
        ElfBuilder::rv32_exec(&[0x01, 0x00, 0x72, 0xb8]).build(),
    ));
    // 0x0000_001f: bits 4:2 all ones, so a 48-bit encoding.
    cases.push((
        "instruction_too_long",
        ElfBuilder::rv32_exec(&[0x1f, 0x00, 0x00, 0x00]).build(),
    ));
    // A 32-bit instruction whose second halfword is past the end of the segment.
    cases.push((
        "text_truncated",
        ElfBuilder::rv32_exec(&[0x01, 0x00, 0x13, 0x00]).build(),
    ));

    // -- the ELF negatives -------------------------------------------------
    // e_type = ET_DYN: a shared object or PIE, which needs a dynamic linker.
    let mut dyn_type = ElfBuilder::rv32_exec(&GOOD_TEXT);
    dyn_type.e_type = 3;
    cases.push(("et_dyn", dyn_type.build()));

    // A static-looking executable carrying a PT_DYNAMIC segment.
    let mut pt_dynamic = ElfBuilder::rv32_exec(&GOOD_TEXT);
    pt_dynamic
        .segments
        .push((2, 6, 0x0002_0000, vec![0u8; 8], 8));
    cases.push(("pt_dynamic", pt_dynamic.build()));

    // e_type = ET_REL: a relocatable object, which is not a program.
    let mut rel = ElfBuilder::rv32_exec(&GOOD_TEXT);
    rel.e_type = 1;
    cases.push(("et_rel", rel.build()));

    // e_machine = EM_ARM.
    let mut arm = ElfBuilder::rv32_exec(&GOOD_TEXT);
    arm.e_machine = 40;
    cases.push(("not_riscv", arm.build()));

    // EI_CLASS = ELFCLASS64: the header would not even parse as 32-bit.
    let mut elf64 = ElfBuilder::rv32_exec(&GOOD_TEXT);
    elf64.ei_class = 2;
    cases.push(("elf64", elf64.build()));

    // One PT_LOAD, read-only: an image with no instruction stream.
    let mut no_exec = ElfBuilder::rv32_exec(&GOOD_TEXT);
    no_exec.segments[0].1 = 4; // PF_R only
    cases.push(("no_executable_segment", no_exec.build()));

    // Two PT_LOADs whose memory spans intersect.
    let mut overlap = ElfBuilder::rv32_exec(&GOOD_TEXT);
    overlap.segments.push((1, 4, 0x0001_0002, vec![0u8; 4], 4));
    cases.push(("overlapping_segments", overlap.build()));

    // e_entry pointing at the second halfword of a 32-bit instruction.
    let mut entry_mid = ElfBuilder::rv32_exec(&[0x13, 0x00, 0x00, 0x00]); // one 32-bit nop
    entry_mid.entry = 0x0001_0002;
    cases.push(("entry_mid_instruction", entry_mid.build()));

    for (name, bytes) in cases {
        let path = format!("crates/loader/tests/vectors/{name}.elf");
        crate::write_bytes(&path, &bytes);
    }
}

// ---------------------------------------------------------------------------
// The fib public-I/O record
// ---------------------------------------------------------------------------

/// `guests/fib`'s public input and journal, host-computed.
///
/// `crates/emulator/tests/guests.rs` asserts the guest agrees; the digest test
/// hashes them. Both are a little-endian `u32`, which is the whole of fib's
/// I/O contract.
fn fib_io() {
    const N: u32 = 24;
    let mut a: u32 = 0;
    let mut b: u32 = 1;
    for _ in 0..N {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    let input = N.to_le_bytes();
    let output = a.to_le_bytes();
    write_vectors(
        "crates/loader/tests/vectors/fib_io.txt",
        &format!(
            "# guests/fib's public values: the input window in, the journal out.\n\
             # Generated by `cargo run -p kat-gen -- loader`. Do not edit.\n\
             #\n\
             # fib({N}) = {a}, both a little-endian u32. The emulator suite\n\
             # checks the guest produces this; the digest test hashes it.\n\
             n {N}\n\
             value {a}\n\
             input {}\n\
             output {}\n",
            test_support::to_hex(&input),
            test_support::to_hex(&output),
        ),
    );
}
