//! ELF loading and RVC expansion: guest bytes in, [`ProgramImage`] out.
//!
//! The image is a deterministic function of the ELF bytes and nothing else —
//! no clock, no filesystem, no hash map iteration order — because S11 derives
//! program identity from it.
//!
//! # What a load does
//!
//! 1. Parse the header. Reject anything that is not a **static, executable,
//!    little-endian, 32-bit RISC-V** ELF: dynamic, relocatable and non-RV32
//!    files each get their own named error.
//! 2. Take the `PT_LOAD` segments, sorted by address, as the post-load memory
//!    image. `PT_DYNAMIC` or `PT_INTERP` anywhere is a refusal.
//! 3. Sweep every **executable** segment linearly, halfword by halfword,
//!    expanding each compressed instruction to the exact 32-bit instruction it
//!    abbreviates.
//!
//! # Addresses are preserved, never compacted
//!
//! A `c.addi` at `0x1002` stays at `0x1002` and occupies two bytes. Expansion
//! changes representation, not layout. Compacting compressed instructions into
//! 4-byte slots would shift every later address and break linker-resolved
//! function pointers and computed jumps — and would change program identity
//! for a program that did not change.
//!
//! That is why the instruction stream is a **pc/2-indexed slot vector**: the
//! slot at `(pc - slot_base) / 2` is the instruction starting at `pc`, the
//! second halfword of a 32-bit instruction, or not code at all, and the three
//! cases are distinguished rather than inferred.
//!
//! # The sweep is fragile, on purpose
//!
//! Instruction boundaries are not local: data embedded in an executable
//! segment desynchronises the sweep, and everything after it decodes as
//! garbage. Compiler output stays synchronised because GCC and LLVM keep
//! constants in `.rodata`, and a desync that reaches real code diverges loudly
//! — under QEMU while testing, and as an [`LoaderError::RvcIllegal`] here the
//! moment it meets a halfword no valid encoding claims. Being loud is the
//! design: a loader that guessed would be a loader that proves the wrong
//! program.

mod rvc;

use constants::guest_memory;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way this crate refuses. One flat enum, one variant per failure class.
///
/// Nothing here is a panic: a malformed ELF is data, and the caller decides
/// what to do about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoaderError {
    /// Not an ELF this loader will look at: bad magic, wrong class, wrong
    /// endianness, wrong version, or a header field with an impossible size.
    NotAnElf { reason: &'static str },
    /// The file ends before a structure it declares does.
    Truncated {
        what: &'static str,
        need: usize,
        have: usize,
    },
    /// `ET_REL`. A relocatable object is not a program.
    RelocatableElf,
    /// `ET_DYN`, `PT_DYNAMIC` or `PT_INTERP`. Dynamic linking would make the
    /// executed program a function of a runtime linker this VM does not have.
    DynamicElf { reason: &'static str },
    /// `e_machine` is not `EM_RISCV`.
    NotRiscV { machine: u16 },
    /// An `e_type` that is neither executable, relocatable nor dynamic.
    UnsupportedElfType { e_type: u16 },
    /// A `PT_LOAD` header that cannot describe this VM's memory: odd address,
    /// `filesz` above `memsz`, an overlap with another segment, or a span that
    /// leaves the frozen RAM window.
    BadSegment { vaddr: u32, reason: &'static str },
    /// No `PT_LOAD` segment is executable, so there is no instruction stream.
    NoExecutableSegment,
    /// `e_entry` is not the address of an instruction: odd, outside the image,
    /// inside a data segment, or in the middle of a 32-bit instruction.
    EntryNotAnInstruction { entry: u32 },
    /// A 16-bit halfword that no RV32C encoding claims. `reason` says which
    /// rule it broke; `pc` is where it is.
    RvcIllegal {
        pc: u32,
        encoding: u16,
        reason: &'static str,
    },
    /// An encoding longer than 32 bits (bits 4:2 of a 32-bit-looking word are
    /// all ones). RV32IMAC has no such instruction.
    InstructionTooLong { pc: u32, encoding: u16 },
    /// A 32-bit instruction whose second halfword lies past the end of its
    /// segment.
    TextTruncated { pc: u32 },
}

// ---------------------------------------------------------------------------
// The image
// ---------------------------------------------------------------------------

/// One loaded `PT_LOAD` segment.
///
/// `bytes` is the file-backed part and `mem_len` is the whole span; the
/// `mem_len - bytes.len()` bytes above it are zero, which is `.bss`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u32,
    pub mem_len: u32,
    pub bytes: Vec<u8>,
}

/// What lives at one halfword of the image.
///
/// `compressed` is not decoration: it is the instruction's **length**, and the
/// only thing that says whether the next pc is `pc + 2` or `pc + 4`. The
/// expanded 32-bit `word` alone cannot say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// An instruction starts here. `word` is the 32-bit encoding — the
    /// original for a 32-bit instruction, the expansion for a compressed one.
    Instruction { word: u32, compressed: bool },
    /// The second halfword of a 32-bit instruction.
    MidInstruction,
    /// Not code: a data segment, a `.bss` byte, a gap between segments, or a
    /// tail an instruction could not fit in.
    NonInstruction,
}

/// A loaded program: the post-load memory image, the entry pc, and the
/// expanded instruction stream at halfword granularity.
///
/// **Frozen at S10**, fields and serialization both. The wire form is
/// `postcard` over these four fields in declaration order — sorted vectors,
/// never a hash map — so two loads of the same ELF serialize to the same
/// bytes on any machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramImage {
    /// `e_entry`. Always the address of an [`Slot::Instruction`].
    pub entry: u32,
    /// The `PT_LOAD` segments, sorted by `vaddr` and pairwise disjoint.
    pub segments: Vec<Segment>,
    /// The pc of `slots[0]`. Even, and the lowest address in the image.
    pub slot_base: u32,
    /// One entry per halfword of `[slot_base, slot_base + 2 * slots.len())`,
    /// which runs from the lowest loaded address to the top of the highest
    /// executable segment. Above that, every slot would be
    /// [`Slot::NonInstruction`], so the vector stops and [`ProgramImage::slot_at`]
    /// answers `None`.
    pub slots: Vec<Slot>,
}

impl ProgramImage {
    /// The slot at `pc`, or `None` if `pc` is odd or outside the image.
    pub fn slot_at(&self, pc: u32) -> Option<Slot> {
        if !pc.is_multiple_of(2) || pc < self.slot_base {
            return None;
        }
        self.slots
            .get(((pc - self.slot_base) / 2) as usize)
            .copied()
    }
}

// ---------------------------------------------------------------------------
// ELF constants
// ---------------------------------------------------------------------------

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS32: u8 = 1;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;

const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

const EM_RISCV: u16 = 243;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

const PF_X: u32 = 1;

const EHDR_LEN: usize = 52;
const PHDR_LEN: usize = 32;

// ---------------------------------------------------------------------------
// load_elf
// ---------------------------------------------------------------------------

/// Load a static RV32 ELF executable.
///
/// The one entry point, and the only way a [`ProgramImage`] is built.
pub fn load_elf(bytes: &[u8]) -> Result<ProgramImage, LoaderError> {
    let (entry, phoff, phentsize, phnum) = parse_header(bytes)?;

    let mut loaded = read_segments(bytes, phoff, phentsize, phnum)?;
    if !loaded.iter().any(|(_, executable)| *executable) {
        return Err(LoaderError::NoExecutableSegment);
    }
    // `sort_by_key` is stable, so equal addresses keep file order — and two
    // segments at the same address are rejected by the overlap check anyway.
    loaded.sort_by_key(|(s, _)| s.vaddr);
    for pair in loaded.windows(2) {
        let end = pair[0].0.vaddr as u64 + pair[0].0.mem_len as u64;
        if end > pair[1].0.vaddr as u64 {
            return Err(LoaderError::BadSegment {
                vaddr: pair[1].0.vaddr,
                reason: "overlaps the segment below it",
            });
        }
    }

    // The slot vector runs from the lowest loaded address to the top of the
    // highest **executable** segment. It stops there because no pc above the
    // last executable byte can ever be an instruction, so a slot there would
    // always be `NonInstruction` and would say nothing — and `.bss`, which
    // this memory map always puts above the code, would otherwise cost four
    // bytes of table per byte of zeroes.
    let slot_base = loaded[0].0.vaddr;
    let code_end = loaded
        .iter()
        .filter(|(_, executable)| *executable)
        .map(|(s, _)| s.vaddr as u64 + s.mem_len as u64)
        .max()
        .expect("the executable-segment check above proves there is one");
    let slot_end = (code_end + 1) & !1;
    let mut slots = vec![Slot::NonInstruction; ((slot_end - slot_base as u64) / 2) as usize];

    for (segment, executable) in &loaded {
        if *executable {
            sweep(segment, slot_base, &mut slots)?;
        }
    }

    let image = ProgramImage {
        entry,
        segments: loaded.into_iter().map(|(s, _)| s).collect(),
        slot_base,
        slots,
    };

    // A program whose first instruction is not an instruction is a
    // preprocessing failure, not something to discover at cycle 0.
    match image.slot_at(entry) {
        Some(Slot::Instruction { .. }) => Ok(image),
        _ => Err(LoaderError::EntryNotAnInstruction { entry }),
    }
}

/// Read and validate the ELF header. Returns `(entry, phoff, phentsize, phnum)`.
fn parse_header(bytes: &[u8]) -> Result<(u32, usize, usize, usize), LoaderError> {
    if bytes.len() < EHDR_LEN {
        return Err(LoaderError::Truncated {
            what: "ELF header",
            need: EHDR_LEN,
            have: bytes.len(),
        });
    }
    if bytes[0..4] != ELF_MAGIC {
        return Err(LoaderError::NotAnElf {
            reason: "bad ELF magic",
        });
    }
    if bytes[4] != ELFCLASS32 {
        return Err(LoaderError::NotAnElf {
            reason: "not ELFCLASS32: this VM is 32-bit",
        });
    }
    if bytes[5] != ELFDATA2LSB {
        return Err(LoaderError::NotAnElf {
            reason: "not ELFDATA2LSB: RISC-V is little-endian here",
        });
    }
    if bytes[6] != EV_CURRENT {
        return Err(LoaderError::NotAnElf {
            reason: "e_ident version is not EV_CURRENT",
        });
    }

    let e_type = u16le(bytes, 16);
    match e_type {
        ET_EXEC => {}
        ET_REL => return Err(LoaderError::RelocatableElf),
        ET_DYN => {
            return Err(LoaderError::DynamicElf {
                reason: "e_type is ET_DYN: a shared object or PIE, not a static executable",
            })
        }
        other => return Err(LoaderError::UnsupportedElfType { e_type: other }),
    }

    let machine = u16le(bytes, 18);
    if machine != EM_RISCV {
        return Err(LoaderError::NotRiscV { machine });
    }
    if u32le(bytes, 20) != 1 {
        return Err(LoaderError::NotAnElf {
            reason: "e_version is not 1",
        });
    }

    let entry = u32le(bytes, 24);
    let phoff = u32le(bytes, 28) as usize;
    let phentsize = u16le(bytes, 42) as usize;
    let phnum = u16le(bytes, 44) as usize;

    if phentsize != PHDR_LEN {
        return Err(LoaderError::NotAnElf {
            reason: "e_phentsize is not 32: not a 32-bit program header table",
        });
    }
    if phnum == 0 {
        return Err(LoaderError::NotAnElf {
            reason: "e_phnum is 0: no program headers, so nothing to load",
        });
    }

    Ok((entry, phoff, phentsize, phnum))
}

/// The `PT_LOAD` headers, as `(segment, executable)` pairs in file order.
///
/// Validates each header and refuses dynamic linking; the caller sorts and
/// checks for overlap.
fn read_segments(
    bytes: &[u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
) -> Result<Vec<(Segment, bool)>, LoaderError> {
    let table_end = phoff
        .checked_add(phentsize * phnum)
        .ok_or(LoaderError::NotAnElf {
            reason: "program header table offset overflows",
        })?;
    if table_end > bytes.len() {
        return Err(LoaderError::Truncated {
            what: "program header table",
            need: table_end,
            have: bytes.len(),
        });
    }

    let mut out = Vec::new();
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        let p_type = u32le(bytes, p);
        match p_type {
            PT_DYNAMIC => {
                return Err(LoaderError::DynamicElf {
                    reason: "a PT_DYNAMIC segment: this program expects a dynamic linker",
                })
            }
            PT_INTERP => {
                return Err(LoaderError::DynamicElf {
                    reason: "a PT_INTERP segment: this program names an interpreter",
                })
            }
            PT_LOAD => {}
            // PT_PHDR, PT_NOTE, PT_GNU_STACK, PT_RISCV_ATTRIBUTES and friends
            // describe the file, not the memory image.
            _ => continue,
        }

        let p_offset = u32le(bytes, p + 4) as usize;
        let vaddr = u32le(bytes, p + 8);
        let filesz = u32le(bytes, p + 16);
        let memsz = u32le(bytes, p + 20);
        let flags = u32le(bytes, p + 24);

        if !vaddr.is_multiple_of(2) {
            return Err(LoaderError::BadSegment {
                vaddr,
                reason: "an odd segment address cannot hold an instruction stream",
            });
        }
        if filesz > memsz {
            return Err(LoaderError::BadSegment {
                vaddr,
                reason: "p_filesz above p_memsz",
            });
        }
        // The frozen memory map, enforced. Nothing outside it is addressable,
        // so a segment that leaves it is not something this VM can run — and
        // checking it here is also what stops a hostile `p_memsz` from sizing
        // the slot vector, which is a function of the image span.
        let ram_lo = guest_memory::RAM_ORIGIN as u64;
        let ram_hi = ram_lo + guest_memory::RAM_LENGTH as u64;
        if (vaddr as u64) < ram_lo || vaddr as u64 + memsz as u64 > ram_hi {
            return Err(LoaderError::BadSegment {
                vaddr,
                reason: "segment lies outside the guest RAM window",
            });
        }
        let file_end = p_offset
            .checked_add(filesz as usize)
            .ok_or(LoaderError::BadSegment {
                vaddr,
                reason: "p_offset + p_filesz overflows",
            })?;
        if file_end > bytes.len() {
            return Err(LoaderError::Truncated {
                what: "segment contents",
                need: file_end,
                have: bytes.len(),
            });
        }

        out.push((
            Segment {
                vaddr,
                mem_len: memsz,
                bytes: bytes[p_offset..file_end].to_vec(),
            },
            flags & PF_X != 0,
        ));
    }
    Ok(out)
}

/// Sweep one executable segment, filling its slots.
///
/// The sweep covers the **file-backed** bytes only. A byte above `p_filesz` is
/// zero at load, which is not an instruction, so it stays `NonInstruction`
/// rather than becoming a decode error.
fn sweep(segment: &Segment, slot_base: u32, slots: &mut [Slot]) -> Result<(), LoaderError> {
    let end = segment.vaddr as u64 + segment.bytes.len() as u64;
    let mut pc = segment.vaddr as u64;

    while pc + 2 <= end {
        let off = (pc - segment.vaddr as u64) as usize;
        let half = u16::from_le_bytes([segment.bytes[off], segment.bytes[off + 1]]);
        let index = ((pc - slot_base as u64) / 2) as usize;

        if half & 0b11 == 0b11 {
            // Bits 4:2 all ones means 48-bit or longer. RV32IMAC has none.
            if half & 0b1_1100 == 0b1_1100 {
                return Err(LoaderError::InstructionTooLong {
                    pc: pc as u32,
                    encoding: half,
                });
            }
            if pc + 4 > end {
                return Err(LoaderError::TextTruncated { pc: pc as u32 });
            }
            let word = u32::from_le_bytes([
                segment.bytes[off],
                segment.bytes[off + 1],
                segment.bytes[off + 2],
                segment.bytes[off + 3],
            ]);
            slots[index] = Slot::Instruction {
                word,
                compressed: false,
            };
            slots[index + 1] = Slot::MidInstruction;
            pc += 4;
        } else {
            let word = rvc::expand(half).map_err(|reason| LoaderError::RvcIllegal {
                pc: pc as u32,
                encoding: half,
                reason,
            })?;
            slots[index] = Slot::Instruction {
                word,
                compressed: true,
            };
            pc += 2;
        }
    }
    Ok(())
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

// ---------------------------------------------------------------------------
// Serialization.
//
// Hand-written, like every other serde impl in this workspace, so no derive
// macro enters the build. Each type is its fields in declaration order, which
// `postcard` writes as a bare concatenation.
//
// The workspace takes `serde` with no features at all, which is what S01 chose
// so that the shipped configuration is the one the tests exercise. That means
// no `Vec` impls, so the three sequences below carry their own visitors. It is
// more lines than a feature flag would be, and it is the reason the feature
// graph is still the one S01 froze.
// ---------------------------------------------------------------------------

use core::fmt;
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::ser::SerializeTuple;

const SLOT_KIND_INSTRUCTION_32: u8 = 0;
const SLOT_KIND_INSTRUCTION_16: u8 = 1;
const SLOT_KIND_MID: u8 = 2;
const SLOT_KIND_NON: u8 = 3;

impl serde::Serialize for Slot {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // A `(kind, word)` pair rather than a serde enum: a pair of primitives
        // has one obvious encoding in every format and needs no visitor.
        let (kind, word) = match self {
            Slot::Instruction {
                word,
                compressed: false,
            } => (SLOT_KIND_INSTRUCTION_32, *word),
            Slot::Instruction {
                word,
                compressed: true,
            } => (SLOT_KIND_INSTRUCTION_16, *word),
            Slot::MidInstruction => (SLOT_KIND_MID, 0),
            Slot::NonInstruction => (SLOT_KIND_NON, 0),
        };
        let mut t = s.serialize_tuple(2)?;
        t.serialize_element(&kind)?;
        t.serialize_element(&word)?;
        t.end()
    }
}

impl<'de> serde::Deserialize<'de> for Slot {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Slot, D::Error> {
        let (kind, word) = <(u8, u32) as serde::Deserialize>::deserialize(d)?;
        match (kind, word) {
            (SLOT_KIND_INSTRUCTION_32, _) => Ok(Slot::Instruction {
                word,
                compressed: false,
            }),
            (SLOT_KIND_INSTRUCTION_16, _) => Ok(Slot::Instruction {
                word,
                compressed: true,
            }),
            // A non-instruction slot carries no word, so a nonzero one is a
            // form `serialize` could not have produced.
            (SLOT_KIND_MID, 0) => Ok(Slot::MidInstruction),
            (SLOT_KIND_NON, 0) => Ok(Slot::NonInstruction),
            _ => Err(D::Error::custom(
                "malformed program image slot: unknown kind, or a word on a non-instruction",
            )),
        }
    }
}

/// A `&[u8]` written as a byte string rather than a sequence of `u8`.
struct Bytes<'a>(&'a [u8]);

impl serde::Serialize for Bytes<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a segment's file-backed bytes")
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }

    fn visit_borrowed_bytes<E: serde::de::Error>(self, v: &'de [u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(b) = seq.next_element::<u8>()? {
            out.push(b);
        }
        Ok(out)
    }
}

impl serde::Serialize for Segment {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut t = s.serialize_tuple(3)?;
        t.serialize_element(&self.vaddr)?;
        t.serialize_element(&self.mem_len)?;
        t.serialize_element(&Bytes(&self.bytes))?;
        t.end()
    }
}

struct SegmentVisitor;

impl<'de> Visitor<'de> for SegmentVisitor {
    type Value = Segment;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a loaded segment")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Segment, A::Error> {
        let vaddr = next(&mut seq, "vaddr")?;
        let mem_len = next(&mut seq, "mem_len")?;
        let bytes = seq
            .next_element_seed(BytesSeed)?
            .ok_or_else(|| A::Error::custom("malformed segment: missing bytes"))?;
        if bytes.len() as u64 > mem_len as u64 {
            return Err(A::Error::custom(
                "malformed segment: more file bytes than memory length",
            ));
        }
        Ok(Segment {
            vaddr,
            mem_len,
            bytes,
        })
    }
}

/// Reads the byte string through [`BytesVisitor`] inside a sequence.
struct BytesSeed;

impl<'de> serde::de::DeserializeSeed<'de> for BytesSeed {
    type Value = Vec<u8>;

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Vec<u8>, D::Error> {
        d.deserialize_bytes(BytesVisitor)
    }
}

impl<'de> serde::Deserialize<'de> for Segment {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Segment, D::Error> {
        d.deserialize_tuple(3, SegmentVisitor)
    }
}

/// A `&[Segment]` written as a sequence.
struct Segments<'a>(&'a [Segment]);

impl serde::Serialize for Segments<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.0.iter())
    }
}

/// A `&[Slot]` written as a sequence.
struct Slots<'a>(&'a [Slot]);

impl serde::Serialize for Slots<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.0.iter())
    }
}

struct SegmentsVisitor;

impl<'de> Visitor<'de> for SegmentsVisitor {
    type Value = Vec<Segment>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("the loaded segments")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<Segment>, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(x) = seq.next_element::<Segment>()? {
            out.push(x);
        }
        Ok(out)
    }
}

struct SlotsVisitor;

impl<'de> Visitor<'de> for SlotsVisitor {
    type Value = Vec<Slot>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("the instruction slots")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<Slot>, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(x) = seq.next_element::<Slot>()? {
            out.push(x);
        }
        Ok(out)
    }
}

/// Reads the sequences through their visitors inside the image's tuple.
struct SegmentsSeed;

impl<'de> serde::de::DeserializeSeed<'de> for SegmentsSeed {
    type Value = Vec<Segment>;

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Vec<Segment>, D::Error> {
        d.deserialize_seq(SegmentsVisitor)
    }
}

struct SlotsSeed;

impl<'de> serde::de::DeserializeSeed<'de> for SlotsSeed {
    type Value = Vec<Slot>;

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Vec<Slot>, D::Error> {
        d.deserialize_seq(SlotsVisitor)
    }
}

impl serde::Serialize for ProgramImage {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut t = s.serialize_tuple(4)?;
        t.serialize_element(&self.entry)?;
        t.serialize_element(&Segments(&self.segments))?;
        t.serialize_element(&self.slot_base)?;
        t.serialize_element(&Slots(&self.slots))?;
        t.end()
    }
}

struct ProgramImageVisitor;

impl<'de> Visitor<'de> for ProgramImageVisitor {
    type Value = ProgramImage;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a program image")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ProgramImage, A::Error> {
        let entry = next(&mut seq, "entry")?;
        let segments = seq
            .next_element_seed(SegmentsSeed)?
            .ok_or_else(|| A::Error::custom("malformed program image: missing segments"))?;
        let slot_base = next(&mut seq, "slot_base")?;
        let slots = seq
            .next_element_seed(SlotsSeed)?
            .ok_or_else(|| A::Error::custom("malformed program image: missing slots"))?;
        let image = ProgramImage {
            entry,
            segments,
            slot_base,
            slots,
        };
        validate(&image).map_err(A::Error::custom)?;
        Ok(image)
    }
}

impl<'de> serde::Deserialize<'de> for ProgramImage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<ProgramImage, D::Error> {
        d.deserialize_tuple(4, ProgramImageVisitor)
    }
}

/// Every invariant [`ProgramImage`]'s doc comments declare, re-checked.
///
/// `load_elf` establishes all of these by construction, so this exists for the
/// deserialization path: a wire form is untrusted input, and `ProgramImage` is
/// frozen here as the thing S11 derives program identity from and S12 executes.
/// A field the reader accepts is a field a later stage will believe.
fn validate(image: &ProgramImage) -> Result<(), &'static str> {
    if !image.slot_base.is_multiple_of(2) {
        return Err("malformed program image: slot_base is odd");
    }
    if image.segments.is_empty() {
        return Err("malformed program image: no segments");
    }

    let ram_lo = guest_memory::RAM_ORIGIN as u64;
    let ram_hi = ram_lo + guest_memory::RAM_LENGTH as u64;
    for (i, segment) in image.segments.iter().enumerate() {
        if !segment.vaddr.is_multiple_of(2) {
            return Err("malformed program image: a segment address is odd");
        }
        if segment.bytes.len() as u64 > segment.mem_len as u64 {
            return Err("malformed program image: a segment has more file bytes than memory");
        }
        if (segment.vaddr as u64) < ram_lo || segment.vaddr as u64 + segment.mem_len as u64 > ram_hi
        {
            return Err("malformed program image: a segment leaves the guest RAM window");
        }
        if i > 0 {
            let below = &image.segments[i - 1];
            if below.vaddr as u64 + below.mem_len as u64 > segment.vaddr as u64 {
                return Err("malformed program image: segments are unsorted or overlap");
            }
        }
    }

    if image.slot_base != image.segments[0].vaddr {
        return Err("malformed program image: slot_base is not the lowest loaded address");
    }
    let top = image.slot_base as u64 + 2 * image.slots.len() as u64;
    if top > ram_hi {
        return Err("malformed program image: the slot vector leaves the guest RAM window");
    }

    // A 32-bit instruction and its second halfword come as a pair, in that
    // order, and neither appears without the other.
    let is_wide = |i: usize| {
        matches!(
            image.slots.get(i),
            Some(Slot::Instruction {
                compressed: false,
                ..
            })
        )
    };
    for (i, slot) in image.slots.iter().enumerate() {
        match slot {
            Slot::Instruction {
                compressed: false, ..
            } if image.slots.get(i + 1) != Some(&Slot::MidInstruction) => {
                return Err("malformed program image: a 32-bit instruction with no second halfword")
            }
            Slot::MidInstruction if i == 0 || !is_wide(i - 1) => {
                return Err("malformed program image: a mid-instruction slot follows nothing")
            }
            _ => {}
        }
    }

    match image.slot_at(image.entry) {
        Some(Slot::Instruction { .. }) => Ok(()),
        _ => Err("malformed program image: the entry is not the address of an instruction"),
    }
}

/// One `u32` out of a sequence, with the field name in the error.
fn next<'de, A: SeqAccess<'de>>(seq: &mut A, field: &'static str) -> Result<u32, A::Error> {
    seq.next_element::<u32>()?
        .ok_or_else(|| A::Error::custom(format!("malformed program image: missing {field}")))
}
