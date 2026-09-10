//! The ELF symbol table, read for annotation only.
//!
//! Symbols are **not** part of a [`loader::ProgramImage`]: the image is the
//! post-load memory, the entry pc and the instruction stream, and nothing a
//! linker wrote for a debugger. They are read here because a listing of four
//! thousand hex words with no names in it is a listing nobody can navigate,
//! and every line that carries one says where it came from.
//!
//! Nothing here can fail the dump. A file with no symbol table, or with one
//! this cannot parse, yields an empty map and a report with no symbol column —
//! `crates/loader` has already validated everything the artifact is made of.

use std::collections::{BTreeMap, BTreeSet};

const SHT_SYMTAB: u32 = 2;
const SHDR_LEN: usize = 40;
const SYM_LEN: usize = 16;

/// The first reserved section index. `st_shndx` at or above it is not a
/// section: `SHN_ABS` and `SHN_COMMON` live there, and neither is an address
/// in the image.
const SHN_LORESERVE: u16 = 0xff00;

/// Every defined symbol, by address, with the names that share it.
///
/// A `BTreeSet` of names rather than one name: `_start` and the compiler's
/// `.Lpcrel_hi0` sit on the same address in every guest here, and picking one
/// arbitrarily would make the report depend on symbol table order.
pub fn read(elf: &[u8]) -> BTreeMap<u32, BTreeSet<String>> {
    let mut out: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();

    let Some(sections) = section_headers(elf) else {
        return out;
    };
    for header in &sections {
        if header.kind != SHT_SYMTAB {
            continue;
        }
        // sh_link on a symbol table is the string table it names into.
        let Some(strings) = sections.get(header.link as usize) else {
            continue;
        };
        let Some(table) = slice(elf, header.offset, header.size) else {
            continue;
        };
        let Some(names) = slice(elf, strings.offset, strings.size) else {
            continue;
        };

        for entry in table.chunks_exact(SYM_LEN) {
            let name_at = u32le(entry, 0) as usize;
            let value = u32le(entry, 4);
            let shndx = u16le(entry, 14);
            if shndx == 0 || shndx >= SHN_LORESERVE {
                continue;
            }
            let Some(name) = string_at(names, name_at) else {
                continue;
            };
            // `.L*` are assembler-local labels and `$x`/`$d` are mapping
            // symbols: compiler bookkeeping, not names a reader is looking for.
            if name.is_empty() || name.starts_with(".L") || name.starts_with('$') {
                continue;
            }
            out.entry(value).or_default().insert(name.to_string());
        }
    }
    out
}

struct SectionHeader {
    kind: u32,
    offset: usize,
    size: usize,
    link: u32,
}

fn section_headers(elf: &[u8]) -> Option<Vec<SectionHeader>> {
    // The ELF header this reads has already been validated by `load_elf`;
    // these offsets are the class-32 little-endian ones it checked for.
    if elf.len() < 52 {
        return None;
    }
    let shoff = u32le(elf, 0x20) as usize;
    let shentsize = u16le(elf, 0x2e) as usize;
    let shnum = u16le(elf, 0x30) as usize;
    if shoff == 0 || shentsize < SHDR_LEN {
        return None;
    }

    let mut out = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let at = shoff.checked_add(i.checked_mul(shentsize)?)?;
        let header = slice(elf, at, SHDR_LEN)?;
        out.push(SectionHeader {
            kind: u32le(header, 4),
            offset: u32le(header, 16) as usize,
            size: u32le(header, 20) as usize,
            link: u32le(header, 24),
        });
    }
    Some(out)
}

fn slice(bytes: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    bytes.get(at..at.checked_add(len)?)
}

fn string_at(strings: &[u8], at: usize) -> Option<&str> {
    let rest = strings.get(at..)?;
    let end = rest.iter().position(|b| *b == 0)?;
    std::str::from_utf8(&rest[..end]).ok()
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
