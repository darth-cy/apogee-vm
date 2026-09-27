//! The ELF **symbol table**, read beside the image and never into it.
//!
//! A [`crate::ProgramImage`] is the post-load memory, the entry pc and the
//! instruction stream, and program identity is a commitment over exactly that
//! (`docs/spec/memory.md` §6.2). A symbol table is what a linker wrote for a
//! debugger: it is not part of the image, it is not committed, and nothing here
//! can change what a proof is about. What it is for is reading — a listing of
//! four thousand hex words with no names in it is a listing nobody can
//! navigate — and, since S26, **attributing cycles**: `tools/profiler` turns a
//! pc into the function that owns it, which is the whole basis of a cycle
//! profile (`docs/spec/profiling.md` §2).
//!
//! Nothing here can fail. A file with no symbol table, or with one this cannot
//! parse, yields an empty result: `load_elf` has already validated everything
//! the artifact is made of, and a missing symbol table is a report with no names
//! rather than an error.

use std::collections::{BTreeMap, BTreeSet};

const SHT_SYMTAB: u32 = 2;
const SHDR_LEN: usize = 40;
const SYM_LEN: usize = 16;

/// `st_info & 0xf`: the symbol's type. `STT_FUNC` is code.
const STT_FUNC: u8 = 2;

/// The first reserved section index. `st_shndx` at or above it is not a
/// section: `SHN_ABS` and `SHN_COMMON` live there, and neither is an address
/// in the image.
const SHN_LORESERVE: u16 = 0xff00;

/// One defined **function** symbol: the half-open address range it owns, and
/// its name exactly as the symbol table spells it — mangled, because demangling
/// is a reader's concern and this is the linker's answer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FuncSymbol {
    pub addr: u32,
    pub size: u32,
    pub name: String,
}

impl FuncSymbol {
    /// Whether `pc` lies in this function's body.
    pub fn holds(&self, pc: u32) -> bool {
        pc >= self.addr && pc - self.addr < self.size
    }
}

/// Every defined `STT_FUNC` symbol with a nonzero size, ascending by address
/// and then by name.
///
/// A zero-size entry owns no instruction and would make an interval nothing
/// falls in; an undefined one (`st_shndx == 0`) is an import, which a statically
/// linked guest has none of. Two symbols can share an address and a size — an
/// alias, and `guests/revm-block` has 28 groups of them — so the result is a
/// list rather than a map and a caller that wants one name per address picks by
/// its own rule.
pub fn function_symbols(elf: &[u8]) -> Vec<FuncSymbol> {
    let mut out = Vec::new();
    for_each_symbol(elf, |name, value, size, info, _shndx| {
        if info & 0xf != STT_FUNC || size == 0 {
            return;
        }
        out.push(FuncSymbol {
            addr: value,
            size,
            name: name.to_string(),
        });
    });
    out.sort();
    out
}

/// Every defined symbol, by address, with the names that share it.
///
/// A `BTreeSet` of names rather than one name: `_start` and the compiler's
/// `.Lpcrel_hi0` sit on the same address in every guest here, and picking one
/// arbitrarily would make a report depend on symbol table order. Assembler-local
/// labels (`.L*`) and mapping symbols (`$x`, `$d`) are dropped — compiler
/// bookkeeping, not names a reader is looking for.
pub fn symbol_names(elf: &[u8]) -> BTreeMap<u32, BTreeSet<String>> {
    let mut out: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for_each_symbol(elf, |name, value, _size, _info, _shndx| {
        if name.starts_with(".L") || name.starts_with('$') {
            return;
        }
        out.entry(value).or_default().insert(name.to_string());
    });
    out
}

/// Walk every defined, named symbol of every `SHT_SYMTAB` section.
fn for_each_symbol(elf: &[u8], mut each: impl FnMut(&str, u32, u32, u8, u16)) {
    let Some(sections) = section_headers(elf) else {
        return;
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
            let size = u32le(entry, 8);
            let info = entry[12];
            let shndx = u16le(entry, 14);
            if shndx == 0 || shndx >= SHN_LORESERVE {
                continue;
            }
            let Some(name) = string_at(names, name_at) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            each(name, value, size, info, shndx);
        }
    }
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
