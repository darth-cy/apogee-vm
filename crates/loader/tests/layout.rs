//! The guest image, as a host program loader sees it.
//!
//! `crates/loader` reads an ELF the way the zkVM will: it takes `p_vaddr` and
//! `p_memsz` and lays the bytes into a flat RAM window where every address is
//! addressable by construction. A host loader -- `qemu-riscv32`, or Linux
//! itself -- does something narrower. It `mmap`s exactly the segments the
//! program headers declare, page by page, with exactly the permissions each
//! declares, and nothing else in the address space exists at all.
//!
//! That difference is invisible to every other suite here, and it is a real
//! difference: an image can load perfectly under the zkVM's rules and be
//! unrunnable, or unloadable, under a host's. It happened. The layout S10 first
//! shipped put `__stack_top` at the top of the RAM window with no segment
//! declaring it, so the guest's first stack write hit unmapped memory and died
//! on a signal before `main` ran; and it let `.bss` share a page with
//! `.rodata`, which `qemu-riscv32` refuses outright rather than mapping a
//! read-only page writable. [`the_layout_that_failed_in_ci_is_rejected`] pins
//! both.
//!
//! These tests read the committed ELFs and parse the headers here rather than
//! through `loader`, for two reasons: `ProgramImage` deliberately drops the
//! flags, the file offsets and the alignments these rules are about, and a
//! check that went through the crate under test would be a second reading of
//! the same parser rather than an independent one.
//!
//! Nothing here needs a compiler or an emulator, so it runs everywhere.
//! [`a_freshly_linked_guest_has_the_same_layout`] is the exception and is
//! `#[ignore]`d: it invokes the cross-compiler, which not every machine has.

mod common;

use std::collections::BTreeMap;

use constants::guest_memory::{RAM_LENGTH, RAM_ORIGIN};

/// The page size a host loader maps at. RISC-V's is 4 KiB, and it is also the
/// `max-page-size` lld defaults to for the target, so the linker script and the
/// loader agree on it.
const PAGE: u64 = 4096;

/// The end of the RAM window, exclusive. Also the initial `sp`.
const RAM_END: u64 = RAM_ORIGIN as u64 + RAM_LENGTH as u64;

// ---------------------------------------------------------------------------
// The rules
// ---------------------------------------------------------------------------

/// One `PT_LOAD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Load {
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    flags: u32,
}

impl Load {
    const X: u32 = 0x1;
    const W: u32 = 0x2;

    fn writable(self) -> bool {
        self.flags & Self::W != 0
    }

    fn executable(self) -> bool {
        self.flags & Self::X != 0
    }

    /// Does this segment make `addr` exist?
    fn covers(self, addr: u64) -> bool {
        addr >= self.vaddr && addr < self.vaddr + self.memsz
    }

    /// The half-open range of pages this segment's mapping touches.
    fn pages(self) -> (u64, u64) {
        (
            self.vaddr / PAGE,
            (self.vaddr + self.memsz)
                .div_ceil(PAGE)
                .max(self.vaddr / PAGE + 1),
        )
    }

    fn describe(self) -> String {
        format!(
            "[{:#x}..{:#x}) filesz {:#x} flags {:#x}",
            self.vaddr,
            self.vaddr + self.memsz,
            self.filesz,
            self.flags
        )
    }
}

/// Every mapping must start on a page, and `p_offset` must agree with `p_vaddr`
/// modulo the page size.
///
/// A host loader maps from `page_down(p_vaddr)` at file offset
/// `page_down(p_offset)`. If the two are not congruent it cannot place the
/// bytes at all.
fn page_alignment(loads: &[Load]) -> Result<(), String> {
    for l in loads {
        if l.vaddr % PAGE != 0 {
            return Err(format!("{} does not start on a page", l.describe()));
        }
        if l.offset % PAGE != l.vaddr % PAGE {
            return Err(format!(
                "{}: p_offset {:#x} and p_vaddr {:#x} disagree modulo {PAGE:#x}",
                l.describe(),
                l.offset,
                l.vaddr
            ));
        }
    }
    Ok(())
}

/// No two mappings may touch the same page.
///
/// Each `PT_LOAD` is mapped independently, so a shared page takes the second
/// mapping's permissions for the whole page. `.rodata` sharing a page with
/// `.text` silently strips execute from the tail of the code.
fn page_separation(loads: &[Load]) -> Result<(), String> {
    for (i, a) in loads.iter().enumerate() {
        for b in &loads[i + 1..] {
            let ((a_lo, a_hi), (b_lo, b_hi)) = (a.pages(), b.pages());
            if a_lo < b_hi && b_lo < a_hi {
                return Err(format!(
                    "{} and {} share a page; the second mapping's permissions \
                     would win for the whole page",
                    a.describe(),
                    b.describe()
                ));
            }
        }
    }
    Ok(())
}

/// Zero fill -- the `p_memsz - p_filesz` tail -- only ever lands on a writable
/// mapping.
///
/// This is the rule `qemu-riscv32` reports as "PT_LOAD with bss overlapping
/// non-writable page", and it refuses to run the image at all.
fn zero_fill_is_writable(loads: &[Load]) -> Result<(), String> {
    for l in loads {
        if l.memsz > l.filesz && !l.writable() {
            return Err(format!(
                "{} has {:#x} bytes of zero fill but is not writable",
                l.describe(),
                l.memsz - l.filesz
            ));
        }
    }
    Ok(())
}

/// `addr` is mapped, and mapped writable.
fn writable_at(loads: &[Load], addr: u64, what: &str) -> Result<(), String> {
    match loads.iter().find(|l| l.covers(addr)) {
        None => Err(format!(
            "{what} is {addr:#x}, which no PT_LOAD declares -- a host loader \
             leaves it unmapped and the first access faults"
        )),
        Some(l) if !l.writable() => Err(format!(
            "{what} is {addr:#x}, in the read-only {}",
            l.describe()
        )),
        Some(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// The guests
// ---------------------------------------------------------------------------

const GUESTS: [&str; 3] = ["fib", "echo", "rvc-dense"];

/// Every rule above, over one image. The single place the rules are composed,
/// so the committed fixtures and a fresh link are held to exactly one standard.
fn check(elf: &[u8], name: &str) {
    let loads = loads(elf);
    assert!(!loads.is_empty(), "{name} declares no PT_LOAD");

    page_alignment(&loads).unwrap_or_else(|e| panic!("{name}: {e}"));
    page_separation(&loads).unwrap_or_else(|e| panic!("{name}: {e}"));
    zero_fill_is_writable(&loads).unwrap_or_else(|e| panic!("{name}: {e}"));

    let syms = symbols(elf);
    let sym = |k: &str| {
        *syms
            .get(k)
            .unwrap_or_else(|| panic!("{name} has no {k} -- link.ld freezes the name"))
            as u64
    };

    // The stack. `sp` starts at __stack_top and grows down, so the top usable
    // byte is one below it; __stack_top itself is one past the window.
    let stack_top = sym("__stack_top");
    assert_eq!(
        stack_top, RAM_END,
        "{name}: __stack_top must be the top of the RAM window"
    );
    writable_at(&loads, stack_top - 1, "the first stack byte")
        .unwrap_or_else(|e| panic!("{name}: {e}"));

    // The heap. The bump allocator hands out memory from here upward.
    let heap = sym("__heap_start");
    writable_at(&loads, heap, "__heap_start").unwrap_or_else(|e| panic!("{name}: {e}"));

    // .bss, which crt0 zeroes before main runs.
    let (bss_start, bss_end) = (sym("__bss_start"), sym("__bss_end"));
    assert!(
        bss_start <= bss_end && bss_end <= heap,
        "{name}: __bss_start {bss_start:#x} .. __bss_end {bss_end:#x} must precede \
         __heap_start {heap:#x}"
    );
    if bss_end > bss_start {
        writable_at(&loads, bss_start, "__bss_start").unwrap_or_else(|e| panic!("{name}: {e}"));
        writable_at(&loads, bss_end - 1, "the last .bss byte")
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }

    // The entry point, which must be both mapped and executable.
    let entry = u32_at(elf, 0x18) as u64;
    assert_eq!(
        entry, RAM_ORIGIN as u64,
        "{name}: _start must be at the base of RAM"
    );
    assert_eq!(entry, sym("_start"), "{name}: e_entry is not _start");
    assert!(
        loads.iter().any(|l| l.covers(entry) && l.executable()),
        "{name}: the entry point {entry:#x} is not in an executable segment"
    );

    // Nothing may sit outside the window the zkVM will allocate.
    for l in &loads {
        assert!(
            l.vaddr >= RAM_ORIGIN as u64 && l.vaddr + l.memsz <= RAM_END,
            "{name}: {} escapes the RAM window [{RAM_ORIGIN:#x}..{RAM_END:#x})",
            l.describe()
        );
    }
}

/// Every committed guest is loadable by a host program loader.
///
/// This is the test that fails when the linker script regresses, and it needs
/// neither a cross-compiler nor an emulator to say so.
#[test]
fn every_committed_guest_is_host_loadable() {
    for name in GUESTS {
        check(&common::bytes(&format!("{name}.elf")), name);
    }
}

/// The writable segment really does reach the stack -- it is not merely present.
///
/// Stated separately from [`check`] because it is the specific claim that the
/// heap and the stack are one contiguous writable region growing toward each
/// other, which is what the memory map in `docs/spec/ecall-abi.md` section 7
/// promises and what the bump allocator assumes.
#[test]
fn the_heap_and_the_stack_share_one_writable_segment() {
    for name in GUESTS {
        let elf = common::bytes(&format!("{name}.elf"));
        let loads = loads(&elf);
        let heap = *symbols(&elf).get("__heap_start").expect("__heap_start") as u64;

        let holding = loads
            .iter()
            .find(|l| l.covers(heap))
            .unwrap_or_else(|| panic!("{name}: nothing maps __heap_start"));
        assert!(holding.writable(), "{name}: the heap segment is read-only");
        assert_eq!(
            holding.vaddr + holding.memsz,
            RAM_END,
            "{name}: the writable segment stops at {:#x}, short of the top of RAM -- \
             the bump allocator would run off the end of it",
            holding.vaddr + holding.memsz
        );
        assert_eq!(
            holding.filesz, 0,
            "{name}: the heap and stack reservation must be NOBITS, or the ELF \
             carries {:#x} bytes of zeroes on disk",
            holding.filesz
        );
    }
}

/// The exact layout that failed in CI, rejected.
///
/// A negative control, and a regression pin: these are the real program headers
/// of the ELFs that `qemu-riscv32` killed, transcribed. Without the assertions
/// in this file a change that reintroduced either would go out green.
#[test]
fn the_layout_that_failed_in_ci_is_rejected() {
    // fib, as first shipped: .text and .rodata, and nothing writable at all.
    // __stack_top was 0x10000000 and __heap_start 0x12410; neither existed.
    let fib_as_shipped = [
        Load {
            offset: 0x1000,
            vaddr: 0x10000,
            filesz: 5950,
            memsz: 5950,
            flags: 0x5,
        },
        Load {
            offset: 0x2740,
            vaddr: 0x11740,
            filesz: 3276,
            memsz: 3276,
            flags: 0x4,
        },
    ];
    assert!(
        writable_at(&fib_as_shipped, RAM_END - 1, "the first stack byte").is_err(),
        "an unmapped stack must be caught: this is the SIGSEGV three guests died on"
    );
    assert!(
        writable_at(&fib_as_shipped, 0x12410, "__heap_start").is_err(),
        "an unmapped heap must be caught"
    );
    // ... and its .text and .rodata shared page 0x11.
    assert!(
        page_separation(&fib_as_shipped).is_err(),
        "two segments on one page must be caught: the second mapping would strip \
         execute from the tail of .text"
    );

    // echo, as first shipped: a 4-byte .bss whose page was already mapped
    // read-only by .rodata. qemu-riscv32 reported this one out loud, as
    // "PT_LOAD with bss overlapping non-writable page".
    let echo_as_shipped = [
        Load {
            offset: 0x1000,
            vaddr: 0x10000,
            filesz: 26650,
            memsz: 26650,
            flags: 0x5,
        },
        Load {
            offset: 0x7820,
            vaddr: 0x16820,
            filesz: 18568,
            memsz: 18568,
            flags: 0x4,
        },
        Load {
            offset: 0xC0A8,
            vaddr: 0x1B0A8,
            filesz: 0,
            memsz: 4,
            flags: 0x6,
        },
    ];
    assert!(
        page_separation(&echo_as_shipped).is_err(),
        "zero fill sharing a page with read-only data must be caught"
    );
    assert!(
        page_alignment(&echo_as_shipped).is_err(),
        "an unaligned segment must be caught"
    );

    // And the rule stated on its own: zero fill in a non-writable segment.
    let bss_in_a_read_only_segment = [Load {
        offset: 0x1000,
        vaddr: 0x10000,
        filesz: 16,
        memsz: 4096,
        flags: 0x4,
    }];
    assert!(
        zero_fill_is_writable(&bss_in_a_read_only_segment).is_err(),
        "zero fill must imply a writable mapping"
    );

    // The controls are controls: the shipping layout passes every one of them.
    for name in GUESTS {
        let loads = loads(&common::bytes(&format!("{name}.elf")));
        page_alignment(&loads).unwrap_or_else(|e| panic!("{name} must pass: {e}"));
        page_separation(&loads).unwrap_or_else(|e| panic!("{name} must pass: {e}"));
        zero_fill_is_writable(&loads).unwrap_or_else(|e| panic!("{name} must pass: {e}"));
        writable_at(&loads, RAM_END - 1, "the first stack byte")
            .unwrap_or_else(|e| panic!("{name} must pass: {e}"));
    }
}

/// The same rules, over a guest linked right now.
///
/// The committed ELFs are refreshed by hand, so on their own they would go on
/// passing after `link.ld` regressed and until someone remembered to rebuild.
/// This closes that window. It is `#[ignore]`d because it shells out to the
/// cross-compiler: it needs the `riscv32imac-unknown-none-elf` target installed
/// and a cargo that can run offline, which is a property of the machine rather
/// than of the repository.
///
/// ```text
/// cargo test -p loader --test layout -- --ignored
/// ```
#[test]
#[ignore = "invokes the cross-compiler; run with --ignored after editing link.ld"]
fn a_freshly_linked_guest_has_the_same_layout() {
    for name in GUESTS {
        check(&common::build(name, "layout"), name);
    }
}

// ---------------------------------------------------------------------------
// A small ELF32 reader
// ---------------------------------------------------------------------------
//
// Deliberately not `loader`'s: `ProgramImage` drops the flags, offsets and
// alignments every rule above is about, and routing the check through the crate
// under test would make it a second reading of one parser rather than a witness
// against it.

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().expect("in range"))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("in range"))
}

/// Every `PT_LOAD` with a nonzero span, in header order.
fn loads(elf: &[u8]) -> Vec<Load> {
    assert_eq!(&elf[..4], b"\x7fELF", "not an ELF");
    assert_eq!(elf[4], 1, "not ELF32");
    assert_eq!(elf[5], 1, "not little-endian");

    let (phoff, phentsize, phnum) = (
        u32_at(elf, 0x1C) as usize,
        u16_at(elf, 0x2A) as usize,
        u16_at(elf, 0x2C) as usize,
    );
    (0..phnum)
        .map(|i| phoff + i * phentsize)
        .filter(|&at| u32_at(elf, at) == 1) // PT_LOAD
        .map(|at| Load {
            offset: u32_at(elf, at + 4) as u64,
            vaddr: u32_at(elf, at + 8) as u64,
            filesz: u32_at(elf, at + 16) as u64,
            memsz: u32_at(elf, at + 20) as u64,
            flags: u32_at(elf, at + 24),
        })
        .filter(|l| l.memsz > 0)
        .collect()
}

/// `.symtab`, as name -> value.
fn symbols(elf: &[u8]) -> BTreeMap<String, u32> {
    let (shoff, shentsize, shnum) = (
        u32_at(elf, 0x20) as usize,
        u16_at(elf, 0x2E) as usize,
        u16_at(elf, 0x30) as usize,
    );
    let header = |i: usize| shoff + i * shentsize;

    let symtab = (0..shnum)
        .map(header)
        .find(|&at| u32_at(elf, at + 4) == 2) // SHT_SYMTAB
        .expect("the guest ELF is not stripped, so it has a .symtab");
    let (off, size, entsize) = (
        u32_at(elf, symtab + 16) as usize,
        u32_at(elf, symtab + 20) as usize,
        u32_at(elf, symtab + 36) as usize,
    );
    let strtab = u32_at(elf, header(u32_at(elf, symtab + 24) as usize) + 16) as usize;

    let mut out = BTreeMap::new();
    for at in (off..off + size).step_by(entsize) {
        let name_at = strtab + u32_at(elf, at) as usize;
        let end = elf[name_at..]
            .iter()
            .position(|&c| c == 0)
            .expect("a strtab entry is NUL-terminated")
            + name_at;
        if end > name_at {
            let name = String::from_utf8_lossy(&elf[name_at..end]).into_owned();
            out.insert(name, u32_at(elf, at + 4));
        }
    }
    out
}
