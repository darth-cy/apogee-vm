//! **The cycle profiler**: where a guest's RV32 cycles go, by function and by
//! semantic workload. `docs/spec/profiling.md` is the design.
//!
//! It invokes nothing proving-related. Three inputs — a guest ELF, the bytes it
//! runs on, and the ELF's own symbol table — and arithmetic. No SRS, no key, no
//! circuit, no commitment.
//!
//! # How it collects
//!
//! One histogram over pc, one entry per halfword slot of the image, incremented
//! once per executed cycle. Everything else is derived from it:
//!
//! - a **function's** cycles are the sum over its `[st_value, st_value + st_size)`
//!   range, and its **calls** are the count at its first instruction — a
//!   function's entry executes exactly once per call;
//! - a **mnemonic's** cycles are the sum over the slots holding it;
//! - a **category's** are the sum over its functions'.
//!
//! The executor is `emulator::StreamingRun`, so the profiler's memory is one
//! partial trace buffer per family plus the histogram — 8 bytes a halfword of
//! image, 16 MB for the largest image on the menu. **A whole Ethereum block
//! profiles in a minute and a few hundred megabytes**, where `trace_run` would
//! need ~520 GB for the same execution (`docs/spec/streaming.md` §1).

pub mod categories;
pub mod demangle;
pub mod report;

use std::collections::BTreeMap;

use categories::Category;
use emulator::{ChunkRows, Execution, GuestIo, StreamingRun};
use isa::Instr;
use loader::{FuncSymbol, ProgramImage};
use program::{DecodedTables, VmConfig};
use trace::CycleProfile;

/// One function's share of an execution.
#[derive(Clone, Debug)]
pub struct FuncProfile {
    pub name: String,
    /// The demangled path, which is what the category rules read.
    pub path: String,
    pub addr: u32,
    pub size: u32,
    pub category: Category,
    /// Cycles executed inside `[addr, addr + size)`.
    pub cycles: u64,
    /// Times the function's first instruction ran, which is once per call.
    pub calls: u64,
}

/// One execution, profiled.
pub struct Profile {
    /// Cycles the execution ran, transfer cycles included.
    pub cycles: u64,
    /// Per halfword slot of the image, how many cycles ran there. Slot `i` is
    /// pc `slot_base + 2i`, the same indexing `ProgramImage::slots` has.
    pub hist: Vec<u64>,
    pub slot_base: u32,
    /// Per family: cycles for a cycle-owning one, invocations for a delegation
    /// one (`docs/spec/delegation.md` §8).
    pub profile: CycleProfile,
    /// Every function symbol of the image, with its share.
    pub funcs: Vec<FuncProfile>,
    /// Cycles by instruction mnemonic, descending.
    pub mnemonics: Vec<(String, u64)>,
    /// Cycles at a pc no function symbol claims.
    pub unclaimed: u64,
    pub execution: Execution,
}

/// Run `image` over `io` and profile it.
///
/// `tables` and `config` must be one `program::decode_program` of `image`, as
/// `emulator::trace_run`'s must be. `elf` is the file `image` was loaded from,
/// read for its symbol table alone — symbols are not part of the image and
/// nothing here can change what a proof would be about
/// (`crates/loader/src/symbols.rs`).
pub fn profile(
    elf: &[u8],
    image: &ProgramImage,
    io: &GuestIo,
    tables: &DecodedTables,
    config: &VmConfig,
) -> Result<Profile, String> {
    let mut hist = vec![0u64; image.slots.len()];
    let slot_base = image.slot_base;
    let mut run = StreamingRun::new(image, io, tables, config).map_err(|e| e.to_string())?;
    // The executor hands back one shard at a time and this drops each as soon as
    // its pc column has been counted, so the profiler's own memory is the
    // histogram and one partial buffer per family.
    loop {
        let ready = run.next_shards().map_err(|e| e.to_string())?;
        if ready.is_empty() {
            break;
        }
        for chunk in &ready {
            count(&mut hist, slot_base, chunk);
        }
    }
    let (tail, done) = run.finish().map_err(|e| e.to_string())?;
    for chunk in &tail {
        count(&mut hist, slot_base, chunk);
    }

    let funcs = attribute(elf, slot_base, &hist);
    let claimed: u64 = claimed_cycles(&funcs, slot_base, &hist);
    let total: u64 = hist.iter().sum();
    Ok(Profile {
        cycles: done.execution.cycle_count,
        mnemonics: by_mnemonic(image, &hist),
        unclaimed: total - claimed,
        hist,
        slot_base,
        profile: done.profile,
        funcs,
        execution: done.execution,
    })
}

/// Add one shard's rows to the histogram. A delegation family's rows are
/// invocations rather than cycles, and their requesting cycle is already counted
/// by the family that owns the ecall row, so they add nothing here.
fn count(hist: &mut [u64], slot_base: u32, chunk: &emulator::ShardChunk) {
    let ChunkRows::Cycles(rows) = &chunk.rows else {
        return;
    };
    for pc in &rows.pc {
        let slot = ((pc - slot_base) / 2) as usize;
        hist[slot] += 1;
    }
}

/// Every function symbol with its cycles, its calls and its category.
///
/// Overlapping symbols are possible — an alias shares an address and a size, and
/// `guests/revm-block` has 28 such groups — so a cycle can be inside two
/// entries' ranges. Each entry reports its own range's sum, and
/// [`claimed_cycles`] counts each *slot* once so that the shares still add up.
fn attribute(elf: &[u8], slot_base: u32, hist: &[u64]) -> Vec<FuncProfile> {
    let mut out: Vec<FuncProfile> = loader::function_symbols(elf)
        .into_iter()
        .map(|FuncSymbol { addr, size, name }| {
            let path = demangle::demangle(&name);
            let category = categories::classify(&path, &name);
            let (mut cycles, mut calls) = (0u64, 0u64);
            if addr >= slot_base {
                let first = ((addr - slot_base) / 2) as usize;
                let last = ((addr - slot_base + size) / 2) as usize;
                cycles = hist[first.min(hist.len())..last.min(hist.len())]
                    .iter()
                    .sum();
                calls = hist.get(first).copied().unwrap_or(0);
            }
            FuncProfile {
                name,
                path,
                addr,
                size,
                category,
                cycles,
                calls,
            }
        })
        .collect();
    out.sort_by(|a, b| b.cycles.cmp(&a.cycles).then(a.addr.cmp(&b.addr)));
    out
}

/// The cycles some function symbol claims, counting each slot once.
fn claimed_cycles(funcs: &[FuncProfile], slot_base: u32, hist: &[u64]) -> u64 {
    let mut claimed = vec![false; hist.len()];
    for f in funcs {
        if f.addr < slot_base {
            continue;
        }
        let first = ((f.addr - slot_base) / 2) as usize;
        let last = ((f.addr - slot_base + f.size) / 2) as usize;
        for seen in &mut claimed[first.min(hist.len())..last.min(hist.len())] {
            *seen = true;
        }
    }
    hist.iter()
        .zip(&claimed)
        .filter(|(_, c)| **c)
        .map(|(n, _)| n)
        .sum()
}

/// Cycles by instruction mnemonic, descending.
///
/// A second, independent lens on the same histogram: it says whether a workload
/// is multiply-bound or load-bound without reference to any symbol, and it is
/// what a symbol table cannot be wrong about.
fn by_mnemonic(image: &ProgramImage, hist: &[u64]) -> Vec<(String, u64)> {
    let mut by: BTreeMap<String, u64> = BTreeMap::new();
    for (slot, count) in hist.iter().enumerate() {
        if *count == 0 {
            continue;
        }
        let name = match image.slots.get(slot) {
            Some(loader::Slot::Instruction { word, .. }) => match isa::decode(*word) {
                Ok(instr) => mnemonic(&instr),
                Err(_) => "<illegal>".to_string(),
            },
            _ => "<not code>".to_string(),
        };
        *by.entry(name).or_default() += count;
    }
    let mut out: Vec<(String, u64)> = by.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out
}

/// An instruction's mnemonic, as `isa::Instr`'s `Debug` spells its variant.
///
/// The variant name and not the operands: `Debug` on an `Instr` prints the
/// fields too, and what a mix wants is the opcode. Computed once per **slot**
/// the execution reached, not once per cycle.
fn mnemonic(instr: &Instr) -> String {
    format!("{instr:?}")
        .split(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or("?")
        .to_string()
}

impl Profile {
    /// Cycles and calls per category, in `Category::ALL` order.
    ///
    /// Each function's cycles are credited to its own category; the
    /// `unattributed` category also carries every cycle at a pc no function
    /// symbol claims.
    pub fn by_category(&self) -> Vec<(Category, u64, u64)> {
        let mut cycles: BTreeMap<Category, (u64, u64)> = BTreeMap::new();
        for f in &self.funcs {
            let e = cycles.entry(f.category).or_default();
            e.0 += f.cycles;
            e.1 += f.calls;
        }
        cycles.entry(Category::Other).or_default().0 += self.unclaimed;
        Category::ALL
            .iter()
            .map(|c| {
                let (cycles, calls) = cycles.get(c).copied().unwrap_or_default();
                (*c, cycles, calls)
            })
            .collect()
    }

    /// Calls into `entries`: the sum of the call counts of every function whose
    /// path contains one of those substrings.
    pub fn entry_calls(&self, entries: &[&str]) -> u64 {
        self.funcs
            .iter()
            .filter(|f| entries.iter().any(|e| f.path.contains(e)))
            .map(|f| f.calls)
            .sum()
    }
}
