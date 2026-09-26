//! Execution traces: the memory event log, the per-family buffers, the cycle
//! profile and the shard plan, the archive that snapshots them, and the memory
//! argument's columns filled from them.
//!
//! `docs/spec/execution-trace.md` is the frozen convention every value here
//! follows: the timestamps, the slot of every query kind, the x0 rule, the
//! ecall frame. `crates/trace/CLAUDE.md` is the design record. `crates/emulator`
//! is the only producer; everything here is a data structure over what it
//! produced, or a column built from one.

mod archive;
mod family;
mod log;
mod lookup;
mod memory;

pub use archive::{IoStreams, Phase, PhaseTiming, TraceArchive, PHASES};
pub use family::{
    DelegationTrace, FamilyTrace, FamilyTraces, FrameSlice, Query, QueryColumns, Role, Row,
    RowSlice, WordSlice, ROLES,
};
pub use log::{
    addressable, in_ram, AddressSpace, FinalValue, InitialMemory, MemoryEvent, MemoryEventLog,
    MemoryState, SelfCheckError, DELEGATION_SPACES,
};

pub use lookup::{build_multiplicities, check_multiplicities};
pub use memory::{
    build_boundary_finals, build_frame_witness, build_init_teardown_columns, build_memory_columns,
    build_value_window_columns,
};

use program::{FamilyId, VmConfig};

/// How many rows each family filled: one count per family of the `VmConfig`,
/// in its order, zero for a family the execution never reached.
///
/// A cycle-owning family's count is its cycles, transfer cycles included, and
/// those counts sum to the execution's cycle count — [`CycleProfile::total`].
/// A **delegation** family's count is its *invocations*, which are not cycles:
/// they ride a requesting cycle that the add/sub family already counts
/// (`docs/spec/delegation.md` §8), so they are outside that sum. Either way
/// the count is what [`plan_shards`] divides by the family's height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CycleProfile {
    pub counts: Vec<(FamilyId, u64)>,
}

impl CycleProfile {
    /// The execution's cycle count: the cycle-owning families' counts alone.
    pub fn total(&self) -> u64 {
        self.counts
            .iter()
            .filter(|(f, _)| program::claims_pcs(*f))
            .map(|(_, n)| n)
            .sum()
    }
}

/// How many shards each family proves: one count per family of the
/// `VmConfig`, in its order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardPlan {
    pub shards: Vec<(FamilyId, u32)>,
}

/// Shard counts from a cycle profile: `ceil(occupancy / height)` per family,
/// so a family the execution never reached plans zero shards.
///
/// A pure function of its two arguments. `profile` must count exactly the
/// families of `config`, in its order — a profile from another config is a
/// caller error and panics.
///
/// `INIT_TEARDOWN` and `ZERO_WINDOWS` run no cycles, so both plan 0 shards
/// here. Their rows are addresses rather than cycles: the prover assembles
/// exactly 1 `INIT_TEARDOWN` shard, RAM window 0, and one `ZERO_WINDOWS`
/// shard per entry of [`init_windows`] (`docs/spec/memory.md` §3).
pub fn plan_shards(profile: &CycleProfile, config: &VmConfig) -> ShardPlan {
    assert!(
        profile.counts.len() == config.families.len()
            && profile
                .counts
                .iter()
                .zip(&config.families)
                .all(|((p, _), (c, _))| p == c),
        "plan_shards: the profile counts {:?}, not the config's families {:?}",
        profile.counts,
        config.families
    );
    let shards = profile
        .counts
        .iter()
        .zip(&config.families)
        .map(|((family, count), (_, height))| {
            let n = count.div_ceil(*height as u64);
            let n = u32::try_from(n)
                .unwrap_or_else(|_| panic!("plan_shards: family {family} needs {n} shards"));
            (*family, n)
        })
        .collect();
    ShardPlan { shards }
}

/// The `ZERO_WINDOWS` family's shard list: the distinct RAM window ids
/// `addr / (4 * height)` of every **ordinary RAM** word the execution touched,
/// ascending, without window 0, which is `INIT_TEARDOWN`'s. `height` is the
/// window families' one height. `docs/spec/memory.md` §3.4.
///
/// Only ordinary RAM: the two public windows and the advice region are
/// `AddressSpace::Ram` tuples too, and each has a family of its own that
/// initializes it. A zero window over either would give those words a second
/// init row and a prover a second value to choose
/// (`docs/spec/public-values.md` §2).
pub fn init_windows(state: &MemoryState, height: u32) -> Vec<u32> {
    state
        .touched_ram_windows(height)
        .into_iter()
        .filter(|w| *w != 0)
        .collect()
}

/// How many words the advice region holds for `advice`: its length word and
/// its payload, `docs/spec/public-values.md` §6.
///
/// Word 0 at `guest_memory::ADVICE_ORIGIN` is the payload's **byte length**
/// and the payload follows, exactly as a public window is laid out. The
/// executor writes it, `guest_sdk::advice` reads it, and the prover's fill
/// commits it, so there is one layout and not three — and a host never has to
/// frame the bytes itself.
///
/// **No advice means no region**, not a region holding a zero length word.
/// Otherwise every program in the repository would pay one `ADVICE_WINDOWS`
/// shard — a whole window at the window height — to say that it has no advice.
/// The consequence is that `guest_sdk::advice` is a fatal `OutOfBounds` on a
/// run that was given none, which is the right answer to a guest asking for
/// what it was not handed.
pub fn advice_region_words(advice: &[u8]) -> u64 {
    match advice.is_empty() {
        true => 0,
        false => 1 + (advice.len() as u64).div_ceil(4),
    }
}

/// Word `index` of the advice region, counting from
/// `guest_memory::ADVICE_ORIGIN`: the length word, then the payload
/// little-endian, and 0 past the end.
pub fn advice_word(advice: &[u8], index: u64) -> u32 {
    match index.checked_sub(1) {
        None => advice.len() as u32,
        Some(i) => {
            let at = 4 * i as usize;
            let mut word = [0u8; 4];
            for (k, b) in word.iter_mut().enumerate() {
                *b = advice.get(at + k).copied().unwrap_or(0);
            }
            u32::from_le_bytes(word)
        }
    }
}

/// The `ADVICE_WINDOWS` family's shard count: how many windows of `height`
/// rows the advice region spans, counted from `guest_memory::ADVICE_ORIGIN`
/// up.
///
/// A count and not a list, because the windows are consecutive from the origin
/// (`docs/spec/public-values.md` §6). It is a function of what the host
/// supplied and not of what the guest read: the words a guest never touched
/// still have to be initialized, and their init and teardown tuples cancel.
pub fn advice_window_count(advice: &[u8], height: u32) -> u32 {
    let n = advice_region_words(advice).div_ceil(height as u64);
    u32::try_from(n).expect("the advice region is at most 2^29 words, so at most 2^21 windows")
}
