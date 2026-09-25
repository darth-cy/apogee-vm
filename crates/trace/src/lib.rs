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
    DelegationTrace, FamilyTrace, FamilyTraces, Query, QueryColumns, Role, Row, ROLES,
};
pub use log::{
    AddressSpace, FinalValue, MemoryEvent, MemoryEventLog, SelfCheckError, DELEGATION_SPACES,
};
pub use lookup::{build_multiplicities, check_multiplicities};
pub use memory::{
    build_advice_window_columns, build_boundary_finals, build_frame_witness,
    build_init_teardown_columns, build_memory_columns,
};

use std::collections::BTreeSet;

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
/// The three window families run no cycles, so each plans 0 shards here.
/// Their rows are addresses rather than cycles, and the prover assembles them
/// from the log instead: exactly 1 `INIT_TEARDOWN` shard, RAM window 0; one
/// `ZERO_WINDOWS` shard per entry of [`init_windows`]
/// (`docs/spec/memory.md` §3); and [`advice_windows`] `ADVICE_WINDOWS` shards
/// (`docs/spec/advice.md` §6).
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
/// `addr / (4 * height)` of every RAM word the log touches, ascending, without
/// window 0, which is `INIT_TEARDOWN`'s. `height` is the window families' one
/// height, `verifier_core::window_height`. `docs/spec/memory.md` §3.4.
pub fn init_windows(log: &MemoryEventLog, height: u32) -> Vec<u32> {
    let windows: BTreeSet<u32> = log
        .touched_addresses()
        .into_iter()
        .filter(|(space, _)| *space == AddressSpace::Ram)
        .map(|(_, addr)| addr / (4 * height))
        .filter(|w| *w != 0)
        .collect();
    windows.into_iter().collect()
}

/// The `ADVICE_WINDOWS` family's shard count: enough windows, contiguous from
/// `guest_memory::ADVICE_ORIGIN`, to cover every advice word the log touches;
/// 0 for a run that read no advice. `docs/spec/advice.md` §6.
///
/// There is no id list, and that is the difference from [`init_windows`]:
/// advice is a blob and a blob has no holes, so the count *is* the map. A
/// window between `ADVICE_ORIGIN` and the highest word read is proved whether
/// or not the guest touched it — its rows cost an init tuple and a teardown
/// tuple that cancel, and its committed values are 0.
///
/// `height` is the **same** `verifier_core::window_height` [`init_windows`]
/// takes, and that is the reason all three window families share one: the
/// advice stride is read here, to count the windows, and again in the fill, to
/// size each one, and only a rule makes those the same number
/// (`docs/spec/advice.md` §5.0).
pub fn advice_windows(log: &MemoryEventLog, height: u32) -> u32 {
    let stride = 4 * height as u64;
    let last = log
        .touched_addresses()
        .into_iter()
        .filter(|(space, _)| *space == AddressSpace::Advice)
        .map(|(_, addr)| addr as u64 - constants::guest_memory::ADVICE_ORIGIN as u64)
        .max();
    match last {
        None => 0,
        Some(offset) => (offset / stride + 1) as u32,
    }
}
