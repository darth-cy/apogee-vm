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
    build_boundary_finals, build_frame_witness, build_init_teardown_columns, build_memory_columns,
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
/// `addr / (4 * height)` of every RAM word the log touches, ascending, without
/// window 0, which is `INIT_TEARDOWN`'s. `height` is the two init families'
/// one height. `docs/spec/memory.md` §3.4.
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
