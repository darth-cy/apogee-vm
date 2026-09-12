//! Execution traces: the memory event log, the per-family buffers, the cycle
//! profile and the shard plan, and the archive that snapshots them.
//!
//! `docs/spec/execution-trace.md` is the frozen convention every value here
//! follows: the timestamps, the slot of every query kind, the x0 rule, the
//! ecall frame. `crates/trace/CLAUDE.md` is the design record. `crates/emulator`
//! is the only producer; everything here is a data structure over what it
//! produced.

mod archive;
mod family;
mod log;

pub use archive::{IoStreams, Phase, PhaseTiming, TraceArchive, PHASES};
pub use family::{FamilyTrace, FamilyTraces, Query, QueryColumns, Role, Row, ROLES};
pub use log::{AddressSpace, FinalValue, MemoryEvent, MemoryEventLog, SelfCheckError};

use program::{FamilyId, VmConfig};

/// How many cycles each family ran: one count per family of the `VmConfig`,
/// in its order, zero for a family the execution never reached. The counts
/// sum to the execution's cycle count, transfer cycles included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CycleProfile {
    pub counts: Vec<(FamilyId, u64)>,
}

impl CycleProfile {
    pub fn total(&self) -> u64 {
        self.counts.iter().map(|(_, n)| n).sum()
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
/// Init/teardown's count is 0 here, because it runs no cycles. Its rows are
/// addresses rather than cycles, so the stage that builds that family decides
/// what its occupancy is.
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
