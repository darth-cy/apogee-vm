//! The block: one execution's shards as one object. `docs/spec/block-proof.md`
//! is normative.
//!
//! A statement is proven by one `ShardProof` per shard of every family, every
//! one of them against one `PublicInputs` (`docs/spec/shard-proof.md` §1). A
//! [`BlockProof`] is that set, closed: the static `VmConfig` it was proven
//! under, the statement, and the proofs in statement order. Nothing in it is
//! new evidence — `verify_block` is `verify_shard` over every shard plus the
//! block's own structural checks — and its public-data API is what S24's
//! occupancy assertions and S26/S27's replay read.
//!
//! [`BlockReconciliation`] is the cross-shard record set as a named type, in
//! the frozen layout S27's aggregation guest replays.

use alloc::vec::Vec;

use constants::family;
use field::Fr;

use crate::statement::{statement_shards, VmConfig};
use crate::types::{PublicInputs, ShardProof};
use crate::wire::{Reader, Writer};

/// One shard's cross-shard record: what the other shards' verification reads
/// of it, and nothing else. `docs/spec/block-proof.md` §2, the frozen layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardRecord {
    pub family: u32,
    pub shard_index: u32,
    /// `[ts_start, ts_end)`, the shard's claimed time window.
    pub ts_window: [u64; 2],
    /// The shard's `M` commitments in layout order.
    pub memory_commitments: Vec<[u8; 64]>,
    /// `[read_root, write_root]`.
    pub roots: [Fr; 2],
}

/// The cross-shard record set: every shard's record in statement order,
/// `verifier_core::statement_shards`'. S27's aggregation guest replays it, so
/// its serialization is frozen (`docs/spec/block-proof.md` §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockReconciliation {
    pub records: Vec<ShardRecord>,
}

/// One execution proven: the static shape, the statement, and one
/// `ShardProof` per statement shard in statement order.
///
/// The `VmConfig` is carried rather than only read from the key because the
/// statement descriptor — the static shape plus the per-proof shard counts —
/// is public data of the proof (`docs/spec/shard-proof.md` §2, G3 and G4), and
/// `verify_block` holds the carried copy to the key's. The statement is
/// carried for the same reason and held to the one the verifier was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockProof {
    pub config: VmConfig,
    pub statement: PublicInputs,
    pub shards: Vec<ShardProof>,
}

impl BlockProof {
    /// The static VM shape this block was proven under.
    pub fn config(&self) -> &VmConfig {
        &self.config
    }

    /// One shard count per family of [`BlockProof::config`], in its order.
    pub fn shard_counts(&self) -> &[u32] {
        &self.statement.shard_counts
    }

    /// How many shards `family` proved: 0 for a family this execution never
    /// reached, and 0 for one the config detaches.
    pub fn shard_count(&self, family: u32) -> u32 {
        self.config
            .families
            .iter()
            .position(|(f, _)| *f == family)
            .and_then(|i| self.statement.shard_counts.get(i).copied())
            .unwrap_or(0)
    }

    /// The statement every shard of this block is proven against.
    pub fn statement(&self) -> &PublicInputs {
        &self.statement
    }

    /// The shard proofs, in statement order.
    pub fn shard_proofs(&self) -> &[ShardProof] {
        &self.shards
    }

    /// The cross-shard record set, in statement order.
    ///
    /// Well-shaped by construction for a block [`BlockProof::from_bytes`]
    /// decoded or `prove_block` assembled. A hand-built block whose statement
    /// and proofs disagree is a caller error and panics, as
    /// `statement_shards` does on counts that are not its config's.
    pub fn reconciliation(&self) -> BlockReconciliation {
        let shards = statement_shards(&self.config, &self.statement.shard_counts);
        assert!(
            shards.len() == self.shards.len()
                && shards.len() == self.statement.memory_commitments.len()
                && shards.len() == self.statement.memory_roots.len(),
            "BlockProof::reconciliation: the statement and the proofs are different shard sets"
        );
        let records = shards
            .iter()
            .enumerate()
            .map(|(i, &(family, shard_index))| ShardRecord {
                family,
                shard_index,
                ts_window: self.shards[i].ts_window,
                memory_commitments: self.statement.memory_commitments[i].clone(),
                roots: self.statement.memory_roots[i],
            })
            .collect();
        BlockReconciliation { records }
    }

    /// The frozen wire form, `docs/spec/block-proof.md` §6: the `VmConfig`
    /// encoding, the `PublicInputs` encoding, then each `ShardProof`
    /// encoding, each as a length-prefixed byte string.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.config.to_bytes());
        w.bytes(&self.statement.to_bytes());
        w.count(self.shards.len());
        for p in &self.shards {
            w.bytes(&p.to_bytes());
        }
        w.bytes
    }

    /// Decode, refusing anything [`BlockProof::to_bytes`] would not write and
    /// any block whose statement and proofs are different shard sets. So a
    /// decoded block's public-data API is total.
    pub fn from_bytes(bytes: &[u8]) -> Result<BlockProof, &'static str> {
        let mut r = Reader::new(bytes);
        let config = VmConfig::from_bytes(r.bytes()?).ok_or("the block's VmConfig is refused")?;
        let statement = PublicInputs::from_bytes(r.bytes()?)?;
        let n = r.count(4)?;
        let shards = (0..n)
            .map(|_| ShardProof::from_bytes(r.bytes()?))
            .collect::<Result<Vec<_>, _>>()?;
        r.finish()?;
        let block = BlockProof {
            config,
            statement,
            shards,
        };
        block.shape()?;
        Ok(block)
    }

    /// The structural rule every decoded block keeps: one shard count per
    /// config family, one commitment list, one root pair and one proof per
    /// statement shard, and the proofs naming the statement's shards in its
    /// order. Checked at decode and again by `verify_block`, which takes
    /// blocks built in memory too.
    pub fn shape(&self) -> Result<(), &'static str> {
        let counts = &self.statement.shard_counts;
        if counts.len() != self.config.families.len() {
            return Err("the block has not one shard count per config family");
        }
        // Bounded before statement_shards builds the list: counts are data.
        let total: u64 = counts.iter().map(|c| *c as u64).sum();
        if total != self.shards.len() as u64
            || total != self.statement.memory_commitments.len() as u64
            || total != self.statement.memory_roots.len() as u64
        {
            return Err("the block has not one proof, commitment list and root pair per shard");
        }
        let shards = statement_shards(&self.config, counts);
        if shards
            .iter()
            .zip(&self.shards)
            .any(|(&(f, i), p)| (p.family, p.shard_index) != (f, i))
        {
            return Err("the block's proofs are not the statement's shards, in statement order");
        }
        Ok(())
    }
}

impl BlockReconciliation {
    /// The frozen wire form, `docs/spec/block-proof.md` §6: a list of records,
    /// each `family, shard index, ts_start, ts_end, memory commitments in
    /// column order, read root, write root`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.count(self.records.len());
        for r in &self.records {
            w.u32(r.family);
            w.u32(r.shard_index);
            w.u64(r.ts_window[0]);
            w.u64(r.ts_window[1]);
            w.g1s(&r.memory_commitments);
            w.fr(&r.roots[0]);
            w.fr(&r.roots[1]);
        }
        w.bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BlockReconciliation, &'static str> {
        let mut r = Reader::new(bytes);
        // A record is at least two `u32`s, two `u64`s, an empty list and two
        // field elements.
        let n = r.count(4 + 4 + 8 + 8 + 4 + 32 + 32)?;
        let records = (0..n)
            .map(|_| {
                Ok(ShardRecord {
                    family: r.u32()?,
                    shard_index: r.u32()?,
                    ts_window: [r.u64()?, r.u64()?],
                    memory_commitments: r.g1s()?,
                    roots: [r.fr()?, r.fr()?],
                })
            })
            .collect::<Result<Vec<_>, &'static str>>()?;
        r.finish()?;
        Ok(BlockReconciliation { records })
    }
}

/// The block's time-window rule, `docs/spec/block-proof.md` §4: **within each
/// cycle-owning family**, the shards' windows are non-empty, ordered and
/// pairwise disjoint — `ts_end` of shard `i` is at or below `ts_start` of
/// shard `i + 1`.
///
/// Per family, because cycle numbers are global and two families interleave:
/// `ADD_SUB_LUI_AUIPC` may own cycles 1 and 3 while `JUMP_BRANCH_SLT` owns 2,
/// so their windows overlap by construction and a block-wide disjointness
/// rule could never hold. A family that owns no cycles — the two RAM window
/// families, whose rows are words, and the delegation families to come — is
/// exempt: its window is a claim about invocations, not a slice of the
/// execution (`constants::family::CYCLE_OWNING`).
///
/// `records` is in statement order, so a family's records are consecutive and
/// ascending by shard index; that is what makes checking neighbours enough.
/// Each record's window is already `[start, end)` inside the clock: step 4 of
/// `docs/spec/shard-proof.md` §6 holds every shard's to that.
///
/// **What this does and does not bind.** It is a check on the *plan*: nothing
/// in a family's circuit ties a claimed window to the rows committed under it,
/// so `ts_start` is a claim (`docs/spec/block-proof.md` §4.1, the owner's S20
/// decision). Cross-shard ordering, cycle uniqueness and pc continuity are
/// carried by the global memory multiset alone (`docs/spec/memory.md` §4.2).
pub fn check_ts_windows(records: &[ShardRecord]) -> Result<(), &'static str> {
    let owns_cycles = |r: &ShardRecord| {
        family::CYCLE_OWNING
            .get(r.family as usize)
            .copied()
            .unwrap_or(false)
    };
    for r in records.iter().filter(|r| owns_cycles(r)) {
        if r.ts_window[0] >= r.ts_window[1] {
            return Err("a cycle-owning shard's time window is empty");
        }
    }
    for pair in records.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        if prev.family != next.family || !owns_cycles(prev) {
            continue;
        }
        if prev.ts_window[1] > next.ts_window[0] {
            return Err("a family's shard time windows are not ordered and disjoint");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn record(family: u32, shard_index: u32, window: [u64; 2]) -> ShardRecord {
        ShardRecord {
            family,
            shard_index,
            ts_window: window,
            memory_commitments: vec![[7; 64]],
            roots: [Fr::from_u64(3), Fr::from_u64(5)],
        }
    }

    /// Two families' windows overlap freely; one family's must be ordered and
    /// disjoint, and neither an empty window nor an overlap passes.
    #[test]
    fn the_window_rule_is_per_cycle_owning_family() {
        let interleaved = vec![
            record(family::ADD_SUB_LUI_AUIPC, 0, [4, 100]),
            record(family::ADD_SUB_LUI_AUIPC, 1, [100, 200]),
            record(family::JUMP_BRANCH_SLT, 0, [8, 180]),
        ];
        assert_eq!(check_ts_windows(&interleaved), Ok(()));

        let mut overlapping = interleaved.clone();
        overlapping[1].ts_window[0] = 99;
        assert_eq!(
            check_ts_windows(&overlapping),
            Err("a family's shard time windows are not ordered and disjoint")
        );

        let mut swapped = interleaved.clone();
        swapped.swap(0, 1);
        swapped[0].shard_index = 0;
        swapped[1].shard_index = 1;
        assert_eq!(
            check_ts_windows(&swapped),
            Err("a family's shard time windows are not ordered and disjoint")
        );

        let mut empty = interleaved.clone();
        empty[0].ts_window = [4, 4];
        assert_eq!(
            check_ts_windows(&empty),
            Err("a cycle-owning shard's time window is empty")
        );
    }

    /// A RAM window family owns no cycles: its shards claim the trivial
    /// window, all of them the same one, and the rule lets them.
    #[test]
    fn a_family_that_owns_no_cycles_is_exempt() {
        let windows = vec![
            record(family::INIT_TEARDOWN, 0, crate::TRIVIAL_TS_WINDOW),
            record(family::ZERO_WINDOWS, 0, crate::TRIVIAL_TS_WINDOW),
            record(family::ZERO_WINDOWS, 1, crate::TRIVIAL_TS_WINDOW),
        ];
        assert_eq!(check_ts_windows(&windows), Ok(()));
    }
}
