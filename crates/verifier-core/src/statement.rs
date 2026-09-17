//! The statement: the static `VmConfig`, its descriptor and window rules, the
//! identity and SRS digests, the order of a statement's shards, and the global
//! transcript that turns a statement into the memory challenges and the digest
//! every shard is seeded with.
//!
//! `VmConfig`, `ProgramIdentity`, `absorb_statement_descriptor`,
//! `check_memory_windows` and the identity digest were S11's and S14's in
//! `crates/program`, which re-exports or wraps each: they moved here so the
//! verifier core, which is `#![no_std]`, implements statement binding once, for
//! the prover and the verifier alike. `docs/spec/shard-proof.md` §1–§4.

use alloc::vec::Vec;

use constants::memory::TS_BITS;
use constants::{challenge_slot, family, transcript_tags as tags, PROTOCOL_VERSION};
use field::Fr;
use gkr_verify::{window_challenges, BoundaryFinals, ExternalChallenges};
use transcript::{append_g1_points, io_digest, Transcript};

use crate::{PublicInputs, VerifyingKey};

// ---------------------------------------------------------------------------
// The static shape
// ---------------------------------------------------------------------------

/// The static VM shape a program derives: which families it needs, how tall
/// each family's trace is, and the bytecode ceiling it was checked against.
///
/// Per-proof shard counts are deliberately **not** here — they vary with the
/// execution, and a program's shape does not. They join it in the statement
/// descriptor; see [`absorb_statement_descriptor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmConfig {
    /// `(family, height)`, strictly ascending by family, heights on the menu.
    pub families: Vec<(u32, u32)>,
    pub bytecode_size_words: u32,
}

impl VmConfig {
    /// The height of `family`, or `None` if it is detached.
    pub fn height(&self, family: u32) -> Option<u32> {
        self.families
            .iter()
            .find(|(f, _)| *f == family)
            .map(|(_, h)| *h)
    }

    /// The frozen wire form: `u32` LE family count `k`, then `k` pairs of
    /// `u32` LE `(family, height)`, then `u32` LE `bytecode_size_words`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 8 * self.families.len());
        out.extend_from_slice(&(self.families.len() as u32).to_le_bytes());
        for (f, h) in &self.families {
            out.extend_from_slice(&f.to_le_bytes());
            out.extend_from_slice(&h.to_le_bytes());
        }
        out.extend_from_slice(&self.bytecode_size_words.to_le_bytes());
        out
    }

    /// Decode, refusing anything [`VmConfig::to_bytes`] could not have written
    /// from a derived config: a wrong length, an unknown or out-of-order family,
    /// a height off the menu, a family set without `INIT_TEARDOWN` or
    /// `ZERO_WINDOWS` — which derivation puts in every config — or those two
    /// at different heights. `None` rather than a panic.
    ///
    /// The two init families are required to be *present*, not last. They
    /// have the highest ids today, but `FamilyId`s are append-only and the
    /// delegation families take ids above them, so a config holding one lists
    /// it after both.
    pub fn from_bytes(bytes: &[u8]) -> Option<VmConfig> {
        let word = |i: usize| -> Option<u32> {
            Some(u32::from_le_bytes(
                bytes.get(4 * i..4 * i + 4)?.try_into().ok()?,
            ))
        };
        let k = word(0)? as usize;
        if k > family::COUNT as usize || bytes.len() != 4 * (2 * k + 2) {
            return None;
        }
        let mut families = Vec::with_capacity(k);
        for j in 0..k {
            let (f, h) = (word(1 + 2 * j)?, word(2 + 2 * j)?);
            if f >= family::COUNT || !family::HEIGHT_MENU.contains(&h) {
                return None;
            }
            if families.last().is_some_and(|(prev, _)| *prev >= f) {
                return None;
            }
            families.push((f, h));
        }
        let config = VmConfig {
            families,
            bytecode_size_words: word(1 + 2 * k)?,
        };
        window_height(&config).ok()?;
        Some(config)
    }
}

/// The one height of the two init families, or the rule a config breaks:
/// `INIT_TEARDOWN` and `ZERO_WINDOWS` both present, at one height.
/// `docs/spec/memory.md` §3.2: a `ZERO_WINDOWS` height below
/// `INIT_TEARDOWN`'s would give image words a second init row.
pub fn window_height(config: &VmConfig) -> Result<u32, &'static str> {
    match (
        config.height(family::INIT_TEARDOWN),
        config.height(family::ZERO_WINDOWS),
    ) {
        (Some(init), Some(zero)) if init == zero => Ok(init),
        (Some(_), Some(_)) => Err("INIT_TEARDOWN and ZERO_WINDOWS have one height"),
        _ => Err("INIT_TEARDOWN and ZERO_WINDOWS are in every VmConfig"),
    }
}

/// The static `VmConfig` as one typed message: the family ids ascending, then
/// their heights in the same order, then `bytecode_size_words`. Its length,
/// `2k + 1`, is what fixes `k`.
fn absorb_vm_config(tr: &mut Transcript, config: &VmConfig) {
    let mut message: Vec<Fr> = config
        .families
        .iter()
        .map(|(f, _)| Fr::from_u64(*f as u64))
        .collect();
    message.extend(config.families.iter().map(|(_, h)| Fr::from_u64(*h as u64)));
    message.push(Fr::from_u64(config.bytecode_size_words as u64));
    tr.append_scalars(tags::VM_CONFIG, &message);
}

/// The statement descriptor: the static `VmConfig`, the per-proof shard count
/// of each of its families, and the RAM window list, as three adjacent typed
/// messages.
///
/// The first is exactly the `VmConfig` message program identity absorbs; the
/// second is one count per family, in the same ascending order, under
/// `SHARD_COUNTS`. A family present in the config and run zero times has count
/// 0 — it still has a slot, so the counts line up with the families by
/// position and by nothing else. The third is `ZERO_WINDOWS`' window ids
/// `[w_1 … w_k]` under `MEMORY_WINDOWS`, empty when `k = 0`: its length varies
/// per execution exactly as the counts do. Absorbing checks nothing;
/// [`check_memory_windows`] is the rule over the same three.
/// `docs/spec/memory.md` §6.1.
pub fn absorb_statement_descriptor(
    tr: &mut Transcript,
    config: &VmConfig,
    shard_counts: &[u32],
    windows: &[u32],
) {
    assert_eq!(
        shard_counts.len(),
        config.families.len(),
        "the statement descriptor carries one shard count per family in the VmConfig"
    );
    absorb_vm_config(tr, config);
    let counts: Vec<Fr> = shard_counts
        .iter()
        .map(|c| Fr::from_u64(*c as u64))
        .collect();
    tr.append_scalars(tags::SHARD_COUNTS, &counts);
    let ids: Vec<Fr> = windows.iter().map(|w| Fr::from_u64(*w as u64)).collect();
    tr.append_scalars(tags::MEMORY_WINDOWS, &ids);
}

/// The verifier's RAM window rules over the statement, checked before the
/// memory challenges (`docs/spec/memory.md` §3.5): `INIT_TEARDOWN` and
/// `ZERO_WINDOWS` present at one height `h`; exactly one `INIT_TEARDOWN`
/// shard; one window id per `ZERO_WINDOWS` shard; the ids strictly increasing;
/// every id in `[1, 2^29 / h - 1]`. `ZERO_WINDOWS` shard `i` is window
/// `windows[i]`, so together they give every RAM word exactly one init row.
/// The error names the rule broken.
///
/// `config` is one derivation produced or [`VmConfig::from_bytes`] decoded —
/// families strictly ascending, heights on the menu — and nothing here checks
/// that again. `shard_counts` holds one count per family of `config`, as the
/// statement descriptor does; anything else is a caller error and panics.
pub fn check_memory_windows(
    config: &VmConfig,
    shard_counts: &[u32],
    windows: &[u32],
) -> Result<(), &'static str> {
    assert_eq!(
        shard_counts.len(),
        config.families.len(),
        "check_memory_windows: one shard count per family in the VmConfig"
    );
    let height = window_height(config)?;
    let count = |id: u32| {
        let i = config.families.iter().position(|(f, _)| *f == id);
        shard_counts[i.expect("window_height found both init families")]
    };
    if count(family::INIT_TEARDOWN) != 1 {
        return Err("INIT_TEARDOWN proves exactly one shard");
    }
    if windows.len() as u64 != count(family::ZERO_WINDOWS) as u64 {
        return Err("the window list has one id per ZERO_WINDOWS shard");
    }
    if windows.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("the window ids are strictly increasing");
    }
    let n = (1u64 << 29) / height as u64;
    if windows.iter().any(|w| *w == 0 || *w as u64 >= n) {
        return Err("every window id is in [1, 2^29 / h - 1]");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The digests
// ---------------------------------------------------------------------------

/// A program's identity: one `Fr`, squeezed from the recipe in
/// [`identity_digest`]. Its wire form is that element's canonical 32-byte
/// little-endian encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramIdentity(pub Fr);

impl ProgramIdentity {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// `None` for a non-canonical encoding; never reduces.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<ProgramIdentity> {
        Fr::from_bytes(bytes).map(ProgramIdentity)
    }
}

/// The identity digest over given setup commitments, each a 64-byte canonical
/// `G1` encoding. It needs no SRS and no curve: this is what a verifying-key
/// loader recomputes. A fresh typed transcript absorbs, in this frozen order
/// (`docs/spec/memory.md` §6.2):
///
/// 1. `PROGRAM_IDENTITY`: `code_version`, one scalar;
/// 2. `VM_CONFIG`: the family ids, their heights, `bytecode_size_words`;
/// 3. `PROGRAM_ENTRY`: `entry_pc`, one scalar;
/// 4. per family of `config`, in its order, `COMMITMENT`: that family's list
///    in `commitments`, as one message of 4-limb points;
/// 5. one raw squeeze, which is the identity.
///
/// `program::identity_from_commitments` is this over `G1Affine`s.
/// `commitments` holds one list per family of `config`; anything else is a
/// caller error and panics.
pub fn identity_digest(
    code_version: u32,
    config: &VmConfig,
    entry_pc: u32,
    commitments: &[Vec<[u8; 64]>],
) -> ProgramIdentity {
    assert_eq!(
        commitments.len(),
        config.families.len(),
        "identity_digest: one commitment list per family in the VmConfig"
    );
    let mut tr = Transcript::new();
    tr.append_scalar(tags::PROGRAM_IDENTITY, Fr::from_u64(code_version as u64));
    absorb_vm_config(&mut tr, config);
    tr.append_scalar(tags::PROGRAM_ENTRY, Fr::from_u64(entry_pc as u64));
    for points in commitments {
        append_g1_points(&mut tr, tags::COMMITMENT, points);
    }
    ProgramIdentity(tr.sample())
}

/// The SRS digest, `docs/spec/shard-proof.md` §3: a fresh typed transcript
/// absorbs the 320-byte `SrsVerifier` encoding — `g1_gen ‖ g2_gen ‖ g2_tau`,
/// S07's layout — as one `SRS_VERIFIER` bytes message, then, since S17, the
/// packed generic table's three commitments as one `GENERIC_TABLE` message of
/// twelve limbs; the digest is one raw squeeze, as `io_digest`'s is. Raw,
/// because a challenge under a bytes tag would be one tag in two kinds.
///
/// Both are constants of the ceremony — the table's commitments are the same
/// at every height — so one trusted digest pins the points every pairing reads
/// and the table every generic lookup reads (`docs/spec/jump-branch-slt.md`
/// §6).
pub fn srs_digest(
    verifier: &[u8; 320],
    generic_table: &[[u8; 64]; constants::generic_table::WIDTH],
) -> Fr {
    let mut sponge = Transcript::new();
    sponge.append_bytes(tags::SRS_VERIFIER, verifier);
    append_g1_points(&mut sponge, tags::GENERIC_TABLE, generic_table);
    sponge.sample()
}

// ---------------------------------------------------------------------------
// The statement's shards and its transcript
// ---------------------------------------------------------------------------

/// The time window every shard binds at S16: the whole clock, `[0, 2^38)`.
/// `docs/spec/shard-proof.md` §4.
pub const TRIVIAL_TS_WINDOW: [u64; 2] = [0, 1 << TS_BITS];

/// A statement's shards in statement order, `docs/spec/shard-proof.md` §1.2:
/// `INIT_TEARDOWN`'s, then `ZERO_WINDOWS`', then every other family's,
/// ascending, each family's shards ascending. `(family, shard index)`.
///
/// `shard_counts` holds one count per family of `config`; anything else is a
/// caller error and panics. The caller bounds the total first: a statement's
/// counts are data.
pub fn statement_shards(config: &VmConfig, shard_counts: &[u32]) -> Vec<(u32, u32)> {
    assert_eq!(
        shard_counts.len(),
        config.families.len(),
        "statement_shards: one shard count per family in the VmConfig"
    );
    let mut out = Vec::new();
    for (family, count) in groups(config, shard_counts) {
        out.extend((0..count).map(|i| (family, i)));
    }
    out
}

/// `(family, count)` per family of `config`, in the global transcript's group
/// order: `INIT_TEARDOWN`, `ZERO_WINDOWS`, then every other family ascending.
fn groups(config: &VmConfig, shard_counts: &[u32]) -> Vec<(u32, u32)> {
    let pairs = config
        .families
        .iter()
        .zip(shard_counts)
        .map(|((f, _), c)| (*f, *c));
    let init = pairs.clone().filter(|(f, _)| *f == family::INIT_TEARDOWN);
    let zero = pairs.clone().filter(|(f, _)| *f == family::ZERO_WINDOWS);
    let rest = pairs.filter(|(f, _)| *f != family::INIT_TEARDOWN && *f != family::ZERO_WINDOWS);
    init.chain(zero).chain(rest).collect()
}

/// The 64 boundary scalars in `MEMORY_BOUNDARY`'s order,
/// `docs/spec/memory.md` §4.1: `t_0 … t_31`, `t_pc`, `v_1 … v_31`.
pub fn boundary_scalars(finals: &BoundaryFinals) -> Vec<Fr> {
    let mut out = Vec::with_capacity(64);
    out.extend(finals.reg_ts.iter().map(|t| Fr::from_u64(*t)));
    out.push(Fr::from_u64(finals.pc_ts));
    out.extend(finals.reg_values.iter().map(|v| Fr::from_u64(*v as u64)));
    out
}

/// What the global transcript yields: the transcript after its last squeeze,
/// the four memory challenges `γ_M, α_addr, α_ts, α_val`, and the global state
/// digest.
pub struct GlobalTranscript {
    pub transcript: Transcript,
    pub memory: [Fr; 4],
    pub digest: Fr,
}

/// The global transcript, `docs/spec/shard-proof.md` §2, G1 to G11: run
/// identically by the prover's global commit phase and by the verifier. Every
/// field of `statement` is absorbed but two: `memory_roots`, computed after the
/// challenges and bound by each shard's own proof, and `exit_status`, bound only
/// by `reduce_shard`'s step 10, which holds it to `x10`'s final value in the
/// boundary G9 absorbs. A caller that skips step 10 has not bound the status.
///
/// `statement` must be consistent with `vk`: one shard count per config family
/// and one commitment list per statement shard. The verifier checks that first
/// and refuses as `Statement`; a broken one here is a caller error and panics.
pub fn global_commit(vk: &VerifyingKey, statement: &PublicInputs) -> GlobalTranscript {
    let mut t = Transcript::new();
    t.append_scalar(tags::PROTOCOL_SUITE, Fr::from_u64(PROTOCOL_VERSION as u64));
    t.append_scalar(tags::SRS_DIGEST, vk.srs_digest);
    absorb_statement_descriptor(
        &mut t,
        &vk.config,
        &statement.shard_counts,
        &statement.windows,
    );
    t.append_scalar(tags::PROGRAM_IDENTITY, vk.identity.0);
    let io = io_digest(&statement.input, &statement.output);
    t.append_bytes(tags::PUBLIC_INPUTS, &io.to_bytes());

    let mut lists = statement.memory_commitments.iter();
    for (family, count) in groups(&vk.config, &statement.shard_counts) {
        t.append_scalars(
            tags::MEMORY_GROUP,
            &[Fr::from_u64(family as u64), Fr::from_u64(count as u64)],
        );
        for _ in 0..count {
            let list = lists
                .next()
                .expect("global_commit: one commitment list per statement shard");
            append_g1_points(&mut t, tags::COMMITMENT, list);
        }
    }
    assert!(
        lists.next().is_none(),
        "global_commit: one commitment list per statement shard, and no more"
    );
    t.append_scalars(
        tags::MEMORY_BOUNDARY,
        &boundary_scalars(&statement.boundary),
    );

    let mut memory = [Fr::ZERO; 4];
    for slot in memory.iter_mut() {
        *slot = t.challenge_scalar(tags::MEMORY_CHALLENGE);
    }
    let digest = t.challenge_scalar(tags::GLOBAL_STATE_DIGEST);
    GlobalTranscript {
        transcript: t,
        memory,
        digest,
    }
}

/// A shard transcript through its lookup challenges, `docs/spec/shard-proof.md`
/// §4, S1 to S4: the seed, the time window, the witness commitments, then `g`
/// and `β`. Returns the transcript and the two challenges.
pub fn shard_transcript(
    digest: Fr,
    family: u32,
    index: u32,
    ts_window: [u64; 2],
    witness_commitments: &[[u8; 64]],
) -> (Transcript, Fr, Fr) {
    let mut t = Transcript::new();
    t.append_scalars(
        tags::SHARD_SEED,
        &[
            digest,
            Fr::from_u64(family as u64),
            Fr::from_u64(index as u64),
        ],
    );
    t.append_scalars(
        tags::SHARD_TS_WINDOW,
        &[Fr::from_u64(ts_window[0]), Fr::from_u64(ts_window[1])],
    );
    append_g1_points(&mut t, tags::COMMITMENT, witness_commitments);
    let g = t.challenge_scalar(tags::LOOKUP_CHALLENGE);
    let beta = t.challenge_scalar(tags::LOOKUP_CHALLENGE);
    (t, g, beta)
}

/// Slots 1 to 4, `γ_M, α_addr, α_ts, α_val`, from the global transcript's four
/// memory challenges.
pub fn memory_slots(memory: &[Fr; 4]) -> ExternalChallenges {
    let mut drawn = ExternalChallenges::new();
    let slots = [
        challenge_slot::MEM_GAMMA,
        challenge_slot::MEM_ALPHA_ADDR,
        challenge_slot::MEM_ALPHA_TS,
        challenge_slot::MEM_ALPHA_VAL,
    ];
    for (slot, value) in slots.iter().zip(memory) {
        drawn.insert(*slot, *value);
    }
    drawn
}

/// The external challenges shard `(family, index)`'s circuit reads,
/// `docs/spec/shard-proof.md` §4: slots 1 to 4 from `memory`; for a RAM window
/// family, the derived slot 5 at its window — 0 for `INIT_TEARDOWN`,
/// `windows[index]` for `ZERO_WINDOWS`; then the LogUp slots from `g`, `β` and
/// the circuit.
///
/// `index` is below the family's count and `windows` is the statement's list,
/// which the window rules hold to that count; anything else panics.
pub fn shard_challenges(
    circuit: &constraints::FamilyCircuit,
    index: u32,
    windows: &[u32],
    memory: &[Fr; 4],
    g: Fr,
    beta: Fr,
) -> ExternalChallenges {
    let drawn = memory_slots(memory);
    let trace_vars = circuit.artifact.trace_vars;
    let mut out = match circuit.family {
        family::INIT_TEARDOWN => window_challenges(&drawn, 0, trace_vars),
        family::ZERO_WINDOWS => window_challenges(&drawn, windows[index as usize], trace_vars),
        _ => drawn,
    };
    gkr_verify::insert_lookup_challenges(&mut out, g, beta, &circuit.artifact);
    out
}

/// Every final 0: a helper for tests building a statement by hand.
#[cfg(test)]
pub(crate) fn empty_finals() -> BoundaryFinals {
    BoundaryFinals {
        reg_ts: [0; 32],
        pc_ts: 0,
        reg_values: [0; 31],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn config() -> VmConfig {
        VmConfig {
            families: vec![
                (family::ADD_SUB_LUI_AUIPC, 1 << 20),
                (family::MEM_WORD, 1 << 20),
                (family::INIT_TEARDOWN, 1 << 16),
                (family::ZERO_WINDOWS, 1 << 16),
            ],
            bytecode_size_words: 1 << 20,
        }
    }

    /// The init families lead, then every other family ascending, each
    /// family's shards ascending; a family with count 0 has no entry.
    #[test]
    fn the_statement_order_puts_the_init_families_first() {
        assert_eq!(
            statement_shards(&config(), &[2, 0, 1, 2]),
            vec![
                (family::INIT_TEARDOWN, 0),
                (family::ZERO_WINDOWS, 0),
                (family::ZERO_WINDOWS, 1),
                (family::ADD_SUB_LUI_AUIPC, 0),
                (family::ADD_SUB_LUI_AUIPC, 1),
            ]
        );
    }

    /// The window height is `INIT_TEARDOWN`'s, and the two init families must
    /// agree on it.
    #[test]
    fn the_window_height_is_the_init_families_one_height() {
        assert_eq!(window_height(&config()), Ok(1 << 16));
        let mut bad = config();
        bad.families[3].1 = 1 << 18;
        assert_eq!(
            window_height(&bad),
            Err("INIT_TEARDOWN and ZERO_WINDOWS have one height")
        );
        bad.families.pop();
        assert_eq!(
            window_height(&bad),
            Err("INIT_TEARDOWN and ZERO_WINDOWS are in every VmConfig")
        );
    }

    /// The boundary message is `t_0 … t_31, t_pc, v_1 … v_31`.
    #[test]
    fn the_boundary_scalars_are_in_the_frozen_order() {
        let mut f = empty_finals();
        f.reg_ts[31] = 5;
        f.pc_ts = 6;
        f.reg_values[0] = 7;
        let s = boundary_scalars(&f);
        assert_eq!(s.len(), 64);
        assert_eq!(s[31], Fr::from_u64(5));
        assert_eq!(s[32], Fr::from_u64(6));
        assert_eq!(s[33], Fr::from_u64(7));
    }

    /// The trivial window is the 38-bit clock.
    #[test]
    fn the_trivial_window_is_the_whole_clock() {
        assert_eq!(TRIVIAL_TS_WINDOW, [0, 1u64 << 38]);
    }
}
