//! The proof-side types, frozen at S16: `PublicInputs`, `ShardProof`,
//! `VerifyingKey`, `VerifyError`, and the opening claim the core hands its
//! wrapper. Their byte layouts are `docs/spec/shard-proof.md` §9, and a key's
//! load rules §7.2.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use constants::memory::TS_BITS;
use constants::{generic_table, lookup_channel};
use constraints::lookup::{check_discharge, ChannelSpec};
use constraints::memory::check_memory;
use constraints::{family_circuit, CircuitArtifact, FamilyCircuit, PolyAddress, VirtualKind};
use field::Fr;
use gkr_verify::{BoundaryFinals, GkrProof, SumcheckProof};
use transcript::Transcript;

use crate::statement::{identity_digest, srs_digest, ProgramIdentity, VmConfig};
use crate::wire::{Read, Reader, Writer};

/// The bytes of one Mercury proof: 8 `G1` points and 6 `Fr`, S08's
/// `pcs::PROOF_BYTES`. The core holds it opaque; `crates/verifier` decodes it.
pub const OPENING_BYTES: usize = 704;

/// The bytes of an `SrsVerifier`: `g1_gen ‖ g2_gen ‖ g2_tau`, S07's layout.
pub const SRS_VERIFIER_BYTES: usize = 320;

// ---------------------------------------------------------------------------
// The error classes
// ---------------------------------------------------------------------------

/// Why a shard proof was refused, `docs/spec/shard-proof.md` §6. The class is
/// the variant; the payload says which check of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The statement is not one the key describes, or the proof was made for
    /// another statement.
    Statement(&'static str),
    /// The proof does not have its circuit's shape.
    Malformed(&'static str),
    /// A round or final check of GKR transition `layer` failed: a violated
    /// gate, or a claim that does not descend.
    Constraint { layer: usize },
    /// Channel `channel`'s root pair is not `(0, nonzero)`.
    Lookup { channel: u32 },
    /// The memory argument: the shard's roots, the boundary, the exit status
    /// or the reconciliation.
    MemoryArgument(&'static str),
    /// The Mercury opening, or a point it reads, is refused.
    Opening,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VerifyError::Statement(why) => write!(f, "statement: {why}"),
            VerifyError::Malformed(why) => write!(f, "malformed proof: {why}"),
            VerifyError::Constraint { layer } => {
                write!(f, "constraint: GKR transition {layer} is inconsistent")
            }
            VerifyError::Lookup { channel } => write!(
                f,
                "lookup: channel `{}` does not balance",
                lookup_channel::NAMES
                    .get(*channel as usize)
                    .copied()
                    .unwrap_or("?")
            ),
            VerifyError::MemoryArgument(why) => write!(f, "memory argument: {why}"),
            VerifyError::Opening => write!(f, "opening: the batched Mercury opening is refused"),
        }
    }
}

// ---------------------------------------------------------------------------
// PublicInputs
// ---------------------------------------------------------------------------

/// What a statement is about, `docs/spec/shard-proof.md` §1.1: the streams and
/// the result the outside world asserts, then the record the prover's global
/// commit phase fixed — every shard's memory commitments and roots, the
/// boundary, the counts and the window list. Every shard of a statement is
/// verified against one `PublicInputs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub exit_status: u32,
    pub shard_counts: Vec<u32>,
    pub windows: Vec<u32>,
    pub boundary: BoundaryFinals,
    /// Per shard, in statement order, its `M` commitments in layout order.
    pub memory_commitments: Vec<Vec<[u8; 64]>>,
    /// Per shard, in statement order, `[read_root, write_root]`.
    pub memory_roots: Vec<[Fr; 2]>,
}

/// `v` as a `u64`, when it is one.
fn small(v: Fr) -> Option<u64> {
    let b = v.to_bytes();
    if b[8..].iter().any(|x| *x != 0) {
        return None;
    }
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[..8]);
    Some(u64::from_le_bytes(w))
}

impl PublicInputs {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.input);
        w.bytes(&self.output);
        w.u32(self.exit_status);
        w.u32s(&self.shard_counts);
        w.u32s(&self.windows);
        for x in crate::statement::boundary_scalars(&self.boundary) {
            w.fr(&x);
        }
        w.count(self.memory_commitments.len());
        for list in &self.memory_commitments {
            w.g1s(list);
        }
        w.count(self.memory_roots.len());
        for [read, write] in &self.memory_roots {
            w.fr(read);
            w.fr(write);
        }
        w.bytes
    }

    /// Decode, refusing anything [`PublicInputs::to_bytes`] would not write,
    /// and a boundary timestamp at or above `2^38` or value at or above
    /// `2^32` (`docs/spec/memory.md` §4.1).
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicInputs, &'static str> {
        let mut r = Reader::new(bytes);
        let input = r.bytes()?.to_vec();
        let output = r.bytes()?.to_vec();
        let exit_status = r.u32()?;
        let shard_counts = r.u32s()?;
        let windows = r.u32s()?;
        let mut boundary = BoundaryFinals {
            reg_ts: [0; 32],
            pc_ts: 0,
            reg_values: [0; 31],
        };
        let timestamp = |r: &mut Reader| -> Read<u64> {
            small(r.fr()?)
                .filter(|t| *t < 1 << TS_BITS)
                .ok_or("a boundary timestamp is not below 2^38")
        };
        for t in boundary.reg_ts.iter_mut() {
            *t = timestamp(&mut r)?;
        }
        boundary.pc_ts = timestamp(&mut r)?;
        for v in boundary.reg_values.iter_mut() {
            *v = small(r.fr()?)
                .and_then(|v| u32::try_from(v).ok())
                .ok_or("a boundary value is not below 2^32")?;
        }
        let shards = r.count(4)?;
        let memory_commitments = (0..shards)
            .map(|_| r.g1s())
            .collect::<Result<Vec<_>, _>>()?;
        let roots = r.count(64)?;
        let memory_roots = (0..roots)
            .map(|_| Ok([r.fr()?, r.fr()?]))
            .collect::<Result<Vec<_>, _>>()?;
        r.finish()?;
        Ok(PublicInputs {
            input,
            output,
            exit_status,
            shard_counts,
            windows,
            boundary,
            memory_commitments,
            memory_roots,
        })
    }
}

// ---------------------------------------------------------------------------
// ShardProof
// ---------------------------------------------------------------------------

/// One shard's proof, `docs/spec/shard-proof.md` §4 and §9. Its lengths are
/// fixed by the key's circuit for `family`, and it holds exactly one Mercury
/// proof. No accumulator entries: a base verification pairs inside `pcs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardProof {
    pub family: u32,
    pub shard_index: u32,
    /// `[start, end)`: [`crate::TRIVIAL_TS_WINDOW`] at S16.
    pub ts_window: [u64; 2],
    /// The global state digest the prover seeded this shard with.
    pub global_digest: Fr,
    /// The circuit's `W` columns' commitments, in layout order.
    pub witness_commitments: Vec<[u8; 64]>,
    /// The top layer: one value per output-map entry, in its order.
    pub outputs: Vec<Fr>,
    /// One sumcheck per gate list, transition 0 first.
    pub gkr: GkrProof,
    /// The batched Mercury opening, `pcs::MercuryProof::to_bytes`.
    pub opening: [u8; OPENING_BYTES],
}

impl ShardProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.family);
        w.u32(self.shard_index);
        w.u64(self.ts_window[0]);
        w.u64(self.ts_window[1]);
        w.fr(&self.global_digest);
        w.g1s(&self.witness_commitments);
        w.frs(&self.outputs);
        write_gkr(&mut w, &self.gkr);
        w.raw(&self.opening);
        w.bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ShardProof, &'static str> {
        let mut r = Reader::new(bytes);
        let family = r.u32()?;
        let shard_index = r.u32()?;
        let ts_window = [r.u64()?, r.u64()?];
        let global_digest = r.fr()?;
        let witness_commitments = r.g1s()?;
        let outputs = r.frs()?;
        let gkr = read_gkr(&mut r)?;
        let mut opening = [0u8; OPENING_BYTES];
        opening.copy_from_slice(r.take(OPENING_BYTES)?);
        r.finish()?;
        Ok(ShardProof {
            family,
            shard_index,
            ts_window,
            global_digest,
            witness_commitments,
            outputs,
            gkr,
            opening,
        })
    }
}

/// A `GkrProof` on the wire: per transition, its rounds then its claims,
/// `docs/spec/shard-proof.md` §9.
pub fn write_gkr(w: &mut Writer, gkr: &GkrProof) {
    w.count(gkr.layers.len());
    for layer in &gkr.layers {
        w.count(layer.rounds.len());
        for round in &layer.rounds {
            for c in round {
                w.fr(c);
            }
        }
        w.frs(&layer.final_evals);
    }
}

/// [`write_gkr`]'s reader.
pub fn read_gkr(r: &mut Reader) -> Read<GkrProof> {
    let layers = r.count(8)?;
    let mut out = Vec::new();
    for _ in 0..layers {
        let n = r.count(4 * 32)?;
        let rounds = (0..n)
            .map(|_| Ok([r.fr()?, r.fr()?, r.fr()?, r.fr()?]))
            .collect::<Read<Vec<[Fr; 4]>>>()?;
        let final_evals = r.frs()?;
        out.push(SumcheckProof {
            rounds,
            final_evals,
        });
    }
    Ok(GkrProof { layers: out })
}

// ---------------------------------------------------------------------------
// VerifyingKey
// ---------------------------------------------------------------------------

/// Everything `verify_shard` needs beyond a proof and its public inputs,
/// `docs/spec/shard-proof.md` §7. A key comes from a channel the prover does
/// not control, and a verifier compares its `identity` with a registered one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    pub code_version: u32,
    pub config: VmConfig,
    pub entry_pc: u32,
    pub identity: ProgramIdentity,
    /// Program identity's commitment lists, one per config family.
    pub setup_commitments: Vec<Vec<[u8; 64]>>,
    pub srs_verifier: [u8; SRS_VERIFIER_BYTES],
    /// The packed generic table's commitments, key column first: one set for
    /// every key, the same at every height, which a family that reads the
    /// generic channel opens its last setup columns against. Not in identity;
    /// the SRS digest covers them (`docs/spec/shard-proof.md` §3, §7; S17).
    pub generic_table: [[u8; 64]; generic_table::WIDTH],
    /// The digest of `srs_verifier` and `generic_table`.
    pub srs_digest: Fr,
    /// One per config family, in its order.
    pub circuits: Vec<FamilyCircuit>,
}

/// An address a channel spec names: tag 0 `M`, 1 `W`, 2 `S`, 3 `V`, then the
/// index — a virtual table's being its kind's artifact wire tag.
fn write_address(w: &mut Writer, a: PolyAddress) {
    let (tag, index) = match a {
        PolyAddress::Memory(i) => (0, i),
        PolyAddress::Witness(i) => (1, i),
        PolyAddress::Setup(i) => (2, i),
        PolyAddress::Virtual(kind) => (
            3,
            match kind {
                VirtualKind::RowIndex => 0,
                VirtualKind::RamLive => 1,
                VirtualKind::Range19 => 2,
                VirtualKind::Range16 => 3,
            },
        ),
        other => panic!("a channel spec names committed and virtual columns only, not {other}"),
    };
    w.u8(tag);
    w.u32(index);
}

fn read_address(r: &mut Reader) -> Read<PolyAddress> {
    let (tag, index) = (r.u8()?, r.u32()?);
    Ok(match tag {
        0 => PolyAddress::Memory(index),
        1 => PolyAddress::Witness(index),
        2 => PolyAddress::Setup(index),
        3 => PolyAddress::Virtual(match index {
            0 => VirtualKind::RowIndex,
            1 => VirtualKind::RamLive,
            2 => VirtualKind::Range19,
            3 => VirtualKind::Range16,
            _ => return Err("an unknown virtual table"),
        }),
        _ => return Err("an unknown address tag"),
    })
}

impl VerifyingKey {
    /// The circuit of `family`, if the key has one.
    pub fn circuit(&self, family: u32) -> Option<&FamilyCircuit> {
        self.circuits.iter().find(|c| c.family == family)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.code_version);
        w.bytes(&self.config.to_bytes());
        w.u32(self.entry_pc);
        w.fr(&self.identity.0);
        w.count(self.setup_commitments.len());
        for list in &self.setup_commitments {
            w.g1s(list);
        }
        w.raw(&self.srs_verifier);
        for point in &self.generic_table {
            w.raw(point);
        }
        w.fr(&self.srs_digest);
        w.count(self.circuits.len());
        for c in &self.circuits {
            w.u32(c.family);
            w.bytes(&c.artifact.to_bytes());
            w.count(c.channels.len());
            for spec in &c.channels {
                w.u32(spec.channel);
                w.count(spec.table.len());
                for t in &spec.table {
                    write_address(&mut w, *t);
                }
                write_address(&mut w, spec.multiplicity);
            }
        }
        w.bytes
    }

    /// Decode, then [`VerifyingKey::check`]. Curve points are not decoded here:
    /// `verifier::load_verifying_key` does that too.
    pub fn from_bytes(bytes: &[u8]) -> Result<VerifyingKey, String> {
        let key = Self::decode(bytes).map_err(String::from)?;
        if key.to_bytes() != bytes {
            return Err("the key is not the canonical encoding of itself".into());
        }
        key.check()?;
        Ok(key)
    }

    fn decode(bytes: &[u8]) -> Read<VerifyingKey> {
        let mut r = Reader::new(bytes);
        let code_version = r.u32()?;
        let config = VmConfig::from_bytes(r.bytes()?).ok_or("the VmConfig does not decode")?;
        let entry_pc = r.u32()?;
        let identity = ProgramIdentity(r.fr()?);
        let lists = r.count(4)?;
        let setup_commitments = (0..lists).map(|_| r.g1s()).collect::<Read<Vec<_>>>()?;
        let mut srs_verifier = [0u8; SRS_VERIFIER_BYTES];
        srs_verifier.copy_from_slice(r.take(SRS_VERIFIER_BYTES)?);
        let mut generic_table = [[0u8; 64]; generic_table::WIDTH];
        for point in generic_table.iter_mut() {
            point.copy_from_slice(r.take(64)?);
        }
        let srs_digest = r.fr()?;
        let n = r.count(12)?;
        let mut circuits = Vec::new();
        for _ in 0..n {
            let family = r.u32()?;
            let artifact = CircuitArtifact::from_bytes(r.bytes()?)
                .map_err(|_| "a circuit artifact does not decode")?;
            let specs = r.count(4 + 4 + 5)?;
            let mut channels = Vec::new();
            for _ in 0..specs {
                let channel = r.u32()?;
                let width = r.count(5)?;
                let table = (0..width)
                    .map(|_| read_address(&mut r))
                    .collect::<Read<Vec<_>>>()?;
                let multiplicity = read_address(&mut r)?;
                channels.push(ChannelSpec {
                    channel,
                    table,
                    multiplicity,
                });
            }
            circuits.push(FamilyCircuit {
                family,
                artifact,
                channels,
            });
        }
        r.finish()?;
        Ok(VerifyingKey {
            code_version,
            config,
            entry_pc,
            identity,
            setup_commitments,
            srs_verifier,
            generic_table,
            srs_digest,
            circuits,
        })
    }

    /// The load rules of `docs/spec/shard-proof.md` §7.2, everything but the
    /// curve points. Run once, where a key is built or loaded.
    pub fn check(&self) -> Result<(), String> {
        if VmConfig::from_bytes(&self.config.to_bytes()).as_ref() != Some(&self.config) {
            return Err("the key's VmConfig is not one a program derives".into());
        }
        if self.code_version != constants::family::CODE_VERSION {
            return Err(format!(
                "code version {} is not {}",
                self.code_version,
                constants::family::CODE_VERSION
            ));
        }
        let families = &self.config.families;
        if self.setup_commitments.len() != families.len() {
            return Err("the key has not one setup list per config family".into());
        }
        let identity = identity_digest(
            self.code_version,
            &self.config,
            self.entry_pc,
            &self.setup_commitments,
        );
        if identity != self.identity {
            return Err("the identity is not the digest of the key's setup commitments".into());
        }
        if srs_digest(&self.srs_verifier, &self.generic_table) != self.srs_digest {
            return Err(
                "the SRS digest is not the digest of the key's SrsVerifier and generic table"
                    .into(),
            );
        }
        if self.circuits.len() != families.len() {
            return Err("the key has not one circuit per config family".into());
        }
        for ((c, (family, height)), setup) in self
            .circuits
            .iter()
            .zip(families)
            .zip(&self.setup_commitments)
        {
            let name = format!("family {family}");
            if c.family != *family {
                return Err(format!(
                    "{name}: the key's circuits are not its config's families"
                ));
            }
            let trace_vars = height.trailing_zeros();
            let canonical = family_circuit(*family, trace_vars)
                .ok_or(format!("{name}: no circuit proves it at height {height}"))?;
            if *c != canonical {
                return Err(format!("{name}: the circuit is not the protocol's"));
            }
            c.artifact.validate().map_err(|e| format!("{name}: {e}"))?;
            check_memory(&c.artifact).map_err(|e| format!("{name}: {e}"))?;
            check_discharge(&c.artifact, &c.channels).map_err(|e| format!("{name}: {e}"))?;
            // A family that reads the generic channel opens the key's generic
            // table after identity's commitments (`reduce_shard`'s step 11).
            let generic = if c.reads_generic_table() {
                generic_table::WIDTH
            } else {
                0
            };
            if setup.len() + generic != c.artifact.setup.len() {
                return Err(format!(
                    "{name}: {} setup commitments and {generic} of the generic table for {} \
                     setup columns",
                    setup.len(),
                    c.artifact.setup.len()
                ));
            }
            // The registry's own consistency, which no key can break once its
            // circuit is the registry's: the table is the setup columns right
            // after identity's, the order the opening lists them in.
            let after_identity: Vec<PolyAddress> = (0..generic as u32)
                .map(|j| PolyAddress::Setup(setup.len() as u32 + j))
                .collect();
            let named = c
                .channels
                .iter()
                .filter(|spec| spec.channel == lookup_channel::GENERIC)
                .all(|spec| spec.table == after_identity);
            if !named {
                return Err(format!(
                    "{name}: the circuit does not name the generic table as its last setup columns"
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The opening claim
// ---------------------------------------------------------------------------

/// What `reduce_shard` leaves for the wrapper: one batched opening of every
/// committed column of the shard at one point, and the shard transcript to run
/// it in. `docs/spec/shard-proof.md` §5.1.
pub struct OpeningClaim {
    /// Layout order: `M`, `W`, `S`.
    pub commitments: Vec<[u8; 64]>,
    pub point: Vec<Fr>,
    pub values: Vec<Fr>,
    pub transcript: Transcript,
}
