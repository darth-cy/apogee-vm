//! The proof-side types: `PublicInputs`, `ShardProof`, `VerifyingKey`,
//! `VerifyError`, and the column claims the core hands its wrapper. Their byte
//! layouts are `docs/spec/proof.md` §9, and a key's load rules §7.2.
//!
//! **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** None of these
//! types carries a commitment: not the statement's memory columns, not a proof's
//! witness columns, not the key's setup columns, and no proof carries an
//! opening. Each is a void a commitment scheme must fill
//! (`docs/architecture.md` §0).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use constants::memory::TS_BITS;
use constants::{generic_table, lookup_channel};
use constraints::lookup::{check_discharge, ChannelSpec};
use constraints::memory::check_memory;
use constraints::{CircuitArtifact, FamilyCircuit, PolyAddress, VirtualKind};
use field::Fr;
use gkr_verify::{BoundaryFinals, GkrProof, SumcheckProof};
use transcript::Transcript;

use crate::statement::{identity_digest, ProgramIdentity, VmConfig};
use crate::wire::{Read, Reader, Writer};

// ---------------------------------------------------------------------------
// The error classes
// ---------------------------------------------------------------------------

/// Why a shard proof was refused, `docs/spec/proof.md` §6. The class is
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
        }
    }
}

// ---------------------------------------------------------------------------
// PublicInputs
// ---------------------------------------------------------------------------

/// What a statement is about, `docs/spec/proof.md` §1.1: the two public
/// payloads and the exit status the outside world asserts, then the record the
/// prover's global phase fixed — every shard's roots, the boundary, the counts
/// and the window list. Every shard of a statement is verified against one
/// `PublicInputs`.
///
/// **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** The record
/// is meant to carry every statement shard's memory-column commitments, between
/// `boundary` and `memory_roots`; it carries none (`docs/architecture.md` §0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub exit_status: u32,
    pub shard_counts: Vec<u32>,
    pub windows: Vec<u32>,
    pub boundary: BoundaryFinals,
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
            memory_roots,
        })
    }
}

// ---------------------------------------------------------------------------
// ShardProof
// ---------------------------------------------------------------------------

/// One shard's proof, `docs/spec/proof.md` §4 and §9. Its lengths are
/// fixed by the key's circuit for `family`.
///
/// **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** A shard's
/// proof is meant to carry its `W` columns' commitments, after
/// `global_digest`, and the opening of every committed column at the GKR
/// pass's point, after `gkr`. It carries neither (`docs/architecture.md` §0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardProof {
    pub family: u32,
    pub shard_index: u32,
    /// `[start, end)`, the claimed time window: [`crate::TRIVIAL_TS_WINDOW`]
    /// for a window family (`docs/spec/proof.md` §8).
    pub ts_window: [u64; 2],
    /// The global state digest the prover seeded this shard with.
    pub global_digest: Fr,
    /// The top layer: one value per output-map entry, in its order.
    pub outputs: Vec<Fr>,
    /// One sumcheck per gate list, transition 0 first.
    pub gkr: GkrProof,
}

impl ShardProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.family);
        w.u32(self.shard_index);
        w.u64(self.ts_window[0]);
        w.u64(self.ts_window[1]);
        w.fr(&self.global_digest);
        w.frs(&self.outputs);
        write_gkr(&mut w, &self.gkr);
        w.bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ShardProof, &'static str> {
        let mut r = Reader::new(bytes);
        let family = r.u32()?;
        let shard_index = r.u32()?;
        let ts_window = [r.u64()?, r.u64()?];
        let global_digest = r.fr()?;
        let outputs = r.frs()?;
        let gkr = read_gkr(&mut r)?;
        r.finish()?;
        Ok(ShardProof {
            family,
            shard_index,
            ts_window,
            global_digest,
            outputs,
            gkr,
        })
    }
}

/// A `GkrProof` on the wire: per transition, its rounds then its claims,
/// `docs/spec/proof.md` §9.
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
/// `docs/spec/proof.md` §7. A key comes from a channel the prover does
/// not control, and a verifier compares its `identity` with a registered one.
///
/// **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** A key is
/// meant to carry, after `identity`, one list of setup-column commitments per
/// config family — which identity digests — and the packed generic table's
/// commitments, with whatever public parameters the commitment scheme's verifier
/// reads. It carries none: nothing ties a shard's setup columns, the decoded
/// tables and the image among them, to the key (`docs/architecture.md` §0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    pub code_version: u32,
    pub config: VmConfig,
    pub entry_pc: u32,
    pub identity: ProgramIdentity,
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
                VirtualKind::Xor8A => 4,
                VirtualKind::Xor8B => 5,
                VirtualKind::Xor8Out => 6,
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
            4 => VirtualKind::Xor8A,
            5 => VirtualKind::Xor8B,
            6 => VirtualKind::Xor8Out,
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

    /// Decode, then [`VerifyingKey::check`].
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
            circuits,
        })
    }

    /// The load rules of `docs/spec/proof.md` §7.2. Run once, where a key is
    /// built or loaded.
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
        // ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME. The key's
        // setup-commitment lists, one per config family, are counted against
        // the config HERE, and digested into the identity just below, once a
        // commitment scheme exists (`docs/architecture.md` §0).
        let identity = identity_digest(self.code_version, &self.config, self.entry_pc);
        if identity != self.identity {
            return Err("the identity is not the digest of the key's config and entry pc".into());
        }
        if self.circuits.len() != families.len() {
            return Err("the key has not one circuit per config family".into());
        }
        for (c, (family, height)) in self.circuits.iter().zip(families) {
            let name = format!("family {family}");
            if c.family != *family {
                return Err(format!(
                    "{name}: the key's circuits are not its config's families"
                ));
            }
            let trace_vars = height.trailing_zeros();
            let canonical = self
                .config
                .circuit(*family, trace_vars)
                .ok_or(format!("{name}: no circuit proves it at height {height}"))?;
            if *c != canonical {
                return Err(format!("{name}: the circuit is not the protocol's"));
            }
            c.artifact.validate().map_err(|e| format!("{name}: {e}"))?;
            check_memory(&c.artifact).map_err(|e| format!("{name}: {e}"))?;
            check_discharge(&c.artifact, &c.channels).map_err(|e| format!("{name}: {e}"))?;
            // The registry's own consistency, which no key can break once its
            // circuit is the registry's: a family that reads the generic channel
            // names the packed generic table as its last setup columns, after
            // the family's own (`docs/spec/lookup.md` §9).
            let generic = if c.reads_generic_table() {
                generic_table::WIDTH
            } else {
                0
            };
            let own = c.artifact.setup.len().checked_sub(generic).ok_or(format!(
                "{name}: {} setup columns cannot hold the generic table's {generic}",
                c.artifact.setup.len()
            ))?;
            let last: Vec<PolyAddress> = (0..generic as u32)
                .map(|j| PolyAddress::Setup(own as u32 + j))
                .collect();
            let named = c
                .channels
                .iter()
                .filter(|spec| spec.channel == lookup_channel::GENERIC)
                .all(|spec| spec.table == last);
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
// The column claims
// ---------------------------------------------------------------------------

/// What `reduce_shard` leaves: every committed column's claimed value at the one
/// point the GKR pass ends on, and the shard transcript a discharge would run
/// in. `docs/spec/proof.md` §5.
///
/// **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** These are the
/// claims a commitment scheme's opening must prove against the shard's committed
/// columns — `M` from the statement, `W` from the proof, `S` from the key.
/// Nothing proves them: every verifier entry point drops them, so the values are
/// whatever the prover said and a shard's proof is **UNSOUND**
/// (`docs/architecture.md` §0).
pub struct ColumnClaims {
    /// The committed columns, in layout order: `M`, `W`, `S`.
    pub columns: Vec<PolyAddress>,
    pub point: Vec<Fr>,
    /// One per column, in the same order.
    pub values: Vec<Fr>,
    pub transcript: Transcript,
}
