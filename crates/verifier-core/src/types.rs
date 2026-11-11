//! The proof-side types: `PublicInputs`, `ShardProof`, `VerifyingKey`,
//! `VerifyError`, and the shape of a family's opening. Their byte layouts are
//! `docs/spec/proof.md` §9, and a key's load rules §7.2.
//!
//! Every committed column is committed by Akita (`docs/spec/pcs.md`), in three
//! groups whose commitments three different parties carry: a statement shard's
//! `M` columns in the statement, its `W` columns in its proof, and its family's
//! `S` columns in the key.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use constants::memory::TS_BITS;
use constants::{generic_table, lookup_channel};
use constraints::lookup::{check_discharge, ChannelSpec};
use constraints::memory::check_memory;
use constraints::{CircuitArtifact, FamilyCircuit, PolyAddress, VirtualKind};
use field::{Fp, Fp2};
use gkr_verify::{BoundaryFinals, GkrProof, SumcheckProof};
use pcs_verify::proof::{Fold, Stage, Tensor, Terminal};
use pcs_verify::{setup_need, Commitment, Schedule, Setup};

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
    /// The opening of the shard's committed columns at the GKR pass's point.
    Opening(&'static str),
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
            VerifyError::Opening(why) => write!(f, "opening: {why}"),
        }
    }
}

// ---------------------------------------------------------------------------
// PublicInputs
// ---------------------------------------------------------------------------

/// What a statement is about, `docs/spec/proof.md` §1.1: the two public
/// payloads and the exit status the outside world asserts, then the record the
/// prover's global phase fixed — every shard's memory commitment and roots, the
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
    /// Per shard, in statement order, the commitment to its `M` columns.
    pub memory_commitments: Vec<Commitment>,
    /// Per shard, in statement order, `[read_root, write_root]`.
    pub memory_roots: Vec<[Fp2; 2]>,
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
            w.fp(x);
        }
        w.count(self.memory_commitments.len());
        for c in &self.memory_commitments {
            write_commitment(&mut w, c);
        }
        w.count(self.memory_roots.len());
        for [read, write] in &self.memory_roots {
            w.fp2(*read);
            w.fp2(*write);
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
            Some(r.fp()?.to_u64())
                .filter(|t| *t < 1 << TS_BITS)
                .ok_or("a boundary timestamp is not below 2^38")
        };
        for t in boundary.reg_ts.iter_mut() {
            *t = timestamp(&mut r)?;
        }
        boundary.pc_ts = timestamp(&mut r)?;
        for v in boundary.reg_values.iter_mut() {
            *v = u32::try_from(r.fp()?.to_u64())
                .map_err(|_| "a boundary value is not below 2^32")?;
        }
        let commitments = r.count(4)?;
        let memory_commitments = (0..commitments)
            .map(|_| read_commitment(&mut r))
            .collect::<Read<Vec<_>>>()?;
        let roots = r.count(32)?;
        let memory_roots = (0..roots)
            .map(|_| Ok([r.fp2()?, r.fp2()?]))
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

/// One shard's proof, `docs/spec/proof.md` §4 and §9. Its lengths are
/// fixed by the key's circuit for `family`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardProof {
    pub family: u32,
    pub shard_index: u32,
    /// `[start, end)`, the claimed time window: [`crate::TRIVIAL_TS_WINDOW`]
    /// for a window family (`docs/spec/proof.md` §8).
    pub ts_window: [u64; 2],
    /// The global state digest the prover seeded this shard with.
    pub global_digest: Fp2,
    /// The commitment to the shard's `W` columns, multiplicities included.
    pub witness_commitment: Commitment,
    /// The top layer: one value per output-map entry, in its order.
    pub outputs: Vec<Fp2>,
    /// One sumcheck per gate list, transition 0 first.
    pub gkr: GkrProof,
    /// Every committed column — `M`, `W`, `S` — opened at the GKR pass's
    /// point.
    pub opening: pcs_verify::Proof,
}

impl ShardProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.family);
        w.u32(self.shard_index);
        w.u64(self.ts_window[0]);
        w.u64(self.ts_window[1]);
        w.fp2(self.global_digest);
        write_commitment(&mut w, &self.witness_commitment);
        w.fp2s(&self.outputs);
        write_gkr(&mut w, &self.gkr);
        write_opening(&mut w, &self.opening);
        w.bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ShardProof, &'static str> {
        let mut r = Reader::new(bytes);
        let family = r.u32()?;
        let shard_index = r.u32()?;
        let ts_window = [r.u64()?, r.u64()?];
        let global_digest = r.fp2()?;
        let witness_commitment = read_commitment(&mut r)?;
        let outputs = r.fp2s()?;
        let gkr = read_gkr(&mut r)?;
        let opening = read_opening(&mut r)?;
        r.finish()?;
        Ok(ShardProof {
            family,
            shard_index,
            ts_window,
            global_digest,
            witness_commitment,
            outputs,
            gkr,
            opening,
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
                w.fp2(*c);
            }
        }
        w.fp2s(&layer.final_evals);
    }
}

/// [`write_gkr`]'s reader.
pub fn read_gkr(r: &mut Reader) -> Read<GkrProof> {
    let layers = r.count(8)?;
    let mut out = Vec::new();
    for _ in 0..layers {
        let n = r.count(4 * 16)?;
        let rounds = (0..n)
            .map(|_| Ok([r.fp2()?, r.fp2()?, r.fp2()?, r.fp2()?]))
            .collect::<Read<Vec<[Fp2; 4]>>>()?;
        let final_evals = r.fp2s()?;
        out.push(SumcheckProof {
            rounds,
            final_evals,
        });
    }
    Ok(GkrProof { layers: out })
}

/// A commitment on the wire: its payloads, each a list of `Fp`.
pub fn write_commitment(w: &mut Writer, c: &Commitment) {
    write_lists(w, &c.0);
}

/// [`write_commitment`]'s reader.
pub fn read_commitment(r: &mut Reader) -> Read<Commitment> {
    Ok(Commitment(read_lists(r)?))
}

fn write_lists(w: &mut Writer, xs: &[Vec<Fp>]) {
    w.count(xs.len());
    for x in xs {
        w.fps(x);
    }
}

fn read_lists(r: &mut Reader) -> Read<Vec<Vec<Fp>>> {
    let n = r.count(4)?;
    (0..n).map(|_| r.fps()).collect()
}

fn write_rounds(w: &mut Writer, rounds: &[Vec<Fp2>]) {
    w.count(rounds.len());
    for round in rounds {
        w.fp2s(round);
    }
}

fn read_rounds(r: &mut Reader) -> Read<Vec<Vec<Fp2>>> {
    let n = r.count(4)?;
    (0..n).map(|_| r.fp2s()).collect()
}

fn write_tensor(w: &mut Writer, t: &Tensor) {
    w.fp2(t.partials[0]);
    w.fp2(t.partials[1]);
    write_rounds(w, &t.rounds);
}

fn read_tensor(r: &mut Reader) -> Read<Tensor> {
    Ok(Tensor {
        partials: [r.fp2()?, r.fp2()?],
        rounds: read_rounds(r)?,
    })
}

fn write_digest(w: &mut Writer, d: &[Fp; 8]) {
    for x in d {
        w.fp(*x);
    }
}

fn read_digest(r: &mut Reader) -> Read<[Fp; 8]> {
    let mut d = [Fp::ZERO; 8];
    for x in d.iter_mut() {
        *x = r.fp()?;
    }
    Ok(d)
}

/// An opening on the wire, `docs/spec/proof.md` §9: per fold its messages in
/// transcript order, each optional one after a presence byte, then the
/// terminal's. Every length is the schedule's, which the opening's verifier
/// checks; the reader holds a count to the bytes left and nothing more.
pub fn write_opening(w: &mut Writer, p: &pcs_verify::Proof) {
    w.count(p.folds.len());
    for f in &p.folds {
        w.flag(f.tensor.is_some());
        if let Some(t) = &f.tensor {
            write_tensor(w, t);
        }
        w.fps(&f.opening);
        w.u32(f.nonce);
        write_lists(w, &f.successor);
        w.flag(f.digest.is_some());
        if let Some(d) = &f.digest {
            write_digest(w, d);
        }
        w.flag(f.norm.is_some());
        if let Some(x) = f.norm {
            w.fp(x);
        }
        w.count(f.range.len());
        for stage in &f.range {
            write_rounds(w, &stage.rounds);
            w.fp2s(&stage.claims);
        }
        w.flag(f.response_at.is_some());
        if let Some(x) = f.response_at {
            w.fp2(x);
        }
        write_rounds(w, &f.fused);
        w.fp2(f.value);
    }
    let t = &p.terminal;
    write_tensor(w, &t.tensor);
    write_lists(w, &t.partials);
    write_digest(w, &t.digest);
    w.u32(t.nonce);
    w.bytes(&t.response);
}

/// [`write_opening`]'s reader.
pub fn read_opening(r: &mut Reader) -> Read<pcs_verify::Proof> {
    // A fold's fixed part: five presence bytes and counts, the nonce, the value.
    let n = r.count(4 * 5 + 4 + 16)?;
    let mut folds = Vec::new();
    for _ in 0..n {
        let tensor = if r.flag()? {
            Some(read_tensor(r)?)
        } else {
            None
        };
        let opening = r.fps()?;
        let nonce = r.u32()?;
        let successor = read_lists(r)?;
        let digest = if r.flag()? {
            Some(read_digest(r)?)
        } else {
            None
        };
        let norm = if r.flag()? { Some(r.fp()?) } else { None };
        let stages = r.count(8)?;
        let range = (0..stages)
            .map(|_| {
                Ok(Stage {
                    rounds: read_rounds(r)?,
                    claims: r.fp2s()?,
                })
            })
            .collect::<Read<Vec<_>>>()?;
        let response_at = if r.flag()? { Some(r.fp2()?) } else { None };
        let fused = read_rounds(r)?;
        let value = r.fp2()?;
        folds.push(Fold {
            tensor,
            opening,
            nonce,
            successor,
            digest,
            norm,
            range,
            response_at,
            fused,
            value,
        });
    }
    let terminal = Terminal {
        tensor: read_tensor(r)?,
        partials: read_lists(r)?,
        digest: read_digest(r)?,
        nonce: r.u32()?,
        response: r.bytes()?.to_vec(),
    };
    Ok(pcs_verify::Proof { folds, terminal })
}

// ---------------------------------------------------------------------------
// The opening's shape
// ---------------------------------------------------------------------------

/// A family's committed groups in layout order — `M`, `W`, `S` — as column
/// counts. A group of no column has an empty commitment and no part in the
/// opening. `docs/spec/proof.md` §5.
pub fn committed_groups(artifact: &CircuitArtifact) -> [usize; 3] {
    [
        artifact.memory.len(),
        artifact.witness.len(),
        artifact.setup.len(),
    ]
}

/// The schedule every shard of a family is committed and opened under:
/// Akita's over the circuit's nonempty groups at its trace height.
pub fn opening_schedule(artifact: &CircuitArtifact) -> Schedule {
    let groups: Vec<usize> = committed_groups(artifact)
        .into_iter()
        .filter(|&c| c > 0)
        .collect();
    Schedule::new(artifact.trace_vars, &groups)
}

/// The setup prefix every family's opening reads: the longest any one needs.
pub fn pcs_setup_len(circuits: &[FamilyCircuit]) -> usize {
    circuits
        .iter()
        .map(|c| setup_need(&opening_schedule(&c.artifact)))
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// VerifyingKey
// ---------------------------------------------------------------------------

/// Everything `verify_shard` needs beyond a proof and its public inputs,
/// `docs/spec/proof.md` §7. A key comes from a channel the prover does
/// not control, and a verifier compares its `identity` with a registered one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    pub code_version: u32,
    pub config: VmConfig,
    pub entry_pc: u32,
    pub identity: ProgramIdentity,
    /// One per config family, in its order: the commitment to the family's
    /// `S` columns — its decoded table, the image column, the packed generic
    /// table — which the identity digests. Empty for a family with none.
    pub setup_commitments: Vec<Commitment>,
    /// One per config family, in its order.
    pub circuits: Vec<FamilyCircuit>,
    /// Akita's public setup, [`pcs_setup_len`] of the circuits: a function of
    /// them and a constant seed, so it is not on the wire, and
    /// [`VerifyingKey::from_bytes`] expands it once the key has loaded.
    pub pcs: Setup,
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
        w.raw(&self.identity.to_bytes());
        w.count(self.setup_commitments.len());
        for c in &self.setup_commitments {
            write_commitment(&mut w, c);
        }
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

    /// Decode, then [`VerifyingKey::check`], then expand the setup.
    pub fn from_bytes(bytes: &[u8]) -> Result<VerifyingKey, String> {
        let mut key = Self::decode(bytes).map_err(String::from)?;
        if key.to_bytes() != bytes {
            return Err("the key is not the canonical encoding of itself".into());
        }
        key.check()?;
        key.pcs = Setup::expand(pcs_setup_len(&key.circuits));
        Ok(key)
    }

    fn decode(bytes: &[u8]) -> Read<VerifyingKey> {
        let mut r = Reader::new(bytes);
        let code_version = r.u32()?;
        let config = VmConfig::from_bytes(r.bytes()?).ok_or("the VmConfig does not decode")?;
        let entry_pc = r.u32()?;
        let identity = ProgramIdentity::from_bytes(r.take(64)?.try_into().expect("64 bytes"))
            .ok_or("a field element is not canonical")?;
        let lists = r.count(4)?;
        let setup_commitments = (0..lists)
            .map(|_| read_commitment(&mut r))
            .collect::<Read<Vec<_>>>()?;
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
            circuits,
            pcs: Setup(Vec::new()),
        })
    }

    /// The load rules of `docs/spec/proof.md` §7.2. Run once, where a key is
    /// built or loaded. The setup is derived, not loaded, and not read here.
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
            return Err("the key has not one setup commitment per config family".into());
        }
        let identity = identity_digest(
            self.code_version,
            &self.config,
            self.entry_pc,
            &self.setup_commitments,
        );
        if identity != self.identity {
            return Err(
                "the identity is not the digest of the key's config, entry pc and setup".into(),
            );
        }
        if self.circuits.len() != families.len() {
            return Err("the key has not one circuit per config family".into());
        }
        for (i, (c, (family, height))) in self.circuits.iter().zip(families).enumerate() {
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
            let schedule = opening_schedule(&c.artifact);
            if !schedule.fits(&self.setup_commitments[i], c.artifact.setup.len()) {
                return Err(format!(
                    "{name}: the setup commitment is not its setup columns' shape"
                ));
            }
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
