//! A recursion node (`docs/spec/recursion.md` §8): what its image holds, and
//! what it does, as one procedure a host and a guest both run through a
//! [`Driver`] — the host natively, computing every word of advice the guest
//! will read, and the guest by its coprocessor calls.
//!
//! A node verifies **statements** of one or two programs and folds their
//! deferred checks into one accumulator. A **leaf** verifies a slice of one
//! statement of the base program. An **internal node** verifies two to four
//! whole statements of the recursion programs — its children's proofs —
//! reads each child's journal out of the public window step 10c binds, holds
//! the children to one another, and folds their accumulators beside their
//! shards' checks.
//!
//! **The image** ([`node_image`]) is everything static: each program's
//! families' shard tapes, pooled so a tape two programs share is held once,
//! the prologue filling a shard's slots from the node's cells and the fold
//! after it, the MSMs' templates, step 10b's boundary half and the node's
//! constants — encoded as a guest replays them, so a host replays the very
//! words a guest does. [`NodeImage::read`] reads it on both sides.
//!
//! **The procedure** ([`node`]) is everything the statements decide: which
//! shards, the global transcript's chain through them (`crate::chain`), the
//! checks that cross shards and children, and the journal ([`journal`]). What
//! it builds at run time it builds as tapes too, with no field arithmetic of
//! its own: a delegated `Fr` would bring two families.

use alloc::vec::Vec;

use constants::memory::TS_BITS;
use constants::{family, fr_op, generic_table, guest_memory, transcript_tags as tags};

use crate::chain::{self, Shape};
use crate::fold::{
    finish, load_point, point_template, prelude, shard_fold, FoldPoint, Hole, Node, Side, Template,
    POINT_CELLS,
};
use crate::tape::{encode, shard_tape, Cell, CellTranscript, Limbs, Op, Tape, ZERO};
use crate::{check_memory_windows, shard_window, statement_shards, VerifyingKey, VmConfig};

/// Every shard tape's first cell: cells `0..3` are the zero state.
pub const FIRST: Cell = 3;

/// The statement cells' offsets from [`NodeImage::claims`]: what a node is
/// told of the statement it is verifying, and holds itself to where it can —
/// the global digest and the memory challenges, by the node with the
/// statement's last shard; `io_digest`, by one with a public shard; the exit
/// status and the entry pc, by the last again and by the identity; the
/// chain's state at the node's first shard, by the node before it. Then the
/// boundary's 64 scalars, the boundary template's scratch, and an internal
/// node's claimed identities of the two recursion programs.
pub mod claim {
    pub const DIGEST: u32 = 0;
    pub const MEMORY: u32 = 1;
    pub const IO: u32 = 5;
    pub const EXIT: u32 = 6;
    pub const CHAIN: u32 = 7;
    pub const PENDING: u32 = 10;
    pub const ENTRY: u32 = 11;
    pub const CELLS: u32 = 12;
    pub const BOUNDARY: u32 = 12;
    pub const SCRATCH: u32 = 76;
    pub const IDENTITIES: u32 = SCRATCH + 2048;
    /// The region's size.
    pub const REGION: u32 = IDENTITIES + 2;
}

/// A node's journal, one cell a 32-byte word: the base statement's facts
/// every node of its tree agrees on, what this node covers of it, and the
/// accumulator.
pub mod journal {
    /// [`crate::chain::shape_digest`] of the base statement.
    pub const SHAPE: usize = 0;
    /// The base statement's claims: digest, memory challenges, `io_digest`,
    /// exit status.
    pub const DIGEST: usize = 1;
    pub const MEMORY: usize = 2;
    pub const IO: usize = 6;
    pub const EXIT: usize = 7;
    /// Its shard count, and the shards this node covers, `FROM..TO`.
    pub const TOTAL: usize = 8;
    pub const FROM: usize = 9;
    pub const TO: usize = 10;
    /// The chain's state at `FROM` and at `TO`: three lanes and a pending
    /// input, 0 where there is none.
    pub const CHAIN_IN: usize = 11;
    pub const CHAIN_OUT: usize = 15;
    /// The products of the covered shards' read roots and write roots.
    pub const READS: usize = 19;
    pub const WRITES: usize = 20;
    /// The boundary factors `(W_b, R_b)` where `TO` is `TOTAL`, `(1, 1)`
    /// otherwise.
    pub const FACTORS: usize = 21;
    /// The first and last covered shard's family and time window.
    pub const FIRST: usize = 23;
    pub const LAST: usize = 26;
    /// The accumulator: `A`'s `x` and `y`, four limbs each, then `B`'s.
    pub const A: usize = 29;
    pub const B: usize = 37;
    /// The identities an internal node required of its children, the leaf
    /// program's and its own; 0 for a leaf.
    pub const IDENTITIES: usize = 45;
    pub const CELLS: usize = 47;
    /// The journal's bytes, a window's payload.
    pub const BYTES: u32 = 32 * CELLS as u32;
}

/// A program whose statements a node verifies: its config, and its
/// families' counts of identity's setup commitments — both of which its
/// image derives — but not its identity, which is a constant of a leaf for
/// the base program and a claim of an internal node for its children's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramKey {
    pub code_version: u32,
    pub config: VmConfig,
    pub setups: Vec<u32>,
}

impl ProgramKey {
    /// The key a config implies: a family's setup commitments are its
    /// decoded table's columns — its circuit's `S` columns less the generic
    /// table's, which the SRS digest binds — and `INIT_TEARDOWN`'s image.
    pub fn of(config: &VmConfig) -> ProgramKey {
        let setups = config
            .families
            .iter()
            .map(|(f, h)| {
                let circuit = config
                    .circuit(*f, h.trailing_zeros())
                    .expect("node: a family the registry has");
                let table = if circuit.reads_generic_table() {
                    generic_table::WIDTH
                } else {
                    0
                };
                (circuit.artifact.setup.len() - table) as u32
            })
            .collect();
        ProgramKey {
            code_version: family::CODE_VERSION,
            config: config.clone(),
            setups,
        }
    }

    fn write(&self, w: &mut Words) {
        w.put(self.code_version);
        let config = self.config.to_bytes();
        w.list(&words_of(&config));
        w.put(config.len() as u32);
        w.list(&self.setups);
    }

    fn read(r: &mut Reader) -> Option<ProgramKey> {
        let code_version = r.get()?;
        let words = r.list()?;
        let len = r.get()? as usize;
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let config = VmConfig::from_bytes(bytes.get(..len)?)?;
        let setups = r.list()?.to_vec();
        (setups.len() == config.families.len()).then_some(ProgramKey {
            code_version,
            config,
            setups,
        })
    }

    /// Several keys, as an internal node's build reads them.
    pub fn list_to_bytes(keys: &[ProgramKey]) -> Vec<u8> {
        let mut w = Words::default();
        w.put(keys.len() as u32);
        for k in keys {
            k.write(&mut w);
        }
        w.0.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    pub fn list_from_bytes(bytes: &[u8]) -> Option<Vec<ProgramKey>> {
        let words: Vec<u32> = bytes
            .chunks(4)
            .map(|c| Some(u32::from_le_bytes(c.try_into().ok()?)))
            .collect::<Option<Vec<_>>>()?;
        let mut r = Reader {
            words: &words,
            at: 0,
        };
        let keys = (0..r.get()?)
            .map(|_| ProgramKey::read(&mut r))
            .collect::<Option<Vec<_>>>()?;
        (r.at == words.len()).then_some(keys)
    }
}

/// Bytes as little-endian words, zero-padded.
fn words_of(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|c| {
            let mut w = [0u8; 4];
            w[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(w)
        })
        .collect()
}

/// What every node of a tree shares of the base program and the ceremony:
/// the base program's key and identity, the SRS digest and the generic
/// table, as canonical bytes — a node builds them as constants by `IMM` and
/// `SHL`, with no field arithmetic of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseKey {
    pub program: ProgramKey,
    pub identity: [u8; 32],
    pub srs_digest: [u8; 32],
    pub generic_table: [[u8; 64]; generic_table::WIDTH],
}

impl BaseKey {
    /// The base key of `vk`, whose setup counts must be the ones its config
    /// implies.
    pub fn of(vk: &VerifyingKey) -> BaseKey {
        let program = ProgramKey::of(&vk.config);
        let counts: Vec<u32> = vk
            .setup_commitments
            .iter()
            .map(|s| s.len() as u32)
            .collect();
        assert_eq!(
            program.setups, counts,
            "node: the key's setups are its config's"
        );
        BaseKey {
            program,
            identity: vk.identity.0.to_bytes(),
            srs_digest: vk.srs_digest.to_bytes(),
            generic_table: vk.generic_table,
        }
    }

    /// The program's words ([`ProgramKey`]), then the identity, the SRS
    /// digest and the table's points, little-endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Words::default();
        self.program.write(&mut w);
        for b in [&self.identity[..], &self.srs_digest[..]]
            .into_iter()
            .chain(self.generic_table.iter().map(|p| &p[..]))
        {
            w.0.extend(words_of(b));
        }
        w.0.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<BaseKey> {
        let words = words_of(bytes);
        let mut r = Reader {
            words: &words,
            at: 0,
        };
        let program = ProgramKey::read(&mut r)?;
        let mut bytes_of = |n: usize| -> Option<Vec<u8>> {
            let ws = r.words.get(r.at..r.at + n / 4)?;
            r.at += n / 4;
            Some(ws.iter().flat_map(|w| w.to_le_bytes()).collect())
        };
        let identity = bytes_of(32)?.try_into().ok()?;
        let srs_digest = bytes_of(32)?.try_into().ok()?;
        let mut generic_table = [[0u8; 64]; generic_table::WIDTH];
        for p in generic_table.iter_mut() {
            p.copy_from_slice(&bytes_of(64)?);
        }
        (r.at == words.len() && 4 * words.len() == bytes.len()).then_some(BaseKey {
            program,
            identity,
            srs_digest,
            generic_table,
        })
    }
}

// ---------------------------------------------------------------------------
// The image
// ---------------------------------------------------------------------------

/// What a node is: a leaf of the base program, or an internal node over the
/// two recursion programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Leaf,
    Internal,
}

/// An encoded tape: the cells its imports fill, in blob order, and its body.
#[derive(Clone, Copy, Debug)]
pub struct Body<'a> {
    pub imports: &'a [u32],
    pub body: &'a [u32],
}

/// A template, replayed `times` in a row, its witnesses imported before each
/// replay: `before` cells, then two a hole.
#[derive(Clone, Debug)]
pub struct ImageTemplate<'a> {
    pub body: Body<'a>,
    pub times: u32,
    pub before: u32,
    pub holes: Vec<Hole>,
}

impl ImageTemplate<'_> {
    /// The run of cells its witnesses fill, if it has any.
    pub fn witnesses(&self) -> Option<core::ops::Range<Cell>> {
        let first = self.holes.first()?.into - self.before;
        Some(first..first + self.before + 2 * self.holes.len() as u32)
    }
}

/// One side's MSM: its prelude's phases, a point's template, its finish's.
#[derive(Clone, Debug)]
pub struct MsmImage<'a> {
    pub prelude: Vec<ImageTemplate<'a>>,
    pub point: ImageTemplate<'a>,
    pub finish: Vec<ImageTemplate<'a>>,
}

/// A family's shard, as the image holds it for one program.
#[derive(Clone, Debug)]
pub struct FamilyImage<'a> {
    pub family: u32,
    pub trace_vars: u32,
    /// The slots the procedure fills: the shard's index and window, its
    /// roots, and its memory commitments' limbs, four a point.
    pub index: Cell,
    pub window: Cell,
    pub roots: [Cell; 2],
    pub commitments: &'a [u32],
    /// What the procedure reads after it: the time window, and for step 10c
    /// the GKR point and the claims of `M[1]` and `M[2]`.
    pub ts: [Cell; 2],
    pub point: &'a [u32],
    pub claims: [Cell; 2],
    pub tape: Body<'a>,
    pub prologue: Body<'a>,
    pub fold: Body<'a>,
    pub points: Vec<FoldPoint>,
}

/// A program as an image holds it: its key, where its setup commitments are
/// among the merged points, and its families.
#[derive(Clone, Debug)]
pub struct ProgramImage<'a> {
    pub key: ProgramKey,
    pub merged: u32,
    pub families: Vec<FamilyImage<'a>>,
}

impl<'a> ProgramImage<'a> {
    pub fn family(&self, family: u32) -> Option<&FamilyImage<'a>> {
        self.families.iter().find(|f| f.family == family)
    }
}

/// A node's image, read: [`node_image`]'s words, borrowed.
#[derive(Clone, Debug)]
pub struct NodeImage<'a> {
    pub kind: Kind,
    pub node: Node,
    /// The statement cells ([`claim`]).
    pub claims: Cell,
    /// Where the procedure's own tapes take their cells.
    pub runtime: Cell,
    /// A leaf's base program identity; zeros for an internal node.
    pub identity: [u8; 32],
    pub srs_digest: [u8; 32],
    pub programs: Vec<ProgramImage<'a>>,
    pub constants: Body<'a>,
    /// Step 10b's statement half over the statement cells
    /// (`crate::chain::boundary`), and the factors `(W_b, R_b)` it leaves.
    pub boundary: Body<'a>,
    pub factors: (Cell, Cell),
    pub msm: [MsmImage<'a>; 2],
}

impl<'a> NodeImage<'a> {
    /// Read [`node_image`]'s words, or `None` if they are not its form.
    pub fn read(words: &'a [u32]) -> Option<NodeImage<'a>> {
        let mut r = Reader { words, at: 0 };
        let kind = match r.get()? {
            0 => Kind::Leaf,
            1 => Kind::Internal,
            _ => return None,
        };
        let (end, setups, points) = (r.get()?, r.get()?, r.get()?);
        let factors = (r.get()?, r.get()?);
        let bytes = |r: &mut Reader| -> Option<[u8; 32]> {
            let ws = r.words.get(r.at..r.at + 8)?;
            r.at += 8;
            let b: Vec<u8> = ws.iter().flat_map(|w| w.to_le_bytes()).collect();
            b.try_into().ok()
        };
        let identity = bytes(&mut r)?;
        let srs_digest = bytes(&mut r)?;
        let claims = end;
        let node = Node::at(claims + claim::REGION, setups, points);
        let pool = (0..r.get()?)
            .map(|_| r.body())
            .collect::<Option<Vec<_>>>()?;
        let msm = |r: &mut Reader<'a>| -> Option<MsmImage<'a>> {
            let phases = |r: &mut Reader<'a>| {
                let n = r.get()?;
                (0..n).map(|_| r.template()).collect::<Option<Vec<_>>>()
            };
            let prelude = phases(r)?;
            let point = r.template()?;
            let finish = phases(r)?;
            Some(MsmImage {
                prelude,
                point,
                finish,
            })
        };
        let msm = [msm(&mut r)?, msm(&mut r)?];
        let constants = r.body()?;
        let boundary = r.body()?;
        let programs = (0..r.get()?)
            .map(|_| {
                let key = ProgramKey::read(&mut r)?;
                let merged = r.get()?;
                let families = (0..r.get()?)
                    .map(|_| {
                        let (family, trace_vars, index, window) =
                            (r.get()?, r.get()?, r.get()?, r.get()?);
                        let roots = [r.get()?, r.get()?];
                        let commitments = r.list()?;
                        let ts = [r.get()?, r.get()?];
                        let point = r.list()?;
                        let claims = [r.get()?, r.get()?];
                        let tape = *pool.get(r.get()? as usize)?;
                        let (prologue, fold) = (r.body()?, r.body()?);
                        let points = (0..r.get()?)
                            .map(|_| {
                                Some(FoldPoint {
                                    limbs: r.get()?,
                                    scalar: r.get()?,
                                    side: if r.get()? == 0 { Side::A } else { Side::B },
                                })
                            })
                            .collect::<Option<Vec<_>>>()?;
                        Some(FamilyImage {
                            family,
                            trace_vars,
                            index,
                            window,
                            roots,
                            commitments,
                            ts,
                            point,
                            claims,
                            tape,
                            prologue,
                            fold,
                            points,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?;
                Some(ProgramImage {
                    key,
                    merged,
                    families,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        (r.at == words.len()).then_some(NodeImage {
            kind,
            runtime: node.end(),
            node,
            claims,
            identity,
            srs_digest,
            programs,
            constants,
            boundary,
            factors,
            msm,
        })
    }
}

#[derive(Default)]
struct Words(Vec<u32>);

impl Words {
    fn put(&mut self, w: u32) {
        self.0.push(w);
    }
    fn list(&mut self, ws: &[u32]) {
        self.put(ws.len() as u32);
        self.0.extend_from_slice(ws);
    }
    fn body(&mut self, ops: &[Op]) {
        let encoded = encode(ops);
        self.list(&encoded.imports);
        self.list(&encoded.body);
    }
    fn template(&mut self, t: &Template, times: u32, before: u32) {
        self.body(&t.ops);
        self.put(times);
        self.put(before);
        self.put(t.holes.len() as u32);
        for h in &t.holes {
            for w in [h.at as u32, h.of, h.into] {
                self.put(w);
            }
        }
    }
}

struct Reader<'a> {
    words: &'a [u32],
    at: usize,
}

impl<'a> Reader<'a> {
    fn get(&mut self) -> Option<u32> {
        let w = *self.words.get(self.at)?;
        self.at += 1;
        Some(w)
    }
    fn list(&mut self) -> Option<&'a [u32]> {
        let n = self.get()? as usize;
        let out = self.words.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(out)
    }
    fn body(&mut self) -> Option<Body<'a>> {
        Some(Body {
            imports: self.list()?,
            body: self.list()?,
        })
    }
    fn template(&mut self) -> Option<ImageTemplate<'a>> {
        let body = self.body()?;
        let (times, before) = (self.get()?, self.get()?);
        let holes = (0..self.get()?)
            .map(|_| {
                Some(Hole {
                    at: self.get()? as usize,
                    of: self.get()?,
                    into: self.get()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(ImageTemplate {
            body,
            times,
            before,
            holes,
        })
    }
}

/// A node's image as words: a leaf's for `base`'s program, or an internal
/// node's for `programs`, the leaf program's key and its own.
pub fn node_image(kind: Kind, base: &BaseKey, programs: &[ProgramKey]) -> Vec<u32> {
    use generic_table::WIDTH;
    let programs: Vec<&ProgramKey> = match kind {
        Kind::Leaf => alloc::vec![&base.program],
        Kind::Internal => programs.iter().collect(),
    };
    let own: u32 = programs.iter().flat_map(|p| &p.setups).sum();
    // Each program's families' tapes from `FIRST`, a tape two of them share
    // held once; and where each family's setup commitments are among the
    // merged points: the programs' in order, then the generic table's.
    let mut pool: Vec<Vec<Op>> = Vec::new();
    let mut shapes = Vec::new();
    let mut offset = 0;
    for p in &programs {
        let config = &p.config;
        let merged_at = offset;
        let mut families = Vec::new();
        for ((family, height), n) in config.families.iter().zip(&p.setups) {
            let vars = height.trailing_zeros();
            let circuit = config
                .circuit(*family, vars)
                .expect("node: a family the registry has");
            let mut merged: Vec<u32> = (0..*n).map(|j| 1 + offset + j).collect();
            if circuit.reads_generic_table() {
                merged.extend((0..WIDTH as u32).map(|k| 1 + own + k));
            }
            offset += n;
            let tape = shard_tape(config, &circuit, merged.len(), FIRST);
            let at = match pool.iter().position(|ops| *ops == tape.ops) {
                Some(at) => at,
                None => {
                    pool.push(tape.ops.clone());
                    pool.len() - 1
                }
            };
            families.push((*family, vars, tape, merged, at));
        }
        shapes.push((*p, merged_at, families));
    }
    let tapes = shapes.iter().flat_map(|s| &s.2);
    let end = tapes.clone().map(|f| f.2.end).max().unwrap_or(FIRST);
    let points = tapes
        .map(|f| 12 + f.2.outputs.commitments.len() as u32)
        .max()
        .unwrap_or(0)
        .max(12);
    let setups = own + WIDTH as u32;
    let claims = end;
    let node = Node::at(claims + claim::REGION, setups, points);

    // Step 10b's statement half, over the statement cells.
    let mut t = Tape::new(claims + claim::SCRATCH);
    let memory: [Cell; 4] = core::array::from_fn(|k| claims + claim::MEMORY + k as u32);
    let boundary: Vec<Cell> = (0..64).map(|k| claims + claim::BOUNDARY + k).collect();
    let pc = claims + claim::ENTRY;
    let factors = chain::boundary(&mut t, &boundary, claims + claim::EXIT, memory, pc);
    assert!(
        t.end() <= claims + claim::IDENTITIES,
        "node: the boundary's scratch"
    );
    let boundary = t.ops;

    let mut w = Words::default();
    w.put(match kind {
        Kind::Leaf => 0,
        Kind::Internal => 1,
    });
    for v in [end, setups, points, factors.0, factors.1] {
        w.put(v);
    }
    let identity = match kind {
        Kind::Leaf => base.identity,
        Kind::Internal => [0; 32],
    };
    w.0.extend(words_of(&identity));
    w.0.extend(words_of(&base.srs_digest));
    w.put(pool.len() as u32);
    for ops in &pool {
        w.body(ops);
    }
    for l in [&node.a, &node.b] {
        let phases = prelude(l);
        w.put(phases.len() as u32);
        for (t, times) in &phases {
            w.template(t, *times, 0);
        }
        // A point's split, six cells, sits just below its inverses.
        w.template(&point_template(l), 1, 6);
        let phases = finish(l);
        w.put(phases.len() as u32);
        for (t, times) in &phases {
            w.template(t, *times, 0);
        }
    }

    // The node's constants: `[1]_1`, the sentinel and the table's points.
    let mut ops = node.prelude();
    let mut t = Tape::new(node.scratch);
    for (k, point) in base.generic_table.iter().enumerate() {
        for (i, v) in transcript::g1_limbs(point).into_iter().enumerate() {
            let c = t.constant(v);
            t.fr(
                fr_op::ADD,
                node.setup + 4 * (own + k as u32) + i as u32,
                c,
                ZERO,
            );
        }
    }
    ops.extend(t.ops);
    w.body(&ops);
    w.body(&boundary);

    w.put(shapes.len() as u32);
    for (key, merged_at, families) in &shapes {
        key.write(&mut w);
        w.put(*merged_at);
        w.put(families.len() as u32);
        for (family, vars, tape, merged, at) in families {
            let (slots, out) = (&tape.slots, &tape.outputs);
            for v in [
                *family,
                *vars,
                slots.index,
                slots.window,
                slots.roots[0],
                slots.roots[1],
            ] {
                w.put(v);
            }
            let limbs: Vec<u32> = slots.memory_commitments.iter().flatten().copied().collect();
            w.list(&limbs);
            w.put(out.ts_window[0]);
            w.put(out.ts_window[1]);
            w.list(&out.point);
            // `PUBLIC_OUTPUT` has no `M[2]`: its circuit is `ZERO_WINDOWS`'.
            let public = matches!(*family, family::PUBLIC_INPUT | family::PUBLIC_OUTPUT);
            for i in [1, 2] {
                let claim = out.claims.get(i).filter(|_| public);
                w.put(claim.copied().unwrap_or(ZERO));
            }
            w.put(*at as u32);
            // The prologue: the claims and the setup commitments into the
            // slots.
            let mut t = Tape::new(node.scratch);
            t.fr(fr_op::ADD, slots.digest, claims + claim::DIGEST, ZERO);
            for (i, m) in slots.memory.iter().enumerate() {
                t.fr(fr_op::ADD, *m, claims + claim::MEMORY + i as u32, ZERO);
            }
            for (limbs, m) in slots.setup.iter().zip(merged) {
                for (i, c) in limbs.iter().enumerate() {
                    t.fr(fr_op::ADD, *c, node.setup + 4 * (m - 1) + i as u32, ZERO);
                }
            }
            w.body(&t.ops);
            let (fold, points) = shard_fold(tape, &node, merged);
            w.body(&fold);
            w.put(points.len() as u32);
            for p in &points {
                for v in [p.limbs, p.scalar, (p.side == Side::B) as u32] {
                    w.put(v);
                }
            }
        }
    }
    w.0
}

// ---------------------------------------------------------------------------
// The procedure
// ---------------------------------------------------------------------------

/// One statement a node verifies: which program's, its shape, the shards
/// of it, and its public windows' byte lengths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementHeader {
    pub program: u32,
    pub shard_counts: Vec<u32>,
    pub windows: Vec<u32>,
    pub from: u32,
    pub to: u32,
    pub input_len: u32,
    pub output_len: u32,
}

/// What a [`node`] is told at run time beside its image: its statements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub statements: Vec<StatementHeader>,
}

impl Header {
    /// A count of statements, then each: its program, a count and the
    /// counts, a count and the windows, `from`, `to` and the two lengths.
    pub fn to_words(&self) -> Vec<u32> {
        let mut w = Words::default();
        w.put(self.statements.len() as u32);
        for s in &self.statements {
            w.put(s.program);
            w.list(&s.shard_counts);
            w.list(&s.windows);
            for v in [s.from, s.to, s.input_len, s.output_len] {
                w.put(v);
            }
        }
        w.0
    }

    /// The header at the front of `words`, and how many words it took.
    pub fn read(words: &[u32]) -> Option<(Header, usize)> {
        let mut r = Reader { words, at: 0 };
        let statements = (0..r.get()?)
            .map(|_| {
                Some(StatementHeader {
                    program: r.get()?,
                    shard_counts: r.list()?.to_vec(),
                    windows: r.list()?.to_vec(),
                    from: r.get()?,
                    to: r.get()?,
                    input_len: r.get()?,
                    output_len: r.get()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some((Header { statements }, r.at))
    }
}

/// Advice a [`node`] asks for, named so a host knows what to give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Advice {
    /// An internal node's claimed identities: the leaf program's, its own.
    Identities,
    /// Program `p`'s setup commitments' limbs, every family's in order.
    Setup(u32),
    /// Statement `s`'s [`claim`] cells.
    Claims(u32),
    /// Statement `s`'s position `p`: its memory commitments' limbs, its read
    /// and write roots, its shard proof as its tape's blob.
    Commitments(u32, u32),
    Roots(u32, u32),
    Blob(u32, u32),
    /// Statement `s`'s public windows' words (`crate::public_io_words`).
    Input(u32),
    Output(u32),
    /// Statement `s`'s boundary scalars (`crate::boundary_scalars`).
    Boundary(u32),
}

/// How a [`node`] runs: natively on a host, by its calls in a guest.
pub trait Driver {
    /// Replay an image body; any imports it has were advised just before.
    fn replay(&mut self, body: &[u32]);
    /// Run ops built at run time.
    fn run(&mut self, ops: Vec<Op>);
    /// Fill `cells` with the advice `what` names.
    fn advise(&mut self, cells: &[Cell], what: Advice);
    /// Replay a template once, its witnesses imported first; `scalar` is
    /// the cell a point's split is of.
    fn template(&mut self, template: &ImageTemplate, scalar: Option<Cell>);
    /// Whether the point at `limbs` is infinity, as the advice says.
    fn infinity(&mut self, limbs: Cell) -> bool;
    /// A cell's value, which must be below `2^32`: what a node's control
    /// follows of the values its checks bind.
    fn read(&mut self, cell: Cell) -> u32;
    /// Publish the journal's cells.
    fn export(&mut self, cells: &[Cell]);
}

fn flush<D: Driver>(d: &mut D, t: &mut Tape) {
    let ops = core::mem::take(&mut t.ops);
    if !ops.is_empty() {
        d.run(ops);
    }
}

fn range(first: Cell, n: u32) -> Vec<Cell> {
    (first..first + n).collect()
}

/// One point into its side's MSM: held to the sentinel if the advice says it
/// is infinity, loaded and added if not.
fn point<D: Driver>(d: &mut D, image: &NodeImage, p: &FoldPoint) {
    let node = &image.node;
    let (l, msm) = match p.side {
        Side::A => (&node.a, &image.msm[0]),
        Side::B => (&node.b, &image.msm[1]),
    };
    let infinity = d.infinity(p.limbs);
    d.run(load_point(p, l, node.sentinel, infinity));
    if !infinity {
        d.template(&msm.point, Some(l.scalar));
    }
}

/// What verifying a statement leaves for the journal.
struct Statement {
    shape: Cell,
    /// The chain's state at the first shard and after the last: three lanes
    /// and a pending input, 0 where there is none.
    chain_in: [Cell; 4],
    chain_out: [Cell; 4],
    reads: Cell,
    writes: Cell,
    factors: (Cell, Cell),
    first: [Cell; 3],
    last: [Cell; 3],
    windows: Option<(Vec<Cell>, Vec<Cell>)>,
}

/// Shards `h.from..h.to` of statement `s`, of program `h.program`, whose
/// identity is the cell `identity`: verified and folded into the node's
/// accumulator. A shape the statement rules refuse, or shards it has not, is
/// a panic: the node has no proof.
fn statement<D: Driver>(
    d: &mut D,
    image: &NodeImage,
    s: u32,
    h: &StatementHeader,
    identity: Cell,
    rt: &mut Tape,
) -> Statement {
    let program = &image.programs[h.program as usize];
    let config = &program.key.config;
    let shape = Shape {
        config,
        shard_counts: &h.shard_counts,
        windows: &h.windows,
    };
    // Steps 1 to 3's rules, which a shape alone decides.
    assert_eq!(
        h.shard_counts.len(),
        config.families.len(),
        "node: a count a family"
    );
    check_memory_windows(config, &h.shard_counts, &h.windows).expect("node: the window rules");
    let payload = guest_memory::PUBLIC_PAYLOAD_BYTES;
    assert!(
        h.input_len <= payload && h.output_len <= payload,
        "node: a window's payload"
    );
    let total = shape.total();
    assert!(
        h.from < h.to && h.to <= total,
        "node: shards of the statement"
    );
    let shards = statement_shards(config, &h.shard_counts);
    let node = &image.node;
    let c = image.claims;

    // The claims; the program's identity over its setup commitments; the
    // shape every node of the statement journals.
    d.advise(&range(c, claim::CELLS), Advice::Claims(s));
    if image.kind == Kind::Internal {
        // A child ran to its exit.
        rt.assert_eq(c + claim::EXIT, ZERO);
    }
    let mut next = node.setup + 4 * program.merged;
    let lists: Vec<Vec<Limbs>> = program
        .key
        .setups
        .iter()
        .map(|n| {
            (0..*n)
                .map(|_| {
                    next += 4;
                    [next - 4, next - 3, next - 2, next - 1]
                })
                .collect()
        })
        .collect();
    let computed = chain::identity(
        rt,
        program.key.code_version,
        config,
        c + claim::ENTRY,
        &lists,
    );
    rt.assert_eq(computed, identity);
    let shape_digest = chain::shape_digest(rt, &shape);

    // The chain at the first shard: the prefix's end, or the claims'.
    let pending = chain::pending(&shape);
    let mut tr = if h.from == 0 {
        chain::prefix(rt, &shape, &image.srs_digest, identity, c + claim::IO)
    } else {
        CellTranscript::resume(c + claim::CHAIN, pending.then_some(c + claim::PENDING))
    };
    assert_eq!(
        tr.checkpoint().1.is_some(),
        pending,
        "node: the chain's parity"
    );
    let chain_in = lanes(tr.checkpoint());

    let one = rt.small(1);
    let (reads, writes) = (rt.copy(one), rt.copy(one));
    let mut ends: Option<(u32, Cell)> = None;
    let mut first: Option<[Cell; 3]> = None;
    let mut last = [ZERO; 3];
    let mut windows: Option<(Vec<Cell>, Vec<Cell>)> = None;
    for p in h.from..h.to {
        let (family, index) = shards[p as usize];
        let f = program
            .family(family)
            .expect("node: every family has its image");

        // The shard's memory commitments, absorbed; its index and window.
        flush(d, rt);
        d.advise(f.commitments, Advice::Commitments(s, p));
        let list: Vec<Limbs> = f
            .commitments
            .chunks_exact(4)
            .map(|l| [l[0], l[1], l[2], l[3]])
            .collect();
        chain::segment(rt, &mut tr, &shape, p, &[list]);
        let window = shard_window(family, index, &h.windows, f.trace_vars).unwrap_or(0);
        for (slot, v) in [(f.index, index), (f.window, window)] {
            let v = rt.small(v as u64);
            rt.fr(fr_op::ADD, slot, v, ZERO);
        }
        flush(d, rt);

        // The shard.
        d.replay(f.prologue.body);
        d.advise(&f.roots, Advice::Roots(s, p));
        d.advise(f.tape.imports, Advice::Blob(s, p));
        d.replay(f.tape.body);

        // Across shards: the roots' products, the time windows, step 10c.
        rt.fr(fr_op::MUL, reads, reads, f.roots[0]);
        rt.fr(fr_op::MUL, writes, writes, f.roots[1]);
        let id = rt.small(family as u64);
        let (start, end) = (rt.copy(f.ts[0]), rt.copy(f.ts[1]));
        if family::CYCLE_OWNING[family as usize] {
            // Not empty, and after the last of its family's windows.
            let span = rt.sub(end, start);
            let span = rt.sub(span, one);
            chain::below(rt, span, TS_BITS + 1);
            if let Some((g, e)) = ends {
                if g == family {
                    let gap = rt.sub(start, e);
                    chain::below(rt, gap, TS_BITS + 1);
                }
            }
        }
        ends = Some((family, end));
        first.get_or_insert([id, start, end]);
        last = [id, start, end];
        if matches!(family, family::PUBLIC_INPUT | family::PUBLIC_OUTPUT) {
            if windows.is_none() {
                let n = |len: u32| 1 + len.div_ceil(4);
                let (i, o) = (rt.fresh(n(h.input_len)), rt.fresh(n(h.output_len)));
                let (i, o) = (range(i, n(h.input_len)), range(o, n(h.output_len)));
                flush(d, rt);
                d.advise(&i, Advice::Input(s));
                d.advise(&o, Advice::Output(s));
                let ib = chain::window_bytes(rt, &i, h.input_len as usize);
                let ob = chain::window_bytes(rt, &o, h.output_len as usize);
                let io = chain::io_digest(rt, &ib, &ob);
                rt.assert_eq(io, c + claim::IO);
                windows = Some((i, o));
            }
            let (i, o) = windows.as_ref().expect("the windows are advised");
            let (claim, words) = if family == family::PUBLIC_INPUT {
                (f.claims[1], i)
            } else {
                (f.claims[0], o)
            };
            chain::public_value(rt, f.point, claim, words);
        }
        flush(d, rt);

        // The fold.
        d.replay(f.fold.body);
        for pt in &f.points {
            point(d, image, pt);
        }
    }
    let chain_out = lanes(tr.checkpoint());

    // The statement's end: the suffix, the claims it settles, the boundary,
    // and where the node holds the whole statement, the memory argument.
    let factors = if h.to == total {
        let b = range(c + claim::BOUNDARY, 64);
        flush(d, rt);
        d.advise(&b, Advice::Boundary(s));
        let (memory, digest) = chain::suffix(rt, &mut tr, &shape, &b);
        for (k, m) in memory.iter().enumerate() {
            rt.assert_eq(*m, c + claim::MEMORY + k as u32);
        }
        rt.assert_eq(digest, c + claim::DIGEST);
        flush(d, rt);
        d.replay(image.boundary.body);
        let factors = (rt.copy(image.factors.0), rt.copy(image.factors.1));
        if h.from == 0 {
            chain::reconcile(rt, reads, writes, factors);
        }
        factors
    } else {
        (one, one)
    };
    flush(d, rt);
    Statement {
        shape: shape_digest,
        chain_in,
        chain_out,
        reads,
        writes,
        factors,
        first: first.expect("a node verifies a shard"),
        last,
        windows,
    }
}

/// A transcript checkpoint's lanes — cells of the transcript's own, which no
/// later op overwrites — and its pending input, a copy (`chain::segment`).
fn lanes((state, pending): (Cell, Option<Cell>)) -> [Cell; 4] {
    [state, state + 1, state + 2, pending.unwrap_or(ZERO)]
}

/// The journal's cells over what a statement left, the accumulator, and the
/// identities.
fn journal_cells(
    facts: &[Cell],
    [total, from, to]: [Cell; 3],
    s: &Statement,
    node: &Node,
    identities: [Cell; 2],
) -> Vec<Cell> {
    let mut cells = Vec::with_capacity(journal::CELLS);
    cells.push(s.shape);
    cells.extend_from_slice(facts);
    cells.extend([total, from, to]);
    cells.extend(s.chain_in);
    cells.extend(s.chain_out);
    cells.extend([s.reads, s.writes, s.factors.0, s.factors.1]);
    cells.extend(s.first);
    cells.extend(s.last);
    cells.extend(range(node.a.result, POINT_CELLS));
    cells.extend(range(node.b.result, POINT_CELLS));
    cells.extend(identities);
    assert_eq!(cells.len(), journal::CELLS);
    cells
}

/// A node: its statements verified and folded, and its journal
/// ([`journal`]).
pub fn node<D: Driver>(d: &mut D, image: &NodeImage, h: &Header) {
    let node = &image.node;
    let c = image.claims;
    let mut rt = Tape::new(image.runtime);
    match image.kind {
        Kind::Leaf => assert!(
            h.statements.len() == 1 && h.statements[0].program == 0,
            "node: a leaf verifies one base statement"
        ),
        Kind::Internal => assert!(
            (2..=4).contains(&h.statements.len())
                && h.statements.iter().all(|s| {
                    s.program < 2
                        && s.from == 0
                        && s.to == s.shard_counts.iter().sum::<u32>()
                        && s.input_len == 0
                        && s.output_len == journal::BYTES
                }),
            "node: an internal node verifies two to four whole children"
        ),
    }

    // The node's constants and the MSMs' preludes.
    d.replay(image.constants.body);
    for msm in &image.msm {
        for t in &msm.prelude {
            for _ in 0..t.times {
                d.template(t, None);
            }
        }
    }

    // The identities, and the setup commitments of every program verified.
    let identities = match image.kind {
        Kind::Leaf => [rt.bytes(&image.identity), ZERO],
        Kind::Internal => {
            let ids = range(c + claim::IDENTITIES, 2);
            d.advise(&ids, Advice::Identities);
            [ids[0], ids[1]]
        }
    };
    let mut used = [false; 2];
    for s in &h.statements {
        used[s.program as usize] = true;
    }
    for (p, program) in image.programs.iter().enumerate() {
        if used[p] {
            let n: u32 = program.key.setups.iter().sum();
            d.advise(
                &range(node.setup + 4 * program.merged, 4 * n),
                Advice::Setup(p as u32),
            );
        }
    }

    let small = |rt: &mut Tape, v: u32| rt.small(v as u64);
    let journal = match image.kind {
        Kind::Leaf => {
            let h = &h.statements[0];
            let s = statement(d, image, 0, h, identities[0], &mut rt);
            let facts = [
                range(c + claim::DIGEST, 1),
                range(c + claim::MEMORY, 4),
                alloc::vec![c + claim::IO, c + claim::EXIT],
            ]
            .concat();
            let (total, from, to) = (
                small(&mut rt, h.shard_counts.iter().sum()),
                small(&mut rt, h.from),
                small(&mut rt, h.to),
            );
            merged(d, image, &used);
            journal_cells(&facts, [total, from, to], &s, node, [ZERO, ZERO])
        }
        Kind::Internal => internal(d, image, h, identities, &mut rt),
    };
    flush(d, &mut rt);
    d.export(&journal);
}

/// The merged points of the programs verified, then the MSMs' finishes.
fn merged<D: Driver>(d: &mut D, image: &NodeImage, used: &[bool; 2]) {
    let node = &image.node;
    let own: u32 = image.programs.iter().flat_map(|p| &p.key.setups).sum();
    let mut points = alloc::vec![FoldPoint {
        limbs: node.generator,
        scalar: node.merged,
        side: Side::A,
    }];
    for (p, program) in image.programs.iter().enumerate() {
        let n: u32 = program.key.setups.iter().sum();
        if used[p] {
            points.extend((program.merged..program.merged + n).map(|j| FoldPoint {
                limbs: node.setup + 4 * j,
                scalar: node.merged + 1 + j,
                side: Side::A,
            }));
        }
    }
    points.extend((own..own + generic_table::WIDTH as u32).map(|j| FoldPoint {
        limbs: node.setup + 4 * j,
        scalar: node.merged + 1 + j,
        side: Side::A,
    }));
    for p in &points {
        point(d, image, p);
    }
    for msm in &image.msm {
        for t in &msm.finish {
            for _ in 0..t.times {
                d.template(t, None);
            }
        }
    }
}

/// An internal node's glue: each child verified, its journal read out of
/// its output window, held to its neighbour, and its accumulator folded.
fn internal<D: Driver>(
    d: &mut D,
    image: &NodeImage,
    h: &Header,
    identities: [Cell; 2],
    rt: &mut Tape,
) -> Vec<Cell> {
    let node = &image.node;
    let mut children: Vec<(Vec<Cell>, Statement)> = Vec::new();
    for (s, child) in h.statements.iter().enumerate() {
        let identity = identities[child.program as usize];
        let st = statement(d, image, s as u32, child, identity, rt);

        // The child's journal: a cell a 32-byte word of its output window,
        // `Σ_i w_i·2^{32i}` over its eight words.
        let (_, output) = st.windows.as_ref().expect("a child has its public windows");
        let cells: Vec<Cell> = (0..journal::CELLS)
            .map(|k| {
                let words = &output[1 + 8 * k..1 + 8 * (k + 1)];
                let acc = rt.copy(words[0]);
                for (i, w) in words.iter().enumerate().skip(1) {
                    let mut unit = [0u8; 32];
                    unit[4 * i] = 1;
                    let unit = rt.bytes(&unit);
                    rt.mac(acc, *w, unit);
                }
                acc
            })
            .collect();
        if child.program == 1 {
            // An internal child required what this node requires.
            for (i, id) in identities.iter().enumerate() {
                rt.assert_eq(cells[journal::IDENTITIES + i], *id);
            }
        }

        // Its neighbour: one base statement, adjacent shards, a chain that
        // meets, and time windows in order across the seam.
        if let Some((before, _)) = children.last() {
            let same = journal::SHAPE..journal::FROM;
            for k in same {
                rt.assert_eq(cells[k], before[k]);
            }
            rt.assert_eq(cells[journal::FROM], before[journal::TO]);
            for k in 0..4 {
                rt.assert_eq(cells[journal::CHAIN_IN + k], before[journal::CHAIN_OUT + k]);
            }
            flush(d, rt);
            let (g, f) = (d.read(before[journal::LAST]), d.read(cells[journal::FIRST]));
            if g == f && family::CYCLE_OWNING.get(f as usize) == Some(&true) {
                let gap = rt.sub(cells[journal::FIRST + 1], before[journal::LAST + 2]);
                chain::below(rt, gap, TS_BITS + 1);
            }
        }

        // Its accumulator, under a weight drawn after its journal.
        let mut tr = CellTranscript::at(node.state);
        tr.append(rt, tags::FOLD_CHILD, &cells);
        let w = tr.challenge(rt, tags::FOLD_WEIGHT);
        for k in 0..3 {
            rt.fr(fr_op::ADD, node.state + k, tr.state() + k, ZERO);
        }
        for (at, side) in [(journal::A, Side::A), (journal::B, Side::B)] {
            // A coordinate's four 64-bit limbs as the two 128-bit halves a
            // point's load reads.
            let halves = rt.fresh(4);
            let mut shift = [0u8; 32];
            shift[8] = 1;
            let shift = rt.bytes(&shift);
            for half in 0..4 {
                let (lo, hi) = (cells[at + 2 * half], cells[at + 2 * half + 1]);
                rt.fr(fr_op::ADD, halves + half as u32, lo, ZERO);
                rt.mac(halves + half as u32, hi, shift);
            }
            flush(d, rt);
            point(
                d,
                image,
                &FoldPoint {
                    limbs: halves,
                    scalar: w,
                    side,
                },
            );
        }
        flush(d, rt);
        children.push((cells, st));
    }

    // The node's journal: the children's statement facts, the shards they
    // cover together, the products, and where they cover the whole base
    // statement, the memory argument over them.
    let (first, _) = &children[0];
    let (last, _) = children.last().expect("two children at least");
    let (reads, writes) = (
        rt.copy(first[journal::READS]),
        rt.copy(first[journal::WRITES]),
    );
    for (cells, _) in &children[1..] {
        rt.fr(fr_op::MUL, reads, reads, cells[journal::READS]);
        rt.fr(fr_op::MUL, writes, writes, cells[journal::WRITES]);
    }
    let factors = (last[journal::FACTORS], last[journal::FACTORS + 1]);
    flush(d, rt);
    let (from, to, total) = (
        d.read(first[journal::FROM]),
        d.read(last[journal::TO]),
        d.read(first[journal::TOTAL]),
    );
    if from == 0 && to == total {
        chain::reconcile(rt, reads, writes, factors);
    }
    let combined = Statement {
        shape: first[journal::SHAPE],
        chain_in: [0, 1, 2, 3].map(|k| first[journal::CHAIN_IN + k]),
        chain_out: [0, 1, 2, 3].map(|k| last[journal::CHAIN_OUT + k]),
        reads,
        writes,
        factors,
        first: [0, 1, 2].map(|k| first[journal::FIRST + k]),
        last: [0, 1, 2].map(|k| last[journal::LAST + k]),
        windows: None,
    };
    let used = [
        h.statements.iter().any(|s| s.program == 0),
        h.statements.iter().any(|s| s.program == 1),
    ];
    merged(d, image, &used);
    journal_cells(
        &first[journal::DIGEST..journal::TOTAL],
        [
            first[journal::TOTAL],
            first[journal::FROM],
            last[journal::TO],
        ],
        &combined,
        node,
        identities,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tape::decode;

    fn config() -> VmConfig {
        VmConfig {
            families: alloc::vec![
                (family::ADD_SUB_LUI_AUIPC, 1 << 20),
                (family::INIT_TEARDOWN, 1 << 20),
                (family::ZERO_WINDOWS, 1 << 20),
                (family::PUBLIC_INPUT, 1 << 12),
                (family::PUBLIC_OUTPUT, 1 << 12),
                (family::ADVICE_WINDOWS, 1 << 20),
            ],
            bytecode_size_words: 1 << 20,
        }
    }

    /// The keys and a header round-trip their bytes and words, and both
    /// kinds of image read back: a program a key, a family a config family,
    /// every body runs of field frames, a tape two programs share held once,
    /// and a word more refused.
    #[test]
    fn a_node_image_reads_back() {
        let program = ProgramKey::of(&config());
        assert_eq!(program.setups, [7, 1, 0, 0, 0, 0]);
        let base = BaseKey {
            program: program.clone(),
            identity: [7; 32],
            srs_digest: [9; 32],
            generic_table: [[3; 64]; generic_table::WIDTH],
        };
        assert_eq!(BaseKey::from_bytes(&base.to_bytes()), Some(base.clone()));
        let programs = [program.clone(), program.clone()];
        let bytes = ProgramKey::list_to_bytes(&programs);
        assert_eq!(
            ProgramKey::list_from_bytes(&bytes).as_deref(),
            Some(&programs[..])
        );
        let header = Header {
            statements: alloc::vec![
                StatementHeader {
                    program: 0,
                    shard_counts: alloc::vec![2, 1, 0, 1, 1, 0],
                    windows: alloc::vec![],
                    from: 0,
                    to: 5,
                    input_len: 0,
                    output_len: journal::BYTES,
                };
                2
            ],
        };
        let words = header.to_words();
        assert_eq!(Header::read(&words), Some((header, words.len())));

        for (kind, n) in [(Kind::Leaf, 1), (Kind::Internal, 2)] {
            let words = node_image(kind, &base, &programs);
            let image = NodeImage::read(&words).expect("the image reads");
            assert_eq!(image.kind, kind);
            assert_eq!(image.programs.len(), n);
            let want: Vec<u32> = program.config.families.iter().map(|(f, _)| *f).collect();
            for p in &image.programs {
                assert_eq!(p.key, program);
                let families: Vec<u32> = p.families.iter().map(|f| f.family).collect();
                assert_eq!(families, want);
            }
            if kind == Kind::Internal {
                let [a, b] = [0, 1].map(|p| image.programs[p].families[0].tape.body.as_ptr());
                assert_eq!(a, b, "one tape for the two programs' family");
            }
            let bodies = image
                .programs
                .iter()
                .flat_map(|p| &p.families)
                .flat_map(|f| [f.tape.body, f.prologue.body, f.fold.body])
                .chain([image.constants.body, image.boundary.body]);
            for body in bodies {
                assert!(decode(body).is_some());
            }
            let mut longer = words.clone();
            longer.push(0);
            assert!(NodeImage::read(&longer).is_none());
        }
    }
}
