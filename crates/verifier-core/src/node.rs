//! A recursion leaf (`docs/spec/recursion.md` §8): what its image holds, and
//! what it does, as one procedure a host and a guest both run through a
//! [`Driver`] — the host natively, computing every word of advice the guest
//! will read, and the guest by its coprocessor calls.
//!
//! **The image** ([`leaf_image`]) is everything static, built from the base
//! program's [`BaseKey`]: each family's shard tape, the prologue that fills
//! its slots from the node's cells and the fold that follows it, the MSMs'
//! templates and the node's constants — encoded as a guest replays them, so a
//! host replays the very words a guest does. [`LeafImage::read`] reads it on
//! both sides.
//!
//! **The procedure** ([`leaf`]) is everything the statement decides: which
//! shards, the global transcript's chain through them (`crate::chain`), the
//! checks that cross shards, and the journal. What it builds at run time it
//! builds as tapes too.

use alloc::vec::Vec;

use constants::memory::TS_BITS;
use constants::{family, fr_op, generic_table, guest_memory};

use crate::chain::{self, Shape};
use crate::fold::{
    finish, load_point, merged_points, point_template, prelude, shard_fold, FoldPoint, Hole, Node,
    Side, Template, POINT_CELLS,
};
use crate::tape::{encode, shard_tape, Cell, CellTranscript, Limbs, Op, Tape, ZERO};
use crate::{check_memory_windows, shard_window, statement_shards, VerifyingKey, VmConfig};

/// Every shard tape's first cell: cells `0..3` are the zero state.
pub const FIRST: Cell = 3;

/// The claim cells' offsets from [`LeafImage::claims`]: what a leaf is told
/// and holds itself to where it can — the global digest and the four memory
/// challenges, checked by the leaf holding the statement's last shard;
/// `io_digest`, by a leaf holding a public shard; the exit status, by the
/// last; and the chain's state at the leaf's first shard, three lanes and a
/// pending input, by the leaf before it.
pub mod claim {
    pub const DIGEST: u32 = 0;
    pub const MEMORY: u32 = 1;
    pub const IO: u32 = 5;
    pub const EXIT: u32 = 6;
    pub const CHAIN: u32 = 7;
    pub const PENDING: u32 = 10;
    pub const CELLS: u32 = 11;
    /// The boundary's 64 scalars follow the claims, then the scratch of the
    /// image's boundary template.
    pub const BOUNDARY: u32 = 11;
    pub const SCRATCH: u32 = 75;
    /// The region's size.
    pub const REGION: u32 = SCRATCH + 2048;
}

/// A leaf's journal, one cell a word of 32 bytes, at these offsets.
pub mod journal {
    /// [`crate::chain::shape_digest`].
    pub const SHAPE: usize = 0;
    /// The claims: digest, memory challenges, `io_digest`, exit status.
    pub const DIGEST: usize = 1;
    pub const MEMORY: usize = 2;
    pub const IO: usize = 6;
    pub const EXIT: usize = 7;
    /// The statement's shard count and the leaf's shards, `FROM..TO`.
    pub const TOTAL: usize = 8;
    pub const FROM: usize = 9;
    pub const TO: usize = 10;
    /// The chain's state at `FROM` and at `TO`: three lanes and a pending
    /// input, 0 where there is none.
    pub const CHAIN_IN: usize = 11;
    pub const CHAIN_OUT: usize = 15;
    /// The products of the shards' read roots and write roots.
    pub const READS: usize = 19;
    pub const WRITES: usize = 20;
    /// The boundary factors `(W_b, R_b)` where `TO` is `TOTAL`, `(1, 1)`
    /// otherwise.
    pub const FACTORS: usize = 21;
    /// The first and last shard's family and time window.
    pub const FIRST: usize = 23;
    pub const LAST: usize = 26;
    /// The accumulator: `A`'s `x` and `y`, four limbs each, then `B`'s.
    pub const A: usize = 29;
    pub const B: usize = 37;
    pub const CELLS: usize = 45;
}

/// What a leaf's image is built from: the base program's key but for its
/// circuits, which the registry gives from the config, and its setup
/// commitments, which a leaf takes as advice and holds to `identity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseKey {
    pub code_version: u32,
    pub config: VmConfig,
    pub entry_pc: u32,
    /// The identity and the SRS digest, canonical bytes: a leaf builds them
    /// as constants by `IMM` and `SHL`, with no field arithmetic of its own.
    pub identity: [u8; 32],
    /// Each family's count of identity's setup commitments.
    pub setups: Vec<u32>,
    pub srs_digest: [u8; 32],
    pub generic_table: [[u8; 64]; generic_table::WIDTH],
}

impl BaseKey {
    pub fn of(vk: &VerifyingKey) -> BaseKey {
        BaseKey {
            code_version: vk.code_version,
            config: vk.config.clone(),
            entry_pc: vk.entry_pc,
            identity: vk.identity.0.to_bytes(),
            setups: vk
                .setup_commitments
                .iter()
                .map(|s| s.len() as u32)
                .collect(),
            srs_digest: vk.srs_digest.to_bytes(),
            generic_table: vk.generic_table,
        }
    }

    /// `u32` code version; the config's wire form behind its byte length;
    /// `u32` entry pc; the identity; a `u32` count and that many setup counts;
    /// the SRS digest; the generic table's points. Little-endian throughout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let config = self.config.to_bytes();
        for w in [self.code_version, config.len() as u32] {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.extend_from_slice(&config);
        out.extend_from_slice(&self.entry_pc.to_le_bytes());
        out.extend_from_slice(&self.identity);
        out.extend_from_slice(&(self.setups.len() as u32).to_le_bytes());
        for s in &self.setups {
            out.extend_from_slice(&s.to_le_bytes());
        }
        out.extend_from_slice(&self.srs_digest);
        for p in &self.generic_table {
            out.extend_from_slice(p);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<BaseKey> {
        let mut at = 0;
        let mut take = |n: usize| {
            let out = bytes.get(at..at + n)?;
            at += n;
            Some(out)
        };
        let mut u32 = || Some(u32::from_le_bytes(take(4)?.try_into().ok()?));
        let code_version = u32()?;
        let n = u32()? as usize;
        let mut take = |n: usize| {
            let out = bytes.get(at..at + n)?;
            at += n;
            Some(out)
        };
        let config = VmConfig::from_bytes(take(n)?)?;
        let entry_pc = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let identity: [u8; 32] = take(32)?.try_into().ok()?;
        let count = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let setups = (0..count)
            .map(|_| Some(u32::from_le_bytes(take(4)?.try_into().ok()?)))
            .collect::<Option<Vec<_>>>()?;
        let srs_digest: [u8; 32] = take(32)?.try_into().ok()?;
        let mut generic_table = [[0u8; 64]; generic_table::WIDTH];
        for p in generic_table.iter_mut() {
            p.copy_from_slice(take(64)?);
        }
        (at == bytes.len() && setups.len() == config.families.len()).then_some(BaseKey {
            code_version,
            config,
            entry_pc,
            identity,
            setups,
            srs_digest,
            generic_table,
        })
    }
}

// ---------------------------------------------------------------------------
// The image
// ---------------------------------------------------------------------------

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

/// A family's shard, as the image holds it.
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

/// A leaf's image, read: [`leaf_image`]'s words, borrowed.
#[derive(Clone, Debug)]
pub struct LeafImage<'a> {
    pub node: Node,
    /// The claim cells ([`claim`]), the boundary's after them.
    pub claims: Cell,
    /// Where the procedure's own tapes take their cells.
    pub runtime: Cell,
    pub constants: Body<'a>,
    /// Step 10b's statement half over the boundary cells
    /// (`crate::chain::boundary`), and the factors `(W_b, R_b)` it leaves.
    pub boundary: Body<'a>,
    pub factors: (Cell, Cell),
    pub msm: [MsmImage<'a>; 2],
    pub families: Vec<FamilyImage<'a>>,
}

impl<'a> LeafImage<'a> {
    pub fn family(&self, family: u32) -> Option<&FamilyImage<'a>> {
        self.families.iter().find(|f| f.family == family)
    }

    /// Read [`leaf_image`]'s words, or `None` if they are not its form.
    pub fn read(words: &'a [u32]) -> Option<LeafImage<'a>> {
        let mut r = Reader { words, at: 0 };
        let (end, setups, points) = (r.get()?, r.get()?, r.get()?);
        let factors = (r.get()?, r.get()?);
        let claims = end;
        let node = Node::at(claims + claim::REGION, setups, points);
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
        let families = (0..r.get()?)
            .map(|_| {
                let (family, trace_vars, index, window) = (r.get()?, r.get()?, r.get()?, r.get()?);
                let roots = [r.get()?, r.get()?];
                let commitments = r.list()?;
                let ts = [r.get()?, r.get()?];
                let point = r.list()?;
                let claims = [r.get()?, r.get()?];
                let (tape, prologue, fold) = (r.body()?, r.body()?, r.body()?);
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
        (r.at == words.len()).then_some(LeafImage {
            runtime: node.end(),
            node,
            claims,
            constants,
            boundary,
            factors,
            msm,
            families,
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

/// A leaf's image for the base program `key` describes, as words.
pub fn leaf_image(key: &BaseKey) -> Vec<u32> {
    use generic_table::WIDTH;
    let config = &key.config;
    let own: u32 = key.setups.iter().sum();
    // Each family's tape from `FIRST`, and where its setup commitments are
    // among the merged points: identity's in config order, then the table's.
    let mut shapes = Vec::new();
    let mut offset = 0;
    for ((family, height), n) in config.families.iter().zip(&key.setups) {
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
        shapes.push((*family, vars, tape, merged));
    }
    let end = shapes.iter().map(|s| s.2.end).max().unwrap_or(FIRST);
    let points = shapes
        .iter()
        .map(|s| 12 + s.2.outputs.commitments.len() as u32)
        .max()
        .unwrap_or(0);
    let setups = own + WIDTH as u32;
    let claims = end;
    let node = Node::at(claims + claim::REGION, setups, points);

    // Step 10b's statement half, over the claims and the boundary's cells.
    let mut t = Tape::new(claims + claim::SCRATCH);
    let pc = t.small(key.entry_pc as u64);
    let memory: [Cell; 4] = core::array::from_fn(|k| claims + claim::MEMORY + k as u32);
    let boundary: Vec<Cell> = (0..64).map(|k| claims + claim::BOUNDARY + k).collect();
    let factors = chain::boundary(&mut t, &boundary, claims + claim::EXIT, memory, pc);
    assert!(
        t.end() <= claims + claim::REGION,
        "node: the boundary's scratch"
    );
    let boundary = t.ops;

    let mut w = Words::default();
    for v in [end, setups, points, factors.0, factors.1] {
        w.put(v);
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
    for (k, point) in key.generic_table.iter().enumerate() {
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
    for (family, vars, tape, merged) in &shapes {
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
        w.body(&tape.ops);
        // The prologue: the claims and the setup commitments into the slots.
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
    w.0
}

// ---------------------------------------------------------------------------
// The procedure
// ---------------------------------------------------------------------------

/// What a [`leaf`] is told at run time beside its image: the statement's
/// shape, the shards it verifies, and the public windows' byte lengths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub shard_counts: Vec<u32>,
    pub windows: Vec<u32>,
    pub from: u32,
    pub to: u32,
    pub input_len: u32,
    pub output_len: u32,
}

impl Header {
    /// A count and the counts, a count and the windows, then `from`, `to` and
    /// the two lengths.
    pub fn to_words(&self) -> Vec<u32> {
        let mut w = Words::default();
        w.list(&self.shard_counts);
        w.list(&self.windows);
        for v in [self.from, self.to, self.input_len, self.output_len] {
            w.put(v);
        }
        w.0
    }

    /// The header at the front of `words`, and how many words it took.
    pub fn read(words: &[u32]) -> Option<(Header, usize)> {
        let mut r = Reader { words, at: 0 };
        let header = Header {
            shard_counts: r.list()?.to_vec(),
            windows: r.list()?.to_vec(),
            from: r.get()?,
            to: r.get()?,
            input_len: r.get()?,
            output_len: r.get()?,
        };
        Some((header, r.at))
    }
}

/// Advice a [`leaf`] asks for, named so a host knows what to give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Advice {
    /// The [`claim`] cells.
    Claims,
    /// Identity's setup commitments' limbs, every family's in config order.
    Setup,
    /// Statement position `p`'s memory commitments' limbs.
    Commitments(u32),
    /// Position `p`'s read and write roots.
    Roots(u32),
    /// Position `p`'s shard proof, as its tape's blob (`tape::shard_blob`).
    Blob(u32),
    /// The public windows' words (`crate::public_io_words`, its payload).
    Input,
    Output,
    /// The boundary's 64 scalars (`crate::boundary_scalars`).
    Boundary,
}

/// How a [`leaf`] runs: natively on a host, by its calls in a guest.
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
fn point<D: Driver>(d: &mut D, image: &LeafImage, p: &FoldPoint) {
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

/// A leaf: shards `h.from..h.to` of a base statement of `key`'s program,
/// verified and folded, and the journal ([`journal`]). A statement the shape
/// rules refuse, or shards it has not, is a panic: the leaf has no proof.
pub fn leaf<D: Driver>(d: &mut D, image: &LeafImage, key: &BaseKey, h: &Header) {
    let config = &key.config;
    let shape = Shape {
        config,
        shard_counts: &h.shard_counts,
        windows: &h.windows,
    };
    // Steps 1 to 3's rules, which a shape alone decides.
    assert_eq!(
        h.shard_counts.len(),
        config.families.len(),
        "leaf: a count a family"
    );
    check_memory_windows(config, &h.shard_counts, &h.windows).expect("leaf: the window rules");
    let payload = guest_memory::PUBLIC_PAYLOAD_BYTES;
    assert!(
        h.input_len <= payload && h.output_len <= payload,
        "leaf: a window's payload"
    );
    let total = shape.total();
    assert!(
        h.from < h.to && h.to <= total,
        "leaf: shards of the statement"
    );
    let shards = statement_shards(config, &h.shard_counts);

    let node = &image.node;
    let c = image.claims;
    let mut rt = Tape::new(image.runtime);

    // The node's constants and the MSMs' preludes.
    d.replay(image.constants.body);
    for msm in &image.msm {
        for t in &msm.prelude {
            for _ in 0..t.times {
                d.template(t, None);
            }
        }
    }

    // The claims; the setup commitments, held to the base program's identity;
    // and the shape every node of the statement journals.
    d.advise(&range(c, claim::CELLS), Advice::Claims);
    let own: u32 = key.setups.iter().sum();
    d.advise(&range(node.setup, 4 * own), Advice::Setup);
    let mut next = node.setup;
    let lists: Vec<Vec<Limbs>> = key
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
    let pc = rt.small(key.entry_pc as u64);
    let identity = chain::identity(&mut rt, key.code_version, config, pc, &lists);
    let want = rt.bytes(&key.identity);
    rt.assert_eq(identity, want);
    let shape_digest = chain::shape_digest(&mut rt, &shape);

    // The chain at the first shard: the prefix's end, or the claims'.
    let pending = chain::pending(&shape);
    let mut tr = if h.from == 0 {
        chain::prefix(&mut rt, &shape, &key.srs_digest, identity, c + claim::IO)
    } else {
        CellTranscript::resume(c + claim::CHAIN, pending.then_some(c + claim::PENDING))
    };
    assert_eq!(
        tr.checkpoint().1.is_some(),
        pending,
        "leaf: the chain's parity"
    );
    let chain_in = tr.checkpoint();

    let one = rt.small(1);
    let (reads, writes) = (rt.copy(one), rt.copy(one));
    let mut ends: Option<(u32, Cell)> = None;
    let mut first: Option<[Cell; 3]> = None;
    let mut last = [ZERO; 3];
    let mut windows: Option<(Vec<Cell>, Vec<Cell>)> = None;
    for p in h.from..h.to {
        let (family, index) = shards[p as usize];
        let f = image
            .family(family)
            .expect("leaf: every family has its image");

        // The shard's memory commitments, absorbed; its index and window.
        flush(d, &mut rt);
        d.advise(f.commitments, Advice::Commitments(p));
        let list: Vec<Limbs> = f
            .commitments
            .chunks_exact(4)
            .map(|l| [l[0], l[1], l[2], l[3]])
            .collect();
        chain::segment(&mut rt, &mut tr, &shape, p, &[list]);
        let window = shard_window(family, index, &h.windows, f.trace_vars).unwrap_or(0);
        for (slot, v) in [(f.index, index), (f.window, window)] {
            let v = rt.small(v as u64);
            rt.fr(fr_op::ADD, slot, v, ZERO);
        }
        flush(d, &mut rt);

        // The shard.
        d.replay(f.prologue.body);
        d.advise(&f.roots, Advice::Roots(p));
        d.advise(f.tape.imports, Advice::Blob(p));
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
            chain::below(&mut rt, span, TS_BITS + 1);
            if let Some((g, e)) = ends {
                if g == family {
                    let gap = rt.sub(start, e);
                    chain::below(&mut rt, gap, TS_BITS + 1);
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
                flush(d, &mut rt);
                d.advise(&i, Advice::Input);
                d.advise(&o, Advice::Output);
                let ib = chain::window_bytes(&mut rt, &i, h.input_len as usize);
                let ob = chain::window_bytes(&mut rt, &o, h.output_len as usize);
                let io = chain::io_digest(&mut rt, &ib, &ob);
                rt.assert_eq(io, c + claim::IO);
                windows = Some((i, o));
            }
            let (i, o) = windows.as_ref().expect("the windows are advised");
            let (claim, words) = if family == family::PUBLIC_INPUT {
                (f.claims[1], i)
            } else {
                (f.claims[0], o)
            };
            chain::public_value(&mut rt, f.point, claim, words);
        }
        flush(d, &mut rt);

        // The fold.
        d.replay(f.fold.body);
        for pt in &f.points {
            point(d, image, pt);
        }
    }
    let chain_out = tr.checkpoint();

    // The statement's end: the suffix, the claims it settles, the boundary.
    let factors = if h.to == total {
        let b = range(c + claim::BOUNDARY, 64);
        flush(d, &mut rt);
        d.advise(&b, Advice::Boundary);
        let (memory, digest) = chain::suffix(&mut rt, &mut tr, &shape, &b);
        for (k, m) in memory.iter().enumerate() {
            rt.assert_eq(*m, c + claim::MEMORY + k as u32);
        }
        rt.assert_eq(digest, c + claim::DIGEST);
        flush(d, &mut rt);
        d.replay(image.boundary.body);
        image.factors
    } else {
        (one, one)
    };
    flush(d, &mut rt);

    // The merged points, then the MSMs' finishes.
    for pt in &merged_points(node) {
        point(d, image, pt);
    }
    for msm in &image.msm {
        for t in &msm.finish {
            for _ in 0..t.times {
                d.template(t, None);
            }
        }
    }

    // The journal.
    let mut cells = Vec::with_capacity(journal::CELLS);
    cells.push(shape_digest);
    cells.extend(range(c + claim::DIGEST, 1));
    cells.extend(range(c + claim::MEMORY, 4));
    cells.extend([c + claim::IO, c + claim::EXIT]);
    for v in [total, h.from, h.to] {
        cells.push(rt.small(v as u64));
    }
    for (state, pending) in [chain_in, chain_out] {
        cells.extend([state, state + 1, state + 2, pending.unwrap_or(ZERO)]);
    }
    cells.extend([reads, writes, factors.0, factors.1]);
    cells.extend(first.expect("a leaf verifies a shard"));
    cells.extend(last);
    cells.extend(range(node.a.result, POINT_CELLS));
    cells.extend(range(node.b.result, POINT_CELLS));
    assert_eq!(cells.len(), journal::CELLS);
    flush(d, &mut rt);
    d.export(&cells);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tape::decode;

    /// A key and a header round-trip their bytes and words, and a leaf's
    /// image reads back: a family a config family, every body runs of field
    /// frames, and a word more refused.
    #[test]
    fn a_leaf_image_reads_back() {
        let config = VmConfig {
            families: alloc::vec![
                (family::ADD_SUB_LUI_AUIPC, 1 << 20),
                (family::INIT_TEARDOWN, 1 << 20),
                (family::ZERO_WINDOWS, 1 << 20),
                (family::PUBLIC_INPUT, 1 << 12),
                (family::PUBLIC_OUTPUT, 1 << 12),
                (family::ADVICE_WINDOWS, 1 << 20),
            ],
            bytecode_size_words: 1 << 20,
        };
        let key = BaseKey {
            code_version: 0,
            config,
            entry_pc: 0x1_0000,
            identity: [7; 32],
            setups: alloc::vec![7, 1, 0, 0, 0, 0],
            srs_digest: [9; 32],
            generic_table: [[3; 64]; generic_table::WIDTH],
        };
        assert_eq!(BaseKey::from_bytes(&key.to_bytes()), Some(key.clone()));
        let header = Header {
            shard_counts: alloc::vec![2, 1, 0, 1, 1, 0],
            windows: alloc::vec![],
            from: 1,
            to: 4,
            input_len: 0,
            output_len: 43,
        };
        let words = header.to_words();
        assert_eq!(Header::read(&words), Some((header, words.len())));

        let words = leaf_image(&key);
        let image = LeafImage::read(&words).expect("the image reads");
        let families: Vec<u32> = image.families.iter().map(|f| f.family).collect();
        let want: Vec<u32> = key.config.families.iter().map(|(f, _)| *f).collect();
        assert_eq!(families, want);
        let bodies = image
            .families
            .iter()
            .flat_map(|f| [f.tape.body, f.prologue.body, f.fold.body])
            .chain([image.constants.body, image.boundary.body]);
        for body in bodies {
            assert!(decode(body).is_some());
        }
        let mut longer = words.clone();
        longer.push(0);
        assert!(LeafImage::read(&longer).is_none());
    }
}
