//! The handle-based verifier (`docs/spec/recursion.md` §7): every check
//! [`crate::verify_shard_local`] makes, and Mercury's field side, written as a
//! **tape** — a straight-line program of coprocessor calls over cells of the
//! field memory — so a recursion guest replays the verification rather than
//! runs one.
//!
//! A shard's checks have a fixed shape per family and height, so its tape is
//! compiled once, on the host, and its cells are absolute. What a statement
//! chooses the length of — the global phase's absorbs, the reconciliation
//! product — the guest records at run time through the same [`Tape`] and
//! replays at once. [`run`] is the native reading of a tape over a `Vec<Fr>`,
//! which is what the differential test holds to `verify_shard_local`.
//!
//! A tape reads three kinds of value. **Constants** it makes itself, from
//! `IMM`, `SHL` and `SUB`, so they are the image's and never the prover's.
//! **Slots** are fixed cells the caller fills before replaying — the statement's
//! digest and challenges, this shard's index and roots. **Inputs** are `IMPORT`s
//! of 32-byte words from a blob the host lays out in [`ShardTape::inputs`]'
//! order: the proof, which the tape's own checks are what bind.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use constants::{fr_op, transcript_tags as tags, G1_INFINITY_SENTINEL};
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};
use field::Fr;

/// A cell of the field memory.
pub type Cell = u32;

/// Never written, so always 0. Cells `0..3` are the zero state every
/// transcript starts from.
pub const ZERO: Cell = 0;

/// One coprocessor call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `FR_OP`'s frame `[op, d, a, b]`.
    Fr([u32; 4]),
    /// `P2_FIELD`'s frame `[n, s, x, y, d]`.
    Duplex([u32; 5]),
    /// `FQ_OP`'s frame `[op, d, a, b]`, the op word carrying the code, the
    /// indirection flags and the digit cell.
    Fq([u32; 4]),
    /// `FIELD_IO`'s `IMPORT` of the eight words at byte `offset` of the input
    /// blob into `cell`.
    Import { cell: Cell, offset: u32 },
}

/// A tape under construction.
pub struct Tape {
    pub ops: Vec<Op>,
    /// The next free cell.
    next: Cell,
    /// Each constant's cell, by its canonical bytes.
    constants: BTreeMap<[u8; 32], Cell>,
    /// Bytes of input blob laid out so far.
    blob: u32,
}

impl Tape {
    /// An empty tape whose scratch starts at `first`.
    pub fn new(first: Cell) -> Tape {
        Tape {
            ops: Vec::new(),
            next: first,
            constants: BTreeMap::new(),
            blob: 0,
        }
    }

    /// The first cell this tape has not used.
    pub fn end(&self) -> Cell {
        self.next
    }

    /// Where the next fresh cell will be, for [`Tape::reset`].
    pub fn mark(&self) -> Cell {
        self.next
    }

    /// Take the cells from `mark` up back, for ops that follow those that
    /// wrote them to reuse: a template's step whose temporaries are dead
    /// once the step is done. Constants made since are forgotten with them.
    pub fn reset(&mut self, mark: Cell) {
        self.next = mark;
        self.constants.retain(|_, c| *c < mark);
    }

    /// `n` fresh, consecutive cells.
    pub fn fresh(&mut self, n: u32) -> Cell {
        let c = self.next;
        self.next += n;
        c
    }

    pub(crate) fn fr(&mut self, op: u32, d: Cell, a: Cell, b: u32) {
        self.ops.push(Op::Fr([op, d, a, b]));
    }

    /// A cell holding `v`, made once per tape.
    pub fn constant(&mut self, v: Fr) -> Cell {
        if v == Fr::ZERO {
            return ZERO;
        }
        let key = v.to_bytes();
        if let Some(c) = self.constants.get(&key) {
            return *c;
        }
        // A small value or its negation is `IMM` and perhaps a `SUB`; anything
        // else is built a word at a time from the top, `SHL` shifting the
        // value up and adding the next word.
        let small = |x: Fr| -> Option<u32> {
            let b = x.to_bytes();
            b[4..]
                .iter()
                .all(|z| *z == 0)
                .then(|| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        let c = self.fresh(1);
        if let Some(w) = small(v) {
            self.fr(fr_op::IMM, c, ZERO, w);
        } else if let Some(w) = small(-v) {
            self.fr(fr_op::IMM, c, ZERO, w);
            self.fr(fr_op::SUB, c, ZERO, c);
        } else {
            let b = v.to_bytes();
            let word =
                |k: usize| u32::from_le_bytes([b[4 * k], b[4 * k + 1], b[4 * k + 2], b[4 * k + 3]]);
            self.fr(fr_op::IMM, c, ZERO, word(7));
            for k in (0..7).rev() {
                self.fr(fr_op::SHL, c, c, word(k));
            }
        }
        self.constants.insert(key, c);
        c
    }

    /// The next 32 bytes of the input blob, imported into a fresh cell.
    pub fn input(&mut self) -> Cell {
        let c = self.fresh(1);
        self.ops.push(Op::Import {
            cell: c,
            offset: self.blob,
        });
        self.blob += 32;
        c
    }

    /// The input blob's length so far.
    pub fn blob_bytes(&self) -> u32 {
        self.blob
    }

    pub fn mul(&mut self, a: Cell, b: Cell) -> Cell {
        let d = self.fresh(1);
        self.fr(fr_op::MUL, d, a, b);
        d
    }

    pub fn add(&mut self, a: Cell, b: Cell) -> Cell {
        let d = self.fresh(1);
        self.fr(fr_op::ADD, d, a, b);
        d
    }

    pub fn sub(&mut self, a: Cell, b: Cell) -> Cell {
        let d = self.fresh(1);
        self.fr(fr_op::SUB, d, a, b);
        d
    }

    /// `acc ← acc + a·b`, in place.
    pub fn mac(&mut self, acc: Cell, a: Cell, b: Cell) {
        self.fr(fr_op::MAC, acc, a, b);
    }

    /// `a⁻¹`, or 0 at `a = 0`.
    pub fn inv(&mut self, a: Cell) -> Cell {
        let d = self.fresh(1);
        self.fr(fr_op::INV, d, a, 0);
        d
    }

    /// `a = b`, or the tape has no witness.
    pub fn assert_eq(&mut self, a: Cell, b: Cell) {
        self.fr(fr_op::EQ, 0, a, b);
    }

    /// `a ≠ 0`: `a·a⁻¹ = 1`.
    pub fn assert_nonzero(&mut self, a: Cell) {
        let i = self.inv(a);
        let one = self.constant(Fr::ONE);
        let p = self.mul(a, i);
        self.assert_eq(p, one);
    }

    /// A copy of `a` in a fresh cell, which a `mac` may then accumulate into.
    pub fn copy(&mut self, a: Cell) -> Cell {
        self.add(a, ZERO)
    }

    /// `Σ_i a_i·b_i`.
    pub fn dot(&mut self, a: &[Cell], b: &[Cell]) -> Cell {
        let acc = self.fresh(1);
        self.fr(fr_op::IMM, acc, ZERO, 0);
        for (x, y) in a.iter().zip(b) {
            self.mac(acc, *x, *y);
        }
        acc
    }

    /// `1, x, x², …`, `n` of them.
    pub fn powers(&mut self, x: Cell, n: usize) -> Vec<Cell> {
        let mut out = Vec::with_capacity(n);
        if n > 0 {
            out.push(self.constant(Fr::ONE));
        }
        if n > 1 {
            out.push(x);
        }
        while out.len() < n {
            let last = out[out.len() - 1];
            out.push(self.mul(last, x));
        }
        out
    }

    /// `Σ_i xs_i`.
    pub fn sum(&mut self, xs: &[Cell]) -> Cell {
        let acc = self.fresh(1);
        self.fr(fr_op::IMM, acc, ZERO, 0);
        for x in xs {
            self.fr(fr_op::ADD, acc, acc, *x);
        }
        acc
    }
}

// ---------------------------------------------------------------------------
// The transcript, over cells
// ---------------------------------------------------------------------------

/// `transcript::Transcript` over cells, operation for operation: rate 2,
/// overwrite absorption, challenges popped from the end of the rate. The
/// state lives in three consecutive cells and each duplex step writes the next
/// state to three fresh ones (`docs/spec/recursion.md` §4), so a state is never
/// overwritten and a challenge is a cell of the state that made it.
pub struct CellTranscript {
    state: Cell,
    input: Vec<Cell>,
    output: Vec<Cell>,
}

impl CellTranscript {
    /// A transcript in the zero state: cells `0..3`, never written.
    pub fn new() -> CellTranscript {
        CellTranscript::at(ZERO)
    }

    /// A transcript resumed from the state at `state`, nothing pending.
    pub fn at(state: Cell) -> CellTranscript {
        CellTranscript {
            state,
            input: Vec::new(),
            output: Vec::new(),
        }
    }

    /// The current state's first cell: the three lanes from here on.
    pub fn state(&self) -> Cell {
        self.state
    }

    /// A transcript resumed between two messages: the state at `state`, and
    /// the one input a duplex has not yet taken, if the messages so far were
    /// an odd number of scalars. Whatever was squeezed is gone, as the next
    /// message's first `observe` would drop it.
    pub fn resume(state: Cell, pending: Option<Cell>) -> CellTranscript {
        CellTranscript {
            state,
            input: pending.into_iter().collect(),
            output: Vec::new(),
        }
    }

    /// Where the transcript is between two messages, for [`Self::resume`].
    pub fn checkpoint(&self) -> (Cell, Option<Cell>) {
        (self.state, self.input.first().copied())
    }

    /// One duplex step, absorbing what is pending.
    fn duplex(&mut self, t: &mut Tape) {
        let n = self.input.len() as u32;
        let x = self.input.first().copied().unwrap_or(ZERO);
        let y = self.input.get(1).copied().unwrap_or(ZERO);
        let next = t.fresh(3);
        t.ops.push(Op::Duplex([n, self.state, x, y, next]));
        self.state = next;
        self.input.clear();
        self.output = vec![next, next + 1];
    }

    /// Absorb one cell.
    pub fn observe(&mut self, t: &mut Tape, x: Cell) {
        self.output.clear();
        self.input.push(x);
        if self.input.len() == 2 {
            self.duplex(t);
        }
    }

    /// Squeeze one cell.
    pub fn sample(&mut self, t: &mut Tape) -> Cell {
        if !self.input.is_empty() || self.output.is_empty() {
            self.duplex(t);
        }
        self.output.pop().expect("a duplex step refills the rate")
    }

    /// `tag, length, xs`.
    pub fn append(&mut self, t: &mut Tape, tag: u64, xs: &[Cell]) {
        let tag = t.constant(Fr::from_u64(tag));
        let len = t.constant(Fr::from_u64(xs.len() as u64));
        self.observe(t, tag);
        self.observe(t, len);
        for x in xs {
            self.observe(t, *x);
        }
    }

    /// A challenge under `tag`.
    pub fn challenge(&mut self, t: &mut Tape, tag: u64) -> Cell {
        let tag = t.constant(Fr::from_u64(tag));
        self.observe(t, tag);
        self.sample(t)
    }
}

impl Default for CellTranscript {
    fn default() -> CellTranscript {
        CellTranscript::new()
    }
}

/// A point's four transcript limbs, `x` low, `x` high, `y` low, `y` high, or
/// four copies of `G1_INFINITY_SENTINEL` for infinity — imported as they are
/// (`transcript::g1_limbs`).
pub type Limbs = [Cell; 4];

/// The sentinel's value, for a test or a caller laying out a blob.
pub fn infinity_sentinel() -> Fr {
    Fr::from_hex(G1_INFINITY_SENTINEL).expect("the sentinel is a canonical literal")
}

/// `transcript::append_g1_points`: one message of `4k` limbs.
pub fn append_points(tr: &mut CellTranscript, t: &mut Tape, tag: u64, points: &[Limbs]) {
    let flat: Vec<Cell> = points.iter().flatten().copied().collect();
    tr.append(t, tag, &flat);
}

// ---------------------------------------------------------------------------
// The gate kernel, over cells
// ---------------------------------------------------------------------------

/// A coefficient's cell: a constant, or the slot's challenge.
fn coeff(t: &mut Tape, c: &Coeff, challenges: &BTreeMap<u32, Cell>) -> Cell {
    match c {
        Coeff::Literal(v) => t.constant(*v),
        Coeff::Challenge(slot) => *challenges
            .get(slot)
            .unwrap_or_else(|| panic!("tape: challenge slot {slot} has no cell")),
    }
}

/// `constant + Σ k·x`.
fn affine(
    t: &mut Tape,
    terms: &[(Coeff, PolyAddress)],
    constant: &Coeff,
    values: &[Cell],
    challenges: &BTreeMap<u32, Cell>,
) -> Cell {
    let c = coeff(t, constant, challenges);
    let acc = t.copy(c);
    for ((k, _), v) in terms.iter().zip(values) {
        let k = coeff(t, k, challenges);
        t.mac(acc, k, *v);
    }
    acc
}

/// `gkr_verify::eval_gate` over cells: one value per operand, in
/// `GateDef::operands` order.
pub fn eval_gate(
    t: &mut Tape,
    gate: &GateDef,
    values: &[Cell],
    challenges: &BTreeMap<u32, Cell>,
) -> Cell {
    match gate {
        GateDef::Linear { terms, constant } => affine(t, terms, constant, values, challenges),
        GateDef::Product { coeff: k, .. } => {
            let p = t.mul(values[0], values[1]);
            let k = coeff(t, k, challenges);
            t.mul(k, p)
        }
        GateDef::MaskIntoIdentity { .. } => {
            // x·m + 1 − m.
            let one = t.constant(Fr::ONE);
            let p = t.mul(values[0], values[1]);
            let q = t.add(p, one);
            t.sub(q, values[1])
        }
        GateDef::AffineProduct {
            left,
            left_constant,
            right,
            right_constant,
        } => {
            let n = left.len();
            let l = affine(t, left, left_constant, &values[..n], challenges);
            let r = affine(t, right, right_constant, &values[n..], challenges);
            t.mul(l, r)
        }
        GateDef::TreeProduct { .. } => t.mul(values[0], values[1]),
        GateDef::TreeCross { .. } => {
            let acc = t.mul(values[0], values[3]);
            t.mac(acc, values[1], values[2]);
            acc
        }
        GateDef::Quadratic {
            constant,
            linear,
            products,
        } => {
            let n = linear.len();
            let acc = affine(t, linear, constant, &values[..n], challenges);
            for ((k, _, _), yz) in products.iter().zip(values[n..].chunks_exact(2)) {
                let p = t.mul(yz[0], yz[1]);
                let k = coeff(t, k, challenges);
                t.mac(acc, k, p);
            }
            acc
        }
    }
}

/// `gkr_verify::virtual_at_point` over cells.
pub fn virtual_at_point(t: &mut Tape, kind: VirtualKind, point: &[Cell]) -> Cell {
    // `Σ_j 2^j·y_j` over `bits`, by Horner from the highest.
    let horner = |t: &mut Tape, bits: &[Cell]| -> Cell {
        let acc = t.fresh(1);
        t.fr(fr_op::IMM, acc, ZERO, 0);
        for y in bits.iter().rev() {
            t.fr(fr_op::ADD, acc, acc, acc);
            t.fr(fr_op::ADD, acc, acc, *y);
        }
        acc
    };
    let at = |j: usize| point.get(j).copied().unwrap_or(ZERO);
    match kind {
        VirtualKind::RowIndex => horner(t, point),
        VirtualKind::RamLive => {
            let one = t.constant(Fr::ONE);
            let acc = t.copy(one);
            let from = point.len().min(constants::memory::RAM_LIVE_BIT as usize);
            for y in &point[from..] {
                let u = t.sub(one, *y);
                t.fr(fr_op::MUL, acc, acc, u);
            }
            t.sub(one, acc)
        }
        VirtualKind::Range19 | VirtualKind::Range16 => {
            let bits = if kind == VirtualKind::Range19 { 19 } else { 16 };
            horner(t, &point[..point.len().min(bits)])
        }
        VirtualKind::Xor8A | VirtualKind::Xor8B => {
            let first = if kind == VirtualKind::Xor8A { 0 } else { 8 };
            let byte: Vec<Cell> = (0..8).map(|j| at(first + j)).collect();
            horner(t, &byte)
        }
        VirtualKind::Xor8Out => {
            let acc = t.fresh(1);
            t.fr(fr_op::IMM, acc, ZERO, 0);
            for j in (0..8).rev() {
                let (y, z) = (at(j), at(j + 8));
                let p = t.mul(y, z);
                t.fr(fr_op::ADD, acc, acc, acc);
                t.fr(fr_op::ADD, acc, acc, y);
                t.fr(fr_op::ADD, acc, acc, z);
                t.fr(fr_op::SUB, acc, acc, p);
                t.fr(fr_op::SUB, acc, acc, p);
            }
            acc
        }
    }
}

/// `eq(p, r) = Π_i ((2p_i − 1)·r_i + 1 − p_i)`.
pub fn eq_eval(t: &mut Tape, p: &[Cell], r: &[Cell]) -> Cell {
    assert_eq!(
        p.len(),
        r.len(),
        "tape: eq over points of different lengths"
    );
    let one = t.constant(Fr::ONE);
    let acc = t.copy(one);
    for (pi, ri) in p.iter().zip(r) {
        let two_p = t.add(*pi, *pi);
        let a = t.sub(two_p, one);
        let e = t.sub(one, *pi);
        t.mac(e, a, *ri);
        t.fr(fr_op::MUL, acc, acc, e);
    }
    acc
}

// ---------------------------------------------------------------------------
// GKR, over cells
// ---------------------------------------------------------------------------

/// Where an operand of a row-wise list is read: `gkr_verify::ResolvedList`'s
/// resolution. A halving list reads a column at both children instead.
enum Source {
    Column(usize),
    Virtual(usize),
    Cached(usize),
}

/// An operand's column in the layer below list `k`, as `gkr_verify` numbers
/// it: `M`, `W`, `S` in layout order at the base, an inner offset above.
fn column_index(a: &CircuitArtifact, k: usize, op: &PolyAddress) -> usize {
    let (m, w) = (a.memory.len(), a.witness.len());
    match *op {
        PolyAddress::Memory(i) => i as usize,
        PolyAddress::Witness(i) => m + i as usize,
        PolyAddress::Setup(i) => m + w + i as usize,
        PolyAddress::Inner { offset, .. } => offset as usize,
        other => panic!("tape: gate list {k} cannot read {other} as a column"),
    }
}

/// `gkr_verify::summand` over cells: list `k`'s gates at the point, weighted
/// by `weights` — cached entries first, then producing gates, then enforcing.
#[allow(clippy::too_many_arguments)]
fn summand(
    t: &mut Tape,
    a: &CircuitArtifact,
    k: usize,
    weights: &[Cell],
    lower: &[Cell],
    upper: &[Cell],
    virtuals: &[Cell],
    challenges: &BTreeMap<u32, Cell>,
) -> Cell {
    let list = &a.layers[k];
    let resolve = |op: &PolyAddress| -> Source {
        match op {
            PolyAddress::Virtual(kind) => Source::Virtual(
                a.virtuals
                    .iter()
                    .position(|(v, _)| v == kind)
                    .expect("a validated artifact lists every virtual it reads"),
            ),
            PolyAddress::Cached { offset, .. } => Source::Cached(*offset as usize),
            other => Source::Column(column_index(a, k, other)),
        }
    };
    let gather = |gate: &GateDef, cached: &[Cell]| -> Vec<Cell> {
        let mut out = Vec::new();
        for op in gate.operands() {
            if list.halving {
                let x = column_index(a, k, &op);
                out.extend([lower[x], upper[x]]);
                continue;
            }
            out.push(match resolve(&op) {
                Source::Column(x) => lower[x],
                Source::Virtual(x) => virtuals[x],
                Source::Cached(x) => cached[x],
            });
        }
        out
    };
    let mut cached: Vec<Cell> = Vec::new();
    if !list.halving {
        for e in &list.cached {
            let values = gather(&e.gate, &cached);
            let v = eval_gate(t, &e.gate, &values, challenges);
            cached.push(v);
        }
    }
    let gates: Vec<&GateDef> = if list.halving {
        list.producing.iter().map(|e| &e.gate).collect()
    } else {
        list.producing
            .iter()
            .map(|e| &e.gate)
            .chain(list.enforcing.iter().map(|e| &e.gate))
            .collect()
    };
    let acc = t.fresh(1);
    t.fr(fr_op::IMM, acc, ZERO, 0);
    for (gate, w) in gates.into_iter().zip(weights) {
        let values = gather(gate, &cached);
        let g = eval_gate(t, gate, &values, challenges);
        t.mac(acc, g, *w);
    }
    acc
}

/// One layer sumcheck's rounds, `gkr_verify::verify_sumcheck`: each
/// `g(0) + g(1)` against the claim, the cubic absorbed and the next variable
/// drawn. Returns the bound point and the last claim.
fn sumcheck(
    t: &mut Tape,
    tr: &mut CellTranscript,
    claim: Cell,
    rounds: &[[Cell; 4]],
) -> (Vec<Cell>, Cell) {
    let mut claim = claim;
    let mut point = Vec::with_capacity(rounds.len());
    for g in rounds {
        // g(0) + g(1) = 2·g0 + g1 + g2 + g3.
        let s = t.add(g[0], g[0]);
        for c in &g[1..] {
            t.fr(fr_op::ADD, s, s, *c);
        }
        t.assert_eq(s, claim);
        tr.append(t, tags::SUMCHECK_ROUND, g);
        let r = tr.challenge(t, tags::SUMCHECK_CHALLENGE);
        // Horner into the coefficients' own cells, which nothing reads again.
        t.mac(g[2], r, g[3]);
        t.mac(g[1], r, g[2]);
        t.mac(g[0], r, g[1]);
        claim = g[0];
        point.push(r);
    }
    (point, claim)
}

/// One GKR proof's cells: its outputs, then per layer — top first, as
/// `gkr_verify::verify` walks them — its rounds and its final evaluations.
pub struct GkrCells {
    pub outputs: Vec<Cell>,
    pub layers: Vec<(Vec<[Cell; 4]>, Vec<Cell>)>,
}

/// The cells a proof of `a` arrives in, imported in order: the outputs, then
/// each layer from the top, its rounds and then its final evaluations.
pub fn gkr_inputs(t: &mut Tape, a: &CircuitArtifact) -> GkrCells {
    let outputs = (0..a.outputs.len()).map(|_| t.input()).collect();
    let mut layers = Vec::new();
    for k in (0..a.depth()).rev() {
        let rounds = (0..a.layer_vars(k + 1))
            .map(|_| [t.input(), t.input(), t.input(), t.input()])
            .collect();
        let width = a.layer_width(k) as usize;
        let claims = if a.layers[k].halving {
            2 * width
        } else {
            width
        };
        let evals = (0..claims).map(|_| t.input()).collect();
        layers.push((rounds, evals));
    }
    GkrCells { outputs, layers }
}

/// `gkr_verify::verify` over cells: the outputs reduced to the base claims,
/// every check an assertion. Returns the claims, in layout order, and their
/// point.
pub fn gkr_verify(
    t: &mut Tape,
    tr: &mut CellTranscript,
    a: &CircuitArtifact,
    proof: &GkrCells,
    challenges: &BTreeMap<u32, Cell>,
) -> (Vec<Cell>, Vec<Cell>) {
    assert_eq!(
        a.layer_vars(a.depth()),
        0,
        "tape: a circuit here halves to a zero-variable top"
    );
    tr.append(t, tags::GKR_OUTPUTS, &proof.outputs);
    let mut point: Vec<Cell> = Vec::new();
    let mut values = vec![ZERO; a.outputs.len()];
    for (v, out) in proof.outputs.iter().zip(&a.outputs) {
        if let PolyAddress::Inner { offset, .. } = *out {
            values[offset as usize] = *v;
        }
    }
    for (step, k) in (0..a.depth()).rev().enumerate() {
        let list = &a.layers[k];
        let (rounds, evals) = &proof.layers[step];
        let lambda = tr.challenge(t, tags::GKR_BATCH);
        let weights = t.powers(lambda, list.producing.len() + list.enforcing.len());
        let claim = t.dot(&values, &weights);
        let (rho, last) = sumcheck(t, tr, claim, rounds);
        tr.append(t, tags::GKR_LAYER_CLAIMS, evals);
        let s = if list.halving {
            let lower: Vec<Cell> = evals.iter().step_by(2).copied().collect();
            let upper: Vec<Cell> = evals.iter().skip(1).step_by(2).copied().collect();
            summand(t, a, k, &weights, &lower, &upper, &[], challenges)
        } else {
            let virtuals: Vec<Cell> = a
                .virtuals
                .iter()
                .map(|(kind, _)| virtual_at_point(t, *kind, &rho))
                .collect();
            summand(t, a, k, &weights, evals, &[], &virtuals, challenges)
        };
        let e = eq_eval(t, &point, &rho);
        let want = t.mul(e, s);
        t.assert_eq(last, want);
        if list.halving {
            let tau = tr.challenge(t, tags::GKR_CHILD);
            values = evals
                .chunks(2)
                .map(|pair| {
                    let d = t.sub(pair[1], pair[0]);
                    let v = t.copy(pair[0]);
                    t.mac(v, tau, d);
                    v
                })
                .collect();
            point = rho;
            point.push(tau);
        } else {
            values = evals.clone();
            point = rho;
        }
    }
    (values, point)
}

// ---------------------------------------------------------------------------
// Mercury's field side, over cells
// ---------------------------------------------------------------------------

/// `pcs_verify::tensor_eval`: `P_u(x) = Π_k (u_k·x^(2^k) + 1 − u_k)`.
fn tensor_eval(t: &mut Tape, u: &[Cell], x: Cell) -> Cell {
    let one = t.constant(Fr::ONE);
    let acc = t.copy(one);
    let mut power = x;
    for (k, uk) in u.iter().enumerate() {
        let e = t.sub(one, *uk);
        t.mac(e, *uk, power);
        t.fr(fr_op::MUL, acc, acc, e);
        if k + 1 < u.len() {
            power = t.mul(power, power);
        }
    }
    acc
}

/// `r(z')` for the line through `(x0, y0)` and `(x1, y1)`.
fn line_at(t: &mut Tape, (x0, y0): (Cell, Cell), (x1, y1): (Cell, Cell), at: Cell) -> Cell {
    let a = t.sub(at, x1);
    let b = t.sub(at, x0);
    let num = t.mul(y0, a);
    let nb = t.mul(y1, b);
    let num = t.sub(num, nb);
    let den = t.sub(x0, x1);
    let inv = t.inv(den);
    t.mul(num, inv)
}

/// `r(z')` for the parabola through three points: Lagrange at `z'`.
fn parabola_at(t: &mut Tape, pts: [(Cell, Cell); 3], at: Cell) -> Cell {
    let acc = t.fresh(1);
    t.fr(fr_op::IMM, acc, ZERO, 0);
    for i in 0..3 {
        let (j, k) = ((i + 1) % 3, (i + 2) % 3);
        let n1 = t.sub(at, pts[j].0);
        let n2 = t.sub(at, pts[k].0);
        let num = t.mul(n1, n2);
        let d1 = t.sub(pts[i].0, pts[j].0);
        let d2 = t.sub(pts[i].0, pts[k].0);
        let den = t.mul(d1, d2);
        let inv = t.inv(den);
        let l = t.mul(num, inv);
        t.mac(acc, l, pts[i].1);
    }
    acc
}

/// `pcs_verify::batch_preamble` over cells: the commitments as one message,
/// `u` and every value as another, then `ρ`. Returns the weights `ρ^i` and
/// `v* = Σ ρ^i v_i`; `cm* = Σ ρ^i cm_i` is the caller's.
pub fn batch_preamble(
    t: &mut Tape,
    tr: &mut CellTranscript,
    commitments: &[Limbs],
    u: &[Cell],
    values: &[Cell],
) -> (Vec<Cell>, Cell) {
    append_points(tr, t, tags::COMMITMENT, commitments);
    let mut claim = u.to_vec();
    claim.extend_from_slice(values);
    tr.append(t, tags::EVALUATION_CLAIM, &claim);
    let rho = tr.challenge(t, tags::MERCURY_BATCH);
    let weights = t.powers(rho, commitments.len());
    let v_star = t.dot(&weights, values);
    (weights, v_star)
}

/// `pcs_verify::scalars` over cells: §5's schedule over `(cm, u, v)` and the
/// proof's eight points and six values, §7's challenge rule as assertions, the
/// two derived values and the BDFG20 batch at `z'`. Returns the twelve
/// scalars in entry order.
pub fn mercury_scalars(
    t: &mut Tape,
    tr: &mut CellTranscript,
    cm: Limbs,
    u: &[Cell],
    v: Cell,
    points: &[Limbs; 8],
    evals: &[Cell; 6],
) -> [Cell; 12] {
    // `pcs_verify::check_num_vars`, which a tape's fixed shape settles once.
    assert!(
        u.len() >= 2 && u.len().is_multiple_of(2),
        "tape: a Mercury instance has an even number of variables, two or more"
    );
    let half = u.len() / 2;
    let [h, q, g, s, d, pi_z, w, w_prime] = *points;
    let instance = t.constant(Fr::from_u64(1u64 << u.len()));
    tr.append(t, tags::MERCURY_INSTANCE, &[instance]);
    append_points(tr, t, tags::COMMITMENT, &[cm]);
    let mut claim = u.to_vec();
    claim.push(v);
    tr.append(t, tags::EVALUATION_CLAIM, &claim);
    append_points(tr, t, tags::PCS_OPENING, &[h]);
    let alpha = tr.challenge(t, tags::MERCURY_ALPHA);
    append_points(tr, t, tags::PCS_OPENING, &[q, g]);
    let gamma = tr.challenge(t, tags::MERCURY_GAMMA);
    append_points(tr, t, tags::PCS_OPENING, &[s, d]);
    // §7: `z` is drawn once and the resample a zero would cost is an
    // assertion — a liveness loss at probability `1/p`, never a soundness one —
    // as are the three degeneracies.
    let z = tr.challenge(t, tags::MERCURY_Z);
    let one = t.constant(Fr::ONE);
    t.assert_nonzero(z);
    let z2 = t.mul(z, z);
    let z2m1 = t.sub(z2, one);
    t.assert_nonzero(z2m1);
    let za = t.sub(z, alpha);
    t.assert_nonzero(za);
    let zalpha = t.mul(z, alpha);
    let zam1 = t.sub(zalpha, one);
    t.assert_nonzero(zam1);
    let z_inv = t.inv(z);
    tr.append(t, tags::PCS_OPENING, evals);
    append_points(tr, t, tags::PCS_OPENING, &[pi_z]);
    let delta = tr.challenge(t, tags::BDFG_BATCH);
    append_points(tr, t, tags::PCS_OPENING, &[w]);
    let z_prime = tr.challenge(t, tags::BDFG_POINT);
    append_points(tr, t, tags::PCS_OPENING, &[w_prime]);
    let rho = tr.challenge(t, tags::PAIRING_MERGE);

    let [g_z, g_inv_z, h_z, h_inv_z, s_z, s_inv_z] = *evals;
    // `pcs_verify::derive_h_alpha`.
    let (u1, u2) = u.split_at(half);
    let inner = t.fresh(1);
    t.fr(fr_op::IMM, inner, ZERO, 0);
    let p = tensor_eval(t, u1, z_inv);
    t.mac(inner, g_z, p);
    let p = tensor_eval(t, u1, z);
    t.mac(inner, g_inv_z, p);
    let hsum = t.fresh(1);
    t.fr(fr_op::IMM, hsum, ZERO, 0);
    let p = tensor_eval(t, u2, z_inv);
    t.mac(hsum, h_z, p);
    let p = tensor_eval(t, u2, z);
    t.mac(hsum, h_inv_z, p);
    t.fr(fr_op::SUB, hsum, hsum, v);
    t.fr(fr_op::SUB, hsum, hsum, v);
    t.mac(inner, gamma, hsum);
    let zs = t.mul(z, s_z);
    t.fr(fr_op::SUB, inner, inner, zs);
    let zs = t.mul(z_inv, s_inv_z);
    t.fr(fr_op::SUB, inner, inner, zs);
    let two_inv = t.constant(Fr::from_u64(2).inverse().expect("2 is invertible"));
    let h_alpha = t.mul(inner, two_inv);
    // `z^b` by `half` squarings; `D(z) = z^(b−1)·g(1/z)`.
    let mut z_pow_b = z;
    for _ in 0..half {
        z_pow_b = t.mul(z_pow_b, z_pow_b);
    }
    let z_pow_b1 = t.mul(z_pow_b, z_inv);
    let d_z = t.mul(z_pow_b1, g_inv_z);

    // `bdfg::items` at `z'`: each item's complement vanishing and its
    // interpolation, both evaluated rather than built.
    let without_alpha = t.sub(z_prime, alpha);
    let without_zinv = t.sub(z_prime, z_inv);
    let complement = [
        without_alpha,
        one,
        without_alpha,
        t.mul(without_zinv, without_alpha),
    ];
    let r = [
        line_at(t, (z, g_z), (z_inv, g_inv_z), z_prime),
        parabola_at(t, [(z, h_z), (z_inv, h_inv_z), (alpha, h_alpha)], z_prime),
        line_at(t, (z, s_z), (z_inv, s_inv_z), z_prime),
        d_z,
    ];
    let deltas = t.powers(delta, 4);
    let mut c = [ZERO; 4];
    let constant = t.fresh(1);
    t.fr(fr_op::IMM, constant, ZERO, 0);
    for i in 0..4 {
        c[i] = t.mul(deltas[i], complement[i]);
        t.mac(constant, c[i], r[i]);
    }
    let without_z = t.sub(z_prime, z);
    let zt = t.mul(without_z, without_zinv);
    let z_t = t.mul(zt, without_alpha);

    let neg = |t: &mut Tape, x: Cell| t.sub(ZERO, x);
    let rho_c1 = t.mul(rho, c[1]);
    let zba = t.sub(z_pow_b, alpha);
    let e2 = neg(t, zba);
    let rho_c0 = t.mul(rho, c[0]);
    let rho_c2 = t.mul(rho, c[2]);
    let rho_c3 = t.mul(rho, c[3]);
    let rzt = t.mul(rho, z_t);
    let e7 = neg(t, rzt);
    let e8 = t.mul(rho, z_prime);
    let e9 = t.copy(g_z);
    t.mac(e9, rho, constant);
    let e9 = neg(t, e9);
    [
        one, rho_c1, e2, rho_c0, rho_c2, rho_c3, z, e7, e8, e9, one, rho,
    ]
}

// ---------------------------------------------------------------------------
// A shard
// ---------------------------------------------------------------------------

/// What a shard's tape imports, one 32-byte word each, in blob order: the
/// layout the host's blob builder reads off this list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// `ts_window[i]`.
    TsWindow(usize),
    /// Limb `limb` of witness stack `stack`'s commitment.
    Witness { stack: usize, limb: usize },
    /// GKR output `i`.
    Output(usize),
    /// Round `round`'s coefficient `coeff` of layer `layer`'s sumcheck.
    Round {
        layer: usize,
        round: usize,
        coeff: usize,
    },
    /// Layer `layer`'s final evaluation `i`.
    Final { layer: usize, i: usize },
    /// Limb `limb` of the batch's combined commitment `cm*`, a hint the
    /// deferred batch check holds to `Σ ρ^i cm_i`.
    CmStar(usize),
    /// Limb `limb` of the Mercury proof's point `point`, in field order.
    Point { point: usize, limb: usize },
    /// The Mercury proof's value `i`, in field order.
    Eval(usize),
}

/// The cells a shard's tape reads and its caller fills before replaying it:
/// the statement's, then this shard's.
pub struct ShardSlots {
    pub digest: Cell,
    pub memory: [Cell; 4],
    pub index: Cell,
    /// [`crate::shard_window`]'s id for a window family's shard; unread
    /// otherwise.
    pub window: Cell,
    pub roots: [Cell; 2],
    /// This shard's memory stacks' commitments, from the statement.
    pub memory_commitments: Vec<Limbs>,
    /// The key's setup commitments for the family, then the generic table's
    /// where the circuit reads it.
    pub setup: Vec<Limbs>,
}

/// What a shard's tape leaves for its caller: the time window, which the
/// block's rule reads across shards, and for the fold the batch's weights and
/// the Mercury check's twelve scalars, and the points they go with.
pub struct ShardOutputs {
    /// `ts_window`, as imported and held to step 4's range: the caller owes
    /// the block's rule across shards.
    pub ts_window: [Cell; 2],
    /// The GKR point, and every column's claim there in layout order — `M`,
    /// `W`, `S` — which step 10c reads on the public value shards.
    pub point: Vec<Cell>,
    pub claims: Vec<Cell>,
    /// The shard transcript's final state, three cells: what a node's own
    /// transcript absorbs, and so what its fold weights depend on.
    pub state: Cell,
    /// `ρ^i`, one per opened commitment in batch order: memory stacks, witness
    /// stacks, setup columns.
    pub batch: Vec<Cell>,
    /// The commitments those weights go with.
    pub commitments: Vec<Limbs>,
    /// `cm*`, the hint.
    pub cm_star: Limbs,
    /// The Mercury proof's eight points.
    pub points: [Limbs; 8],
    /// The Mercury check's twelve scalars, `pcs_verify::ENTRY_POINTS` order.
    pub mercury: [Cell; 12],
}

/// One shard shape's tape.
pub struct ShardTape {
    pub ops: Vec<Op>,
    pub inputs: Vec<Input>,
    pub slots: ShardSlots,
    pub outputs: ShardOutputs,
    /// One past the last cell the tape uses.
    pub end: Cell,
}

/// The tape of every check [`crate::verify_shard_local`] makes on a shard of
/// `circuit` at the key's height for it, under `config`'s format, and the
/// field side of its deferred opening — steps 7 to 11 and Mercury. `setup`
/// is how many setup commitments the opening reads, the generic table's
/// included. Its scratch starts at `first`.
///
/// **Not here**: step 10c, which only the two public value families carry
/// and whose shape is the statement's byte length (`crate::chain::public_value`),
/// and the curve checks a point's limbs owe, which the fold makes.
pub fn shard_tape(
    config: &crate::VmConfig,
    circuit: &constraints::FamilyCircuit,
    setup: usize,
    first: Cell,
) -> ShardTape {
    use constants::challenge_slot as slot;
    let a = &circuit.artifact;
    let sigma = config.stack_vars(a);
    let m = crate::stack_count(a.memory.len(), sigma);
    let w = crate::stack_count(a.witness.len(), sigma);
    let mut t = Tape::new(first);
    let mut inputs: Vec<Input> = Vec::new();
    let mut import = |t: &mut Tape, what: Input| {
        inputs.push(what);
        t.input()
    };
    let limbs = |t: &mut Tape| -> Limbs { [t.fresh(1), t.fresh(1), t.fresh(1), t.fresh(1)] };

    let slots = ShardSlots {
        digest: t.fresh(1),
        memory: [t.fresh(1), t.fresh(1), t.fresh(1), t.fresh(1)],
        index: t.fresh(1),
        window: t.fresh(1),
        roots: [t.fresh(1), t.fresh(1)],
        memory_commitments: (0..m).map(|_| limbs(&mut t)).collect(),
        setup: (0..setup).map(|_| limbs(&mut t)).collect(),
    };

    // 7. The shard transcript: the seed, the window, the witness stacks, then
    //    `g` and `β` (`crate::shard_transcript`).
    let mut tr = CellTranscript::new();
    let family = t.constant(Fr::from_u64(circuit.family as u64));
    tr.append(
        &mut t,
        tags::SHARD_SEED,
        &[slots.digest, family, slots.index],
    );
    let ts = [
        import(&mut t, Input::TsWindow(0)),
        import(&mut t, Input::TsWindow(1)),
    ];
    tr.append(&mut t, tags::SHARD_TS_WINDOW, &ts);
    // 4. `start <= end <= 2^38`: `start`, `end − start` and `2^38 − end` all
    //    below `2^39`.
    let span = t.sub(ts[1], ts[0]);
    let top = t.constant(Fr::from_u64(1 << constants::memory::TS_BITS));
    let room = t.sub(top, ts[1]);
    for x in [ts[0], span, room] {
        crate::chain::below(&mut t, x, constants::memory::TS_BITS + 1);
    }
    let witness: Vec<Limbs> = (0..w)
        .map(|stack| core::array::from_fn(|limb| import(&mut t, Input::Witness { stack, limb })))
        .collect();
    append_points(&mut tr, &mut t, tags::COMMITMENT, &witness);
    let g = tr.challenge(&mut t, tags::LOOKUP_CHALLENGE);
    let beta = tr.challenge(&mut t, tags::LOOKUP_CHALLENGE);

    // The challenge slots, `crate::shard_challenges` and
    // `gkr_verify::insert_lookup_challenges`.
    let mut ch: BTreeMap<u32, Cell> = BTreeMap::new();
    for (i, s) in [
        slot::MEM_GAMMA,
        slot::MEM_ALPHA_ADDR,
        slot::MEM_ALPHA_TS,
        slot::MEM_ALPHA_VAL,
    ]
    .into_iter()
    .enumerate()
    {
        ch.insert(s, slots.memory[i]);
    }
    let window = |space: u8, stride: u64| {
        move |t: &mut Tape| -> Cell {
            // γ + space + α_addr·(stride·2^n·w).
            let span = t.constant(Fr::from_u64(stride << a.trace_vars));
            let first = t.mul(span, slots.window);
            let space = t.constant(Fr::from_u64(space as u64));
            let c = t.add(slots.memory[0], space);
            t.mac(c, slots.memory[1], first);
            c
        }
    };
    use constants::{address_space, family as f};
    let constant = match circuit.family {
        f::INIT_TEARDOWN
        | f::ZERO_WINDOWS
        | f::PUBLIC_INPUT
        | f::PUBLIC_OUTPUT
        | f::ADVICE_WINDOWS => Some(window(address_space::RAM, 4)(&mut t)),
        f::FIELD_WINDOWS => Some(window(address_space::FIELD, 1)(&mut t)),
        _ => None,
    };
    if let Some(c) = constant {
        ch.insert(slot::MEM_WINDOW_CONSTANT, c);
    }
    ch.insert(slot::LOOKUP_G, g);
    let mut power = beta;
    for (i, s) in slot::LOOKUP_BETA_POWERS.iter().enumerate() {
        ch.insert(*s, power);
        if i + 1 < slot::LOOKUP_BETA_POWERS.len() {
            power = t.mul(power, beta);
        }
    }
    let decoder = a
        .lookups
        .iter()
        .find(|l| l.channel == constants::lookup_channel::DECODER)
        .map_or(0, |l| l.tuple.len());
    if decoder > 0 {
        let powers = t.powers(beta, decoder);
        let sum = t.sum(&powers);
        ch.insert(slot::LOOKUP_DECODER_NEUTRAL, t.sub(g, sum));
    }

    // 8. The circuit, the outputs and every layer imported as `gkr_inputs` lays
    //    them out.
    let proof = {
        let outputs = (0..a.outputs.len())
            .map(|i| import(&mut t, Input::Output(i)))
            .collect();
        let mut layers = Vec::new();
        for k in (0..a.depth()).rev() {
            let rounds = (0..a.layer_vars(k + 1) as usize)
                .map(|round| {
                    core::array::from_fn(|coeff| {
                        import(
                            &mut t,
                            Input::Round {
                                layer: k,
                                round,
                                coeff,
                            },
                        )
                    })
                })
                .collect();
            let width = a.layer_width(k) as usize;
            let n = if a.layers[k].halving {
                2 * width
            } else {
                width
            };
            let evals = (0..n)
                .map(|i| import(&mut t, Input::Final { layer: k, i }))
                .collect();
            layers.push((rounds, evals));
        }
        GkrCells { outputs, layers }
    };
    let (claims, u) = gkr_verify(&mut t, &mut tr, a, &proof, &ch);

    // 9. Every channel balances: the numerator 0 and the denominator not.
    for j in 0..circuit.channels.len() {
        t.assert_eq(proof.outputs[2 + 2 * j], ZERO);
        t.assert_nonzero(proof.outputs[3 + 2 * j]);
    }
    // 10a. The shard's roots are the statement's.
    t.assert_eq(proof.outputs[constants::memory::READ_ROOT], slots.roots[0]);
    t.assert_eq(proof.outputs[constants::memory::WRITE_ROOT], slots.roots[1]);

    // 11. Stacks of `2^σ` at `u ‖ r`, a setup column a stack of one
    //     (`crate::stack_values`), then the batch's preamble and Mercury.
    let r: Vec<Cell> = (0..sigma)
        .map(|_| tr.challenge(&mut t, tags::STACK_CHALLENGE))
        .collect();
    // `poly::eq_table`, in its order: bit `j` set lands `2^j` further along.
    let mut eq_r = vec![t.constant(Fr::ONE)];
    for rj in &r {
        let high: Vec<Cell> = eq_r.iter().map(|e| t.mul(*e, *rj)).collect();
        let low: Vec<Cell> = eq_r.iter().zip(&high).map(|(e, h)| t.sub(*e, *h)).collect();
        eq_r = low.into_iter().chain(high).collect();
    }
    let (mc, wc) = (a.memory.len(), a.witness.len());
    let stacked = |t: &mut Tape, columns: &[Cell]| -> Vec<Cell> {
        columns
            .chunks(eq_r.len())
            .map(|stack| t.dot(stack, &eq_r[..stack.len()]))
            .collect()
    };
    let mut values = stacked(&mut t, &claims[..mc]);
    values.extend(stacked(&mut t, &claims[mc..mc + wc]));
    for v in &claims[mc + wc..] {
        values.push(t.mul(*v, eq_r[0]));
    }
    let mut point = u.clone();
    point.extend(r);
    let mut commitments = slots.memory_commitments.clone();
    commitments.extend(witness);
    commitments.extend(slots.setup.iter().copied());
    let (batch, v_star) = batch_preamble(&mut t, &mut tr, &commitments, &point, &values);
    let cm_star: Limbs = core::array::from_fn(|limb| import(&mut t, Input::CmStar(limb)));
    let points: [Limbs; 8] = core::array::from_fn(|point| {
        core::array::from_fn(|limb| import(&mut t, Input::Point { point, limb }))
    });
    let evals: [Cell; 6] = core::array::from_fn(|i| import(&mut t, Input::Eval(i)));
    let mercury = mercury_scalars(&mut t, &mut tr, cm_star, &point, v_star, &points, &evals);

    ShardTape {
        end: t.end(),
        ops: t.ops,
        inputs,
        slots,
        outputs: ShardOutputs {
            ts_window: ts,
            point: u,
            claims,
            state: tr.state(),
            batch,
            commitments,
            cm_star,
            points,
            mercury,
        },
    }
}

/// The input blob `inputs` lays out over `proof`: each value's 32 canonical
/// little-endian bytes, a point's limbs through `transcript::g1_limbs`, and
/// `cm_star` the batch's combined commitment, which the host computes. The
/// Mercury proof's six values are its own bytes, which `IMPORT` reads as they
/// are.
pub fn shard_blob(inputs: &[Input], proof: &crate::ShardProof, cm_star: &[u8; 64]) -> Vec<u8> {
    let limb = |point: &[u8], i: usize| {
        transcript::g1_limbs(point.try_into().expect("a point is 64 bytes"))[i].to_bytes()
    };
    let opening = &proof.opening;
    let mut out = Vec::with_capacity(32 * inputs.len());
    for input in inputs {
        let word: [u8; 32] = match *input {
            Input::TsWindow(i) => Fr::from_u64(proof.ts_window[i]).to_bytes(),
            Input::Witness { stack, limb: i } => limb(&proof.witness_commitments[stack], i),
            Input::Output(i) => proof.outputs[i].to_bytes(),
            Input::Round {
                layer,
                round,
                coeff,
            } => proof.gkr.layers[layer].rounds[round][coeff].to_bytes(),
            Input::Final { layer, i } => proof.gkr.layers[layer].final_evals[i].to_bytes(),
            Input::CmStar(i) => limb(cm_star, i),
            Input::Point { point, limb: i } => limb(&opening[64 * point..64 * point + 64], i),
            Input::Eval(i) => opening[8 * 64 + 32 * i..8 * 64 + 32 * i + 32]
                .try_into()
                .expect("32 bytes"),
        };
        out.extend_from_slice(&word);
    }
    out
}

// ---------------------------------------------------------------------------
// The guest's form
// ---------------------------------------------------------------------------

/// A tape as the guest replays it (`docs/spec/recursion.md` §7): the cells
/// its imports fill, in blob order — the guest imports them up front, the
/// blob's 32-byte word `i` into `imports[i]` — then its body, runs of one
/// family's frames: a run is that family's ecall number, its count, then its
/// frames back to back, which a replay walks with `a0` advancing itself
/// (§1.4). Hoisting the imports is sound because a tape never reuses a cell:
/// an import fills a fresh one, which nothing reads before it.
pub struct Encoded {
    pub imports: Vec<Cell>,
    pub body: Vec<u32>,
}

/// `ops` in the guest's form.
pub fn encode(ops: &[Op]) -> Encoded {
    let mut imports = Vec::new();
    let mut body: Vec<u32> = Vec::new();
    let mut run: Option<(u32, usize)> = None;
    for op in ops {
        let (number, frame): (u32, &[u32]) = match op {
            Op::Fr(frame) => (constants::ecall::PRECOMPILE_FR_OP, frame),
            Op::Duplex(frame) => (constants::ecall::PRECOMPILE_P2_FIELD, frame),
            Op::Fq(frame) => (constants::ecall::PRECOMPILE_FQ_OP, frame),
            Op::Import { cell, offset } => {
                assert_eq!(
                    *offset as usize,
                    32 * imports.len(),
                    "tape: an import out of blob order"
                );
                imports.push(*cell);
                continue;
            }
        };
        match run {
            Some((n, at)) if n == number => body[at + 1] += 1,
            _ => {
                run = Some((number, body.len()));
                body.extend_from_slice(&[number, 1]);
            }
        }
        body.extend_from_slice(frame);
    }
    Encoded { imports, body }
}

// ---------------------------------------------------------------------------
// The native reading
// ---------------------------------------------------------------------------

/// A field element's integer, when it is below `2^128`.
fn small(v: Fr) -> Option<u128> {
    let b = v.to_bytes();
    b[16..]
        .iter()
        .all(|x| *x == 0)
        .then(|| u128::from_le_bytes(b[..16].try_into().expect("sixteen bytes")))
}

/// The field memory as [`run`] keeps it: each cell's value, and when it was
/// last accessed. An access writes its cell back at its own timestamp, and
/// `FQ_OP` reads `b`'s and `d`'s four cells under one (`docs/spec/recursion.md`
/// §6), so an element whose cells were last accessed apart is one the fill
/// refuses — and `run` refuses it first.
#[derive(Clone, Debug, Default)]
pub struct Memory {
    values: Vec<Fr>,
    stamps: Vec<u64>,
    clock: u64,
}

impl Memory {
    /// Cell `c`'s value, 0 until something writes it.
    pub fn get(&self, c: Cell) -> Fr {
        self.values.get(c as usize).copied().unwrap_or(Fr::ZERO)
    }

    /// Write `v` into `c` as an import does: an access of its own.
    pub fn set(&mut self, c: Cell, v: Fr) {
        self.clock += 4;
        self.write(c, v, self.clock);
    }

    fn touch(&mut self, c: Cell, at: u64) {
        let c = c as usize;
        if self.values.len() <= c {
            self.values.resize(c + 1, Fr::ZERO);
            self.stamps.resize(c + 1, 0);
        }
        self.stamps[c] = at;
    }

    fn write(&mut self, c: Cell, v: Fr, at: u64) {
        self.touch(c, at);
        self.values[c as usize] = v;
    }

    /// Whether `c..c + 4` were last accessed together, and so read as one.
    fn whole(&self, c: Cell) -> bool {
        let stamp = |k: u32| self.stamps.get((c + k) as usize).copied().unwrap_or(0);
        (1..4).all(|k| stamp(k) == stamp(0))
    }
}

/// Replay `ops` natively over `memory`, the input blob being `blob`: what the
/// coprocessor would compute, with every assertion — and every element read
/// whole that was not written whole — an `Err` naming the op. Each op's
/// accesses come in the circuits' slot order, so a cell a later access of
/// the same op reads carries the earlier one's stamp. An `FQ_OP` result is
/// the reduced representative, as the executor writes.
pub fn run(ops: &[Op], memory: &mut Memory, blob: &[u8]) -> Result<(), usize> {
    for (i, op) in ops.iter().enumerate() {
        memory.clock += 4;
        let ts = memory.clock;
        match *op {
            Op::Fr([code, d, a, b]) => {
                let (va, vb, vd) = (memory.get(a), memory.get(b), memory.get(d));
                memory.touch(a, ts + 1);
                if !matches!(code, fr_op::IMM | fr_op::SHL) {
                    memory.touch(b, ts + 2);
                }
                let out = match code {
                    fr_op::MUL => va * vb,
                    fr_op::ADD => va + vb,
                    fr_op::SUB => va - vb,
                    fr_op::MAC => vd + va * vb,
                    fr_op::INV => va.inverse().unwrap_or(Fr::ZERO),
                    fr_op::EQ => {
                        if va != vb {
                            return Err(i);
                        }
                        continue;
                    }
                    fr_op::IMM => Fr::from_u64(b as u64),
                    fr_op::SHL => va * Fr::from_u64(1 << 32) + Fr::from_u64(b as u64),
                    // The rest to `b` at its slot, then the digit to `d`.
                    fr_op::DIGIT => {
                        let digit =
                            Fr::from_u64(va.to_bytes()[0] as u64 & ((1 << fr_op::DIGIT_BITS) - 1));
                        let unit = Fr::from_u64(1 << fr_op::DIGIT_BITS)
                            .inverse()
                            .expect("a power of two is invertible");
                        memory.write(b, (va - digit) * unit, ts + 2);
                        digit
                    }
                    _ => return Err(i),
                };
                memory.write(d, out, ts + 3);
            }
            Op::Duplex([n, s, x, y, d]) => {
                let state = [memory.get(s), memory.get(s + 1), memory.get(s + 2)];
                let mut lanes = [
                    if n >= 1 { memory.get(x) } else { state[0] },
                    match n {
                        2 => memory.get(y),
                        1 => Fr::ZERO,
                        _ => state[1],
                    },
                    state[2] + Fr::from_u64(n as u64),
                ];
                transcript::poseidon2_permute(&mut lanes);
                for k in 0..3 {
                    memory.touch(s + k, ts);
                }
                if n >= 1 {
                    memory.touch(x, ts + 1);
                }
                if n >= 2 {
                    memory.touch(y, ts + 2);
                }
                for (j, lane) in lanes.iter().enumerate() {
                    memory.write(d + j as u32, *lane, ts + 3);
                }
            }
            Op::Fq([word, d, a, b]) => {
                use constants::fq_op as q;
                use constraints::fq_op as arith;
                let g = word >> q::DIGIT_SHIFT;
                let digit = small(memory.get(g)).ok_or(i)? as u32;
                memory.touch(g, ts);
                let at = |flag: u32, w: u32| match word & flag {
                    0 => w,
                    _ => w + q::BUCKET_CELLS * digit,
                };
                let (dc, ac, bc) = (at(q::IND_D, d), at(q::IND_A, a), at(q::IND_B, b));
                let element = |m: &Memory, c: u32| -> Option<[u64; 4]> {
                    let mut out = [0u64; 4];
                    for (k, limb) in out.iter_mut().enumerate() {
                        *limb = arith::limb(m.get(c + k as u32))?;
                    }
                    Some(out)
                };
                let code = word & ((1 << q::CODE_BITS) - 1);
                let operands = match code {
                    q::FROM128 => None,
                    _ => Some((element(memory, ac).ok_or(i)?, element(memory, bc).ok_or(i)?)),
                };
                let (lo, hi) = (memory.get(ac), memory.get(ac + 1));
                for k in 0..4 {
                    memory.touch(ac + k, ts + 1);
                }
                if !memory.whole(bc) {
                    return Err(i);
                }
                for k in 0..4 {
                    memory.touch(bc + k, ts + 2);
                }
                if !memory.whole(dc) {
                    return Err(i);
                }
                let out = match (code, operands) {
                    (q::FROM128, _) => {
                        let lo = small(lo).ok_or(i)?;
                        let hi = small(hi).ok_or(i)?;
                        [lo as u64, (lo >> 64) as u64, hi as u64, (hi >> 64) as u64]
                    }
                    (q::MUL, Some((x, y))) => arith::mul_mod_q(x, y),
                    (q::ADD, Some((x, y))) => arith::add_mod_q(x, y),
                    (q::SUB, Some((x, y))) => arith::sub_mod_q(x, y),
                    (q::MULEQ, Some((x, y))) => {
                        let held = element(memory, dc).ok_or(i)?;
                        if arith::mul_mod_q(x, y) != arith::canonical(held) {
                            return Err(i);
                        }
                        held
                    }
                    _ => return Err(i),
                };
                for (k, limb) in out.iter().enumerate() {
                    memory.write(dc + k as u32, Fr::from_u64(*limb), ts + 3);
                }
            }
            Op::Import { cell, offset } => {
                let bytes = blob.get(offset as usize..offset as usize + 32).ok_or(i)?;
                let mut v = Fr::ZERO;
                for k in (0..8).rev() {
                    let w =
                        u32::from_le_bytes(bytes[4 * k..4 * k + 4].try_into().expect("four bytes"));
                    v = v * Fr::from_u64(1 << 32) + Fr::from_u64(w as u64);
                }
                memory.write(cell, v, ts + 3);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An element `FQ_OP` reads under one timestamp — `b`, `d` — is refused
    /// once one of its cells is accessed alone, as the fill refuses it; `a`,
    /// read a timestamp a cell, is not.
    #[test]
    fn an_element_written_apart_is_refused() {
        use constants::fq_op as q;
        let (zero, e, halves, d) = (100, 104, 108, 112);
        let mut m = Memory::default();
        m.set(halves, Fr::from_u64(7));
        run(&[Op::Fq([q::FROM128, e, halves, zero])], &mut m, &[]).expect("written whole");
        run(&[Op::Fq([q::ADD, d, e, e])], &mut m, &[]).expect("read whole");
        m.set(e + 1, Fr::ZERO);
        let fq = |op: [u32; 4]| run(&[Op::Fq(op)], &mut m.clone(), &[]);
        assert_eq!(fq([q::ADD, d, zero, e]), Err(0), "as b");
        assert_eq!(fq([q::ADD, e, zero, zero]), Err(0), "as d");
        assert_eq!(fq([q::ADD, d, e, zero]), Ok(()), "as a");
    }

    /// `encode` keeps every frame in order, a run a family, and hoists the
    /// imports in blob order: the body read back as frames is the tape
    /// without its imports, and a replay of the hoisted form computes what the
    /// tape does.
    #[test]
    fn encoding_keeps_the_order_and_hoists_the_imports() {
        let mut t = Tape::new(3);
        let x = t.input();
        let mut tr = CellTranscript::new();
        tr.append(&mut t, 7, &[x]);
        let c = tr.challenge(&mut t, 9);
        let y = t.input();
        let p = t.mul(c, y);
        let q = t.add(p, x);
        let encoded = encode(&t.ops);
        assert_eq!(encoded.imports, vec![x, y]);

        // The body, read back run by run.
        let mut frames: Vec<Op> = Vec::new();
        let mut at = 0;
        while at < encoded.body.len() {
            let (number, count) = (encoded.body[at], encoded.body[at + 1] as usize);
            at += 2;
            for _ in 0..count {
                let op = match number {
                    constants::ecall::PRECOMPILE_FR_OP => {
                        Op::Fr(encoded.body[at..at + 4].try_into().expect("four words"))
                    }
                    constants::ecall::PRECOMPILE_P2_FIELD => {
                        Op::Duplex(encoded.body[at..at + 5].try_into().expect("five words"))
                    }
                    other => panic!("no family has number {other:#x}"),
                };
                at += if matches!(op, Op::Fr(_)) { 4 } else { 5 };
                frames.push(op);
            }
        }
        let without: Vec<Op> = t
            .ops
            .iter()
            .filter(|op| !matches!(op, Op::Import { .. }))
            .copied()
            .collect();
        assert_eq!(frames, without);

        // The hoisted form replays to the same cells.
        let blob: Vec<u8> = [Fr::from_u64(5), Fr::from_u64(11)]
            .iter()
            .flat_map(|v| v.to_bytes())
            .collect();
        let mut direct = Memory::default();
        run(&t.ops, &mut direct, &blob).expect("the tape runs");
        let mut hoisted = Memory::default();
        let imports: Vec<Op> = encoded
            .imports
            .iter()
            .enumerate()
            .map(|(i, cell)| Op::Import {
                cell: *cell,
                offset: 32 * i as u32,
            })
            .collect();
        run(&imports, &mut hoisted, &blob).expect("the imports run");
        run(&without, &mut hoisted, &blob).expect("the body runs");
        assert_eq!(direct.get(q), hoisted.get(q));
        assert_eq!(
            direct.get(q),
            direct.get(c) * Fr::from_u64(11) + Fr::from_u64(5)
        );
    }
}
