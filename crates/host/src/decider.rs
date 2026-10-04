//! The decider: the recursion tree's root, verified once more — in a Groth16
//! circuit a contract checks.
//!
//! The circuit is `verifier_core::node`'s internal-node procedure over one
//! child, the root, run through a driver that writes every field call as
//! rank-1 constraints: an `FR_OP` is a constraint or an alias, a duplex is
//! Poseidon2's 80 S-boxes, advice is a free wire. It verifies the root's
//! every shard, the global transcript and the memory argument, holds the
//! root's journal to cover its whole base statement, and derives the scalar of
//! every point the root's proof and journal owe a pairing.
//!
//! **It folds nothing.** A point's limbs and its scalar are bound wires
//! (`groth16`), beside what the proof is about — the two recursion programs'
//! identities and the base statement's `io_digest` and exit status — so the
//! verifier holds their values and does the two multi-scalar multiplications
//! itself, with the curve arithmetic a contract has precompiles for and a
//! BN254 circuit does not. Then two pairing checks: the Groth16 proof's, and
//! the accumulator's.

use curve::pairing::pairing_check;
use curve::{G1Affine, G1Projective, G2Affine};
use field::Fr;
use groth16::{Proof, ProvingKey, Sink, Var, VerifyingKey, ONE};
use verifier_core::fold::{FoldPoint, Side};
use verifier_core::node::{journal, node, Advice, Driver, Header, ImageTemplate, NodeImage};
use verifier_core::tape::{infinity_sentinel, run, Cell, Op};
use verifier_core::BlockProof;

use constants::{fr_op, POSEIDON2_RC3_INITIAL, POSEIDON2_RC3_INTERNAL, POSEIDON2_RC3_TERMINAL};

use crate::recursion::{Native, Statement};

/// The tree's root, as the decider takes it.
pub struct Root<'a> {
    /// The internal node's image: the two recursion programs' tapes.
    pub image: &'a [u32],
    /// The root's program: 0 the leaf's, 1 the node's; its key; its proof.
    pub program: u32,
    pub vk: &'a verifier_core::VerifyingKey,
    pub block: &'a BlockProof,
    /// The leaf program's and the node program's identities.
    pub identities: [Fr; 2],
}

/// The values a verifier holds before the points: the two identities, the
/// base statement's `io_digest` and its exit status.
pub const PUBLIC: usize = 4;
/// A point's values: its four limbs, then its scalar.
pub const POINT: usize = 5;

/// A decided root: the proof, the bound values — [`PUBLIC`] of them, then
/// [`POINT`] a point, side `A`'s points and then side `B`'s — and how many
/// points each side has.
pub struct Decision {
    pub proof: Proof,
    pub data: Vec<Fr>,
    pub sides: [usize; 2],
}

/// A cell with no wire: it holds 0, and nothing has constrained it.
const NONE: Var = Var::MAX;

/// The driver: the native one for every value, and a constraint for every
/// call.
struct Circuit<'a, 's> {
    native: Native<'a>,
    sink: &'s mut dyn Sink,
    /// Each cell's wire now: a cell is a new wire every time it is written.
    wires: Vec<Var>,
    /// Poseidon2's round constants, in round order.
    constants: Vec<Fr>,
    public: Vec<Var>,
    points: [Vec<Var>; 2],
}

impl Circuit<'_, '_> {
    fn wire(&self, cell: Cell) -> Var {
        self.wires.get(cell as usize).copied().unwrap_or(NONE)
    }

    fn set(&mut self, cell: Cell, wire: Var) {
        if self.wires.len() <= cell as usize {
            self.wires.resize(cell as usize + 1, NONE);
        }
        self.wires[cell as usize] = wire;
    }

    /// A new wire for `cell`, holding its value.
    fn fresh(&mut self, cell: Cell) -> Var {
        let wire = self.sink.alloc(self.native.memory.get(cell));
        self.set(cell, wire);
        wire
    }

    /// `a·b = c`, each a sum of wires, one with no wire being 0.
    fn enforce(&mut self, a: &[(Var, Fr)], b: &[(Var, Fr)], c: &[(Var, Fr)]) {
        let live = |lc: &[(Var, Fr)]| -> Vec<(Var, Fr)> {
            lc.iter().filter(|t| t.0 != NONE).copied().collect()
        };
        self.sink.enforce(&live(a), &live(b), &live(c));
    }

    /// `cell`'s wire, for a value the verifier holds: one made, and held to
    /// 0, where the cell has none.
    fn bound(&mut self, cell: Cell) -> Var {
        if self.wire(cell) == NONE {
            let wire = self.fresh(cell);
            self.enforce(&[(wire, Fr::ONE)], &[(ONE, Fr::ONE)], &[]);
        }
        self.wire(cell)
    }

    /// One call: run natively, then constrained.
    fn op(&mut self, op: &Op) {
        if self.native.failed.is_some() {
            return;
        }
        let one = Fr::ONE;
        let unit = [(ONE, one)];
        let step = |c: &mut Self| {
            if run(core::slice::from_ref(op), &mut c.native.memory, &[]).is_err() {
                c.native.fail(format!("{op:?} refuses"));
            }
        };
        match *op {
            Op::Fr([code, d, a, b]) => {
                let (wa, wd) = (self.wire(a), self.wire(d));
                // `IMM` and `SHL` read `b` as an integer.
                let word = Fr::from_u64(b as u64);
                let wb = match code {
                    fr_op::IMM | fr_op::SHL => NONE,
                    _ => self.wire(b),
                };
                let zero = self.native.memory.get(a) == Fr::ZERO;
                step(self);
                match code {
                    fr_op::EQ => self.enforce(&[(wa, one), (wb, -one)], &unit, &[]),
                    // A sum with nothing is the other operand's wire.
                    fr_op::ADD if wa == NONE || wb == NONE => self.set(d, wa.min(wb)),
                    fr_op::SUB if wb == NONE => self.set(d, wa),
                    fr_op::IMM if b == 0 => self.set(d, NONE),
                    fr_op::DIGIT => {
                        // `a = digit + 2^8·rest`, the digit eight bits.
                        let digit = self.native.memory.get(d).to_bytes()[0];
                        let bits: Vec<(Var, Fr)> = (0..8)
                            .map(|i| {
                                let bit = self.sink.alloc(Fr::from_u64((digit >> i & 1) as u64));
                                self.enforce(&[(bit, one)], &[(bit, one), (ONE, -one)], &[]);
                                (bit, Fr::from_u64(1 << i))
                            })
                            .collect();
                        let (rest, digit) = (self.fresh(b), self.fresh(d));
                        self.enforce(&bits, &unit, &[(digit, one)]);
                        let shift = Fr::from_u64(1 << 8).inverse().expect("nonzero");
                        self.enforce(&[(wa, one), (digit, -one)], &[(ONE, shift)], &[(rest, one)]);
                    }
                    _ => {
                        let out = self.fresh(d);
                        let out = [(out, one)];
                        match code {
                            fr_op::MUL => self.enforce(&[(wa, one)], &[(wb, one)], &out),
                            fr_op::ADD => self.enforce(&[(wa, one), (wb, one)], &unit, &out),
                            fr_op::SUB => self.enforce(&[(wa, one), (wb, -one)], &unit, &out),
                            fr_op::MAC => {
                                self.enforce(&[(wa, one)], &[(wb, one)], &[out[0], (wd, -one)])
                            }
                            fr_op::IMM => self.enforce(&[(ONE, word)], &unit, &out),
                            fr_op::SHL => {
                                let shift = Fr::from_u64(1 << 32);
                                self.enforce(&[(wa, shift), (ONE, word)], &unit, &out)
                            }
                            // `a·d = 1 − z`, `z·a = 0`, `z·d = 0`: `z` is
                            // whether `a` is 0, and `d` is 0 there.
                            fr_op::INV => {
                                let z = self.sink.alloc(Fr::from_u64(zero as u64));
                                self.enforce(&[(wa, one)], &out, &[(ONE, one), (z, -one)]);
                                self.enforce(&[(z, one)], &[(wa, one)], &[]);
                                self.enforce(&[(z, one)], &out, &[]);
                            }
                            _ => self.native.fail(format!("{op:?} is no field operation")),
                        }
                    }
                }
            }
            Op::Duplex([n, s, x, y, d]) => {
                let state = [0, 1, 2].map(|k| (self.wire(s + k), self.native.memory.get(s + k)));
                let absorbed = [x, y].map(|c| (self.wire(c), self.native.memory.get(c)));
                step(self);
                let lanes = [
                    if n >= 1 { absorbed[0] } else { state[0] },
                    match n {
                        2 => absorbed[1],
                        1 => (NONE, Fr::ZERO),
                        _ => state[1],
                    },
                    state[2],
                ];
                let out = self.permute(lanes, Fr::from_u64(n as u64));
                for (k, wire) in out.into_iter().enumerate() {
                    debug_assert_eq!(self.sink.value(wire), self.native.memory.get(d + k as u32));
                    self.set(d + k as u32, wire);
                }
            }
            _ => self.native.fail(format!("{op:?} is not the decider's")),
        }
    }

    /// `transcript::poseidon2_permute` over three lanes, each a wire and its
    /// value, lane 2 with `count` more: three constraints an S-box, and one a
    /// lane of the result.
    ///
    /// A lane is a sum over `basis`, wire 0 of it the constant: a linear
    /// layer moves coefficients and costs nothing, so through the partial
    /// rounds lanes 1 and 2 grow a term a round.
    fn permute(&mut self, input: [(Var, Fr); 3], count: Fr) -> [Var; 3] {
        let mut basis = vec![ONE];
        let mut lanes: [Vec<Fr>; 3] = core::array::from_fn(|_| vec![Fr::ZERO]);
        let mut values = input.map(|(_, v)| v);
        for (k, (wire, _)) in input.into_iter().enumerate() {
            if wire != NONE {
                basis.push(wire);
                for (j, lane) in lanes.iter_mut().enumerate() {
                    lane.push(if j == k { Fr::ONE } else { Fr::ZERO });
                }
            }
        }
        lanes[2][0] = count;
        values[2] += count;

        // The two linear layers: every lane plus the lanes' sum, the internal
        // one doubling lane 2 first.
        fn mix(lanes: &mut [Vec<Fr>; 3], values: &mut [Fr; 3], internal: bool) {
            for i in 0..lanes[0].len() {
                let sum = lanes[0][i] + lanes[1][i] + lanes[2][i];
                if internal {
                    let double = lanes[2][i] + lanes[2][i];
                    lanes[2][i] = double;
                }
                for lane in lanes.iter_mut() {
                    lane[i] += sum;
                }
            }
            let sum = values[0] + values[1] + values[2];
            if internal {
                values[2] = values[2] + values[2];
            }
            for v in values.iter_mut() {
                *v += sum;
            }
        }

        let constants = core::mem::take(&mut self.constants);
        let mut constant = constants.iter();
        mix(&mut lanes, &mut values, false);
        for round in 0..64 {
            let full = !(4..60).contains(&round);
            let mut outputs = Vec::with_capacity(3);
            for k in 0..if full { 3 } else { 1 } {
                // `y = (lane + rc)^5`, by `u² `, `u⁴` and `u⁴·u`.
                let rc = *constant.next().expect("a constant an S-box");
                lanes[k][0] += rc;
                let u: Vec<(Var, Fr)> = basis
                    .iter()
                    .zip(&lanes[k])
                    .filter(|(_, c)| **c != Fr::ZERO)
                    .map(|(w, c)| (*w, *c))
                    .collect();
                let v = values[k] + rc;
                let (v2, v4) = (v.square(), v.square().square());
                let [u2, u4, y] = [v2, v4, v4 * v].map(|v| self.sink.alloc(v));
                self.sink.enforce(&u, &u, &[(u2, Fr::ONE)]);
                self.sink
                    .enforce(&[(u2, Fr::ONE)], &[(u2, Fr::ONE)], &[(u4, Fr::ONE)]);
                self.sink.enforce(&[(u4, Fr::ONE)], &u, &[(y, Fr::ONE)]);
                values[k] = v4 * v;
                outputs.push(y);
            }
            if full {
                // Three new wires are the whole state.
                basis.truncate(1);
                for lane in lanes.iter_mut() {
                    lane.truncate(1);
                    lane[0] = Fr::ZERO;
                }
            } else {
                lanes[0].fill(Fr::ZERO);
            }
            for (k, y) in outputs.into_iter().enumerate() {
                basis.push(y);
                for (j, lane) in lanes.iter_mut().enumerate() {
                    lane.push(if j == k { Fr::ONE } else { Fr::ZERO });
                }
            }
            mix(&mut lanes, &mut values, !full);
        }
        self.constants = constants;

        core::array::from_fn(|k| {
            let out = self.sink.alloc(values[k]);
            let lane: Vec<(Var, Fr)> = basis
                .iter()
                .copied()
                .zip(lanes[k].iter().copied())
                .filter(|(_, c)| *c != Fr::ZERO)
                .collect();
            self.sink
                .enforce(&lane, &[(ONE, Fr::ONE)], &[(out, Fr::ONE)]);
            out
        })
    }
}

impl Driver for Circuit<'_, '_> {
    fn replay(&mut self, body: &[u32]) {
        match self.native.ops(body) {
            Some(ops) => self.run(&ops),
            None => self.native.fail("an image body does not decode".into()),
        }
    }

    fn run(&mut self, ops: &[Op]) {
        for op in ops {
            self.op(op);
        }
    }

    fn advise(&mut self, cells: &[Cell], what: Advice) {
        self.native.advise(cells, what);
        for cell in cells {
            self.fresh(*cell);
        }
    }

    // The MSMs are the verifier's.
    fn template(&mut self, _: &ImageTemplate, _: Option<Cell>) {}

    fn point(&mut self, _: &NodeImage, p: &FoldPoint) {
        let wires: Vec<Var> = (0..4)
            .map(|k| p.limbs + k)
            .chain([p.scalar])
            .map(|cell| self.bound(cell))
            .collect();
        self.points[(p.side == Side::B) as usize].extend(wires);
    }

    fn infinity(&mut self, _: Cell) -> bool {
        unreachable!("the decider loads no point")
    }

    fn read(&mut self, _: Cell) -> u32 {
        unreachable!("the top follows no value")
    }

    fn export(&mut self, cells: &[Cell]) {
        self.public = [
            journal::IDENTITIES,
            journal::IDENTITIES + 1,
            journal::IO,
            journal::EXIT,
        ]
        .map(|k| self.bound(cells[k]))
        .to_vec();
    }

    fn top(&self) -> bool {
        true
    }
}

/// The decider's circuit over `root`, as `groth16` runs it, with how many
/// points each side has once it has run, and why the root was refused if it
/// was.
struct Decider<'a> {
    image: NodeImage<'a>,
    statement: Statement<'a>,
    identities: [Fr; 2],
    sides: [usize; 2],
    failed: Option<String>,
}

impl<'a> Decider<'a> {
    fn new(root: &Root<'a>) -> Result<Decider<'a>, String> {
        let total = root.block.shard_proofs().len();
        Ok(Decider {
            image: NodeImage::read(root.image).ok_or("the image does not read")?,
            statement: Statement::of(root.vk, root.block, root.program, 0..total)?,
            identities: root.identities,
            sides: [0; 2],
            failed: None,
        })
    }

    fn synthesize(&mut self, sink: &mut dyn Sink) -> Vec<Var> {
        let header = Header {
            statements: vec![self.statement.header.clone()],
        };
        let constants = POSEIDON2_RC3_INITIAL
            .iter()
            .flatten()
            .chain(&POSEIDON2_RC3_INTERNAL)
            .chain(POSEIDON2_RC3_TERMINAL.iter().flatten())
            .map(|hex| Fr::from_hex(hex).expect("a canonical literal"))
            .collect();
        let mut circuit = Circuit {
            native: Native::new(vec![self.statement.clone()], self.identities),
            sink,
            wires: Vec::new(),
            constants,
            public: Vec::new(),
            points: [Vec::new(), Vec::new()],
        };
        node(&mut circuit, &self.image, &header);
        self.failed = circuit.native.failed.take();
        let [a, b] = circuit.points;
        self.sides = [a.len() / POINT, b.len() / POINT];
        [circuit.public, a, b].concat()
    }
}

/// The key of the decider's circuit over a root of `root`'s shape — its
/// program and its statement's shard counts and windows — with trapdoors
/// `groth16::setup` derives from `seed`.
pub fn setup(root: &Root, seed: &[u8]) -> Result<ProvingKey, String> {
    let mut decider = Decider::new(root)?;
    let pk = groth16::setup(&mut |sink: &mut dyn Sink| decider.synthesize(sink), seed);
    decider.failed.map_or(Ok(pk), Err)
}

/// `root`, decided under `pk`.
pub fn prove(pk: &ProvingKey, root: &Root) -> Result<Decision, String> {
    let mut decider = Decider::new(root)?;
    let proved = groth16::prove(pk, &mut |sink: &mut dyn Sink| decider.synthesize(sink));
    if let Some(why) = decider.failed {
        return Err(format!("the root is refused: {why}"));
    }
    let (proof, data) = proved?;
    Ok(Decision {
        proof,
        data,
        sides: decider.sides,
    })
}

/// A bound point's 64 bytes from its four limbs: `x`'s and `y`'s low and high
/// 128 bits, or four sentinels for infinity, whose bytes are zeros.
pub fn point_bytes(limbs: &[Fr]) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    if limbs[0] != infinity_sentinel() {
        for (k, limb) in limbs.iter().enumerate() {
            bytes[16 * k..16 * (k + 1)].copy_from_slice(&limb.to_bytes()[..16]);
        }
    }
    bytes
}

/// What the contract does, natively: the Groth16 proof against the bound
/// values, each side's points folded under their scalars, and the
/// accumulator's pairing check, `e(A, [1]_2) = e(B, [x]_2)`.
pub fn verify(
    vk: &VerifyingKey,
    (g2_one, g2_x): (G2Affine, G2Affine),
    decision: &Decision,
) -> Result<(), String> {
    let data = &decision.data;
    let [a, b] = decision.sides;
    if data.len() != PUBLIC + POINT * (a + b) {
        return Err("the bound values are not the sides' points".into());
    }
    if !groth16::verify(vk, &decision.proof, data) {
        return Err("the Groth16 proof does not verify".into());
    }
    let fold = |points: &[Fr]| -> Result<G1Affine, String> {
        let mut sum = G1Projective::IDENTITY;
        for point in points.chunks_exact(POINT) {
            let p = G1Affine::from_bytes(&point_bytes(&point[..4])).ok_or("a point is not one")?;
            sum = sum.add(&G1Projective::from(p).mul(&point[4]));
        }
        Ok(sum.to_affine())
    };
    let (a, b) = data[PUBLIC..].split_at(POINT * a);
    if !pairing_check(&[(fold(a)?, g2_one), (-fold(b)?, g2_x)]) {
        return Err("the accumulator does not discharge".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

/// `contracts/ApogeeVerifier.sol`'s creation code, in hex:
/// `solc 0.8.30 --bin --optimize --optimize-runs 200`.
const CONTRACT: &str = include_str!("../../../contracts/ApogeeVerifier.bin");

/// 32 little-endian bytes as a contract's word.
fn word(le: &[u8]) -> [u8; 32] {
    groth16::word(le.try_into().expect("32 bytes"))
}

fn count(n: usize) -> [u8; 32] {
    word(&Fr::from_u64(n as u64).to_bytes())
}

fn g1_words(p: &G1Affine) -> Vec<u8> {
    p.to_bytes().chunks_exact(32).flat_map(word).collect()
}

/// A G2 point as the pairing precompile reads it: each coordinate's `c1`
/// before its `c0`.
fn g2_words(p: &G2Affine) -> Vec<u8> {
    let bytes = p.to_bytes();
    [1, 0, 3, 2]
        .into_iter()
        .flat_map(|k| word(&bytes[32 * k..32 * (k + 1)]))
        .collect()
}

/// The contract's constructor arguments: its key — the Groth16 key, the
/// ceremony's `[1]_2` and `[x]_2`, the two identities — and each side's
/// points.
pub fn constructor(
    vk: &VerifyingKey,
    (g2_one, g2_x): (G2Affine, G2Affine),
    identities: [Fr; 2],
    sides: [usize; 2],
) -> Vec<u8> {
    let mut out = g1_words(&vk.alpha);
    for p in [&vk.beta, &vk.gamma, &vk.delta, &vk.eta] {
        out.extend(g2_words(p));
    }
    for p in &vk.ic {
        out.extend(g1_words(p));
    }
    out.extend(g2_words(&g2_one));
    out.extend(g2_words(&g2_x));
    for id in identities {
        out.extend(word(&id.to_bytes()));
    }
    for side in sides {
        out.extend(count(side));
    }
    out
}

/// `verify`'s calldata for `decision`.
pub fn calldata(decision: &Decision) -> Vec<u8> {
    let data = &decision.data;
    let signature = b"verify(uint256,uint256,uint256[10],uint256[])";
    let mut out = revm::primitives::keccak256(signature)[..4].to_vec();
    for v in &data[2..PUBLIC] {
        out.extend(word(&v.to_bytes()));
    }
    let proof = &decision.proof;
    out.extend(g1_words(&proof.a));
    out.extend(g2_words(&proof.b));
    out.extend(g1_words(&proof.c));
    out.extend(g1_words(&proof.d));
    // The points: where the array starts, its length, then three words a
    // point.
    let points = data[PUBLIC..].chunks_exact(POINT);
    out.extend(count(32 * 13));
    out.extend(count(3 * points.len()));
    for point in points {
        out.extend(point_bytes(&point[..4]).chunks_exact(32).flat_map(word));
        out.extend(word(&point[4].to_bytes()));
    }
    out
}

/// The contract deployed with `constructor` and called with `calldata`, in
/// revm: the gas the call used, if the contract answers true.
pub fn onchain(constructor: &[u8], calldata: &[u8]) -> Result<u64, String> {
    use revm::context::TxEnv;
    use revm::database::{CacheDB, EmptyDB};
    use revm::primitives::TxKind;
    use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

    let mut code = test_support::hex_to_bytes(CONTRACT.trim())?;
    code.extend_from_slice(constructor);
    let mut evm = Context::mainnet()
        .with_db(CacheDB::new(EmptyDB::default()))
        .build_mainnet();
    let mut send = |nonce: u64, kind: TxKind, data: Vec<u8>| {
        let tx = TxEnv::builder()
            .kind(kind)
            .data(data.into())
            .gas_limit(16_000_000)
            .nonce(nonce)
            .build_fill();
        evm.transact_one(tx).map_err(|e| format!("{e:?}"))
    };
    let deployed = send(0, TxKind::Create, code)?;
    let address = deployed
        .created_address()
        .ok_or_else(|| format!("the contract does not deploy: {deployed:?}"))?;
    let called = send(1, TxKind::Call(address), calldata.to_vec())?;
    match called.output() {
        Some(output) if called.is_success() && output[..] == count(1) => Ok(called.tx_gas_used()),
        _ => Err(format!("the contract refuses: {called:?}")),
    }
}
