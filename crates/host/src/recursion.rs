//! The recursion guest's host side: what `guests/recursion` is handed.
//!
//! [`leaf_advice`] lays a leaf out for a slice of a base block and runs it
//! first, natively, over one `tape::Memory` in the guest's own order: each
//! shard's tape (`verifier_core::tape`), its fold into the node's
//! accumulator, and the accumulator's two MSMs (`verifier_core::fold`). So a
//! step that would refuse does so here, by name, before any guest runs — a
//! shard's checks, a point off the curve, an element read whole that was
//! written apart — and every inverse an MSM takes is computed where the guest
//! will import it. Building the advice verifies every shard natively, but for
//! the pairings, since a blob's `cm*` is entry 0 of the native deferred
//! verification (`docs/spec/accumulator.md` §2).
//!
//! The advice is a program the guest runs blind, step by step:
//!
//! ```text
//!   words: A's point, scalar and zero cells; B's; the sentinel's
//!   u32 b;  b x words: a body, `tape::encode`'s
//!   u32 l;  l x words: a cell list
//!   u32 n;  n x a step, a `u32` kind and its operands:
//!            0 IMPORT    u32 list;  bytes: one 32-byte word a cell
//!            1 REPLAY    u32 body
//!            2 WITNESS   u32 first; bytes: one 32-byte word a cell, consecutive
//!            3 LOAD      u32 limbs; u32 scalar; u32 side, 0 for A
//!            4 INFINITY  u32 limbs
//!   words: the cells the journal carries, A's result then B's
//! ```
//!
//! `words` is a little-endian `u32` count and that many `u32`s; `bytes` a
//! `u32` length, the bytes, and zero padding to a word. **A measurement
//! format, not a node's**: which steps run is the host's choice here, where a
//! node derives them from the statement and replays tapes its image holds
//! (`docs/spec/recursion.md` §8).

use std::ops::Range;

use curve::G1Affine;
use field::Fr;
use pcs::{batch_verify_deferred, MercuryCommitment, MercuryProof};
use transcript::g1_limbs;
use verifier_core::fold::{
    finish_template, halves, load_point, point_template, prelude, shard_fold, simulate, FoldPoint,
    Node, Side, Template, POINT_CELLS,
};
use verifier_core::tape::{
    encode, infinity_sentinel, run, shard_blob, shard_tape, Cell, Memory, Op, ShardTape,
};
use verifier_core::{
    derive_global_phase, shard_window, verify_shard_local, BlockProof, VerifyingKey,
};

/// Every tape's first scratch cell: cells `0..3` are the zero state.
const FIRST: Cell = 3;

/// One family's shape in the slice: its tape and fold, and their bodies.
struct Shape {
    family: u32,
    tape: ShardTape,
    setup: Vec<[u8; 64]>,
    slots: u32,
    imports: u32,
    body: u32,
    fold: (Vec<Op>, Vec<FoldPoint>),
    fold_body: u32,
}

/// The advice under construction, and the memory it is run over.
#[derive(Default)]
struct Leaf {
    bodies: Vec<Vec<u32>>,
    lists: Vec<Vec<u32>>,
    steps: Vec<u8>,
    count: u32,
    memory: Memory,
}

impl Leaf {
    /// A body for `ops`, which import nothing.
    fn body(&mut self, ops: &[Op]) -> u32 {
        let encoded = encode(ops);
        assert!(encoded.imports.is_empty(), "a body imports nothing");
        self.bodies.push(encoded.body);
        self.bodies.len() as u32 - 1
    }

    fn list(&mut self, cells: Vec<u32>) -> u32 {
        self.lists.push(cells);
        self.lists.len() as u32 - 1
    }

    fn step(&mut self, kind: u32, operands: &[u32]) {
        self.count += 1;
        for w in [kind].iter().chain(operands) {
            self.steps.extend_from_slice(&w.to_le_bytes());
        }
    }

    /// Run `ops` and replay them in the guest.
    fn replay(&mut self, body: u32, ops: &[Op], what: &str) -> Result<(), String> {
        run(ops, &mut self.memory, &[]).map_err(|op| format!("{what}: op {op} refuses"))?;
        self.step(1, &[body]);
        Ok(())
    }

    /// Run a template, its inverses imported first in the guest.
    fn template(&mut self, body: u32, template: &Template, what: &str) -> Result<(), String> {
        let inverses = simulate(template, &mut self.memory)
            .map_err(|op| format!("{what}: op {op} refuses"))?;
        if let Some(first) = template.holes.first() {
            let values: Vec<Fr> = inverses.iter().flat_map(halves).collect();
            self.step(2, &[first.into]);
            bytes(&mut self.steps, &cell_words(&values));
        }
        self.step(1, &[body]);
        Ok(())
    }
}

/// Each side's three templates and their bodies.
struct Msm {
    prelude: (Template, u32),
    point: (Template, u32),
    finish: (Template, u32),
}

/// `guests/recursion`'s advice for shards `shards` of `block`, in statement
/// order, verified against `vk`.
pub fn leaf_advice(
    vk: &VerifyingKey,
    block: &BlockProof,
    shards: Range<usize>,
) -> Result<Vec<u8>, String> {
    let public = block.statement();
    let proofs = block.shard_proofs().get(shards.clone()).ok_or_else(|| {
        format!(
            "the block has {} shards, so no slice {shards:?}",
            block.shard_proofs().len()
        )
    })?;
    let global = derive_global_phase(vk, public).map_err(|e| e.to_string())?;
    let vsrs = verifier::decode_srs_verifier(&vk.srs_verifier)
        .ok_or("the key's SrsVerifier holds a point that is not one")?;
    let mut leaf = Leaf::default();

    // The shapes, every tape from `FIRST`; then the node above them all.
    let mut shapes: Vec<Shape> = Vec::new();
    for proof in proofs {
        if shapes.iter().any(|s| s.family == proof.family) {
            continue;
        }
        let fi = vk
            .config
            .families
            .iter()
            .position(|(f, _)| *f == proof.family)
            .ok_or("a proof names a family the key has not")?;
        let circuit = &vk.circuits[fi];
        let mut setup = vk.setup_commitments[fi].clone();
        if circuit.reads_generic_table() {
            setup.extend(vk.generic_table);
        }
        let tape = shard_tape(&vk.config, circuit, setup.len(), FIRST);
        let encoded = encode(&tape.ops);
        leaf.bodies.push(encoded.body);
        let slots = leaf.list(slot_cells(&tape));
        let imports = leaf.list(encoded.imports);
        shapes.push(Shape {
            family: proof.family,
            body: leaf.bodies.len() as u32 - 1,
            tape,
            setup,
            slots,
            imports,
            fold: (Vec::new(), Vec::new()),
            fold_body: 0,
        });
    }
    let base = shapes.iter().map(|s| s.tape.end).max().unwrap_or(FIRST);
    let most = shapes
        .iter()
        .map(|s| 12 + s.tape.outputs.commitments.len() as u32)
        .max()
        .unwrap_or(0);
    let node = Node::at(base, most);
    for shape in &mut shapes {
        shape.fold = shard_fold(&shape.tape, &node);
        shape.fold_body = leaf.body(&shape.fold.0);
    }
    let msms: Vec<Msm> = [&node.a, &node.b]
        .into_iter()
        .map(|l| {
            let [prelude, point, finish] =
                [prelude(l), point_template(l), finish_template(l)].map(|t| {
                    let body = leaf.body(&t.ops);
                    (t, body)
                });
            Msm {
                prelude,
                point,
                finish,
            }
        })
        .collect();

    // The node's constants and both MSMs' preludes.
    let constants = node.prelude();
    let body = leaf.body(&constants);
    leaf.replay(body, &constants, "the node's constants")?;
    for (msm, side) in msms.iter().zip(["A", "B"]) {
        let (t, body) = &msm.prelude;
        leaf.template(*body, t, &format!("{side}'s prelude"))?;
    }

    let sentinel = infinity_sentinel();
    for (i, proof) in proofs.iter().enumerate() {
        let position = shards.start + i;
        let name = program::family_name(proof.family);
        let claim = verify_shard_local(vk, &global, proof, public).map_err(|e| e.to_string())?;
        let cms = claim
            .commitments
            .iter()
            .map(|b| G1Affine::from_bytes(b).map(MercuryCommitment))
            .collect::<Option<Vec<_>>>()
            .ok_or("a commitment is not a point")?;
        let opening =
            MercuryProof::from_bytes(&proof.opening).ok_or("the opening does not decode")?;
        let mut transcript = claim.transcript;
        let entries = batch_verify_deferred(
            &vsrs,
            &cms,
            &claim.point,
            &claim.values,
            &opening,
            &mut transcript,
        )
        .map_err(|e| format!("the opening is refused: {e:?}"))?;

        let shape = shapes
            .iter()
            .find(|s| s.family == proof.family)
            .expect("every family's shape is built");
        let tape = &shape.tape;
        let blob = shard_blob(&tape.inputs, proof, &entries[0].point.to_bytes());
        let circuit = vk.circuit(proof.family).expect("a key family");
        let window = shard_window(
            proof.family,
            proof.shard_index,
            &public.windows,
            circuit.artifact.trace_vars,
        );
        let mut values: Vec<Fr> = vec![global.digest];
        values.extend(global.memory);
        values.push(Fr::from_u64(proof.shard_index as u64));
        values.push(Fr::from_u64(window.unwrap_or(0) as u64));
        values.extend(public.memory_roots[position]);
        for points in [&public.memory_commitments[position], &shape.setup] {
            values.extend(points.iter().flat_map(g1_limbs));
        }

        // The shard: its slots, its inputs, its tape.
        let cells = &leaf.lists[shape.slots as usize];
        assert_eq!(cells.len(), values.len(), "{name}: one value a slot");
        for (c, v) in cells.clone().iter().zip(&values) {
            leaf.memory.set(*c, *v);
        }
        leaf.step(0, &[shape.slots]);
        bytes(&mut leaf.steps, &cell_words(&values));
        run(&tape.ops, &mut leaf.memory, &blob)
            .map_err(|op| format!("shard {position} ({name}): the tape refuses at op {op}"))?;
        leaf.step(0, &[shape.imports]);
        bytes(&mut leaf.steps, &blob);
        leaf.step(1, &[shape.body]);

        // Its fold: the weights and scalars, then each point into its MSM.
        let what = format!("shard {position} ({name})'s fold");
        leaf.replay(shape.fold_body, &shape.fold.0, &what)?;
        for p in &shape.fold.1 {
            let (l, msm) = match p.side {
                Side::A => (&node.a, &msms[0]),
                Side::B => (&node.b, &msms[1]),
            };
            let infinity = (0..4).all(|k| leaf.memory.get(p.limbs + k) == sentinel);
            run(
                &load_point(p, l, node.sentinel, infinity),
                &mut leaf.memory,
                &[],
            )
            .map_err(|op| format!("{what}: loading a point refuses at op {op}"))?;
            if infinity {
                leaf.step(4, &[p.limbs]);
            } else {
                leaf.step(3, &[p.limbs, p.scalar, (p.side == Side::B) as u32]);
                let (t, body) = &msm.point;
                leaf.template(*body, t, &format!("{what}: a point"))?;
            }
        }
    }

    for (msm, side) in msms.iter().zip(["A", "B"]) {
        let (t, body) = &msm.finish;
        leaf.template(*body, t, &format!("{side}'s finish"))?;
    }

    let mut out = Vec::new();
    let header: Vec<u32> = [&node.a, &node.b]
        .iter()
        .flat_map(|l| [l.point, l.scalar, l.zero])
        .chain([node.sentinel])
        .collect();
    words(&mut out, &header);
    out.extend_from_slice(&(leaf.bodies.len() as u32).to_le_bytes());
    for body in &leaf.bodies {
        words(&mut out, body);
    }
    out.extend_from_slice(&(leaf.lists.len() as u32).to_le_bytes());
    for list in &leaf.lists {
        words(&mut out, list);
    }
    out.extend_from_slice(&leaf.count.to_le_bytes());
    out.extend_from_slice(&leaf.steps);
    let journal: Vec<u32> = [node.a.result, node.b.result]
        .iter()
        .flat_map(|r| *r..*r + POINT_CELLS)
        .collect();
    words(&mut out, &journal);
    Ok(out)
}

/// A shard tape's slots, in the order [`leaf_advice`] fills them: the
/// statement's, the shard's, then the commitments' limbs.
fn slot_cells(tape: &ShardTape) -> Vec<u32> {
    let s = &tape.slots;
    let mut cells = vec![s.digest];
    cells.extend(s.memory);
    cells.extend([s.index, s.window]);
    cells.extend(s.roots);
    for limbs in s.memory_commitments.iter().chain(&s.setup) {
        cells.extend(limbs);
    }
    cells
}

/// Field elements as the 32-byte words `IMPORT` reads.
fn cell_words(values: &[Fr]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_bytes()).collect()
}

/// A little-endian `u32` count and the words.
fn words(out: &mut Vec<u8>, words: &[u32]) {
    out.extend_from_slice(&(words.len() as u32).to_le_bytes());
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
}

/// A little-endian `u32` length, the bytes, and zero padding to a word.
fn bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out.resize(out.len().next_multiple_of(4), 0);
}
