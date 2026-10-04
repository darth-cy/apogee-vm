//! A recursion node's host side (`verifier_core::node`): [`leaf`] and
//! [`internal`] run a node's procedure natively over one `tape::Memory`,
//! through a driver that answers every request for advice from the proofs it
//! is handed and records the words a guest will read, in the order it reads
//! them — every witness the MSMs take included, computed where the guest
//! imports it.
//!
//! So whatever would refuse in the guest refuses here first, by name: a
//! shard's checks, the chain's claims, a child that does not fit beside its
//! neighbour, a point off the curve, an element read whole that was written
//! apart. And the journal's accumulator is discharged here, one pairing
//! check, which holds the fold itself — every weight, side and merged scalar
//! — to the deferred checks it folds.
//!
//! The advice is `u32` `n`, the [`Header`]'s `n` words, then the stream the
//! procedure reads: 32 bytes a cell for advice and witnesses, and a `u32`
//! flag a point for infinity.

use std::collections::BTreeMap;
use std::ops::Range;

use curve::G1Affine;
use field::Fr;
use pcs::{batch_verify_deferred, MercuryCommitment, MercuryProof};
use transcript::g1_limbs;
use verifier_core::chain::{self, Shape};
use verifier_core::fold::{halves, simulate, split, Template};
use verifier_core::node::{
    claim, journal, node, node_image, Advice, BaseKey, Driver, Header, ImageTemplate, Kind,
    NodeImage, ProgramKey, StatementHeader, FIRST,
};
use verifier_core::tape::{
    decode, imported, infinity_sentinel, run, shard_blob, shard_tape, Cell, Memory, Op, Tape,
};
use verifier_core::{
    boundary_scalars, derive_global_phase, public_io_words, verify_global_memory,
    verify_shard_local, BlockProof, PublicInputs, VerifyingKey,
};

/// A node's advice, and the journal its guest will publish, cell by cell.
pub struct Run {
    pub advice: Vec<u8>,
    pub journal: Vec<Fr>,
}

/// The leaf program's parameters, which its identity binds: its execution
/// families at `2^20`, its code being some 50 KB, and its window families at
/// `2^22`, whose window 0 holds its image — the base program's tapes, 5.6 MB
/// (the owner's decision: two images, the leaf's at `2^22`).
pub fn leaf_params() -> program::ProgramParams {
    use constants::family;
    let mut params = program::ProgramParams::defaults();
    for (f, height) in params.heights.iter_mut().enumerate() {
        if family::CYCLE_OWNING[f] {
            *height = 1 << 20;
        }
    }
    params.bytecode_size_words = 1 << 22;
    params
}

/// The internal node program's parameters: as the leaf's, but its window
/// families at `2^20`, the recursion programs' tapes fitting 4 MiB.
pub fn node_params() -> program::ProgramParams {
    use constants::family;
    let mut params = leaf_params();
    for f in [
        family::INIT_TEARDOWN,
        family::ZERO_WINDOWS,
        family::ADVICE_WINDOWS,
    ] {
        params.heights[f as usize] = 1 << 20;
    }
    params.bytecode_size_words = 1 << 20;
    params
}

/// The image a leaf's guest holds for the base program `vk` is the key of.
pub fn leaf_image(vk: &VerifyingKey) -> Vec<u32> {
    node_image(Kind::Leaf, &BaseKey::of(vk), &[])
}

/// The leaf over shards `shards` of `block`, run natively against `vk`, the
/// base program's key, `words` being the leaf's image ([`leaf_image`]).
pub fn leaf(
    vk: &VerifyingKey,
    words: &[u32],
    block: &BlockProof,
    shards: Range<usize>,
) -> Result<Run, String> {
    let image = NodeImage::read(words).ok_or("the image does not read")?;
    let statement = Statement::of(vk, block, 0, shards)?;
    run_node(&image, vec![statement], [Fr::ZERO; 2], vk)
}

/// A child of an internal node: its proof, the key it verifies against, and
/// which recursion program's it is, 0 the leaf's and 1 the node's.
pub struct Child<'a> {
    pub vk: &'a VerifyingKey,
    pub block: &'a BlockProof,
    pub program: u32,
}

/// An internal node over `children`, run natively, `words` being its image
/// and `identities` the leaf program's and the node program's.
pub fn internal(words: &[u32], children: &[Child], identities: [Fr; 2]) -> Result<Run, String> {
    let image = NodeImage::read(words).ok_or("the image does not read")?;
    let statements = children
        .iter()
        .map(|c| {
            let total = c.block.shard_proofs().len();
            Statement::of(c.vk, c.block, c.program, 0..total)
        })
        .collect::<Result<Vec<_>, _>>()?;
    run_node(&image, statements, identities, children[0].vk)
}

/// A statement a node verifies, as the host holds it: its header, its public
/// inputs, each shard's blob and its claims' values.
struct Statement<'a> {
    header: StatementHeader,
    public: &'a PublicInputs,
    blobs: BTreeMap<u32, Vec<u8>>,
    claims: Vec<Fr>,
    setup: Vec<Fr>,
}

impl<'a> Statement<'a> {
    /// Shards `shards` of `block`, each verified natively but for its
    /// pairings, for its blob's `cm*`, entry 0 of its deferred check
    /// (`docs/spec/accumulator.md` §2).
    fn of(
        vk: &VerifyingKey,
        block: &'a BlockProof,
        program: u32,
        shards: Range<usize>,
    ) -> Result<Statement<'a>, String> {
        let public = block.statement();
        let global = derive_global_phase(vk, public).map_err(|e| e.to_string())?;
        verify_global_memory(vk, &global, public).map_err(|e| e.to_string())?;
        let vsrs = verifier::decode_srs_verifier(&vk.srs_verifier)
            .ok_or("the key's SrsVerifier holds a point that is not one")?;
        let mut blobs = BTreeMap::new();
        for position in shards.clone() {
            let proof = block
                .shard_proofs()
                .get(position)
                .ok_or("a shard the block has not")?;
            let claim =
                verify_shard_local(vk, &global, proof, public).map_err(|e| e.to_string())?;
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
            .map_err(|e| format!("shard {position}'s opening is refused: {e:?}"))?;
            let fi = vk
                .config
                .families
                .iter()
                .position(|(f, _)| *f == proof.family)
                .ok_or("a proof names a family the key has not")?;
            let mut setup = vk.setup_commitments[fi].len();
            if vk.circuits[fi].reads_generic_table() {
                setup += vk.generic_table.len();
            }
            let tape = shard_tape(&vk.config, &vk.circuits[fi], setup, FIRST);
            let blob = shard_blob(&tape.inputs, proof, &entries[0].point.to_bytes());
            blobs.insert(position as u32, blob);
        }

        let io = transcript::io_digest(&public.input, &public.output);
        let (lanes, pending) = chain_state(vk, public, io, shards.start as u32);
        let mut claims = vec![global.digest];
        claims.extend(global.memory);
        claims.extend([io, Fr::from_u64(public.exit_status as u64)]);
        claims.extend(lanes);
        claims.extend([pending, Fr::from_u64(vk.entry_pc as u64)]);
        assert_eq!(claims.len(), claim::CELLS as usize);
        Ok(Statement {
            header: StatementHeader {
                program,
                shard_counts: public.shard_counts.clone(),
                windows: public.windows.clone(),
                from: shards.start as u32,
                to: shards.end as u32,
                input_len: public.input.len() as u32,
                output_len: public.output.len() as u32,
            },
            public,
            blobs,
            claims,
            setup: vk
                .setup_commitments
                .iter()
                .flatten()
                .flat_map(g1_limbs)
                .collect(),
        })
    }
}

/// The node over `statements`, natively, and its accumulator discharged
/// under `vk`'s SRS.
fn run_node(
    image: &NodeImage,
    statements: Vec<Statement>,
    identities: [Fr; 2],
    vk: &VerifyingKey,
) -> Result<Run, String> {
    let header = Header {
        statements: statements.iter().map(|s| s.header.clone()).collect(),
    };
    let mut native = Native {
        memory: Memory::default(),
        stream: Vec::new(),
        failed: None,
        at: String::from("the node's constants"),
        statements,
        identities,
        decoded: BTreeMap::new(),
        sentinel: infinity_sentinel(),
        journal: Vec::new(),
    };
    node(&mut native, image, &header);
    if let Some(e) = native.failed {
        return Err(e);
    }

    // The accumulator discharges: `e(A, [1]_2) = e(B, [x]_2)`.
    let vsrs = verifier::decode_srs_verifier(&vk.srs_verifier)
        .ok_or("the key's SrsVerifier holds a point that is not one")?;
    let point = |at: usize| {
        let mut bytes = [0u8; 64];
        for (k, chunk) in bytes.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&native.journal[at + k].to_bytes()[..8]);
        }
        G1Affine::from_bytes(&bytes).ok_or("the accumulator is not a point")
    };
    let (a, b) = (point(journal::A)?, point(journal::B)?);
    if !curve::pairing::pairing_check(&[(a, vsrs.g2_gen), (-b, vsrs.g2_tau)]) {
        return Err("the folded accumulator does not discharge".into());
    }

    let words = header.to_words();
    let mut advice = Vec::with_capacity(4 + 4 * words.len() + native.stream.len());
    advice.extend_from_slice(&(words.len() as u32).to_le_bytes());
    for w in &words {
        advice.extend_from_slice(&w.to_le_bytes());
    }
    advice.extend_from_slice(&native.stream);
    Ok(Run {
        advice,
        journal: native.journal,
    })
}

/// The chain's state at statement position `at`: the prefix and the
/// segments before it, run over cells, its three lanes and its pending input
/// — 0 where there is none.
pub fn chain_state(vk: &VerifyingKey, public: &PublicInputs, io: Fr, at: u32) -> ([Fr; 3], Fr) {
    let shape = Shape {
        config: &vk.config,
        shard_counts: &public.shard_counts,
        windows: &public.windows,
    };
    let mut t = Tape::new(3);
    let mut memory = Memory::default();
    let mut input = |t: &mut Tape, v: Fr| {
        let c = t.fresh(1);
        memory.set(c, v);
        c
    };
    let (identity, io) = (input(&mut t, vk.identity.0), input(&mut t, io));
    let mut tr = chain::prefix(&mut t, &shape, &vk.srs_digest.to_bytes(), identity, io);
    let lists: Vec<_> = public.memory_commitments[..at as usize]
        .iter()
        .map(|points| {
            points
                .iter()
                .map(|p| g1_limbs(p).map(|v| input(&mut t, v)))
                .collect()
        })
        .collect();
    chain::segment(&mut t, &mut tr, &shape, 0, &lists);
    run(&t.ops, &mut memory, &[]).expect("the chain runs");
    let (state, pending) = tr.checkpoint();
    (
        [0, 1, 2].map(|k| memory.get(state + k)),
        pending.map_or(Fr::ZERO, |c| memory.get(c)),
    )
}

/// The native driver: a guest's every call, over one `Memory`.
struct Native<'a> {
    memory: Memory,
    stream: Vec<u8>,
    failed: Option<String>,
    at: String,
    statements: Vec<Statement<'a>>,
    identities: [Fr; 2],
    decoded: BTreeMap<usize, Vec<Op>>,
    sentinel: Fr,
    journal: Vec<Fr>,
}

impl Native<'_> {
    fn fail(&mut self, what: String) {
        self.failed.get_or_insert(format!("{}: {what}", self.at));
    }

    fn ops(&mut self, body: &[u32]) -> Option<Vec<Op>> {
        // An image body is decoded once, keyed by where it lies.
        let key = body.as_ptr() as usize;
        if let std::collections::btree_map::Entry::Vacant(e) = self.decoded.entry(key) {
            e.insert(decode(body)?);
        }
        self.decoded.get(&key).cloned()
    }

    fn words(&self, what: Advice) -> Vec<[u8; 32]> {
        let fr = |v: &Fr| v.to_bytes();
        let window = |bytes: &[u8]| -> Vec<[u8; 32]> {
            public_io_words(bytes)
                .into_iter()
                .take(1 + bytes.len().div_ceil(4))
                .map(|w| Fr::from_u64(w as u64).to_bytes())
                .collect()
        };
        let statement = |s: u32| &self.statements[s as usize];
        match what {
            Advice::Identities => self.identities.iter().map(fr).collect(),
            Advice::Setup(p) => self
                .statements
                .iter()
                .find(|s| s.header.program == p)
                .map_or(Vec::new(), |s| s.setup.iter().map(fr).collect()),
            Advice::Claims(s) => statement(s).claims.iter().map(fr).collect(),
            Advice::Commitments(s, at) => statement(s).public.memory_commitments[at as usize]
                .iter()
                .flat_map(g1_limbs)
                .map(|v| v.to_bytes())
                .collect(),
            Advice::Roots(s, at) => statement(s).public.memory_roots[at as usize]
                .iter()
                .map(fr)
                .collect(),
            Advice::Blob(s, at) => statement(s).blobs[&at]
                .chunks_exact(32)
                .map(|w| w.try_into().expect("32 bytes"))
                .collect(),
            Advice::Input(s) => window(&statement(s).public.input),
            Advice::Output(s) => window(&statement(s).public.output),
            Advice::Boundary(s) => boundary_scalars(&statement(s).public.boundary)
                .iter()
                .map(fr)
                .collect(),
        }
    }
}

impl Driver for Native<'_> {
    fn replay(&mut self, body: &[u32]) {
        if self.failed.is_some() {
            return;
        }
        match self.ops(body) {
            Some(ops) => {
                if let Err(op) = run(&ops, &mut self.memory, &[]) {
                    self.fail(format!("op {op} of an image body refuses"));
                }
            }
            None => self.fail("an image body does not decode".into()),
        }
    }

    fn run(&mut self, ops: Vec<Op>) {
        if self.failed.is_some() {
            return;
        }
        if let Err(op) = run(&ops, &mut self.memory, &[]) {
            self.fail(format!(
                "op {op} of the procedure's own refuses: {:?}",
                ops[op]
            ));
        }
    }

    fn advise(&mut self, cells: &[Cell], what: Advice) {
        if self.failed.is_some() {
            return;
        }
        match what {
            Advice::Claims(s) => self.at = format!("statement {s}"),
            Advice::Blob(s, at) | Advice::Commitments(s, at) => {
                self.at = format!("statement {s}, shard {at}")
            }
            _ => {}
        }
        let words = self.words(what);
        if words.len() != cells.len() {
            let n = (words.len(), cells.len());
            return self.fail(format!("{what:?} is {} words for {} cells", n.0, n.1));
        }
        for (c, w) in cells.iter().zip(&words) {
            self.memory.set(*c, imported(w));
            self.stream.extend_from_slice(w);
        }
    }

    fn template(&mut self, t: &ImageTemplate, scalar: Option<Cell>) {
        if self.failed.is_some() {
            return;
        }
        let before: Vec<Fr> = scalar.map_or(Vec::new(), |s| split(self.memory.get(s)).to_vec());
        if let Some(cells) = t.witnesses() {
            for (c, v) in cells.clone().zip(&before) {
                self.memory.set(c, *v);
            }
        }
        let Some(ops) = self.ops(t.body.body) else {
            return self.fail("a template does not decode".into());
        };
        let template = Template {
            ops,
            holes: t.holes.clone(),
        };
        match simulate(&template, &mut self.memory) {
            Ok(inverses) => {
                let values = before.into_iter().chain(inverses.iter().flat_map(halves));
                for v in values {
                    self.stream.extend_from_slice(&v.to_bytes());
                }
            }
            Err(op) => self.fail(format!("op {op} of a template refuses")),
        }
    }

    fn infinity(&mut self, limbs: Cell) -> bool {
        let infinity = (0..4).all(|k| self.memory.get(limbs + k) == self.sentinel);
        self.stream
            .extend_from_slice(&(infinity as u32).to_le_bytes());
        infinity
    }

    fn read(&mut self, cell: Cell) -> u32 {
        let bytes = self.memory.get(cell).to_bytes();
        if bytes[4..].iter().any(|b| *b != 0) {
            self.fail(format!("cell {cell} is read as a word and is not one"));
            return 0;
        }
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn export(&mut self, cells: &[Cell]) {
        self.journal = cells.iter().map(|c| self.memory.get(*c)).collect();
    }
}

/// The keys an internal node's image is built from, `[leaf, node]`: each
/// program's config as `program::decode_program` derives it from its ELF
/// under its parameters, and the setup counts that config implies.
pub fn program_keys(leaf: &[u8], node: &[u8]) -> Result<Vec<ProgramKey>, String> {
    [(leaf, leaf_params()), (node, node_params())]
        .into_iter()
        .map(|(elf, params)| {
            let image = loader::load_elf(elf).map_err(|e| format!("{e:?}"))?;
            let (_, config) =
                program::decode_program(&image, &params).map_err(|e| e.to_string())?;
            Ok(ProgramKey::of(&config))
        })
        .collect()
}
