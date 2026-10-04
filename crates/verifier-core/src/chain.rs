//! A recursion node's statement work over cells (`docs/spec/recursion.md`
//! §8.2): a program's identity, and the global transcript in three parts, so
//! that a tree of nodes runs it as a chain.
//!
//! - **The prefix**, G1 to G7, is run by the node whose shards start the
//!   statement.
//! - **A segment**, G8, is run by every node over the shards it verifies: the
//!   memory commitments it opens against are the ones it absorbs, from the
//!   state the node before it left.
//! - **The suffix**, G9 to G11 and step 10b's statement half over the
//!   boundary, is run by the node whose shards end the statement.
//!
//! A node's journal carries the transcript states it began and ended at, and
//! a parent holds its children's to meet. Every message but the prefix's is
//! an even number of scalars, so every boundary between two shards has the
//! same parity, and a state there is three lanes and at most one pending
//! input (`CellTranscript::checkpoint`).
//!
//! What a statement's shape decides — its config, its shard counts, its
//! window ids — is a constant of the tapes built from it ([`Shape`]), so a
//! node's loops and the messages it absorbs cannot disagree. The rest is
//! input cells the caller fills.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use constants::memory::{HALT_PC, PART_ADDR, PART_AS, PART_TS, PART_VAL, TS_BITS};
use constants::{challenge_slot as slot, fr_op, transcript_tags as tags, PROTOCOL_VERSION};
use constraints::memory::read_tuple;

use crate::statement::groups;
use crate::tape::{append_points, eval_gate, Cell, CellTranscript, Limbs, Tape, ZERO};
use crate::VmConfig;

/// A statement's shape: what its tapes are built from.
#[derive(Clone, Copy, Debug)]
pub struct Shape<'a> {
    pub config: &'a VmConfig,
    pub shard_counts: &'a [u32],
    pub windows: &'a [u32],
}

impl Shape<'_> {
    /// The statement's shard count.
    pub fn total(&self) -> u32 {
        self.shard_counts.iter().sum()
    }

    /// Each family group in the global transcript's order, with the
    /// statement position its shards start at.
    fn groups(&self) -> Vec<(u32, u32, u32)> {
        let mut start = 0;
        groups(self.config, self.shard_counts)
            .into_iter()
            .map(|(family, count)| {
                start += count;
                (start - count, family, count)
            })
            .collect()
    }

    /// The `MEMORY_GROUP` messages of the groups starting at position `p`.
    fn group_messages(&self, t: &mut Tape, tr: &mut CellTranscript, p: u32) {
        for (start, family, count) in self.groups() {
            if start == p {
                let message = [constant(t, family as u64), constant(t, count as u64)];
                tr.append(t, tags::MEMORY_GROUP, &message);
            }
        }
    }
}

fn constant(t: &mut Tape, v: u64) -> Cell {
    t.small(v)
}

/// `2^k`'s canonical bytes, `k < 256`.
fn power(k: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[k as usize / 8] = 1 << (k % 8);
    b
}

/// The `VM_CONFIG` message: the families, their heights, the bytecode size.
fn config_message(t: &mut Tape, config: &VmConfig) -> Vec<Cell> {
    let families = config.families.iter().map(|(f, _)| *f as u64);
    let heights = config.families.iter().map(|(_, h)| *h as u64);
    families
        .chain(heights)
        .chain([config.bytecode_size_words as u64])
        .map(|v| constant(t, v))
        .collect()
}

/// A program's identity, `crate::identity_digest`, over `setup`: each
/// family's setup commitments' limbs, in config order.
pub fn identity(
    t: &mut Tape,
    code_version: u32,
    config: &VmConfig,
    entry_pc: Cell,
    setup: &[Vec<Limbs>],
) -> Cell {
    let mut tr = CellTranscript::new();
    let version = constant(t, code_version as u64);
    tr.append(t, tags::PROGRAM_IDENTITY, &[version]);
    let message = config_message(t, config);
    tr.append(t, tags::VM_CONFIG, &message);
    tr.append(t, tags::PROGRAM_ENTRY, &[entry_pc]);
    for points in setup {
        append_points(&mut tr, t, tags::COMMITMENT, points);
    }
    tr.sample(t)
}

/// G1 to G7: the protocol suite, the SRS digest, the descriptor, the
/// identity, and `io_digest` — whose 32 canonical bytes `append_bytes`
/// absorbs as two chunks, the low 31 bytes and the top one, split here by 31
/// `DIGIT`s and the top byte held below 256.
///
/// **Canonicity is not checked**: the split is of `io + k·p` for any `k` that
/// keeps it below `2^256`, five at most. A non-canonical one gives another
/// digest, and so base shards proved under that digest — a choice among five,
/// not a forgery.
pub fn prefix(
    t: &mut Tape,
    shape: &Shape,
    srs_digest: &[u8; 32],
    identity: Cell,
    io: Cell,
) -> CellTranscript {
    let mut tr = CellTranscript::new();
    let version = constant(t, PROTOCOL_VERSION as u64);
    tr.append(t, tags::PROTOCOL_SUITE, &[version]);
    let srs = t.bytes(srs_digest);
    tr.append(t, tags::SRS_DIGEST, &[srs]);
    let message = config_message(t, shape.config);
    tr.append(t, tags::VM_CONFIG, &message);
    let counts: Vec<Cell> = shape
        .shard_counts
        .iter()
        .map(|c| constant(t, *c as u64))
        .collect();
    tr.append(t, tags::SHARD_COUNTS, &counts);
    let ids: Vec<Cell> = shape
        .windows
        .iter()
        .map(|w| constant(t, *w as u64))
        .collect();
    tr.append(t, tags::MEMORY_WINDOWS, &ids);
    tr.append(t, tags::PROGRAM_IDENTITY, &[identity]);

    let top = t.copy(io);
    let digit = t.fresh(1);
    for _ in 0..31 {
        t.fr(fr_op::DIGIT, digit, top, top);
    }
    below(t, top, 8);
    let unit = t.bytes(&power(248));
    let high = t.mul(top, unit);
    let low = t.sub(io, high);
    for x in [constant(t, tags::PUBLIC_INPUTS), constant(t, 32), low, top] {
        tr.observe(t, x);
    }
    tr
}

/// Whether a boundary between shards holds a pending input: the prefix
/// absorbs `3k + w + 20` scalars, `k` the config's families and `w` the
/// windows, and every message after it an even number.
pub fn pending(shape: &Shape) -> bool {
    (shape.config.families.len() + shape.windows.len()) % 2 == 1
}

/// A digest of the shape's counts and windows, which every node verifying
/// the statement journals so a parent holds its children to one shape: a
/// node uses the shape to name its shards, and only the prefix absorbs it.
pub fn shape_digest(t: &mut Tape, shape: &Shape) -> Cell {
    let mut tr = CellTranscript::new();
    for (tag, values) in [
        (tags::SHARD_COUNTS, shape.shard_counts),
        (tags::MEMORY_WINDOWS, shape.windows),
    ] {
        let cells: Vec<Cell> = values.iter().map(|v| constant(t, *v as u64)).collect();
        tr.append(t, tag, &cells);
    }
    tr.sample(t)
}

/// G8 over statement positions `from..`: where a family group starts, its
/// `MEMORY_GROUP` message; then each shard's memory commitments, one message a
/// shard, `lists[i]` being position `from + i`'s. A pending input left at the
/// end is one of the caller's cells, which a node reuses for its next shard,
/// so the transcript keeps a copy of it instead.
pub fn segment(
    t: &mut Tape,
    tr: &mut CellTranscript,
    shape: &Shape,
    from: u32,
    lists: &[Vec<Limbs>],
) {
    for (i, list) in lists.iter().enumerate() {
        shape.group_messages(t, tr, from + i as u32);
        append_points(tr, t, tags::COMMITMENT, list);
    }
    if let (state, Some(pending)) = tr.checkpoint() {
        *tr = CellTranscript::resume(state, Some(t.copy(pending)));
    }
}

/// G9 to G11: any group with no shards left at the end, the boundary's 64
/// scalars, the four memory challenges and the digest.
pub fn suffix(
    t: &mut Tape,
    tr: &mut CellTranscript,
    shape: &Shape,
    boundary: &[Cell],
) -> ([Cell; 4], Cell) {
    shape.group_messages(t, tr, shape.total());
    tr.append(t, tags::MEMORY_BOUNDARY, boundary);
    let memory = core::array::from_fn(|_| tr.challenge(t, tags::MEMORY_CHALLENGE));
    let digest = tr.challenge(t, tags::GLOBAL_STATE_DIGEST);
    (memory, digest)
}

/// `x < 2^bits`, consuming a copy of `x`: a `DIGIT` a byte, then a part byte
/// held below `2^(bits mod 8)` from both sides, since a digit is a field
/// element that is the byte only when what is left is 0.
pub fn below(t: &mut Tape, x: Cell, bits: u32) {
    let rest = t.copy(x);
    let digit = t.fresh(1);
    for _ in 0..bits / 8 {
        t.fr(fr_op::DIGIT, digit, rest, rest);
    }
    let part = bits % 8;
    if part > 0 {
        // Below 2^8, and `rest + 2^8 − 2^part` below 2^8 too.
        let shifted = constant(t, 256 - (1 << part));
        let lifted = t.add(rest, shifted);
        for c in [rest, lifted] {
            t.fr(fr_op::DIGIT, digit, c, c);
            t.assert_eq(c, ZERO);
        }
    } else {
        t.assert_eq(rest, ZERO);
    }
}

/// Step 10b's statement half over the boundary's 64 cells, in
/// `boundary_scalars`' order: every timestamp below `2^38` and every value
/// below `2^32`, as `PublicInputs`' decoder holds them; `x10`'s final value
/// the exit status; and the boundary factors `(W_b, R_b)`,
/// `gkr_verify::boundary_factors`, under the memory challenges.
pub fn boundary(
    t: &mut Tape,
    boundary: &[Cell],
    exit: Cell,
    memory: [Cell; 4],
    entry_pc: Cell,
) -> (Cell, Cell) {
    let (reg_ts, pc_ts, values) = (&boundary[..32], boundary[32], &boundary[33..64]);
    for ts in reg_ts.iter().chain([&pc_ts]) {
        below(t, *ts, TS_BITS);
    }
    for v in values {
        below(t, *v, 32);
    }
    t.assert_eq(values[9], exit);

    let mut challenges = BTreeMap::new();
    let slots = [
        slot::MEM_GAMMA,
        slot::MEM_ALPHA_ADDR,
        slot::MEM_ALPHA_TS,
        slot::MEM_ALPHA_VAL,
    ];
    for (s, c) in slots.into_iter().zip(memory) {
        challenges.insert(s, c);
    }
    let one = constant(t, 1);
    let tuple = |t: &mut Tape, query: usize, addr: Cell, ts: Cell, value: Cell| {
        let mut values = [ZERO; 4];
        values[PART_AS] = one;
        values[PART_ADDR] = addr;
        values[PART_TS] = ts;
        values[PART_VAL] = value;
        eval_gate(t, &read_tuple(query), &values, &challenges)
    };
    let halt = constant(t, HALT_PC as u64);
    let write = tuple(t, 0, ZERO, ZERO, entry_pc);
    let read = tuple(t, 0, ZERO, pc_ts, halt);
    for r in 0..32 {
        let addr = constant(t, r as u64);
        let value = if r == 0 { ZERO } else { values[r - 1] };
        let w = tuple(t, 1, addr, ZERO, ZERO);
        t.fr(fr_op::MUL, write, write, w);
        let rd = tuple(t, 1, addr, reg_ts[r], value);
        t.fr(fr_op::MUL, read, read, rd);
    }
    (write, read)
}

/// The memory argument's check (`gkr_verify::reconciles`), at the node whose
/// shards are the whole statement: `Π reads · R_b = Π writes · W_b`, nonzero.
pub fn reconcile(t: &mut Tape, reads: Cell, writes: Cell, factors: (Cell, Cell)) {
    let (w_b, r_b) = factors;
    let read = t.mul(reads, r_b);
    let write = t.mul(writes, w_b);
    t.assert_eq(read, write);
    t.assert_nonzero(read);
}

/// A public window's `len` bytes from its words, `crate::public_io_words`'
/// layout: word 0 held to `len`, then each payload word's four bytes by
/// `DIGIT`, little-endian, every byte past `len` held to 0 — so every word is
/// below `2^32` and the bytes are the statement's.
pub fn window_bytes(t: &mut Tape, words: &[Cell], len: usize) -> Vec<Cell> {
    assert_eq!(
        words.len(),
        1 + len.div_ceil(4),
        "chain: one word a four bytes"
    );
    let length = constant(t, len as u64);
    t.assert_eq(words[0], length);
    let mut bytes = Vec::with_capacity(len);
    for (i, word) in words[1..].iter().enumerate() {
        let rest = t.copy(*word);
        for k in 0..4 {
            let byte = t.fresh(1);
            t.fr(fr_op::DIGIT, byte, rest, rest);
            if 4 * i + k < len {
                bytes.push(byte);
            } else {
                t.assert_eq(byte, ZERO);
            }
        }
        t.assert_eq(rest, ZERO);
    }
    bytes
}

/// `transcript::io_digest` over the two windows' bytes ([`window_bytes`]):
/// each an `append_bytes` message, its length then its 31-byte chunks.
pub fn io_digest(t: &mut Tape, input: &[Cell], output: &[Cell]) -> Cell {
    let mut tr = CellTranscript::new();
    for (tag, bytes) in [
        (tags::PUBLIC_INPUT_STREAM, input),
        (tags::PUBLIC_OUTPUT_STREAM, output),
    ] {
        let (tag, len) = (constant(t, tag), constant(t, bytes.len() as u64));
        tr.observe(t, tag);
        tr.observe(t, len);
        for chunk in bytes.chunks(31) {
            let acc = t.copy(chunk[0]);
            for (k, byte) in chunk.iter().enumerate().skip(1) {
                let unit = t.bytes(&power(8 * k as u32));
                t.mac(acc, *byte, unit);
            }
            tr.observe(t, acc);
        }
    }
    tr.sample(t)
}

/// Step 10c: a public value shard's column is its window — `words`, then
/// zeros — so `claim`, the column's claim at the shard's point, is their
/// multilinear extension there: an eq table over the variables the words
/// span, times `1 − r_j` for every variable above them.
pub fn public_value(t: &mut Tape, point: &[Cell], claim: Cell, words: &[Cell]) {
    let k = words.len().next_power_of_two().trailing_zeros() as usize;
    assert!(k <= point.len(), "chain: more words than the window holds");
    // `poly::eq_table`'s order: bit `j` set lands `2^j` further along.
    let mut eq = alloc::vec![constant(t, 1)];
    for rj in &point[..k] {
        let high: Vec<Cell> = eq.iter().map(|e| t.mul(*e, *rj)).collect();
        let low: Vec<Cell> = eq.iter().zip(&high).map(|(e, h)| t.sub(*e, *h)).collect();
        eq = low.into_iter().chain(high).collect();
    }
    let mut value = t.dot(words, &eq[..words.len()]);
    let one = constant(t, 1);
    for rj in &point[k..] {
        let zero_bit = t.sub(one, *rj);
        value = t.mul(value, zero_bit);
    }
    t.assert_eq(value, claim);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement::global_transcript;
    use crate::tape::{run, Memory};
    use crate::{identity_digest, BoundaryFinals, ProgramIdentity, PublicInputs};
    use constants::family;
    use field::Fr;
    use transcript::g1_limbs;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn fr(&mut self) -> Fr {
            let limbs = [self.next(), self.next(), self.next(), self.next() >> 3];
            limbs.iter().rev().fold(Fr::ZERO, |acc, l| {
                acc * Fr::from_u64(1 << 32) * Fr::from_u64(1 << 32) + Fr::from_u64(*l)
            })
        }
        fn point(&mut self) -> [u8; 64] {
            core::array::from_fn(|_| self.next() as u8)
        }
    }

    fn config() -> VmConfig {
        VmConfig {
            families: alloc::vec![
                (family::ADD_SUB_LUI_AUIPC, 1 << 20),
                (family::INIT_TEARDOWN, 1 << 20),
                (family::ZERO_WINDOWS, 1 << 20),
                (family::PUBLIC_INPUT, 1 << 12),
                (family::PUBLIC_OUTPUT, 1 << 12),
            ],
            bytecode_size_words: 1 << 18,
        }
    }

    /// The prefix, the segments and the suffix over cells are
    /// `global_commit`, however the statement's shards are cut among nodes —
    /// a family with no shards included — and the identity over cells is
    /// `identity_digest`.
    #[test]
    fn the_chain_is_the_global_transcript() {
        for shard_counts in [[3, 1, 2, 0, 1], [3, 1, 2, 1, 0]] {
            chain_over(&shard_counts);
        }
    }

    fn chain_over(shard_counts: &[u32; 5]) {
        let mut rng = Rng(0x6368_6169_6e31);
        let config = config();
        let windows = [5, 9];
        let statement = PublicInputs {
            input: alloc::vec![],
            output: alloc::vec![],
            exit_status: 0,
            shard_counts: shard_counts.to_vec(),
            windows: windows.to_vec(),
            boundary: BoundaryFinals {
                reg_ts: core::array::from_fn(|_| rng.next() >> 26),
                pc_ts: rng.next() >> 26,
                reg_values: core::array::from_fn(|_| rng.next() as u32),
            },
            memory_commitments: (0..7)
                .map(|i| (0..1 + i % 3).map(|_| rng.point()).collect())
                .collect(),
            memory_roots: (0..7).map(|_| [rng.fr(), rng.fr()]).collect(),
        };
        let (srs, id, entry) = (rng.fr(), ProgramIdentity(rng.fr()), 0x1_0000);
        let io = transcript::io_digest(&statement.input, &statement.output);
        let native = global_transcript(srs, &config, id, &statement);
        let shape = Shape {
            config: &config,
            shard_counts,
            windows: &windows,
        };
        let setup: Vec<Vec<[u8; 64]>> = (0..5)
            .map(|i| (0..i).map(|_| rng.point()).collect())
            .collect();

        for cuts in [&[0, 7][..], &[0, 3, 4, 7], &[0, 1, 2, 3, 4, 5, 6, 7]] {
            let mut t = Tape::new(3);
            let mut memory = Memory::default();
            let input = |t: &mut Tape, memory: &mut Memory, v: Fr| {
                let c = t.fresh(1);
                memory.set(c, v);
                c
            };
            let [i, io_cell] = [id.0, io].map(|v| input(&mut t, &mut memory, v));
            let mut tr = prefix(&mut t, &shape, &srs.to_bytes(), i, io_cell);
            assert_eq!(tr.checkpoint().1.is_some(), pending(&shape));
            // Every shard's limbs in one block of cells, as a node's slots
            // are: each segment runs, then the next shard's overwrite them.
            let slots = t.fresh(4 * 3);
            for pair in cuts.windows(2) {
                // A node resumes where the last left off.
                let (state, pending) = tr.checkpoint();
                tr = CellTranscript::resume(state, pending);
                for p in pair[0]..pair[1] {
                    let points = &statement.memory_commitments[p as usize];
                    let list: Vec<Limbs> = (0..points.len() as u32)
                        .map(|k| core::array::from_fn(|i| slots + 4 * k + i as u32))
                        .collect();
                    for (k, point) in points.iter().enumerate() {
                        for (i, v) in g1_limbs(point).into_iter().enumerate() {
                            memory.set(slots + 4 * k as u32 + i as u32, v);
                        }
                    }
                    segment(&mut t, &mut tr, &shape, p, &[list]);
                    run(&core::mem::take(&mut t.ops), &mut memory, &[]).expect("a segment runs");
                    for k in 0..12 {
                        memory.set(slots + k, Fr::from_u64(0xdead));
                    }
                }
            }
            let cells: Vec<Cell> = crate::boundary_scalars(&statement.boundary)
                .into_iter()
                .map(|v| input(&mut t, &mut memory, v))
                .collect();
            let (challenges, digest) = suffix(&mut t, &mut tr, &shape, &cells);
            run(&t.ops, &mut memory, &[]).expect("the suffix runs");
            assert_eq!(challenges.map(|c| memory.get(c)), native.memory, "{cuts:?}");
            assert_eq!(memory.get(digest), native.digest, "{cuts:?}");
        }

        let mut t = Tape::new(3);
        let mut memory = Memory::default();
        let pc = t.fresh(1);
        memory.set(pc, Fr::from_u64(entry));
        let lists: Vec<Vec<Limbs>> = setup
            .iter()
            .map(|points| {
                points
                    .iter()
                    .map(|pt| {
                        g1_limbs(pt).map(|v| {
                            let c = t.fresh(1);
                            memory.set(c, v);
                            c
                        })
                    })
                    .collect()
            })
            .collect();
        let got = identity(&mut t, 7, &config, pc, &lists);
        run(&t.ops, &mut memory, &[]).expect("the identity runs");
        assert_eq!(
            memory.get(got),
            identity_digest(7, &config, entry as u32, &setup).0
        );
    }

    /// The windows over cells are the statement's: `io_digest` from their
    /// words' bytes, and step 10c's extension at a point — and a padding byte
    /// that is not 0 refuses.
    #[test]
    fn the_public_windows_are_the_statements() {
        let mut rng = Rng(0x0031_3063);
        let input: Vec<u8> = (0..43).map(|_| rng.next() as u8).collect();
        let output: Vec<u8> = (0..70).map(|_| rng.next() as u8).collect();
        let point: Vec<Fr> = (0..12).map(|_| rng.fr()).collect();
        let check = |padding: u32| {
            let mut t = Tape::new(3);
            let mut memory = Memory::default();
            let mut input_cell = |v: Fr| {
                let c = t.fresh(1);
                memory.set(c, v);
                c
            };
            let mut window = |bytes: &[u8], padding: u32| -> Vec<Cell> {
                let mut words = crate::public_io_words(bytes);
                words.truncate(1 + bytes.len().div_ceil(4));
                *words.last_mut().expect("a payload") |= padding;
                words
                    .iter()
                    .map(|w| input_cell(Fr::from_u64(*w as u64)))
                    .collect()
            };
            // The padding goes in the input, which step 10c does not read.
            let (i, o) = (window(&input, padding), window(&output, 0));
            let r: Vec<Cell> = point.iter().map(|v| input_cell(*v)).collect();
            let want =
                poly::MultilinearPoly::new(poly::PolyBacking::U32(crate::public_io_words(&output)))
                    .evaluate(&point);
            let claim = input_cell(want);
            let ib = window_bytes(&mut t, &i, input.len());
            let ob = window_bytes(&mut t, &o, output.len());
            let io = io_digest(&mut t, &ib, &ob);
            public_value(&mut t, &r, claim, &o);
            run(&t.ops, &mut memory, &[]).map(|()| memory.get(io))
        };
        assert_eq!(check(0), Ok(transcript::io_digest(&input, &output)));
        // 43 bytes leave a word with one byte of padding, at its top.
        assert!(check(1 << 24).is_err(), "a padding byte that is not 0");
    }

    /// The boundary's checks over cells are `verify_global_memory`'s: the
    /// factors are `boundary_factors`', and a timestamp at `2^38`, a value at
    /// `2^32` or an `x10` that is not the exit status refuses.
    #[test]
    fn the_boundary_is_step_10b() {
        let mut rng = Rng(0x0031_3062);
        let finals = BoundaryFinals {
            reg_ts: core::array::from_fn(|_| rng.next() >> 26),
            pc_ts: rng.next() >> 26,
            reg_values: core::array::from_fn(|_| rng.next() as u32),
        };
        let memory4: [Fr; 4] = core::array::from_fn(|_| rng.fr());
        let entry = 0x1_0004u32;
        let want =
            gkr_verify::boundary_factors(&crate::statement::memory_slots(&memory4), entry, &finals);
        let check = |scalars: Vec<Fr>, exit: u32| {
            let mut t = Tape::new(3);
            let mut memory = Memory::default();
            let mut input = |v: Fr| {
                let c = t.fresh(1);
                memory.set(c, v);
                c
            };
            let cells: Vec<Cell> = scalars.into_iter().map(&mut input).collect();
            let (e, pc) = (
                input(Fr::from_u64(exit as u64)),
                input(Fr::from_u64(entry as u64)),
            );
            let ch = memory4.map(&mut input);
            let (w, r) = boundary(&mut t, &cells, e, ch, pc);
            run(&t.ops, &mut memory, &[]).map(|()| (memory.get(w), memory.get(r)))
        };
        let scalars = crate::boundary_scalars(&finals);
        let exit = finals.reg_values[9];
        assert_eq!(check(scalars.clone(), exit), Ok(want));
        let mut late = scalars.clone();
        late[32] = Fr::from_u64(1 << TS_BITS);
        assert!(check(late, exit).is_err(), "a timestamp at 2^38");
        let mut wide = scalars.clone();
        wide[40] = Fr::from_u64(1 << 32);
        assert!(check(wide, exit).is_err(), "a value at 2^32");
        assert!(
            check(scalars, exit ^ 1).is_err(),
            "x10 is not the exit status"
        );
    }
}
