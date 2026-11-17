//! The family fills: how each family's trace buffer becomes its circuit's
//! committed columns. `docs/spec/circuits.md` §1 and §2.
//!
//! A fill returns every `M`, `W` and `S` column but the multiplicities, which
//! the common path counts over the family's channels.

use std::collections::HashMap;
use std::sync::OnceLock;

use constants::extra_mask::add_sub_lui_auipc as kind;
use constants::extra_mask::atomics as at;
use constants::extra_mask::bitwise as bw;
use constants::extra_mask::jump_branch_slt as jbs;
use constants::extra_mask::mem_subword as kind_sub;
use constants::extra_mask::mem_word as kind_mem;
use constants::extra_mask::mul_div as md;
use constants::extra_mask::system_code;
use constants::{delegation, ecall, family, guest_memory, memory};
use constraints::memory::{frame_queries, rd_selected, rd_selected_hi};
use constraints::PolyAddress;
use field::Fp;
use poly::{MultilinearPoly, PolyBacking};
use program::lookup_tables::generic_table;
use program::FamilyId;
use trace::{
    build_frame_witness, build_init_teardown_columns, build_memory_columns,
    build_value_window_columns, FrameSlice, MemoryState, Role, RowSlice, TraceArchive,
};

use crate::Program;

/// What a fill reads: the program, the execution's two unbound inputs, **this
/// shard's rows**, and which shard — its index, its height, and for a window
/// family its window.
///
/// The rows are already cut to the shard (`docs/spec/streaming.md` §4), so a
/// fill indexes `0..rows.len()` and never the whole execution. That is what lets
/// one fill serve a slice of an archived execution and a streaming executor's
/// freshly filled chunk alike (`docs/spec/streaming.md` §3).
pub struct ShardSource<'a> {
    pub program: &'a Program,
    /// The public input window's payload, which `PUBLIC_INPUT`'s fill commits
    /// as its init column.
    pub input: &'a [u8],
    /// The advice bytes the host supplied, which `ADVICE_WINDOWS`' fill commits
    /// and **nothing binds** (`docs/spec/public-values.md` §6).
    pub advice: &'a [u8],
    pub rows: ShardRows<'a>,
    pub index: u32,
    pub height: usize,
    pub window: u32,
}

/// The rows a shard proves, by the kind of family it belongs to — the two
/// kinds `docs/spec/memory.md` §3 names, and a delegation family's invocations.
pub enum ShardRows<'a> {
    /// A cycle-owning family's shard: its cut of that family's buffer.
    Cycles(RowSlice<'a>),
    /// A delegation family's shard: its cut of that family's invocations.
    Invocations(FrameSlice<'a>),
    /// A window family's shard: its rows are addresses rather than trace rows,
    /// and what fills them is the execution's **final** memory state.
    ///
    /// This arm exists so that no cycle-owning fill can reach the state at all,
    /// and so that constructing one says out loud that the execution is over:
    /// a teardown column is every address's *last* write, which is not a fact
    /// until the last cycle has run.
    Window(&'a MemoryState),
}

impl<'a> ShardSource<'a> {
    /// The source for shard `(family, index)` of an **archived** execution: the
    /// program, the archive's two unbound inputs, and this shard's rows cut out
    /// of the archive by `docs/spec/streaming.md` §4's rule.
    ///
    /// Which arm of [`ShardRows`] a family takes: a delegation family takes its
    /// cut of its invocations, a family that owns cycles its cut of them, and
    /// every other is a window family whose rows are addresses. A
    /// streaming prover builds the same struct from a chunk it has just filled,
    /// which is the whole of what the two paths do differently
    /// (`docs/spec/streaming.md` §3).
    pub fn archived(
        program: &'a Program,
        archive: &'a TraceArchive,
        family: FamilyId,
        index: u32,
        height: u32,
        window: u32,
    ) -> Result<ShardSource<'a>, String> {
        let missing = || format!("the archive has no {} buffer", program::family_name(family));
        let traces = archive.family_traces();
        let rows = if program::delegation_frame_words(family).is_some() {
            ShardRows::Invocations(FrameSlice::shard(
                traces.delegation(family).ok_or_else(missing)?,
                index,
                height as usize,
            ))
        } else if program::owns_cycles(family) {
            ShardRows::Cycles(RowSlice::shard(
                traces.family(family).ok_or_else(missing)?,
                index,
                height as usize,
            ))
        } else {
            ShardRows::Window(archive.memory_log().state())
        };
        Ok(ShardSource {
            program,
            input: &archive.io_streams().input,
            advice: archive.advice(),
            rows,
            index,
            height: height as usize,
            window,
        })
    }

    /// This shard's rows, or why it has none of `family`'s.
    fn cycles(&self, family: FamilyId) -> Result<&RowSlice<'a>, String> {
        match &self.rows {
            ShardRows::Cycles(rows) if rows.family() == family => Ok(rows),
            _ => Err(format!(
                "this shard holds no {} rows",
                program::family_name(family)
            )),
        }
    }

    /// This shard's invocations, or why it has none of `family`'s. A
    /// delegation family's fill reads them.
    fn invocations(&self, family: FamilyId) -> Result<&FrameSlice<'a>, String> {
        match &self.rows {
            ShardRows::Invocations(frames) if frames.family() == family => Ok(frames),
            _ => Err(format!(
                "this shard holds no {} invocations",
                program::family_name(family)
            )),
        }
    }

    /// The execution's final memory state, or why this shard is not a window's.
    fn state(&self) -> Result<&'a MemoryState, String> {
        match self.rows {
            ShardRows::Window(state) => Ok(state),
            _ => Err("this shard is not a window family's".into()),
        }
    }
}

/// A family's fill: a shard's committed columns but its multiplicities, or why
/// the trace cannot be proven.
pub type Fill = fn(&ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String>;

/// The fill of `family`, or `None` for a family no circuit proves — the
/// registry beside `constraints::family_circuit`.
pub fn family_fill(family: FamilyId) -> Option<Fill> {
    match family {
        family::ADD_SUB_LUI_AUIPC => Some(add_sub),
        family::JUMP_BRANCH_SLT => Some(jump_branch_slt),
        family::BITWISE => Some(bitwise),
        family::MUL_DIV => Some(mul_div),
        family::MEM_WORD => Some(mem_word),
        family::MEM_SUBWORD => Some(mem_subword),
        family::ATOMICS => Some(atomics),
        // The journal's window is `ZERO_WINDOWS`' circuit and `ZERO_WINDOWS`'
        // fill: its init leaf is the literal 0, so there is no init column to
        // fill (`docs/spec/public-values.md` §5).
        family::INIT_TEARDOWN | family::ZERO_WINDOWS | family::PUBLIC_OUTPUT => Some(window),
        family::PUBLIC_INPUT => Some(public_input),
        family::ADVICE_WINDOWS => Some(advice),
        family::POSEIDON2 => Some(poseidon2),
        family::POSEIDON2_ROUNDS => Some(poseidon2_rounds),
        family::MUL_DIV_U256 => Some(mul_div_u256),
        family::MERKLE_ROOT => Some(merkle_root),
        family::MERKLE_LEVELS => Some(merkle_levels),
        family::MERKLE_ROUNDS => Some(merkle_rounds),
        family::FALCON => Some(falcon),
        family::FALCON_SPLIT => Some(falcon_split),
        family::FALCON_PRODUCT => Some(falcon_product),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The delegation families' fills
// ---------------------------------------------------------------------------

/// A delegation shard's frame columns by name, `constraints::delegation::frame`:
/// `live`, `cycle`, `number`, each word's four and its two gap chunks, and the
/// room's halfword. Returns the shard's calls and the witness to add to.
fn frame_fill<'a>(
    src: &ShardSource<'a>,
    fam: FamilyId,
) -> Result<(FrameSlice<'a>, Witness), String> {
    let calls = *src.invocations(fam)?;
    let mut w = Witness::new(fam, calls.len());
    let number = delegation::TYPES
        .iter()
        .find(|(f, ..)| *f == fam)
        .map(|(_, n, ..)| *n as u64)
        .expect("a delegation family");
    let [live, cycle, n] = ["live", "cycle", "number"].map(|c| w.col(c));
    for (r, c) in calls.cycles().iter().enumerate() {
        w.row(r, &[(live, 1), (cycle, *c), (n, number)]);
    }
    let words = program::delegation_frame_words(fam).expect("a delegation family");
    for j in 0..words {
        let word = calls.word(j);
        let written = names(fam).contains_key(&format!("w{j}_write_value"));
        let cols = [
            w.col(&format!("w{j}_addr")),
            w.col(&format!("w{j}_read_ts")),
            w.col(&format!("w{j}_read_value")),
        ];
        let write = written.then(|| w.col(&format!("w{j}_write_value")));
        let chunks = [0, 1].map(|c| w.col(&format!("w{j}_gap_c{c}")));
        for r in 0..calls.len() {
            w.put(cols[0], r, word.addr[r] as u64);
            access(&mut w, [cols[1], cols[2]], chunks, &calls, j, r);
            if let Some(c) = write {
                w.put(c, r, word.write_value[r]);
            }
        }
    }
    let room = w.col("room_h16");
    for r in 0..calls.len() {
        let cycle = calls.cycles()[r];
        let end = calls.word(0).addr[r] as u64 + 4 * words as u64;
        let left = (guest_memory::ADVICE_ORIGIN as u64)
            .checked_sub(end)
            .ok_or_else(|| format!("the frame at cycle {cycle} reaches the advice"))?;
        w.put(room, r, left >> 16);
    }
    Ok((calls, w))
}

/// Word `j` of entry `r`, accessed at its cycle's `4·cycle + FRAME_DELTA`
/// (`constraints::delegation::access`): its read timestamp and value, and the
/// gap's two chunks.
fn access(
    w: &mut Witness,
    cols: [usize; 2],
    chunks: [usize; 2],
    calls: &FrameSlice,
    j: usize,
    r: usize,
) {
    access_at(w, cols, chunks, calls, j, r, r);
}

/// [`access`] of entry `e`'s word `j` on row `r`, for a family of several
/// rows an entry.
fn access_at(
    w: &mut Witness,
    [read_ts, read]: [usize; 2],
    [c0, c1]: [usize; 2],
    calls: &FrameSlice,
    j: usize,
    e: usize,
    r: usize,
) {
    let word = calls.word(j);
    let ts = memory::TS_STEP * calls.cycles()[e] + delegation::FRAME_DELTA;
    let gap = ts - word.read_ts[e] - 1;
    w.row(
        r,
        &[
            (read_ts, word.read_ts[e]),
            (read, word.read_value[e]),
            (c0, (gap >> 16) & 0xffff),
            (c1, gap >> 32),
        ],
    );
}

/// A frame word's value as written, `j` counted from the frame's first.
fn frame_word(calls: &FrameSlice, j: usize, r: usize, write: bool) -> u64 {
    let word = calls.word(j);
    match write {
        true => word.write_value[r],
        false => word.read_value[r],
    }
}

/// Lane `i` of a Poseidon2 frame, words `2i` and `2i + 1`, mod `p`.
fn lane(calls: &FrameSlice, i: usize, r: usize, write: bool) -> Fp {
    Fp::from_u64(frame_word(calls, 2 * i, r, write) | frame_word(calls, 2 * i + 1, r, write) << 32)
}

/// `POSEIDON2`, `docs/spec/precompiles.md` §3: the frame, the last boundary's
/// stamp, the input after `M_E`, the output, and each output lane's halfwords
/// and top test.
fn poseidon2(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constraints::poseidon2::{stamp, LAST};
    use transcript::WIDTH;
    let fam = family::POSEIDON2;
    let (calls, mut w) = frame_fill(src, fam)?;
    let last = w.col("last");
    let u: Vec<usize> = (0..WIDTH).map(|j| w.fcol(&format!("u{j}"))).collect();
    let o: Vec<usize> = (0..WIDTH).map(|l| w.col(&format!("o{l}"))).collect();
    let halves: Vec<[usize; 4]> = (0..WIDTH)
        .map(|l| canonical_columns(&mut w, &format!("o{l}")))
        .collect();
    for r in 0..calls.len() {
        w.put(last, r, stamp(LAST));
        let mut x: [Fp; WIDTH] = std::array::from_fn(|i| lane(&calls, i, r, false));
        transcript::external(&mut x);
        for (j, c) in u.iter().enumerate() {
            w.put_fp(*c, r, x[j]);
        }
        let mut out: [Fp; WIDTH] = std::array::from_fn(|i| lane(&calls, i, r, false));
        transcript::poseidon2_permute(&mut out);
        for l in 0..WIDTH {
            let (lo_w, hi_w) = (
                frame_word(&calls, 2 * l, r, true),
                frame_word(&calls, 2 * l + 1, r, true),
            );
            assert_eq!(
                lo_w | hi_w << 32,
                out[l].to_u64(),
                "cycle {}: the trace's Poseidon2 output is not the permutation's",
                calls.cycles()[r]
            );
            w.put(o[l], r, out[l].to_u64());
            canonical(&mut w, halves[l], r, lo_w, hi_w);
        }
    }
    Ok(w.finish(src.height))
}

/// A canonical lane's columns (`constraints::poseidon2::canonical`): its
/// words' high halfwords, the top test's inverse and its bit.
fn canonical_columns(w: &mut Witness, name: &str) -> [usize; 4] {
    [
        w.col(&format!("{name}_lo_h16")),
        w.col(&format!("{name}_hi_h16")),
        w.fcol(&format!("{name}_inv")),
        w.col(&format!("{name}_top")),
    ]
}

/// Row `r`'s cells of the canonical lane whose words are `lo_w` and `hi_w`.
fn canonical(w: &mut Witness, [l1, h1, inv, top]: [usize; 4], r: usize, lo_w: u64, hi_w: u64) {
    w.row(r, &[(l1, lo_w >> 16), (h1, hi_w >> 16)]);
    let all_ones = 3 * 0xffff - (hi_w >> 16) - (hi_w & 0xffff) - (lo_w >> 16);
    match Fp::from_u64(all_ones).inverse() {
        Some(i) => w.put_fp(inv, r, i),
        None => w.put(top, r, 1),
    }
}

/// `POSEIDON2_ROUNDS`, `docs/spec/precompiles.md` §3: sixteen rows a call, row
/// `k` taking the state at boundary `k` through its rounds, the last idle.
fn poseidon2_rounds(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    rounds(src, family::POSEIDON2_ROUNDS)
}

/// `MERKLE_ROUNDS`, `docs/spec/precompiles.md` §6: a level's permutation,
/// boundary `16L + 1` to `16(L + 1)`, its last round writing the node alone.
fn merkle_rounds(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    rounds(src, family::MERKLE_ROUNDS)
}

/// The rounds of one permutation an entry (`constraints::poseidon2::rounds`):
/// a `POSEIDON2` call's frame lanes, or a Merkle level's ordered pair, through
/// `M_E` and then sixteen rows, row `k` at `first + stride·k`, the last idle.
fn rounds(src: &ShardSource, fam: FamilyId) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constraints::merkle::{LEVEL, STRIDE};
    use constraints::poseidon2::{internal, round_constant, stamp, PARTIAL, ROWS};
    use transcript::WIDTH;
    let calls = *src.invocations(fam)?;
    let level = fam == family::MERKLE_ROUNDS;
    let mut w = Witness::new(fam, ROWS * calls.len());
    let [live, cycle, stamp_col, ext, int] =
        ["live", "cycle", "stamp", "ext", "int"].map(|c| w.col(c));
    let keep = level.then(|| w.col("keep"));
    let kinds: Vec<usize> = (0..ROWS - 1).map(|k| w.col(&format!("row{k}"))).collect();
    let lanes = |prefix: &str, w: &mut Witness| -> Vec<usize> {
        (0..WIDTH)
            .map(|i| w.fcol(&format!("{prefix}{i}")))
            .collect()
    };
    let (s, o) = (lanes("s", &mut w), lanes("o", &mut w));
    let y: Vec<[usize; 3]> = (0..WIDTH)
        .map(|j| {
            [
                w.fcol(&format!("y{j}")),
                w.fcol(&format!("y{j}_sq")),
                w.fcol(&format!("y{j}_cube")),
            ]
        })
        .collect();
    for c in 0..calls.len() {
        let input: [Fp; WIDTH] = match level {
            false => std::array::from_fn(|i| lane(&calls, i, c, false)),
            true => level_input(&calls, c),
        };
        let at = |k: usize| match level {
            false => stamp(k as u64),
            true => LEVEL * calls.carry(9)[c] + STRIDE * (k as u64 + 1),
        };
        let mut state = input;
        transcript::external(&mut state);
        for (k, kind_col) in kinds.iter().enumerate() {
            let r = ROWS * c + k;
            let kind = internal(k) as u64;
            w.row(
                r,
                &[
                    (live, 1),
                    (cycle, calls.cycles()[c]),
                    (stamp_col, at(k)),
                    (*kind_col, 1),
                    (ext, 1 - kind),
                    (int, kind),
                ],
            );
            if let Some(keep) = keep {
                w.put(keep, r, (k < ROWS - 2) as u64);
            }
            for (i, col) in s.iter().enumerate() {
                w.put_fp(*col, r, state[i]);
            }
            let sbox = |j: usize, x: Fp, w: &mut Witness| {
                let [a, b, z] = y[j];
                w.put_fp(a, r, x);
                w.put_fp(b, r, x * x);
                w.put_fp(z, r, x * x * x);
                x * x * x
            };
            if internal(k) {
                for m in 0..PARTIAL {
                    state[0] = sbox(m, state[0] + round_constant(k, m), &mut w);
                    transcript::internal(&mut state);
                }
            } else {
                for (j, x) in state.iter_mut().enumerate() {
                    *x = sbox(j, *x + round_constant(k, j), &mut w);
                }
                transcript::external(&mut state);
            }
            for (i, col) in o.iter().enumerate() {
                w.put_fp(*col, r, state[i]);
            }
        }
        let mut out = input;
        transcript::poseidon2_permute(&mut out);
        assert_eq!(state, out, "the rounds' last state is the permutation");
    }
    Ok(w.finish(src.height))
}

/// Level entry `r`'s permutation input: its node and its sibling, the node
/// on the left where the slot's bit is 0 (`constraints::merkle::levels`).
fn level_input(calls: &FrameSlice, r: usize) -> [Fp; 16] {
    let node: [Fp; 8] = std::array::from_fn(|i| Fp::from_u64(calls.carry(i)[r]));
    let sibling: [Fp; 8] = std::array::from_fn(|i| lane(calls, i, r, false));
    let (left, right) = match calls.carry(8)[r] & 1 {
        0 => (node, sibling),
        _ => (sibling, node),
    };
    std::array::from_fn(|i| if i < 8 { left[i] } else { right[i - 8] })
}

/// `MERKLE_ROOT`, `docs/spec/precompiles.md` §6: the frame, the root's
/// boundary and the spent control's sibling address, the leaf's lanes, and
/// the root's, canonical.
fn merkle_root(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constants::delegation::merkle::{DEPTH, SIBLING, SIBLINGS};
    use constraints::merkle::LEVEL;
    let fam = family::MERKLE_ROOT;
    let (calls, mut w) = frame_fill(src, fam)?;
    let [last, end] = ["last", "end"].map(|c| w.col(c));
    let n: Vec<usize> = (0..8).map(|i| w.fcol(&format!("n{i}"))).collect();
    let o: Vec<usize> = (0..8).map(|l| w.col(&format!("o{l}"))).collect();
    let halves: Vec<[usize; 4]> = (0..8)
        .map(|l| canonical_columns(&mut w, &format!("o{l}")))
        .collect();
    for r in 0..calls.len() {
        let depth = frame_word(&calls, DEPTH, r, false);
        let siblings = frame_word(&calls, SIBLINGS, r, false);
        w.put(last, r, LEVEL * depth);
        w.put(end, r, siblings + 4 * SIBLING as u64 * depth);
        for (i, c) in n.iter().enumerate() {
            w.put_fp(*c, r, lane(&calls, i, r, false));
        }
        for l in 0..8 {
            let (lo_w, hi_w) = (
                frame_word(&calls, 2 * l, r, true),
                frame_word(&calls, 2 * l + 1, r, true),
            );
            w.put(o[l], r, lo_w | hi_w << 32);
            canonical(&mut w, halves[l], r, lo_w, hi_w);
        }
    }
    Ok(w.finish(src.height))
}

/// `MERKLE_LEVELS`, `docs/spec/precompiles.md` §6: one row a level, from its
/// entry's carry — the node, the slot's bits not yet taken, the level — and
/// its sibling's words, each with its high halfword.
fn merkle_levels(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constants::delegation::merkle::SIBLING;
    use constraints::merkle::LEVEL;
    let fam = family::MERKLE_LEVELS;
    let calls = *src.invocations(fam)?;
    let mut w = Witness::new(fam, calls.len());
    let [live, cycle, stamp, next, rest, rest_next, ptr, bit] = [
        "live",
        "cycle",
        "stamp",
        "next",
        "rest",
        "rest_next",
        "ptr",
        "bit",
    ]
    .map(|c| w.col(c));
    let words: Vec<([usize; 2], [usize; 2], usize)> = (0..SIBLING)
        .map(|j| {
            let cols = [
                w.col(&format!("w{j}_read_ts")),
                w.col(&format!("w{j}_read_value")),
            ];
            let chunks = [0, 1].map(|c| w.col(&format!("w{j}_gap_c{c}")));
            (cols, chunks, w.col(&format!("w{j}_h16")))
        })
        .collect();
    let n: Vec<usize> = (0..8).map(|i| w.fcol(&format!("n{i}"))).collect();
    let u: Vec<usize> = (0..16).map(|j| w.fcol(&format!("u{j}"))).collect();
    for r in 0..calls.len() {
        let (left, level) = (calls.carry(8)[r], calls.carry(9)[r]);
        w.row(
            r,
            &[
                (live, 1),
                (cycle, calls.cycles()[r]),
                (stamp, LEVEL * level),
                (next, LEVEL * (level + 1)),
                (rest, left),
                (rest_next, left >> 1),
                (ptr, calls.bases()[r] as u64),
                (bit, left & 1),
            ],
        );
        for (j, (cols, chunks, h16)) in words.iter().enumerate() {
            access(&mut w, *cols, *chunks, &calls, j, r);
            w.put(*h16, r, calls.word(j).read_value[r] >> 16);
        }
        for (i, c) in n.iter().enumerate() {
            w.put_fp(*c, r, Fp::from_u64(calls.carry(i)[r]));
        }
        let mut x = level_input(&calls, r);
        transcript::external(&mut x);
        for (j, c) in u.iter().enumerate() {
            w.put_fp(*c, r, x[j]);
        }
    }
    Ok(w.finish(src.height))
}

/// `MUL_DIV_U256`, `docs/spec/precompiles.md` §4: the frame, every word's high
/// halfword, the chunk carries and the bound's borrows and words.
fn mul_div_u256(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constraints::mul_div_u256::{CARRY_OFFSET, WORDS};
    let fam = family::MUL_DIV_U256;
    let (calls, mut w) = frame_fill(src, fam)?;
    let names_of = |p: &str| -> Vec<String> { (0..WORDS).map(|k| format!("{p}{k}_h16")).collect() };
    let h16: Vec<Vec<usize>> = ["a", "b", "d", "q", "r"]
        .iter()
        .map(|p| names_of(p).iter().map(|n| w.col(n)).collect())
        .collect();
    let carries: Vec<[usize; 2]> = (0..2 * WORDS - 1)
        .map(|k| [w.fcol(&format!("carry{k}")), w.col(&format!("carry{k}_c0"))])
        .collect();
    let borrows: Vec<usize> = (0..WORDS - 1)
        .map(|k| w.col(&format!("borrow{k}")))
        .collect();
    let bounds: Vec<usize> = (0..WORDS)
        .map(|k| w.col(&format!("bound{k}_h16")))
        .collect();
    for r in 0..calls.len() {
        let get = |at: usize, write: bool| -> Vec<u64> {
            (0..WORDS)
                .map(|k| frame_word(&calls, at + k, r, write))
                .collect()
        };
        let words = [
            get(0, false),
            get(WORDS, false),
            get(2 * WORDS, false),
            get(0, true),
            get(WORDS, true),
        ];
        for (cols, ws) in h16.iter().zip(&words) {
            for (c, v) in cols.iter().zip(ws) {
                w.put(*c, r, v >> 16);
            }
        }
        let limbs = |ws: &[u64]| -> Vec<i128> {
            ws.iter()
                .flat_map(|v| [(v & 0xffff) as i128, (v >> 16) as i128])
                .collect()
        };
        let [a, b, d, q, _] = &words;
        let (la, lb, ld, lq) = (limbs(a), limbs(b), limbs(d), limbs(q));
        let at = |x: &[i128], y: &[i128], m: usize| -> i128 {
            (0..x.len())
                .filter(|i| m >= *i && m - i < y.len())
                .map(|i| x[i] * y[m - i])
                .sum()
        };
        let mut carry = 0i128;
        for k in 0..2 * WORDS {
            let mut v = at(&la, &lb, 2 * k) + (at(&la, &lb, 2 * k + 1) << 16)
                - at(&lq, &ld, 2 * k)
                - (at(&lq, &ld, 2 * k + 1) << 16)
                + carry;
            if k < WORDS {
                v -= words[4][k] as i128;
            }
            assert_eq!(
                v & 0xffff_ffff,
                0,
                "cycle {}: the trace's quotient and remainder are not a·b's by d",
                calls.cycles()[r]
            );
            carry = v >> 32;
            if k < 2 * WORDS - 1 {
                let [c, c0] = carries[k];
                w.put_fp(c, r, signed(carry));
                w.put(c0, r, ((carry + CARRY_OFFSET as i128) >> 16) as u64);
            } else {
                assert_eq!(carry, 0, "the product and q·d + r agree past 2^512");
            }
        }
        let mut borrow = 0i64;
        for k in 0..WORDS {
            let g = d[k] as i64 - words[4][k] as i64 - (k == 0) as i64 - borrow;
            borrow = (g < 0) as i64;
            let g = (g + (borrow << 32)) as u64;
            if k < WORDS - 1 {
                w.put(borrows[k], r, borrow as u64);
            } else {
                assert_eq!(
                    borrow,
                    0,
                    "cycle {}: the remainder is not below d",
                    calls.cycles()[r]
                );
            }
            w.put(bounds[k], r, g >> 16);
        }
    }
    Ok(w.finish(src.height))
}

// ---------------------------------------------------------------------------
// Falcon-512
// ---------------------------------------------------------------------------

/// One `FALCON512` call as `constraints::falcon` splits it, from its arrays
/// entry's words: each chain's halfwords, `s1`, and every residue.
struct FalconCall {
    /// Chain `P`'s coefficient `t`, its array's halfword `t` as read.
    v: [[u64; delegation::falcon::N]; 3],
    /// `(c − s2·h) mod (q, x^512 + 1)`, centered to `[−6144, 6144]`.
    s1: [i64; delegation::falcon::N],
    /// `sum[P][r][j] = Σ_m V[r][m]·(v_P − s_P)_{32m + j}` over the integers,
    /// `s_P` being `s1` on chain `c` and 0 on the others.
    sum: [[[i64; constraints::falcon::DEGREE]; constraints::falcon::RESIDUES]; 3],
}

impl FalconCall {
    /// Coefficient `t` of what chain `p` splits off its array.
    fn s(&self, p: usize, t: usize) -> i64 {
        match delegation::falcon::CHAINS[p] == delegation::falcon::C {
            true => self.s1[t],
            false => 0,
        }
    }

    /// Residue `r`'s coefficient `j` of chain `p`, in `[0, q)`.
    fn residue(&self, p: usize, r: usize, j: usize) -> u64 {
        self.sum[p][r][j].rem_euclid(delegation::falcon::Q as i64) as u64
    }
}

/// Entry `e`'s call: its 768 words split into halfwords, `s1` as the emulator
/// answers it, [`emulator::falcon512_s1`], and every residue sum.
fn falcon_call(calls: &FrameSlice, e: usize) -> FalconCall {
    use constants::delegation::falcon::{ARRAY, C, CHAINS, H, N, S2};
    use constraints::falcon::{BLOCKS, DEGREE, RESIDUES, V};
    let mut v = [[0u64; N]; 3];
    for (p, chain) in v.iter_mut().enumerate() {
        for i in 0..ARRAY {
            let word = calls.word(ARRAY * p + i);
            assert_eq!(
                word.write_value[e],
                word.read_value[e],
                "cycle {}: FALCON512 wrote a word of its arrays",
                calls.cycles()[e]
            );
            chain[2 * i] = word.read_value[e] & 0xffff;
            chain[2 * i + 1] = word.read_value[e] >> 16;
        }
    }
    let poly = |word: usize| -> [u16; N] {
        let p = CHAINS.iter().position(|w| *w == word).expect("a chain");
        v[p].map(|x| x as u16)
    };
    let s1 = emulator::falcon512_s1(&poly(H), &poly(S2), &poly(C));
    let mut call = FalconCall {
        v,
        s1: s1.map(i64::from),
        sum: [[[0; DEGREE]; RESIDUES]; 3],
    };
    call.sum = std::array::from_fn(|p| {
        std::array::from_fn(|r| {
            std::array::from_fn(|j| {
                (0..BLOCKS)
                    .map(|m| {
                        let t = DEGREE * m + j;
                        V[r][m] as i64 * (call.v[p][t] as i64 - call.s(p, t))
                    })
                    .sum()
            })
        })
    });
    call
}

/// `FALCON`, `constraints::falcon`: the frame, the norm's halfword and its
/// value, each chain's start stamp and its end's pointer.
fn falcon(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constants::delegation::falcon::{CHAINS, NORM_HI, NORM_LO};
    use constraints::falcon::{start, COLUMNS};
    let fam = family::FALCON;
    let (calls, mut w) = frame_fill(src, fam)?;
    let [n, n_lo] = ["n", "n_lo_h16"].map(|c| w.col(c));
    let chains: Vec<[usize; 2]> = (0..CHAINS.len())
        .map(|p| [w.col(&format!("st{p}")), w.col(&format!("end{p}"))])
        .collect();
    for r in 0..calls.len() {
        let (lo, hi) = (
            frame_word(&calls, NORM_LO, r, true),
            frame_word(&calls, NORM_HI, r, true),
        );
        w.row(r, &[(n, lo | hi << 32), (n_lo, lo >> 16)]);
        for (p, [st, end]) in chains.iter().enumerate() {
            let ptr = frame_word(&calls, CHAINS[p], r, false);
            w.row(r, &[(*st, start(p)), (*end, ptr + 4 * COLUMNS as u64)]);
        }
    }
    Ok(w.finish(src.height))
}

/// `FALCON_SPLIT`, `constraints::falcon`: 64 rows a call, row `16P + j`
/// column `j` of chain `P` — its control in and out, its sixteen words and
/// their halfwords, its `s`, and its residues with their quotients — and rows
/// 48–63 zero.
fn falcon_split(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constants::delegation::falcon::{ARRAY, CHAINS, Q};
    use constraints::falcon::{place, start, BLOCKS, COLUMNS, DEGREE, KEY, RESIDUES};
    let fam = family::FALCON_SPLIT;
    let calls = *src.invocations(fam)?;
    let per = program::delegation_rows(fam) as usize;
    let mut w = Witness::new(fam, per * calls.len());
    let [live, cycle, stamp, key, ptr, acc, acc_out] =
        ["live", "cycle", "stamp", "key", "ptr", "acc", "acc_out"].map(|c| w.col(c));
    let addr: Vec<usize> = (1..BLOCKS).map(|m| w.col(&format!("a{m}"))).collect();
    let words: Vec<([usize; 2], [usize; 2], usize)> = (0..BLOCKS)
        .map(|m| {
            let cols = [
                w.col(&format!("w{m}_read_ts")),
                w.col(&format!("w{m}_read_value")),
            ];
            let chunks = [0, 1].map(|c| w.col(&format!("w{m}_gap_c{c}")));
            (cols, chunks, w.col(&format!("w{m}_h16")))
        })
        .collect();
    let s: Vec<[usize; 2]> = (0..BLOCKS)
        .map(|m| [0, 1].map(|e| w.fcol(&format!("s{m}_{e}"))))
        .collect();
    let rr: Vec<[[usize; 3]; 2]> = (0..RESIDUES)
        .map(|r| {
            [0, 1].map(|e| {
                [
                    w.col(&format!("rr{r}_{e}")),
                    w.fcol(&format!("kk{r}_{e}")),
                    w.col(&format!("kk{r}_{e}_h16")),
                ]
            })
        })
        .collect();
    for c in 0..calls.len() {
        let call = falcon_call(&calls, c);
        let at = calls.cycles()[c];
        for p in 0..CHAINS.len() {
            let array = calls.word(ARRAY * p).addr[c] as u64;
            let mut total = 0u64;
            for j in 0..COLUMNS {
                let r = per * c + COLUMNS * p + j;
                let base = array + 4 * j as u64;
                let squares: u64 = (0..BLOCKS)
                    .flat_map(|m| [0, 1].map(|e| call.s(p, DEGREE * m + 2 * j + e)))
                    .map(|x| (x * x) as u64)
                    .sum();
                w.row(
                    r,
                    &[
                        (live, 1),
                        (cycle, at),
                        (stamp, start(p) + j as u64),
                        (key, KEY * at + place(p, j)),
                        (ptr, base),
                        (acc, total),
                        (acc_out, total + squares),
                    ],
                );
                total += squares;
                for (m, col) in addr.iter().enumerate() {
                    w.put(*col, r, base + 64 * (m as u64 + 1));
                }
                for (m, (cols, chunks, h16)) in words.iter().enumerate() {
                    let word = ARRAY * p + COLUMNS * m + j;
                    access_at(&mut w, *cols, *chunks, &calls, word, c, r);
                    w.put(*h16, r, calls.word(word).read_value[c] >> 16);
                }
                for (m, pair) in s.iter().enumerate() {
                    for (e, col) in pair.iter().enumerate() {
                        let x = call.s(p, DEGREE * m + 2 * j + e);
                        w.put_fp(*col, r, signed(x as i128));
                    }
                }
                for (res, pair) in rr.iter().enumerate() {
                    for (e, [out, kk, kk_h16]) in pair.iter().enumerate() {
                        let sum = call.sum[p][res][2 * j + e];
                        let residue = call.residue(p, res, 2 * j + e);
                        let quotient = (sum - residue as i64) / Q as i64;
                        w.put(*out, r, residue);
                        w.put_fp(*kk, r, signed(quotient as i128));
                        w.put(*kk_h16, r, (quotient + (1 << 31)) as u64 >> 16);
                    }
                }
            }
        }
    }
    Ok(w.finish(src.height))
}

/// `FALCON_PRODUCT`, `constraints::falcon`: 16 rows a call, row `r` residue
/// `r` — its one-hot, the three bases, the residues of `s2`, `h` and
/// `c − s1`, the wrapped products and each coefficient's quotient by `q`.
fn falcon_product(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constants::delegation::falcon::{CHAINS, Q};
    use constraints::falcon::{place, BETA, DEGREE, KEY, RESIDUES};
    let fam = family::FALCON_PRODUCT;
    let calls = *src.invocations(fam)?;
    let per = program::delegation_rows(fam) as usize;
    let mut w = Witness::new(fam, per * calls.len());
    let [live, index] = ["live", "r"].map(|c| w.col(c));
    let bases: Vec<usize> = (0..CHAINS.len())
        .map(|p| w.col(&format!("base{p}")))
        .collect();
    let x: Vec<Vec<usize>> = ["a", "b", "d"]
        .iter()
        .map(|n| (0..DEGREE).map(|i| w.col(&format!("{n}{i}"))).collect())
        .collect();
    let o: Vec<usize> = (0..RESIDUES).map(|i| w.col(&format!("o{i}"))).collect();
    let wrap: Vec<usize> = (0..DEGREE - 1)
        .map(|k| w.col(&format!("wrap{k}")))
        .collect();
    let chunks: Vec<[usize; 3]> = (0..DEGREE)
        .map(|k| [0, 1, 2].map(|c| w.col(&format!("w{k}_c{c}"))))
        .collect();
    for c in 0..calls.len() {
        let call = falcon_call(&calls, c);
        let at = calls.cycles()[c];
        for res in 0..RESIDUES {
            let r = per * c + res;
            w.row(r, &[(live, 1), (index, res as u64), (o[res], 1)]);
            for (p, col) in bases.iter().enumerate() {
                w.put(*col, r, KEY * at + place(p, 0));
            }
            let values: Vec<[u64; DEGREE]> = (0..CHAINS.len())
                .map(|p| std::array::from_fn(|j| call.residue(p, res, j)))
                .collect();
            for (cols, vals) in x.iter().zip(&values) {
                for (col, v) in cols.iter().zip(vals) {
                    w.put(*col, r, *v);
                }
            }
            let (a, b, d) = (&values[0], &values[1], &values[2]);
            let wrapped: Vec<u64> = (0..DEGREE - 1)
                .map(|k| (k + 1..DEGREE).map(|i| a[i] * b[k + DEGREE - i]).sum())
                .collect();
            for (col, v) in wrap.iter().zip(&wrapped) {
                w.put(*col, r, *v);
            }
            for (k, cols) in chunks.iter().enumerate() {
                let direct: u64 = (0..=k).map(|i| a[i] * b[k - i]).sum();
                let folded = wrapped.get(k).map_or(0, |v| BETA[res] * v);
                let left = (direct + folded) as i128 - d[k] as i128;
                assert!(
                    left >= 0 && left % Q as i128 == 0,
                    "cycle {at}: residue {res}'s coefficient {k} of s2·h is not c − s1's"
                );
                let quotient = (left / Q as i128) as u64;
                assert!(quotient < 1 << 48, "a product's quotient off its chunks");
                for (i, col) in cols.iter().enumerate() {
                    w.put(*col, r, (quotient >> (16 * i)) & 0xffff);
                }
            }
        }
    }
    Ok(w.finish(src.height))
}

/// A RAM window shard: `trace::build_init_teardown_columns` over its window,
/// with `S[0]`, the image column, for window 0.
fn window(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    Ok(build_init_teardown_columns(
        src.state()?,
        &src.program.image,
        src.window,
        src.height,
    ))
}

/// The public input window: a value window whose init column is the statement's
/// `input`, laid out by `program::public_io_words`.
///
/// The verifier holds that column to its own multilinear extension of the same
/// words at the shard's evaluation point, so this is the one place the prover
/// can put the bytes and have the proof verify (`docs/spec/public-values.md`
/// §5).
fn public_input(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let state = src.state()?;
    if src.input.len() > guest_memory::PUBLIC_PAYLOAD_BYTES as usize {
        return Err(format!(
            "the public input is {} bytes, above the window's {}",
            src.input.len(),
            guest_memory::PUBLIC_PAYLOAD_BYTES
        ));
    }
    Ok(build_value_window_columns(
        state,
        &program::public_io_words(src.input),
        src.window,
        src.height,
    ))
}

/// An advice window: a value window whose init column is this window's slice
/// of the bytes the host supplied, and which **nothing binds**.
fn advice(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let state = src.state()?;
    let first = src.height as u64 * src.index as u64;
    let words: Vec<u32> = (0..src.height as u64)
        .map(|y| trace::advice_word(src.advice, first + y))
        .collect();
    Ok(build_value_window_columns(
        state, &words, src.window, src.height,
    ))
}

fn fp_column(mut values: Vec<Fp>, height: usize) -> MultilinearPoly {
    values.resize(height, Fp::ZERO);
    MultilinearPoly::new(PolyBacking::Fp(values))
}

/// A signed integer as a field element, its residue mod `p`.
fn signed(v: i128) -> Fp {
    let magnitude = Fp::from_u128(v.unsigned_abs());
    match v < 0 {
        true => -magnitude,
        false => magnitude,
    }
}

// ---------------------------------------------------------------------------
// The execution families' fills
// ---------------------------------------------------------------------------
//
// Each circuit names its columns (`constraints::family`), and a fill writes a
// column by that name: `Witness::col` resolves the name once, before the row
// loop, and `put` writes a row of it. A row a fill does not write is 0, which
// is what a padding row holds in every column.

/// The low and high words of a 64-bit value.
fn lo(v: u64) -> u64 {
    v & 0xffff_ffff
}
fn hi(v: u64) -> u64 {
    v >> 32
}
/// A word's sign bit.
fn sign(word: u64) -> u64 {
    (word >> 31) & 1
}
/// A 32-bit value sign-extended.
fn sext32(word: u64) -> u64 {
    word as u32 as i32 as i64 as u64
}
/// The high word of a sign-extended word: `2^32 − 1` or 0.
fn fill(bit: u64) -> u64 {
    bit * 0xffff_ffff
}

/// Every `M` and `W` column of `family`'s circuit by name, from its artifact
/// at the floor of the height menu: a name does not depend on the height.
fn names(family: FamilyId) -> &'static HashMap<String, PolyAddress> {
    static NAMES: [OnceLock<HashMap<String, PolyAddress>>; family::COUNT as usize] =
        [const { OnceLock::new() }; family::COUNT as usize];
    NAMES[family as usize].get_or_init(|| {
        let a = constraints::family_circuit(family, 20)
            .expect("every execution and delegation family has a circuit at 2^20")
            .artifact;
        let memory = a.memory.iter().enumerate();
        let memory = memory.map(|(i, n)| (n.clone(), PolyAddress::Memory(i as u32)));
        let witness = a.witness.iter().enumerate();
        memory
            .chain(witness.map(|(i, n)| (n.clone(), PolyAddress::Witness(i as u32))))
            .collect()
    })
}

enum Values {
    Int(Vec<u64>),
    Field(Vec<Fp>),
}

/// One shard's witness columns of one family, written by name.
struct Witness {
    family: FamilyId,
    rows: usize,
    columns: Vec<(PolyAddress, Values)>,
}

impl Witness {
    fn new(family: FamilyId, rows: usize) -> Witness {
        Witness {
            family,
            rows,
            columns: Vec::new(),
        }
    }

    fn resolve(&self, name: &str) -> PolyAddress {
        *names(self.family).get(name).unwrap_or_else(|| {
            panic!(
                "{} has no column `{name}`",
                program::family_name(self.family)
            )
        })
    }

    /// An integer column named `name`.
    fn col(&mut self, name: &str) -> usize {
        let at = self.resolve(name);
        self.columns.push((at, Values::Int(vec![0; self.rows])));
        self.columns.len() - 1
    }

    /// A field column named `name`: an inverse, a signed carry.
    fn fcol(&mut self, name: &str) -> usize {
        let at = self.resolve(name);
        self.columns
            .push((at, Values::Field(vec![Fp::ZERO; self.rows])));
        self.columns.len() - 1
    }

    fn put(&mut self, c: usize, r: usize, v: u64) {
        match &mut self.columns[c].1 {
            Values::Int(values) => values[r] = v,
            Values::Field(values) => values[r] = Fp::from_u64(v),
        }
    }

    fn put_fp(&mut self, c: usize, r: usize, v: Fp) {
        match &mut self.columns[c].1 {
            Values::Field(values) => values[r] = v,
            Values::Int(_) => panic!("an integer column given a field element"),
        }
    }

    /// `(name, value)` pairs for row `r`, integer columns all.
    fn row(&mut self, r: usize, cells: &[(usize, u64)]) {
        for (c, v) in cells {
            self.put(*c, r, *v);
        }
    }

    fn finish(self, h: usize) -> Vec<(PolyAddress, MultilinearPoly)> {
        self.columns
            .into_iter()
            .map(|(at, values)| match values {
                Values::Int(v) => (at, trace::column(v, h)),
                Values::Field(v) => (at, fp_column(v, h)),
            })
            .collect()
    }
}

/// One live row with what its pc claims: the trace row, the decoded tuple
/// after `pc`, its kind bit, its immediate's low word and the operands read.
struct Decoded {
    row: trace::Row,
    seq: u32,
    imm: u32,
    kind: u32,
    rs1: u64,
    rs2: u64,
}

impl Decoded {
    /// The immediate sign-extended to 64 bits.
    fn imm64(&self) -> u64 {
        self.imm as i32 as i64 as u64
    }
    fn read(&self, role: Role) -> u64 {
        self.row.query(role).map_or(0, |q| q.read_value)
    }
    /// Panics unless the trace wrote `value` to a nonzero `rd`.
    fn check_rd(&self, value: u64) {
        if let Some(rd) = self.row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value, value,
                "cycle {}: the trace's rd write is not what the instruction computes",
                self.row.cycle
            );
        }
    }
    fn check_next(&self, next_pc: u32) {
        assert_eq!(
            self.row.next_pc, next_pc,
            "cycle {}: the trace's next_pc is not the family's",
            self.row.cycle
        );
    }
}

/// The part of every execution family's fill that is the same: the frame
/// columns but `rd_selected`'s two words, which the family writes; the decoded
/// row each cycle's pc claims, its kind bits named `kinds` and its immediate's
/// sign; the decoded table as the first setup columns and the generic table
/// after it where the circuit reads one. Returns the rows, decoded, the
/// witness to add to, and the columns so far.
#[allow(clippy::type_complexity)]
fn prelude(
    src: &ShardSource,
    fam: FamilyId,
    kinds: &[&str],
) -> Result<(Vec<Decoded>, Witness, Vec<(PolyAddress, MultilinearPoly)>), String> {
    let rows = src.cycles(fam)?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or_else(|| format!("the program has no {} table", program::family_name(fam)))?;
    let tuple = program::lookup_tuple(fam);
    let mut w = Witness::new(fam, rows.len());
    let field = |f: program::RowField| tuple.iter().position(|x| *x == f);
    let mut decoded_cols = Vec::new();
    for (j, f) in tuple.iter().enumerate().skip(1) {
        let name = match f {
            program::RowField::NextPc => "decoded_next_pc",
            program::RowField::Rs1 => "decoded_rs1",
            program::RowField::Rs2 => "decoded_rs2",
            program::RowField::Rd => "decoded_rd",
            program::RowField::Imm => "decoded_imm",
            _ => "decoded_extra_mask",
        };
        decoded_cols.push((j, w.col(name)));
    }
    let kind_cols: Vec<usize> = kinds.iter().map(|k| w.col(&format!("kind_{k}"))).collect();
    let neg_col = names(fam)
        .contains_key("imm_negative")
        .then(|| w.col("imm_negative"));
    let mut out = Vec::with_capacity(rows.len());
    for r in 0..rows.len() {
        let row = rows.row(r);
        let slot = row.pc as usize / 2;
        let get = |j: usize| {
            table.get(j, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the {} table does not hold",
                    row.cycle,
                    row.pc,
                    program::family_name(fam)
                )
            })
        };
        for (j, c) in &decoded_cols {
            w.put(*c, r, get(*j) as u64);
        }
        let mask = get(tuple.len() - 1);
        let kind = (mask & !(1 << constants::extra_mask::IMM_NEGATIVE)).trailing_zeros();
        w.put(kind_cols[kind as usize], r, 1);
        if let Some(c) = neg_col {
            w.put(c, r, (mask >> constants::extra_mask::IMM_NEGATIVE) as u64);
        }
        let imm = field(program::RowField::Imm).map_or(0, get);
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        out.push(Decoded {
            row,
            seq: get(1),
            imm,
            kind,
            rs1: read(Role::Rs1),
            rs2: read(Role::Rs2),
        });
    }
    let mut columns = frame_columns(src, fam, rows);
    let width = tuple.len();
    for j in 0..width {
        columns.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    if names(fam).contains_key("mult_generic") {
        for (k, column) in generic_table(src.height.trailing_zeros())
            .into_iter()
            .enumerate()
        {
            columns.push((PolyAddress::Setup((width + k) as u32), column));
        }
    }
    Ok((out, w, columns))
}

/// The frame columns and the frame's own witness columns of a shard of
/// `family`, without `rd_selected`'s two words: every fill writes the value the
/// instruction **computes** there, while the frame builder leaves 0 on an `x0`
/// write and the frame's x0 rule is what masks it back down.
fn frame_columns(
    src: &ShardSource,
    family: FamilyId,
    rows: &RowSlice,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let queries = frame_queries(family);
    let width = queries.len();
    let mut out = build_memory_columns(rows, queries, src.height);
    for (address, column) in build_frame_witness(rows, queries, src.height) {
        if address != rd_selected(width) && address != rd_selected_hi(width) {
            out.push((address, column));
        }
    }
    out
}

/// A word with its `<name>_h16` column, and its sign where `signed`.
fn word_cols(w: &mut Witness, name: &str, signed: bool) -> (usize, Option<usize>) {
    let h = w.col(&format!("{name}_h16"));
    let s = signed.then(|| w.col(&format!("{name}_sign")));
    (h, s)
}

fn put_word(w: &mut Witness, r: usize, cols: (usize, Option<usize>), word: u64) {
    w.put(cols.0, r, word >> 16);
    if let Some(s) = cols.1 {
        w.put(s, r, sign(word));
    }
}

/// `ADD_SUB_LUI_AUIPC`, `docs/spec/add-sub.md`: each kind's sum, difference or
/// immediate over 64 bits with its two carries, a W kind's word sign-extended,
/// and the exit row's `a0` written back. Refuses, naming the cycle, an ecall
/// no family proves: anything but `EXIT`.
fn add_sub(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constraints::add_sub::KINDS;
    let fam = family::ADD_SUB_LUI_AUIPC;
    let (rows, mut w, mut out) = prelude(src, fam, &KINDS)?;
    let [sel, sel_hi, is_exit, delegates, is_fence, c0, c1, pc_wrap] = [
        "rd_selected",
        "rd_selected_hi",
        "is_exit",
        "delegates",
        "is_fence",
        "c0",
        "c1",
        "pc_wrap",
    ]
    .map(|n| w.col(n));
    let (rd_lo, rd_hi, next) = (
        word_cols(&mut w, "rd_lo", true),
        word_cols(&mut w, "rd_hi", false),
        word_cols(&mut w, "next_pc", false),
    );
    for (r, d) in rows.iter().enumerate() {
        let (a, b, imm) = (d.rs1, d.rs2, d.imm64());
        // (result, low carry or borrow, high carry or borrow)
        let add = |x: u64, y: u64| {
            let low = lo(x) + lo(y);
            (
                x.wrapping_add(y),
                low >> 32,
                (hi(x) + hi(y) + (low >> 32)) >> 32,
            )
        };
        let sub = |x: u64, y: u64| {
            let borrow = (lo(x) < lo(y)) as u64;
            let high = hi(x) as i64 - hi(y) as i64 - borrow as i64;
            (x.wrapping_sub(y), borrow, (high < 0) as u64)
        };
        let word = |(v, c, _): (u64, u64, u64)| (sext32(v), c, 0);
        let (mut ecall_row, mut delegation_row, mut fence_row) = (0, 0, 0);
        let (value, carry, carry_hi) = match d.kind {
            kind::ADD => add(a, b),
            kind::ADDI => add(a, imm),
            kind::AUIPC => add(d.row.pc as u64, imm),
            kind::SUB => sub(a, b),
            kind::LUI => (imm, 0, 0),
            kind::ADDW => word(add(lo(a), lo(b))),
            kind::ADDIW => word(add(lo(a), lo(imm))),
            kind::SUBW => word(sub(lo(a), lo(b))),
            kind::SYSTEM => match d.imm {
                system_code::ECALL if a == ecall::EXIT as u64 => {
                    ecall_row = 1;
                    (d.read(Role::Rd), 0, 0)
                }
                // A request writes no register, its anchor in rd's place.
                system_code::ECALL
                    if u32::try_from(a)
                        .ok()
                        .and_then(program::delegation_family)
                        .is_some() =>
                {
                    delegation_row = 1;
                    (0, 0, 0)
                }
                system_code::ECALL => {
                    return Err(format!(
                        "cycle {} calls ecall {a}, which no family proves",
                        d.row.cycle
                    ))
                }
                system_code::FENCE => {
                    fence_row = 1;
                    (0, 0, 0)
                }
                other => panic!("cycle {} is a system row with code {other}", d.row.cycle),
            },
            other => panic!("cycle {} has kind bit {other}", d.row.cycle),
        };
        d.check_rd(value);
        d.check_next(match ecall_row {
            1 => memory::HALT_PC,
            _ => d.seq,
        });
        w.row(
            r,
            &[
                (sel, lo(value)),
                (sel_hi, hi(value)),
                (is_exit, ecall_row),
                (delegates, delegation_row),
                (is_fence, fence_row),
                (c0, carry),
                (c1, carry_hi),
                (pc_wrap, 0),
            ],
        );
        put_word(&mut w, r, rd_lo, lo(value));
        put_word(&mut w, r, rd_hi, hi(value));
        put_word(&mut w, r, next, d.row.next_pc as u64);
    }
    out.extend(w.finish(src.height));
    Ok(out)
}

/// The 64-bit comparison's columns, `crate::family::Family::compare64`:
/// `lhs < rhs`, signed where `signed`. Returns `(lt, gap_lo, gap_hi)`.
fn compare64(
    w: &mut Witness,
    r: usize,
    cols: &Compare,
    (lhs, rhs): (u64, u64),
    signed: bool,
) -> (u64, u64, u64) {
    let borrow = (lo(lhs) < lo(rhs)) as u64;
    let gap_lo = lo(lhs.wrapping_sub(rhs));
    let adjust = |x: u64| {
        hi(x) as i64
            - if signed {
                (sign(hi(x)) << 32) as i64
            } else {
                0
            }
    };
    let x = adjust(lhs) - adjust(rhs) - borrow as i64;
    let lt = (x < 0) as u64;
    let gap_hi = (x + ((lt as i64) << 32)) as u64;
    put_word(w, r, cols.lhs, hi(lhs));
    put_word(w, r, cols.rhs, hi(rhs));
    put_word(w, r, cols.gap_lo, gap_lo);
    put_word(w, r, cols.gap_hi, gap_hi);
    w.row(
        r,
        &[
            (cols.borrow, borrow),
            (cols.lt, lt),
            (cols.gap_lo_value, gap_lo),
            (cols.gap_hi_value, gap_hi),
        ],
    );
    (lt, gap_lo, gap_hi)
}

/// The comparison's columns, by its prefix.
struct Compare {
    lhs: (usize, Option<usize>),
    rhs: (usize, Option<usize>),
    gap_lo: (usize, Option<usize>),
    gap_hi: (usize, Option<usize>),
    borrow: usize,
    lt: usize,
    gap_lo_value: usize,
    gap_hi_value: usize,
}

impl Compare {
    fn new(w: &mut Witness, p: &str) -> Compare {
        Compare {
            lhs: word_cols(w, &format!("{p}_lhs_hi"), true),
            rhs: word_cols(w, &format!("{p}_rhs_hi"), true),
            gap_lo: word_cols(w, &format!("{p}_gap_lo"), false),
            gap_hi: word_cols(w, &format!("{p}_gap_hi"), false),
            borrow: w.col(&format!("{p}_borrow")),
            lt: w.col(&format!("{p}_lt")),
            gap_lo_value: w.col(&format!("{p}_gap_lo")),
            gap_hi_value: w.col(&format!("{p}_gap_hi")),
        }
    }
}

/// `x`'s inverse as a field element, or 0.
fn inverse(x: u64) -> Fp {
    Fp::from_u64(x).inverse().unwrap_or(Fp::ZERO)
}

/// `JUMP_BRANCH_SLT`, `docs/spec/jump-branch-slt.md`: the comparison of `rs1`
/// against `rs2` or the sign-extended immediate, equality, the branch decision,
/// and `next_pc` with its carries — a `jalr` target's high word vanishing.
fn jump_branch_slt(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constraints::jump_branch_slt::KINDS;
    let fam = family::JUMP_BRANCH_SLT;
    let (rows, mut w, mut out) = prelude(src, fam, &KINDS)?;
    // rd's high word is 0 on every row of this family: written as such.
    w.col("rd_selected_hi");
    let [sel, rhs_lo, rhs_hi, eq, taken, jalr_drop, pc_wrap, hi_wrap] = [
        "rd_selected",
        "cmp_rhs_lo",
        "cmp_rhs_hi",
        "eq",
        "taken",
        "jalr_drop",
        "pc_wrap",
        "hi_wrap",
    ]
    .map(|n| w.col(n));
    let eq_inv = w.fcol("eq_inv");
    let cmp = Compare::new(&mut w, "cmp");
    let (rd, next) = (
        word_cols(&mut w, "rd", false),
        word_cols(&mut w, "next_pc", false),
    );
    for (r, d) in rows.iter().enumerate() {
        let k = d.kind;
        let imm_cmp = matches!(k, jbs::SLTI | jbs::SLTIU);
        let rhs = if imm_cmp { d.imm64() } else { d.rs2 };
        let signed = matches!(k, jbs::SLTI | jbs::SLT | jbs::BLT | jbs::BGE);
        let (lt, gap_lo, gap_hi) = compare64(&mut w, r, &cmp, (d.rs1, rhs), signed);
        let is_eq = gap_lo + gap_hi == 0;
        let is_taken = match k {
            jbs::BEQ => is_eq,
            jbs::BNE => !is_eq,
            jbs::BLT | jbs::BLTU => lt == 1,
            jbs::BGE | jbs::BGEU => lt == 0,
            _ => false,
        };
        let pc = d.row.pc as u64;
        let (next_pc, wrap, drop, high_wrap) = match k {
            jbs::JALR => {
                let target = d.rs1.wrapping_add(d.imm64());
                let wrap = (lo(d.rs1) + d.imm as u64) >> 32;
                let high_wrap = (hi(d.rs1) + hi(d.imm64()) + wrap) >> 32;
                (lo(target) & !1, wrap, target & 1, high_wrap)
            }
            jbs::JAL => (lo(pc + d.imm as u64), (pc + d.imm as u64) >> 32, 0, 0),
            _ if is_taken => (lo(pc + d.imm as u64), (pc + d.imm as u64) >> 32, 0, 0),
            _ => (d.seq as u64, 0, 0, 0),
        };
        let value = match k {
            jbs::JAL | jbs::JALR => d.seq as u64,
            jbs::SLTI | jbs::SLTIU | jbs::SLT | jbs::SLTU => lt,
            _ => 0,
        };
        d.check_rd(value);
        d.check_next(next_pc as u32);
        w.row(
            r,
            &[
                (sel, value),
                (rhs_lo, lo(rhs)),
                (rhs_hi, hi(rhs)),
                (eq, is_eq as u64),
                (taken, is_taken as u64),
                (jalr_drop, drop),
                (pc_wrap, wrap),
                (hi_wrap, high_wrap),
            ],
        );
        w.put_fp(eq_inv, r, inverse(gap_lo + gap_hi));
        put_word(&mut w, r, rd, value);
        put_word(&mut w, r, next, next_pc);
    }
    out.extend(w.finish(src.height));
    Ok(out)
}

/// `BITWISE`, `docs/spec/bitwise.md`: `rs1`'s bytes and the second operand's,
/// their AND, and the result.
fn bitwise(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constraints::bitwise::KINDS;
    let fam = family::BITWISE;
    let (rows, mut w, mut out) = prelude(src, fam, &KINDS)?;
    let (sel, sel_hi) = (w.col("rd_selected"), w.col("rd_selected_hi"));
    let bytes: Vec<[usize; 3]> = (0..8)
        .map(|j| {
            [
                w.col(&format!("byte_a{j}")),
                w.col(&format!("byte_b{j}")),
                w.col(&format!("byte_and{j}")),
            ]
        })
        .collect();
    for (r, d) in rows.iter().enumerate() {
        let (a, b) = (d.rs1, d.rs2.wrapping_add(d.imm64()));
        let value = match d.kind {
            bw::AND | bw::ANDI => a & b,
            bw::OR | bw::ORI => a | b,
            bw::XOR | bw::XORI => a ^ b,
            other => panic!("cycle {} has kind bit {other}", d.row.cycle),
        };
        d.check_rd(value);
        d.check_next(d.seq);
        for (j, [ca, cb, cn]) in bytes.iter().enumerate() {
            let (x, y) = ((a >> (8 * j)) & 0xff, (b >> (8 * j)) & 0xff);
            w.row(r, &[(*ca, x), (*cb, y), (*cn, x & y)]);
        }
        w.row(r, &[(sel, lo(value)), (sel_hi, hi(value))]);
    }
    out.extend(w.finish(src.height));
    Ok(out)
}

/// `MUL_DIV`, `docs/spec/mul-div.md`: the operands `A` and `B` — a W form's
/// words extended, a shift's `B` the power its amount looks up — `q`, `r` and
/// the product words, the four chunk carries, the remainder's sign and bound,
/// and `rd`.
fn mul_div(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constraints::mul_div::KINDS;
    let fam = family::MUL_DIV;
    let (rows, mut w, mut out) = prelude(src, fam, &KINDS)?;
    let cols = [
        "rd_selected",
        "rd_selected_hi",
        "f_div",
        "f_shift",
        "a_hi",
        "a_sign",
        "amount_high",
        "amount_w",
        "amount",
        "pow_lo",
        "pow_hi",
        "b_lo",
        "b_hi",
        "b_sign",
        "q_lo",
        "q_hi",
        "q_sign",
        "r_lo",
        "r_hi",
        "r_sign",
        "z0",
        "z1",
        "z2",
        "z3",
        "r_is_zero",
        "dividend_signed",
        "b_is_zero",
        "bound_lo",
        "bound_hi",
        "rd_lo_h16",
        "rd_sign",
    ]
    .map(|n| w.col(n));
    let [sel, sel_hi, f_div, f_shift, a_hi, a_sign, high, amount_w, amount, pow_lo, pow_hi, b_lo, b_hi, b_sign, q_lo, q_hi, q_sign, r_lo, r_hi, r_sign, z0, z1, z2, z3, rz, d1, dz, g_lo, g_hi, rd_h16, rd_sign] =
        cols;
    let carries = ["carry0", "carry1", "carry2", "carry3", "bound_carry"].map(|n| w.fcol(n));
    let [r_inv, b_inv] = ["r_inv", "b_inv"].map(|n| w.fcol(n));
    let words = [
        ("rs1_lo", true),
        ("rs1_hi", true),
        ("amount_high", false),
        ("b_lo", true),
        ("b_hi", true),
        ("q_lo", false),
        ("q_hi", false),
        ("r_lo", false),
        ("r_hi", false),
        ("z0", false),
        ("z1", false),
        ("z2", false),
        ("z3", false),
        ("bound_lo", false),
        ("bound_hi", false),
    ]
    .map(|(n, s)| word_cols(&mut w, n, s));
    let t32 = 1i128 << 32;
    for (r, d) in rows.iter().enumerate() {
        let k = d.kind;
        let is = |set: &[u32]| set.contains(&k);
        let is_word = is(&[
            md::MULW,
            md::DIVW,
            md::DIVUW,
            md::REMW,
            md::REMUW,
            md::SLLIW,
            md::SRLIW,
            md::SRAIW,
            md::SLLW,
            md::SRLW,
            md::SRAW,
        ]);
        let shift64 = is(&[md::SLLI, md::SRLI, md::SRAI, md::SLL, md::SRL, md::SRA]);
        let shift_w = is(&[
            md::SLLIW,
            md::SRLIW,
            md::SRAIW,
            md::SLLW,
            md::SRLW,
            md::SRAW,
        ]);
        let divide = is(&[
            md::DIV,
            md::DIVU,
            md::REM,
            md::REMU,
            md::DIVW,
            md::DIVUW,
            md::REMW,
            md::REMUW,
            md::SRLI,
            md::SRAI,
            md::SRLIW,
            md::SRAIW,
            md::SRL,
            md::SRA,
            md::SRLW,
            md::SRAW,
        ]);
        // A: rs1, or a W form's low word extended.
        let (s1l, s1h) = (sign(lo(d.rs1)), sign(hi(d.rs1)));
        let signed_a_w = is(&[md::DIVW, md::REMW, md::SRAIW, md::SRAW]);
        let a_high = match (is_word, signed_a_w) {
            (false, _) => hi(d.rs1),
            (true, true) => fill(s1l),
            (true, false) => 0,
        };
        let s_a = match () {
            _ if is(&[md::MULH, md::MULHSU, md::DIV, md::REM, md::SRAI, md::SRA]) => s1h,
            _ if signed_a_w => s1l,
            _ => 0,
        };
        // The amount and the power.
        let src2 = lo(d.rs2) + d.imm as u64;
        let tw = if shift_w { (src2 >> 5) & 1 } else { 0 };
        let amt = if shift_w { src2 & 31 } else { src2 & 63 };
        let power = if shift64 || shift_w { 1u64 << amt } else { 0 };
        // B: rs2, a W form's word extended, or the power.
        let (b_l, b_h) = match () {
            _ if shift64 || shift_w => (lo(power), hi(power)),
            _ if is(&[md::DIVW, md::REMW]) => (lo(d.rs2), fill(sign(lo(d.rs2)))),
            _ if is_word => (lo(d.rs2), 0),
            _ => (lo(d.rs2), hi(d.rs2)),
        };
        let s_b = match () {
            _ if is(&[md::MULH, md::DIV, md::REM]) => sign(b_h),
            _ if is(&[md::DIVW, md::REMW]) => sign(b_l),
            _ => 0,
        };
        let big_a = (lo(d.rs1) | a_high << 32) as i128 - ((s_a as i128) << 64);
        let big_b = (b_l | b_h << 32) as i128 - ((s_b as i128) << 64);
        // q, r and Z.
        let truncated = is(&[md::DIV, md::REM, md::DIVW, md::REMW]);
        let (q_s, r_s) = match () {
            _ if !divide => (big_a, 0),
            _ if big_b == 0 => (u64::MAX as i128, big_a),
            _ if truncated => (big_a / big_b, big_a % big_b),
            _ => (big_a.div_euclid(big_b), big_a.rem_euclid(big_b)),
        };
        let (q, s_q) = (q_s as u64, (q_s < 0) as u64);
        let (rem, s_r) = (r_s as u64, (r_s < 0) as u64);
        let product = if divide {
            0
        } else {
            q_s.wrapping_mul(big_b) as u128
        };
        let z = [0, 1, 2, 3].map(|j| ((product >> (32 * j)) as u64) & 0xffff_ffff);
        // The chunk identities' carries, exactly.
        let limbs = |l: u64, h: u64| [l & 0xffff, l >> 16, h & 0xffff, h >> 16].map(|x| x as i128);
        let (ql, bl) = (limbs(lo(q), hi(q)), limbs(b_l, b_h));
        let s = |m: usize| {
            (0..4)
                .filter(|i| m >= *i && m - i < 4)
                .map(|i| ql[i] * bl[m - i])
                .sum::<i128>()
        };
        let a_fill = fill(s_a) as i128;
        let rhs = match divide {
            true => [lo(d.rs1) as i128, a_high as i128, a_fill, a_fill],
            false => z.map(|x| x as i128),
        };
        let (rf, sq, sb) = (fill(s_r) as i128, s_q as i128, s_b as i128);
        let e0 = s(0) + s(1) * 65536 + lo(rem) as i128 - rhs[0];
        let c0 = e0 >> 32;
        let e1 = s(2) + s(3) * 65536 + hi(rem) as i128 + c0 - rhs[1];
        let c1 = e1 >> 32;
        let e2 = s(4) + s(5) * 65536 + rf - sq * b_l as i128 - sb * lo(q) as i128 + c1 - rhs[2];
        let c2 = e2 >> 32;
        let e3 = s(6) + rf - sq * b_h as i128 - sb * hi(q) as i128 + c2 - rhs[3];
        let c3 = e3 >> 32;
        for (e, c) in [(e0, c0), (e1, c1), (e2, c2), (e3, c3)] {
            assert_eq!(e, c * t32, "cycle {}: a chunk does not divide", d.row.cycle);
        }
        // The remainder bound: |B_s| − |r_s| − f_div + 2^64·dz.
        let zero_divisor = divide && big_b == 0;
        let bound = big_b.abs() - r_s.abs() - divide as i128 + ((zero_divisor as i128) << 64);
        assert!(
            (0..1i128 << 64).contains(&bound),
            "cycle {}: the remainder bound is not a word pair",
            d.row.cycle
        );
        let low =
            (1 - 2 * sb) * b_l as i128 - (1 - 2 * s_r as i128) * lo(rem) as i128 - divide as i128;
        let bw_carry = (low - (bound & 0xffff_ffff)) >> 32;
        // rd.
        let (value_lo, value_hi) = match () {
            _ if is(&[md::MUL, md::SLLI, md::SLL]) => (z[0], z[1]),
            _ if is(&[md::MULH, md::MULHSU, md::MULHU]) => (z[2], z[3]),
            _ if is(&[md::DIV, md::DIVU, md::SRLI, md::SRAI, md::SRL, md::SRA]) => (lo(q), hi(q)),
            _ if is(&[md::REM, md::REMU]) => (lo(rem), hi(rem)),
            _ if is(&[md::MULW, md::SLLIW, md::SLLW]) => (z[0], fill(sign(z[0]))),
            _ if is(&[md::REMW, md::REMUW]) => (lo(rem), fill(sign(lo(rem)))),
            _ => (lo(q), fill(sign(lo(q)))),
        };
        d.check_rd(value_lo | value_hi << 32);
        d.check_next(d.seq);
        let r_zero = divide && rem == 0;
        w.row(
            r,
            &[
                (sel, value_lo),
                (sel_hi, value_hi),
                (f_div, divide as u64),
                (f_shift, (shift64 || shift_w) as u64),
                (a_hi, a_high),
                (a_sign, s_a),
                (high, src2 >> 6),
                (amount_w, tw),
                (amount, amt),
                (pow_lo, lo(power)),
                (pow_hi, hi(power)),
                (b_lo, b_l),
                (b_hi, b_h),
                (b_sign, s_b),
                (q_lo, lo(q)),
                (q_hi, hi(q)),
                (q_sign, s_q),
                (r_lo, lo(rem)),
                (r_hi, hi(rem)),
                (r_sign, s_r),
                (z0, z[0]),
                (z1, z[1]),
                (z2, z[2]),
                (z3, z[3]),
                (rz, r_zero as u64),
                (d1, truncated as u64 * s_a),
                (dz, zero_divisor as u64),
                (g_lo, (bound & 0xffff_ffff) as u64),
                (g_hi, (bound >> 32) as u64),
                (rd_h16, value_lo >> 16),
                (rd_sign, sign(value_lo)),
            ],
        );
        for (c, v) in carries.iter().zip([c0, c1, c2, c3, bw_carry]) {
            w.put_fp(*c, r, signed(v));
        }
        if divide {
            w.put_fp(r_inv, r, inverse(lo(rem) + hi(rem)));
            w.put_fp(b_inv, r, inverse(b_l + b_h));
        }
        let values = [
            lo(d.rs1),
            hi(d.rs1),
            src2 >> 6,
            b_l,
            b_h,
            lo(q),
            hi(q),
            lo(rem),
            hi(rem),
            z[0],
            z[1],
            z[2],
            z[3],
            (bound & 0xffff_ffff) as u64,
            (bound >> 32) as u64,
        ];
        for (cols, v) in words.iter().zip(values) {
            put_word(&mut w, r, *cols, v);
        }
    }
    out.extend(w.finish(src.height));
    Ok(out)
}

/// The address columns the memory families share, `constraints::mem_word::
/// address`: `rs1 + imm` as `2^32·wrap + 8·dw + 4·bit2 + low`, and the high
/// word's carry. Returns the address, which is below `2^32`.
fn address(
    w: &mut Witness,
    r: usize,
    cols: &[usize; 4],
    d: &Decoded,
    dw_cols: (usize, Option<usize>),
) -> u64 {
    let addr = d.rs1.wrapping_add(d.imm64());
    assert!(
        hi(addr) == 0,
        "cycle {}: an address at or above 2^32, which the emulator refuses",
        d.row.cycle
    );
    let wrap = (lo(d.rs1) + d.imm as u64) >> 32;
    let hi_wrap = (hi(d.rs1) + hi(d.imm64()) + wrap) >> 32;
    let [c_wrap, c_hi_wrap, c_dw, c_bit2] = *cols;
    w.row(
        r,
        &[
            (c_wrap, wrap),
            (c_hi_wrap, hi_wrap),
            (c_dw, addr >> 3),
            (c_bit2, (addr >> 2) & 1),
        ],
    );
    put_word(w, r, dw_cols, addr >> 3);
    addr
}

fn address_cols(w: &mut Witness) -> ([usize; 4], (usize, Option<usize>)) {
    let cols = ["wrap", "hi_wrap", "dword_index", "bit2"].map(|n| w.col(n));
    (cols, word_cols(w, "dword_index", false))
}

/// `MEM_WORD`, `docs/spec/memory-ops.md` §3: the address split, and `rd`'s two
/// words — the word, sign- or zero-extended, or the doubleword.
fn mem_word(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constraints::mem_word::KINDS;
    let fam = family::MEM_WORD;
    let (rows, mut w, mut out) = prelude(src, fam, &KINDS)?;
    let (sel, sel_hi) = (w.col("rd_selected"), w.col("rd_selected_hi"));
    let (addr_cols, dw) = address_cols(&mut w);
    let (rd_lo, rd_hi) = (
        word_cols(&mut w, "rd_lo", true),
        word_cols(&mut w, "rd_hi", false),
    );
    for (r, d) in rows.iter().enumerate() {
        let addr = address(&mut w, r, &addr_cols, d, dw);
        let (word, high) = (d.read(Role::Load), d.read(Role::Ram));
        let value = match d.kind {
            kind_mem::LW => sext32(word),
            kind_mem::LWU => word,
            kind_mem::LD => word | high << 32,
            _ => 0,
        };
        if let Some(q) = d.row.query(Role::Load) {
            assert_eq!(q.addr as u64, addr, "cycle {}: the load word", d.row.cycle);
        }
        d.check_rd(value);
        d.check_next(d.seq);
        w.row(r, &[(sel, lo(value)), (sel_hi, hi(value))]);
        put_word(&mut w, r, rd_lo, lo(value));
        put_word(&mut w, r, rd_hi, hi(value));
    }
    out.extend(w.finish(src.height));
    Ok(out)
}

/// `MEM_SUBWORD`, `docs/spec/memory-ops.md` §4: the address split and offset
/// bits, the splice of the word into `high`, `sub` and `low` with their scaled
/// bounds, the stored source, the sign, and `rd`.
fn mem_subword(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constraints::mem_subword::KINDS;
    let fam = family::MEM_SUBWORD;
    let (rows, mut w, mut out) = prelude(src, fam, &KINDS)?;
    let (addr_cols, dw) = address_cols(&mut w);
    let cols = [
        "rd_selected",
        "rd_selected_hi",
        "bit0",
        "bit1",
        "p",
        "pcopow",
        "wph",
        "p_ram",
        "word",
        "high",
        "high_scaled",
        "sub",
        "sub_scaled",
        "low",
        "low_scaled",
        "src_sub",
        "src_sub_scaled",
        "src_high",
        "sign_in",
        "sign",
        "se",
    ]
    .map(|n| w.col(n));
    let ranged = [
        "high",
        "high_scaled",
        "sub_scaled",
        "low",
        "low_scaled",
        "src_sub_scaled",
        "src_high",
        "rd",
    ]
    .map(|n| word_cols(&mut w, n, false));
    for (r, d) in rows.iter().enumerate() {
        let addr = address(&mut w, r, &addr_cols, d, dw);
        let is_byte = matches!(d.kind, kind_sub::LB | kind_sub::LBU | kind_sub::SB);
        let is_load = matches!(
            d.kind,
            kind_sub::LB | kind_sub::LH | kind_sub::LBU | kind_sub::LHU
        );
        let sign_extends = matches!(d.kind, kind_sub::LB | kind_sub::LH);
        let (bit0, bit1) = (addr & 1, (addr >> 1) & 1);
        let p = 1u64 << (8 * (addr & 3));
        let wd = if is_byte { 1u64 << 8 } else { 1u64 << 16 };
        let word = if is_load {
            d.read(Role::Load)
        } else {
            d.read(Role::Ram)
        };
        let (low, sub, high) = (word % p, (word / p) % wd, word / (wd * p));
        let (src_sub, src_high) = (lo(d.rs2) % wd, lo(d.rs2) / wd);
        let sign_in = sub * if is_byte { 1 << 8 } else { 1 };
        let s = sign_in >> 15;
        let se = (sign_extends && s == 1) as u64;
        let value = match is_load {
            true => (sub + se * ((1u64 << 32) - wd)) | fill(se) << 32,
            false => 0,
        };
        if let Some(ram) = d.row.query(Role::Ram) {
            assert_eq!(
                ram.write_value,
                high * wd * p + src_sub * p + low,
                "cycle {}: the trace's stored word is not the spliced one",
                d.row.cycle
            );
        }
        d.check_rd(value);
        d.check_next(d.seq);
        let scale = |x: u64, by: u64| x * ((1u64 << 32) / by);
        let values = [
            lo(value),
            hi(value),
            bit0,
            bit1,
            p,
            (1u64 << 31) / p,
            wd * p / 2,
            if is_load { 0 } else { p },
            word,
            high,
            high * wd * p,
            sub,
            scale(sub, wd),
            low,
            scale(low, p),
            src_sub,
            scale(src_sub, wd),
            src_high,
            sign_in,
            s,
            se,
        ];
        for (c, v) in cols.iter().zip(values) {
            w.put(*c, r, v);
        }
        let ranged_values = [
            high,
            high * wd * p,
            scale(sub, wd),
            low,
            scale(low, p),
            scale(src_sub, wd),
            src_high,
            lo(value),
        ];
        for (c, v) in ranged.iter().zip(ranged_values) {
            put_word(&mut w, r, *c, v);
        }
    }
    out.extend(w.finish(src.height));
    Ok(out)
}

/// `ATOMICS`, `docs/spec/memory-ops.md` §6: the address, the old value and the
/// source as 64-bit values — a `.w` form's extended — their comparison, sum,
/// bytes and AND, and `rd`.
fn atomics(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    use constraints::atomics::KINDS;
    let fam = family::ATOMICS;
    let (rows, mut w, mut out) = prelude(src, fam, &KINDS)?;
    let cols = [
        "rd_selected",
        "rd_selected_hi",
        "dword_index",
        "bit2",
        "lhs_hi",
        "rhs_hi",
        "min_lo",
        "min_hi",
        "sum_lo",
        "sum_hi",
        "add_carry_lo",
        "add_carry_hi",
        "f_bitwise",
    ]
    .map(|n| w.col(n));
    let [sel, sel_hi, c_dw, c_bit2, c_lhs, c_rhs, c_min_lo, c_min_hi, c_sum_lo, c_sum_hi, c_c0, c_c1, c_fb] =
        cols;
    let ranged = ["dword_index", "sum_lo", "sum_hi"].map(|n| word_cols(&mut w, n, false));
    let signed_words = ["old_lo", "src_lo"].map(|n| word_cols(&mut w, n, true));
    let cmp = Compare::new(&mut w, "cmp");
    let bytes: Vec<[usize; 3]> = (0..8)
        .map(|j| {
            [
                w.col(&format!("byte_a{j}")),
                w.col(&format!("byte_b{j}")),
                w.col(&format!("byte_and{j}")),
            ]
        })
        .collect();
    for (r, d) in rows.iter().enumerate() {
        let double = d.kind >= at::DOUBLE;
        let op = d.kind % at::DOUBLE;
        let addr = d.rs1;
        let (old_lo, old_hi) = (d.read(Role::Ram), d.read(Role::Load));
        let src_lo = lo(d.rs2);
        let minmax_w = !double && matches!(op, at::AMOMIN_W | at::AMOMAX_W);
        let lhs_hi = if double {
            old_hi
        } else {
            fill(sign(old_lo) * minmax_w as u64)
        };
        let rhs_hi = if double {
            hi(d.rs2)
        } else {
            fill(sign(src_lo) * minmax_w as u64)
        };
        let (lhs, rhs) = (old_lo | lhs_hi << 32, src_lo | rhs_hi << 32);
        let signed = matches!(op, at::AMOMIN_W | at::AMOMAX_W);
        let (lt, _, _) = compare64(&mut w, r, &cmp, (lhs, rhs), signed);
        let min = if lt == 1 { lhs } else { rhs };
        let sum_lo = old_lo + src_lo;
        let sum_hi = old_hi + rhs_hi + (sum_lo >> 32);
        let and = lhs & rhs;
        let new = match op {
            at::LR_W => lhs,
            at::SC_W | at::AMOSWAP_W => rhs,
            at::AMOADD_W => lo(sum_lo) | lo(sum_hi) << 32,
            at::AMOAND_W => and,
            at::AMOOR_W => lhs | rhs,
            at::AMOXOR_W => lhs ^ rhs,
            at::AMOMIN_W | at::AMOMINU_W => min,
            _ => lhs.wrapping_add(rhs).wrapping_sub(min),
        };
        if let Some(q) = d.row.query(Role::Ram) {
            assert_eq!(
                q.write_value,
                lo(new),
                "cycle {}: the word written",
                d.row.cycle
            );
        }
        if double {
            let q = d.row.query(Role::Load).expect("a .d form's high word");
            assert_eq!(
                q.write_value,
                hi(new),
                "cycle {}: the high word",
                d.row.cycle
            );
        }
        let value = match (op, double) {
            (at::SC_W, _) => 0,
            (_, true) => old_lo | old_hi << 32,
            (_, false) => sext32(old_lo),
        };
        d.check_rd(value);
        d.check_next(d.seq);
        let bitwise = matches!(op, at::AMOAND_W | at::AMOOR_W | at::AMOXOR_W);
        w.row(
            r,
            &[
                (sel, lo(value)),
                (sel_hi, hi(value)),
                (c_dw, addr >> 3),
                (c_bit2, (addr >> 2) & 1),
                (c_lhs, lhs_hi),
                (c_rhs, rhs_hi),
                (c_min_lo, lo(min)),
                (c_min_hi, hi(min)),
                (c_sum_lo, lo(sum_lo)),
                (c_sum_hi, lo(sum_hi)),
                (c_c0, sum_lo >> 32),
                (c_c1, sum_hi >> 32),
                (c_fb, bitwise as u64),
            ],
        );
        for (c, v) in ranged.iter().zip([addr >> 3, lo(sum_lo), lo(sum_hi)]) {
            put_word(&mut w, r, *c, v);
        }
        for (c, v) in signed_words.iter().zip([old_lo, src_lo]) {
            put_word(&mut w, r, *c, v);
        }
        // old's bytes are its two words as read — 0 above a `.w` form's word —
        // and src's are the comparison's operand.
        let old = old_lo | old_hi << 32;
        for (j, [ca, cb, cn]) in bytes.iter().enumerate() {
            let (x, y) = ((old >> (8 * j)) & 0xff, (rhs >> (8 * j)) & 0xff);
            w.row(r, &[(*ca, x), (*cb, y), (*cn, x & y)]);
        }
    }
    out.extend(w.finish(src.height));
    Ok(out)
}
