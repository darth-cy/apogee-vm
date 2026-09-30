//! The family fills: how each family's trace buffer becomes its circuit's
//! committed columns. `docs/spec/shard-proof.md` §8.1 and §11.
//!
//! A fill returns every `M`, `W` and `S` column but the multiplicities, which
//! the common path counts over the family's channels.

use constants::ec_add as ea;
use constants::extra_mask::add_sub_lui_auipc as kind;
use constants::extra_mask::atomics as at;
use constants::extra_mask::jump_branch_slt as jbs;
use constants::extra_mask::mem_subword as kind_sub;
use constants::extra_mask::mem_word as kind_mem;
use constants::extra_mask::mul_div as md;
use constants::extra_mask::shift_bitwise as sb;
use constants::extra_mask::system_code;
use constants::fr_arith as fa;
use constants::mod_mul as mm;
use constants::poseidon2 as p2;
use constants::sha256 as sh;
use constants::{delegation, ecall, family, guest_memory, keccak, memory};
use constraints::add_sub::{
    DECODED, IS_ECALL, IS_FENCE, KINDS, NEXT_PC_HI, PC_WRAP, RD_HI, TABLE_WIDTH, WRAP,
};
use constraints::atomics as at_circuit;
use constraints::delegation as deleg;
use constraints::ec_add as ea_circuit;
use constraints::fr_arith as fa_circuit;
use constraints::jump_branch_slt as jbs_circuit;
use constraints::keccak as kec_circuit;
use constraints::mem_subword as ms_circuit;
use constraints::mem_word as mw_circuit;
use constraints::memory::{frame_queries, rd_selected};
use constraints::mod_mul as mm_circuit;
use constraints::mul_div as md_circuit;
use constraints::poseidon2 as p2_circuit;
use constraints::sha256 as sh_circuit;
use constraints::shift_bitwise as sb_circuit;
use constraints::PolyAddress;
use field::Fr;
use poly::{MultilinearPoly, PolyBacking};
use program::lookup_tables::generic_table;
use program::FamilyId;
use trace::{
    build_frame_witness, build_init_teardown_columns, build_memory_columns,
    build_value_window_columns, FrameSlice, MemoryState, Role, RowSlice, TraceArchive,
};

#[cfg(feature = "debug-info")]
use crate::debug;
use crate::Program;

/// What a fill reads: the program, the execution's two unbound inputs, **this
/// shard's rows**, and which shard — its index, its height, and for a window
/// family its window.
///
/// The rows are already cut to the shard (`docs/spec/block-proof.md` §5.1), so a
/// fill indexes `0..rows.len()` and never the whole execution. That is what lets
/// one fill serve a slice of an archived execution and a streaming executor's
/// freshly filled chunk alike (`docs/spec/streaming.md` §2).
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

/// The rows a shard proves, by the kind of family it belongs to — the three
/// kinds `docs/spec/delegation.md` §1 and `docs/spec/memory.md` §3 name.
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
    /// of the archive by `docs/spec/block-proof.md` §5.1's rule.
    ///
    /// Which arm of [`ShardRows`] a family takes is the three presence rules of
    /// `docs/spec/delegation.md` §1: a delegation family is invoked, a family
    /// that claims pcs owns cycles, and everything else is a window family
    /// whose rows are addresses. A streaming prover builds the same struct from
    /// a chunk it has just filled, which is the whole of what the two paths do
    /// differently (`docs/spec/streaming.md` §2).
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
        } else if program::claims_pcs(family) {
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

    /// This shard's invocations, or why it has none of `family`'s.
    fn invocations(&self, family: FamilyId) -> Result<&FrameSlice<'a>, String> {
        match &self.rows {
            ShardRows::Invocations(rows) if rows.family() == family => Ok(rows),
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

/// The fill of `family`, or `None` for a family no circuit proves yet — the
/// registry beside `constraints::family_circuit`.
pub fn family_fill(family: FamilyId) -> Option<Fill> {
    match family {
        family::ADD_SUB_LUI_AUIPC => Some(add_sub),
        family::JUMP_BRANCH_SLT => Some(jump_branch_slt),
        family::SHIFT_BITWISE => Some(shift_bitwise),
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
        family::KECCAK_F => Some(keccak_f),
        family::POSEIDON2 => Some(poseidon2),
        family::FR_ARITH => Some(fr_arith),
        family::MOD_MUL => Some(mod_mul),
        family::SHA256_COMP => Some(sha256_comp),
        family::EC_ADD => Some(ec_add),
        _ => None,
    }
}

/// A delegation shard's rows: the invocations this shard holds, and the height
/// to pad to.
struct Invocations<'a> {
    frames: &'a FrameSlice<'a>,
    height: usize,
}

/// The invocations a delegation shard proves.
fn invocations<'a>(src: &'a ShardSource<'a>, family: FamilyId) -> Result<Invocations<'a>, String> {
    Ok(Invocations {
        frames: src.invocations(family)?,
        height: src.height,
    })
}

/// Every column the delegation frame itself owns, for a frame of `words`
/// words: `docs/spec/delegation.md` §4 and §6.1 — the four head columns, four
/// per frame word, 38 gap bits a word, and the frame pointer's two
/// decompositions.
///
/// The words come from the buffer, which the tracer filled from the log, so
/// this does **not** rerun the delegated function: what it writes is what the
/// execution did, and the circuit is what says that was the function. Padding
/// rows are zero in every column, which is the artifact's padding row.
///
/// Every family that takes this puts the frame's own witness columns first, at
/// `W[0]`, which is where `constraints::delegation::gap_bit` and its two base
/// decompositions are. S21's `keccak` was the one exception — its 1,600 state
/// bits came first and its frame's bits began at `W[1600]`, so this function
/// carried a `witness_base` offset for it alone — and S26d's re-shaping moved
/// that family to `delegation_frame_range16`, so the offset is gone.
fn delegation_frame(
    inv: &Invocations,
    words: usize,
    frame_bytes: u64,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let (frames, h) = (inv.frames, inv.height);
    let rows = 0..frames.len();
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    let cycles: Vec<Fr> = frames.cycles().iter().map(|c| Fr::from_u64(*c)).collect();
    out.push((deleg::CYCLE, fr_column(cycles, h)));
    out.push((
        deleg::LIVE,
        u32_column(rows.clone().map(|_| 1).collect(), h),
    ));
    out.push((deleg::BASE, u32_column(frames.bases().to_vec(), h)));
    // The value the request wrote back on its mirror query. Free on both
    // sides, and 0 on both in an honest fill (`docs/spec/delegation.md` §5.2).
    out.push((deleg::ANCHOR_VALUE, u32_column(Vec::new(), h)));

    for j in 0..words {
        let w = frames.word(j);
        for (field, values) in [
            (
                deleg::WORD_ADDR,
                rows.clone().map(|r| w.addr[r]).collect::<Vec<u32>>(),
            ),
            (
                deleg::WORD_READ_VALUE,
                rows.clone().map(|r| w.read_value[r]).collect(),
            ),
            (
                deleg::WORD_WRITE_VALUE,
                rows.clone().map(|r| w.write_value[r]).collect(),
            ),
        ] {
            out.push((deleg::word(j, field), u32_column(values, h)));
        }
        let read_ts: Vec<Fr> = rows.clone().map(|r| Fr::from_u64(w.read_ts[r])).collect();
        out.push((deleg::word(j, deleg::WORD_READ_TS), fr_column(read_ts, h)));
        // `gap = 4·cycle + Δ − read_ts − 1`, as 38 bits.
        for bit in 0..memory::TS_BITS as usize {
            let values: Vec<u32> = rows
                .clone()
                .map(|r| {
                    let ts = memory::TS_STEP * frames.cycles()[r] + delegation::FRAME_DELTA;
                    let gap = ts - w.read_ts[r] - 1;
                    ((gap >> bit) & 1) as u32
                })
                .collect();
            out.push((deleg::gap_bit(j, bit), u32_column(values, h)));
        }
    }
    for bit in 0..deleg::BASE_LOW_BITS {
        let values: Vec<u32> = rows
            .clone()
            .map(|r| (((frames.bases()[r] - guest_memory::RAM_ORIGIN) / 4) >> bit) & 1)
            .collect();
        out.push((deleg::base_low_bit(words, bit), u32_column(values, h)));
    }
    for bit in 0..deleg::BASE_ROOM_BITS {
        let values: Vec<u32> = rows
            .clone()
            .map(|r| {
                let room = (1u64 << 31) - frame_bytes - frames.bases()[r] as u64;
                ((room >> bit) & 1) as u32
            })
            .collect();
        out.push((deleg::base_room_bit(words, bit), u32_column(values, h)));
    }
    out
}

/// A frame value's eight words on row `r`, from the field its circuit reads.
fn value_words(frames: &FrameSlice, first: usize, field: u32, r: usize) -> [u32; 8] {
    core::array::from_fn(|k| {
        let w = frames.word(first + k);
        match field {
            deleg::WORD_READ_VALUE => w.read_value[r],
            _ => w.write_value[r],
        }
    })
}

/// The borrow chain of `X − p` over eight 32-bit limbs: the difference limbs
/// and the borrows, the last of which is 1 exactly when `X` is below `p`.
///
/// The honest witness of the canonicity gates of `docs/spec/delegation.md`
/// §11.3. It is computed here rather than read from anywhere, because it is a
/// function of the words the execution wrote.
fn borrow_chain(words: &[u32; 8]) -> ([u64; 8], [u64; 8]) {
    let mut p = [0u64; 8];
    for (i, limb) in constants::FR_MODULUS.iter().enumerate() {
        p[2 * i] = limb & 0xffff_ffff;
        p[2 * i + 1] = limb >> 32;
    }
    let (mut diff, mut borrow) = ([0u64; 8], [0u64; 8]);
    let mut carry = 0i64;
    for i in 0..8 {
        let d = words[i] as i64 - p[i] as i64 - carry;
        carry = i64::from(d < 0);
        diff[i] = if d < 0 {
            (d + (1i64 << 32)) as u64
        } else {
            d as u64
        };
        borrow[i] = carry as u64;
    }
    (diff, borrow)
}

/// One frame value's 256 word bits and 264 canonicity bits.
fn value_columns(
    inv: &Invocations,
    first: usize,
    field: u32,
    bits: &dyn Fn(usize, usize) -> PolyAddress,
    diffs: &dyn Fn(usize, usize) -> PolyAddress,
    borrows: &dyn Fn(usize) -> PolyAddress,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let (frames, h) = (inv.frames, inv.height);
    let rows = 0..frames.len();
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    for k in 0..8 {
        for t in 0..32 {
            let values: Vec<u32> = rows
                .clone()
                .map(|r| (value_words(frames, first, field, r)[k] >> t) & 1)
                .collect();
            out.push((bits(k, t), u32_column(values, h)));
        }
    }
    for k in 0..8 {
        for t in 0..32 {
            let values: Vec<u32> = rows
                .clone()
                .map(|r| {
                    ((borrow_chain(&value_words(frames, first, field, r)).0[k] >> t) & 1) as u32
                })
                .collect();
            out.push((diffs(k, t), u32_column(values, h)));
        }
    }
    for k in 0..8 {
        let values: Vec<u32> = rows
            .clone()
            .map(|r| borrow_chain(&value_words(frames, first, field, r)).1[k] as u32)
            .collect();
        out.push((borrows(k), u32_column(values, h)));
    }
    out
}

// ---------------------------------------------------------------------------
// The `debug-info` scans over a delegation frame
// ---------------------------------------------------------------------------

/// Every delegation family's shared frame facts, as log lines.
///
/// Called at the top of each of the six fills, so a run says what the shard
/// actually holds before any family-specific gate can fail: the invocation
/// count against the height, the cycle and base ranges, and the timestamp gap
/// against the 38-bit clock (`debug::frame_scan` is what each means).
#[cfg(feature = "debug-info")]
fn deleg_frame_log(family: FamilyId, index: u32, inv: &Invocations) {
    if !debug::enabled_for(debug::Level::Detail, family) {
        return;
    }
    let who = debug::shard(family, index);
    for text in debug::frame_scan(inv.frames, inv.height) {
        debug::line(&format!("apogee deleg    {who:<22} {text}"));
    }
}

/// A canonicity **tally** over frame values checked against `Fr`'s modulus:
/// for each named value, how many live rows carry a last borrow of 1.
///
/// A tally and not a verdict, deliberately. A value's `< p` conclusion is gated
/// to the rows that read it, so a row whose operation does not read a value may
/// legitimately carry a value at or above `p`; calling that a failure would
/// report the honest prover as broken. What the tally gives instead is
/// unambiguous either way — `out: 0/256 below p` on a family whose every row
/// writes `out` is a bug you can see, and `b: 137/256` on a family with three
/// operations is the operation mix.
#[cfg(feature = "debug-info")]
fn canon_tally_log(family: FamilyId, index: u32, inv: &Invocations, values: &[(&str, usize, u32)]) {
    if !debug::enabled_for(debug::Level::Detail, family) {
        return;
    }
    let (frames, live) = (inv.frames, inv.frames.len());
    if live == 0 {
        return;
    }
    let names: Vec<&str> = values.iter().map(|(n, ..)| *n).collect();
    let below: Vec<usize> = values
        .iter()
        .map(|(_, first, field)| {
            (0..live)
                .filter(|r| {
                    let words = value_words(frames, *first, *field, *r);
                    borrow_chain(&words).1[7] == 1
                })
                .count()
        })
        .collect();
    let who = debug::shard(family, index);
    debug::line(&format!(
        "apogee deleg    {who:<22} {} of {live} live rows",
        debug::histogram("below-p", &names, &below)
    ));
}

/// One `KECCAK_F` row's intermediates, as 64-bit lanes.
///
/// Every field is a stage of `emulator::keccak_round` over the frame's read
/// values, and the circuit's byte columns are this struct's bytes: byte `b` of
/// lane `i` is `(lane >> (8·b)) as u8`. Recomputing the round here is not
/// re-deciding what the row says — the frame words come from the buffer, which
/// the tracer filled from the log — it is producing the intermediates the
/// circuit's obligations read, which no log event carries.
struct KeccakRow {
    round: usize,
    state_in: [u64; keccak::LANES],
    /// `parity[x][s]`: `s + 2` lanes of column `x` folded, so `parity[x][3]` is
    /// `C[x]`.
    parity: [[u64; 4]; 5],
    c_mask: [u64; 5],
    theta_d: [u64; 5],
    theta_a: [u64; keccak::LANES],
    rho_mask: [u64; keccak::LANES],
    rho_out: [u64; keccak::LANES],
    chi_and: [u64; keccak::LANES],
    chi_out: [u64; keccak::LANES],
}

/// Each byte of a `u64` masked to its top `s` bits, which is what one `XOR8`
/// obligation against the literal mask gives the circuit.
fn keccak_byte_mask(s: u32) -> u64 {
    let byte = (256u64 - (1u64 << (8 - s))) as u8;
    u64::from_le_bytes([byte; 8])
}

fn keccak_row(frames: &FrameSlice, r: usize) -> Result<KeccakRow, String> {
    let round = frames.word(keccak::ROUND_WORD).read_value[r] as usize;
    if round >= keccak::ROUNDS {
        return Err(format!(
            "keccak fill: invocation {r} claims round {round}, and a keccak-f round is below {}",
            keccak::ROUNDS
        ));
    }
    let words: [u32; keccak::STATE_WORDS] =
        core::array::from_fn(|j| frames.word(keccak::STATE_WORD + j).read_value[r]);
    let state_in = emulator::lanes_of(&words);

    let mut parity = [[0u64; 4]; 5];
    for (x, chain) in parity.iter_mut().enumerate() {
        let mut acc = state_in[x];
        for (s, slot) in chain.iter_mut().enumerate() {
            acc ^= state_in[x + 5 * (s + 1)];
            *slot = acc;
        }
    }
    let c: [u64; 5] = core::array::from_fn(|x| parity[x][3]);
    let c_mask: [u64; 5] = core::array::from_fn(|x| c[x] ^ keccak_byte_mask(1));
    let theta_d: [u64; 5] =
        core::array::from_fn(|x| c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1));
    let theta_a: [u64; keccak::LANES] = core::array::from_fn(|i| state_in[i] ^ theta_d[i % 5]);
    let rho_mask: [u64; keccak::LANES] = core::array::from_fn(|i| {
        let s = keccak::ROTATIONS[i / 5][i % 5] % 8;
        match s {
            0 => 0,
            _ => theta_a[i] ^ keccak_byte_mask(s),
        }
    });
    let mut rho_out = [0u64; keccak::LANES];
    for x in 0..5 {
        for y in 0..5 {
            rho_out[y + 5 * ((2 * x + 3 * y) % 5)] =
                theta_a[x + 5 * y].rotate_left(keccak::ROTATIONS[y][x]);
        }
    }
    let chi_and: [u64; keccak::LANES] = core::array::from_fn(|i| {
        let (x, y) = (i % 5, i / 5);
        rho_out[(x + 1) % 5 + 5 * y] ^ rho_out[(x + 2) % 5 + 5 * y]
    });
    let chi_out: [u64; keccak::LANES] = core::array::from_fn(|i| {
        let (x, y) = (i % 5, i / 5);
        rho_out[i] ^ (!rho_out[(x + 1) % 5 + 5 * y] & rho_out[(x + 2) % 5 + 5 * y])
    });
    Ok(KeccakRow {
        round,
        state_in,
        parity,
        c_mask,
        theta_d,
        theta_a,
        rho_mask,
        rho_out,
        chi_and,
        chi_out,
    })
}

/// The round histogram: how many of this shard's invocations claim each round.
///
/// **What it is for is that the 24 counts should be equal.** A permutation is 24
/// consecutive invocations and a shard holds whole permutations up to its cut, so
/// a shard whose rounds are not near-uniform has a guest that is not looping 24
/// times — which is the one failure `docs/spec/delegation.md` §6.4's glue cannot
/// see, the circuit proving each row honestly whatever the sequence. It is the
/// analogue of `MOD_MUL`'s modulus histogram and `EC_ADD`'s curve/group one
/// (`docs/spec/debug-info.md` §5).
///
/// A tally and not a verdict: a shard cut mid-permutation leaves the low rounds
/// one ahead of the high ones, which is legitimate and expected.
#[cfg(feature = "debug-info")]
fn keccak_round_log(index: u32, witness: &[KeccakRow]) {
    if !debug::enabled_for(debug::Level::Detail, family::KECCAK_F) {
        return;
    }
    let live = witness.len();
    if live == 0 {
        return;
    }
    let mut tally = vec![0usize; keccak::ROUNDS];
    for w in witness {
        tally[w.round] += 1;
    }
    let labels: Vec<String> = (0..keccak::ROUNDS).map(|r| r.to_string()).collect();
    let names: Vec<&str> = labels.iter().map(String::as_str).collect();
    let who = debug::shard(family::KECCAK_F, index);
    debug::line(&format!(
        "apogee deleg    {who:<22} {} of {live} live rows",
        debug::histogram("round", &names, &tally)
    ));
    let (lo, hi) = (
        tally.iter().min().copied().unwrap_or(0),
        tally.iter().max().copied().unwrap_or(0),
    );
    if hi > lo + 1 {
        debug::line(&format!(
            "apogee deleg    {who:<22} round counts spread {lo}..{hi} -- a permutation is 24 \
             consecutive rounds, so a spread above 1 is a guest that is NOT LOOPING 24 TIMES"
        ));
    }
}

/// A `KECCAK_F` shard, `docs/spec/delegation.md` §6.1: the delegation frame over
/// `RANGE16`, the 24 round selectors, the round constant's four bytes, and the
/// round's nine byte-wide stages.
///
/// Every column here is a **byte**. There is no bit in this fill, which is the
/// whole of S26d's re-shaping seen from the prover's side: S21's wrote 1,600
/// boolean columns and 1,900 gap bits, this one writes 1,556 bytes and chunks.
fn keccak_f(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let inv = invocations(src, family::KECCAK_F)?;
    debug_only!(deleg_frame_log(family::KECCAK_F, src.index, &inv));
    let mut out = delegation_frame_range16(
        &inv,
        keccak::FRAME_WORDS,
        keccak::FRAME_BYTES as u64,
        kec_circuit::gap_chunk,
        [
            kec_circuit::base_low(),
            kec_circuit::base_low_hi(),
            kec_circuit::base_room(),
            kec_circuit::base_room_hi(),
        ],
    );
    let (frames, h) = (inv.frames, inv.height);
    let rows = 0..frames.len();
    let witness: Vec<KeccakRow> = rows
        .clone()
        .map(|r| keccak_row(frames, r))
        .collect::<Result<Vec<_>, String>>()?;
    debug_only!(keccak_round_log(src.index, &witness));

    // The round selector, one-hot, and the round constant it names.
    for round in 0..keccak::ROUNDS {
        let values: Vec<u32> = witness
            .iter()
            .map(|w| u32::from(w.round == round))
            .collect();
        out.push((kec_circuit::round_sel(round), u32_column(values, h)));
    }
    for (t, b) in keccak::IOTA_BYTES.iter().enumerate() {
        let values: Vec<u32> = witness
            .iter()
            .map(|w| ((keccak::ROUND_CONSTANTS[w.round] >> (8 * b)) & 0xff) as u32)
            .collect();
        out.push((kec_circuit::rc(t), u32_column(values, h)));
    }

    // The round's stages, byte by byte, in the circuit's layout order.
    let byte = |lane: u64, b: usize| ((lane >> (8 * b)) & 0xff) as u32;
    let push_state = |out: &mut Vec<(PolyAddress, MultilinearPoly)>,
                      address: &dyn Fn(usize, usize) -> PolyAddress,
                      lane: &dyn Fn(&KeccakRow) -> [u64; keccak::LANES]| {
        for i in 0..keccak::LANES {
            for b in 0..8 {
                let values: Vec<u32> = witness.iter().map(|w| byte(lane(w)[i], b)).collect();
                out.push((address(i, b), u32_column(values, h)));
            }
        }
    };
    push_state(&mut out, &kec_circuit::state_in, &|w| w.state_in);
    for x in 0..5 {
        for b in 0..8 {
            for s in 0..4 {
                let values: Vec<u32> = witness.iter().map(|w| byte(w.parity[x][s], b)).collect();
                out.push((kec_circuit::parity(x, b, s), u32_column(values, h)));
            }
        }
    }
    for x in 0..5 {
        for b in 0..8 {
            let values: Vec<u32> = witness.iter().map(|w| byte(w.c_mask[x], b)).collect();
            out.push((kec_circuit::c_mask(x, b), u32_column(values, h)));
        }
    }
    for x in 0..5 {
        for b in 0..8 {
            let values: Vec<u32> = witness.iter().map(|w| byte(w.theta_d[x], b)).collect();
            out.push((kec_circuit::theta_d(x, b), u32_column(values, h)));
        }
    }
    push_state(&mut out, &kec_circuit::theta_a, &|w| w.theta_a);
    for i in 0..keccak::LANES {
        if keccak::ROTATIONS[i / 5][i % 5].is_multiple_of(8) {
            continue;
        }
        for b in 0..8 {
            let values: Vec<u32> = witness.iter().map(|w| byte(w.rho_mask[i], b)).collect();
            out.push((kec_circuit::rho_mask(i, b), u32_column(values, h)));
        }
    }
    push_state(&mut out, &kec_circuit::rho_out, &|w| w.rho_out);
    push_state(&mut out, &kec_circuit::chi_and, &|w| w.chi_and);
    push_state(&mut out, &kec_circuit::chi_out, &|w| w.chi_out);
    for (t, b) in keccak::IOTA_BYTES.iter().enumerate() {
        let values: Vec<u32> = witness
            .iter()
            .map(|w| {
                byte(w.chi_out[0], *b)
                    ^ ((keccak::ROUND_CONSTANTS[w.round] >> (8 * b)) & 0xff) as u32
            })
            .collect();
        out.push((kec_circuit::iota_out(t), u32_column(values, h)));
    }
    Ok(out)
}

/// A `POSEIDON2` shard, `docs/spec/delegation.md` §12.1: the delegation frame,
/// plus the six lane values' word and canonicity bits — three read, three
/// written.
fn poseidon2(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let inv = invocations(src, family::POSEIDON2)?;
    debug_only!(deleg_frame_log(family::POSEIDON2, src.index, &inv));
    let mut out = delegation_frame(&inv, p2::FRAME_WORDS, p2::FRAME_BYTES as u64);
    for v in 0..2 * p2::WIDTH {
        let lane = v % p2::WIDTH;
        let field = if v < p2::WIDTH {
            deleg::WORD_READ_VALUE
        } else {
            deleg::WORD_WRITE_VALUE
        };
        out.extend(value_columns(
            &inv,
            p2::WORDS_PER_LANE * lane,
            field,
            &|k, t| p2_circuit::value_bit(v, k, t),
            &|k, t| p2_circuit::diff_bit(v, k, t),
            &|k| p2_circuit::borrow_bit(v, k),
        ));
    }
    // Every lane, in and out: this family's frame is canonical values by
    // design, the circuit being `poseidon2_permute` itself
    // (`docs/spec/delegation.md` §13.2), so a lane that is not below `p` is a
    // guest that handed the shim something that is not a field element.
    debug_only!(
        if debug::enabled_for(debug::Level::Detail, family::POSEIDON2) {
            let lanes: Vec<(String, usize, u32)> = (0..2 * p2::WIDTH)
                .map(|v| {
                    let field = if v < p2::WIDTH {
                        deleg::WORD_READ_VALUE
                    } else {
                        deleg::WORD_WRITE_VALUE
                    };
                    let side = if v < p2::WIDTH { "in" } else { "out" };
                    (
                        format!("{side}{}", v % p2::WIDTH),
                        p2::WORDS_PER_LANE * (v % p2::WIDTH),
                        field,
                    )
                })
                .collect();
            let borrowed: Vec<(&str, usize, u32)> =
                lanes.iter().map(|(n, f, k)| (n.as_str(), *f, *k)).collect();
            canon_tally_log(family::POSEIDON2, src.index, &inv, &borrowed);
        }
    );
    Ok(out)
}

/// An `FR_ARITH` shard, `docs/spec/delegation.md` §13.1: the delegation frame,
/// the three values' bits, the operation selectors, and the three witnessed
/// scalars — the product helper, the inverse and the is-zero flag.
fn fr_arith(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let inv = invocations(src, family::FR_ARITH)?;
    debug_only!(deleg_frame_log(family::FR_ARITH, src.index, &inv));
    let mut out = delegation_frame(&inv, fa::FRAME_WORDS, fa::FRAME_BYTES as u64);
    let (frames, h) = (inv.frames, inv.height);
    let rows = 0..frames.len();
    for (v, (first, field)) in [
        (fa::A_WORD, deleg::WORD_READ_VALUE),
        (fa::B_WORD, deleg::WORD_READ_VALUE),
        (fa::OUT_WORD, deleg::WORD_WRITE_VALUE),
    ]
    .into_iter()
    .enumerate()
    {
        out.extend(value_columns(
            &inv,
            first,
            field,
            &|k, t| fa_circuit::value_bit(v, k, t),
            &|k, t| fa_circuit::diff_bit(v, k, t),
            &|k| fa_circuit::borrow_bit(v, k),
        ));
    }
    debug_only!(canon_tally_log(
        family::FR_ARITH,
        src.index,
        &inv,
        &[
            ("a", fa::A_WORD, deleg::WORD_READ_VALUE),
            ("b", fa::B_WORD, deleg::WORD_READ_VALUE),
            ("out", fa::OUT_WORD, deleg::WORD_WRITE_VALUE),
        ],
    ));
    let opcodes = frames.word(fa::OPCODE_WORD).read_value;
    let opcode = |r: usize| opcodes[r];
    for (i, op) in fa::OPS.iter().enumerate() {
        let values: Vec<u32> = rows.clone().map(|r| u32::from(opcode(r) == *op)).collect();
        out.push((fa_circuit::selector(i), u32_column(values, h)));
    }
    // The three `Fr`-valued witnesses. `a` and `b` are the frame's own words
    // read as `Fr`'s in-memory representation; every one is canonical, which
    // the emulator refused to run without.
    let value = |first: usize, field: u32, r: usize| -> Fr {
        let words = value_words(frames, first, field, r);
        let mut bytes = [0u8; 32];
        for k in 0..8 {
            bytes[4 * k..4 * k + 4].copy_from_slice(&words[k].to_le_bytes());
        }
        Fr::from_bytes(&bytes).expect("the emulator refuses a non-canonical frame value")
    };
    let a = |r: usize| value(fa::A_WORD, deleg::WORD_READ_VALUE, r);
    let b = |r: usize| value(fa::B_WORD, deleg::WORD_READ_VALUE, r);
    out.push((
        fa_circuit::prod(),
        fr_column(rows.clone().map(|r| a(r) * b(r)).collect(), h),
    ));
    out.push((
        fa_circuit::inv(),
        fr_column(
            rows.clone()
                .map(|r| match opcode(r) == fa::OP_INV {
                    true => a(r).inverse().unwrap_or(Fr::ZERO),
                    false => Fr::ZERO,
                })
                .collect(),
            h,
        ),
    ));
    out.push((
        fa_circuit::is_zero(),
        fr_column(
            rows.clone()
                .map(|r| match opcode(r) == fa::OP_INV && a(r) == Fr::ZERO {
                    true => Fr::ONE,
                    false => Fr::ZERO,
                })
                .collect(),
            h,
        ),
    ));
    Ok(out)
}

/// One `MOD_MUL` row's witness, computed once and then transposed.
///
/// Every field here is a function of the **whole** row rather than of one
/// limb, and the circuit reads each of them across 256 or 264 bit columns, so
/// computing them inside the `(k, t)` loops would redo the same long division
/// and the same three borrow chains hundreds of times a row.
struct ModMulRow {
    /// The index into `mm::CODES` the frame's selector word names.
    selector: usize,
    /// The selected modulus' limbs — the circuit's `m_limb` columns.
    m: [u64; mm::LIMBS],
    /// `a`, `b` and `out`, in `mm_circuit::{A, B, OUT}` order.
    values: [[u64; mm::LIMBS]; 3],
    /// The quotient, which nothing in the trace records.
    q: [u64; mm::LIMBS],
    /// The fourteen signed carries of the limb identity.
    carries: Vec<i128>,
    /// Each value's `< m` borrow chain: difference limbs, then borrows.
    chains: [([u64; mm::LIMBS], [u64; mm::LIMBS]); 3],
}

/// A `MOD_MUL` shard, `docs/spec/delegation.md` §14: the delegation frame, the
/// modulus selector and the limbs it names, the three frame values' word bits
/// and `< m` chains, the quotient with its limbs and bits, and the fifteen
/// positions' signed carries.
///
/// It computes no product: the frame's words are what the execution wrote and
/// the circuit is what says that was `a * b mod m`. What it *does* compute is
/// the witness the circuit needs and nothing records — the modulus, the
/// quotient, the carries and the three borrow chains — each a function of the
/// words alone.
///
/// Panics on anything the emulator refuses: a selector naming no modulus, an
/// operand at or above it, or an identity that does not hold over those words.
/// None of the three is producible by `emulator::mod_mul_frame`, which refuses
/// each by name — the assertions are what say so out loud rather than leaving
/// a wrong witness to surface as an anonymous layer inconsistency in a proof
/// nobody can verify.
fn mod_mul(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let inv = invocations(src, family::MOD_MUL)?;
    debug_only!(deleg_frame_log(family::MOD_MUL, src.index, &inv));
    // Since S26c this family range-checks through `RANGE16`, so its frame is
    // `delegation_frame_range16`'s and not `delegation_frame`'s: two gap chunks
    // a word rather than 38 bits, and one value plus one halfword for each of
    // the base's two decompositions.
    let mut out = delegation_frame_range16(
        &inv,
        mm::FRAME_WORDS,
        mm::FRAME_BYTES as u64,
        mm_circuit::gap_chunk,
        [
            mm_circuit::base_low(),
            mm_circuit::base_low_hi(),
            mm_circuit::base_room(),
            mm_circuit::base_room_hi(),
        ],
    );
    let (frames, h) = (inv.frames, inv.height);
    let rows = 0..frames.len();

    let limbs = |first: usize, field: u32, r: usize| -> [u64; mm::LIMBS] {
        core::array::from_fn(|k| {
            let w = frames.word(first + k);
            let column = match field {
                deleg::WORD_READ_VALUE => w.read_value,
                _ => w.write_value,
            };
            column[r] as u64
        })
    };

    // **A pre-flight scan, before the witness loop.** That loop panics on the
    // first row whose selector names no modulus or whose operand is not below
    // the selected one, and its message names neither the invocation, nor the
    // value, nor which of the four moduli was selected. This reports all of
    // them, with the numbers, and it has to run first to be read at all.
    debug_only!(
        if debug::enabled_for(debug::Level::Detail, family::MOD_MUL) {
            let who = debug::shard(family::MOD_MUL, src.index);
            let live = frames.len();
            let mut tally = vec![0usize; mm::CODES.len()];
            let mut unknown: Vec<(usize, u32)> = Vec::new();
            let mut bad: Vec<(usize, String, String)> = Vec::new();
            for r in 0..live {
                let code = frames.word(mm::SELECTOR_WORD).read_value[r];
                let Some(sel) = mm::CODES.iter().position(|c| *c == code) else {
                    unknown.push((r, code));
                    continue;
                };
                tally[sel] += 1;
                let m: [u64; mm::LIMBS] = core::array::from_fn(|k| mm::MODULI[sel][k] as u64);
                for (first, name) in [(mm::A_WORD, "a"), (mm::B_WORD, "b")] {
                    let x = limbs(first, deleg::WORD_READ_VALUE, r);
                    if !below(&x, &m) {
                        bad.push((
                            r,
                            format!("{name}={}", debug::limbs(&x.map(|v| v as u32))),
                            debug::limbs(&m.map(|v| v as u32)),
                        ));
                    }
                }
            }
            debug::line(&format!(
                "apogee deleg    {who:<22} {} of {live} live rows",
                debug::histogram("modulus", &debug::MOD_MUL_SELECTORS, &tally)
            ));
            if let Some((r, code)) = unknown.first() {
                debug::line(&format!(
                    "apogee deleg    {who:<22} selector {code} on invocation {r} NAMES NO MODULUS \
                 ({} such rows) -- the fill panics next",
                    unknown.len()
                ));
            }
            debug::line(&format!(
                "apogee deleg    {who:<22} {}",
                debug::canonical("operands a<m and b<m", 2 * live, &bad)
            ));
        }
    );

    // One pass over the live rows. Padding rows are the zeros `u32_column`
    // pads with, which is what every gate wants of them: a zero modulus, zero
    // selectors, and a borrow chain whose last borrow is 0 = `live`.
    let witness: Vec<ModMulRow> = rows
        .clone()
        .map(|r| {
            let code = frames.word(mm::SELECTOR_WORD).read_value[r];
            let selector = mm::CODES
                .iter()
                .position(|c| *c == code)
                .unwrap_or_else(|| panic!("mod_mul: selector {code} names no modulus"));
            let m: [u64; mm::LIMBS] = core::array::from_fn(|k| mm::MODULI[selector][k] as u64);
            let values = [
                limbs(mm::A_WORD, deleg::WORD_READ_VALUE, r),
                limbs(mm::B_WORD, deleg::WORD_READ_VALUE, r),
                limbs(mm::OUT_WORD, deleg::WORD_WRITE_VALUE, r),
            ];
            // The three bounds the circuit states. `out < m` is the emulator's
            // own output and cannot fail; `a < m` and `b < m` are the guest's
            // to get right, and naming the operand here is the difference
            // between a panic a reader can act on and a layer number.
            for (v, name) in [(mm_circuit::A, "a"), (mm_circuit::B, "b")] {
                assert!(
                    below(&values[v], &m),
                    "mod_mul: operand {name} is not below the selected modulus"
                );
            }
            let (q, carries) = mod_mul_witness(&m, &values[0], &values[1], &values[2]);
            let q: [u64; mm::LIMBS] = core::array::from_fn(|k| q[k]);
            ModMulRow {
                selector,
                m,
                values,
                q,
                carries,
                chains: core::array::from_fn(|v| borrow_chain_against(&values[v], &m)),
            }
        })
        .collect();

    // The four selectors, one-hot on a live row, and the eight limbs they name.
    for i in 0..mm::CODES.len() {
        let values: Vec<u32> = witness.iter().map(|w| u32::from(w.selector == i)).collect();
        out.push((mm_circuit::selector(i), u32_column(values, h)));
    }
    for k in 0..mm::LIMBS {
        let values: Vec<u32> = witness.iter().map(|w| w.m[k] as u32).collect();
        out.push((mm_circuit::m_limb(k), u32_column(values, h)));
    }

    // Each value's eight limb halfwords, then its 24 chain columns.
    for v in [mm_circuit::A, mm_circuit::B, mm_circuit::OUT] {
        for k in 0..mm::LIMBS {
            let values: Vec<u32> = witness
                .iter()
                .map(|w| (w.values[v][k] >> 16) as u32)
                .collect();
            out.push((mm_circuit::value_hi(v, k), u32_column(values, h)));
        }
        for i in 0..mm::LIMBS {
            let values: Vec<u32> = witness.iter().map(|w| w.chains[v].0[i] as u32).collect();
            out.push((mm_circuit::diff(v, i), u32_column(values, h)));
        }
        for i in 0..mm::LIMBS {
            let values: Vec<u32> = witness
                .iter()
                .map(|w| (w.chains[v].0[i] >> 16) as u32)
                .collect();
            out.push((mm_circuit::diff_hi(v, i), u32_column(values, h)));
        }
        for i in 0..mm::LIMBS {
            let values: Vec<u32> = witness.iter().map(|w| w.chains[v].1[i] as u32).collect();
            out.push((mm_circuit::borrow_bit(v, i), u32_column(values, h)));
        }
    }

    // The quotient, its halfwords, and every position's signed carry as the
    // unsigned `carry + 2^36` with its two chunks.
    for k in 0..mm::LIMBS {
        let values: Vec<u32> = witness.iter().map(|w| w.q[k] as u32).collect();
        out.push((mm_circuit::q_limb(k), u32_column(values, h)));
    }
    for k in 0..mm::LIMBS {
        let values: Vec<u32> = witness.iter().map(|w| (w.q[k] >> 16) as u32).collect();
        out.push((mm_circuit::q_hi(k), u32_column(values, h)));
    }
    for k in 0..mm::CARRIES {
        let offsets: Vec<i128> = witness
            .iter()
            .map(|w| w.carries[k] + mm::CARRY_OFFSET as i128)
            .collect();
        out.push((
            mm_circuit::carry(k),
            fr_column(offsets.iter().map(|v| signed(*v)).collect(), h),
        ));
        for j in 0..2 {
            let values: Vec<u32> = offsets
                .iter()
                .map(|v| ((v >> (16 * (j as u32 + 1))) & 0xffff) as u32)
                .collect();
            out.push((mm_circuit::carry_chunk(k, j), u32_column(values, h)));
        }
    }
    Ok(out)
}

/// The frame's columns for a family that range-checks through `RANGE16`.
///
/// The `M` side is `delegation_frame`'s exactly; the witness side is two gap
/// chunks a word and one value plus one halfword for each of the base's two
/// decompositions, where that one writes 38 bits a word and 29 plus 31.
fn delegation_frame_range16(
    inv: &Invocations,
    words: usize,
    frame_bytes: u64,
    chunk: fn(usize, usize) -> PolyAddress,
    base: [PolyAddress; 4],
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let (frames, h) = (inv.frames, inv.height);
    let rows = 0..frames.len();
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    let cycles: Vec<Fr> = frames.cycles().iter().map(|c| Fr::from_u64(*c)).collect();
    out.push((deleg::CYCLE, fr_column(cycles, h)));
    out.push((
        deleg::LIVE,
        u32_column(rows.clone().map(|_| 1).collect(), h),
    ));
    out.push((deleg::BASE, u32_column(frames.bases().to_vec(), h)));
    out.push((deleg::ANCHOR_VALUE, u32_column(Vec::new(), h)));
    for j in 0..words {
        let w = frames.word(j);
        for (field, values) in [
            (
                deleg::WORD_ADDR,
                rows.clone().map(|r| w.addr[r]).collect::<Vec<u32>>(),
            ),
            (
                deleg::WORD_READ_VALUE,
                rows.clone().map(|r| w.read_value[r]).collect(),
            ),
            (
                deleg::WORD_WRITE_VALUE,
                rows.clone().map(|r| w.write_value[r]).collect(),
            ),
        ] {
            out.push((deleg::word(j, field), u32_column(values, h)));
        }
        let read_ts: Vec<Fr> = rows.clone().map(|r| Fr::from_u64(w.read_ts[r])).collect();
        out.push((deleg::word(j, deleg::WORD_READ_TS), fr_column(read_ts, h)));
    }
    for j in 0..words {
        for c in 0..2 {
            let values: Vec<u32> = rows
                .clone()
                .map(|r| {
                    let ts = memory::TS_STEP * frames.cycles()[r] + delegation::FRAME_DELTA;
                    let gap = ts - frames.word(j).read_ts[r] - 1;
                    ((gap >> (16 * (c as u32 + 1))) & 0xffff) as u32
                })
                .collect();
            out.push((chunk(j, c), u32_column(values, h)));
        }
    }
    let low: Vec<u32> = rows
        .clone()
        .map(|r| (frames.bases()[r] - guest_memory::RAM_ORIGIN) / 4)
        .collect();
    out.push((base[0], u32_column(low.clone(), h)));
    out.push((
        base[1],
        u32_column(low.iter().map(|v| v >> 16).collect(), h),
    ));
    let room: Vec<u32> = rows
        .clone()
        .map(|r| ((1u64 << 31) - frame_bytes - frames.bases()[r] as u64) as u32)
        .collect();
    out.push((base[2], u32_column(room.clone(), h)));
    out.push((
        base[3],
        u32_column(room.iter().map(|v| v >> 16).collect(), h),
    ));
    out
}

/// `SHA256_COMP`'s fill: one compression a row.
///
/// Every committed column but the frame's own is a **bit**, and every bit comes
/// from re-running the compression over the frame's read values. That is not
/// re-deciding what the row says — the frame words come from the buffer, which
/// the tracer filled from the log — it is producing the intermediate sequences
/// the circuit's gates read, which no log event carries.
fn sha256_comp(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let inv = invocations(src, family::SHA256_COMP)?;
    debug_only!(deleg_frame_log(family::SHA256_COMP, src.index, &inv));
    let mut out = delegation_frame(&inv, sh::FRAME_WORDS, sh::FRAME_BYTES as u64);
    let (frames, h) = (inv.frames, inv.height);
    let rows = 0..frames.len();

    /// One row's intermediates: the schedule, the two working sequences, and
    /// every carry the circuit commits. `a[i + 3]` is `A_i`, so indices 0..4
    /// are `A_{-3}..A_0` — the state words standing in for `D`, `C`, `B`, `A`.
    struct Row {
        w: [u32; sh::ROUNDS],
        cw: [u32; sh::ROUNDS],
        a: Vec<u32>,
        e: Vec<u32>,
        ca: [u32; sh::ROUNDS],
        ce: [u32; sh::ROUNDS],
        co: [u32; sh::STATE_WORDS],
    }

    let witness: Vec<Row> = rows
        .clone()
        .map(|r| {
            let read = |j: usize| frames.word(j).read_value[r];
            let mut w = [0u32; sh::ROUNDS];
            let mut cw = [0u32; sh::ROUNDS];
            for (i, slot) in w.iter_mut().take(sh::BLOCK_WORDS).enumerate() {
                *slot = read(sh::BLOCK_WORD + i);
            }
            for i in sh::BLOCK_WORDS..sh::ROUNDS {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                let raw = s1 as u64 + w[i - 7] as u64 + s0 as u64 + w[i - 16] as u64;
                cw[i] = (raw >> 32) as u32;
                w[i] = raw as u32;
            }
            let mut a = vec![read(3), read(2), read(1), read(0)];
            let mut e = vec![read(7), read(6), read(5), read(4)];
            let mut ca = [0u32; sh::ROUNDS];
            let mut ce = [0u32; sh::ROUNDS];
            for i in 0..sh::ROUNDS {
                let (ai, am1, am2, am3) = (a[i + 3], a[i + 2], a[i + 1], a[i]);
                let (ei, em1, em2, em3) = (e[i + 3], e[i + 2], e[i + 1], e[i]);
                let s1 = ei.rotate_right(6) ^ ei.rotate_right(11) ^ ei.rotate_right(25);
                let ch = (ei & em1) ^ (!ei & em2);
                let t1 = em3 as u64
                    + s1 as u64
                    + ch as u64
                    + sh::ROUND_CONSTANTS[i] as u64
                    + w[i] as u64;
                let s0 = ai.rotate_right(2) ^ ai.rotate_right(13) ^ ai.rotate_right(22);
                let maj = (ai & am1) ^ (ai & am2) ^ (am1 & am2);
                let t2 = s0 as u64 + maj as u64;
                ca[i] = ((t1 + t2) >> 32) as u32;
                ce[i] = ((am3 as u64 + t1) >> 32) as u32;
                a.push((t1 + t2) as u32);
                e.push((am3 as u64 + t1) as u32);
            }
            let v = [
                a[sh::ROUNDS + 3],
                a[sh::ROUNDS + 2],
                a[sh::ROUNDS + 1],
                a[sh::ROUNDS],
                e[sh::ROUNDS + 3],
                e[sh::ROUNDS + 2],
                e[sh::ROUNDS + 1],
                e[sh::ROUNDS],
            ];
            let co: [u32; sh::STATE_WORDS] =
                core::array::from_fn(|j| ((read(j) as u64 + v[j] as u64) >> 32) as u32);
            Row {
                w,
                cw,
                a,
                e,
                ca,
                ce,
                co,
            }
        })
        .collect();

    // **The one delegation family with no emulator refusal path, checked.**
    // This fill re-runs the whole compression and then commits only its *bits*,
    // so the comparison it is in a position to make — the state this row
    // computed against the state the frame says the guest wrote — is never
    // actually made. Every other delegation family has the executor refusing a
    // frame it cannot answer; this one does not, so a disagreement between the
    // recomputation and the frame reaches a reader as a broken `out_bit` gate at
    // whatever layer it sits on. Eight `u32` compares a row on a `2^8` family.
    //
    // `v` mirrors the closure above, which builds it from `a` and `e` and then
    // discards it into `co`.
    debug_only!(
        if debug::enabled_for(debug::Level::Detail, family::SHA256_COMP) {
            let mut disagree: Vec<(usize, usize, u32, u32)> = Vec::new();
            for (r, row) in witness.iter().enumerate() {
                let v = [
                    row.a[sh::ROUNDS + 3],
                    row.a[sh::ROUNDS + 2],
                    row.a[sh::ROUNDS + 1],
                    row.a[sh::ROUNDS],
                    row.e[sh::ROUNDS + 3],
                    row.e[sh::ROUNDS + 2],
                    row.e[sh::ROUNDS + 1],
                    row.e[sh::ROUNDS],
                ];
                for (j, vj) in v.iter().enumerate() {
                    let want = frames.word(j).read_value[r].wrapping_add(*vj);
                    let got = frames.word(j).write_value[r];
                    if want != got {
                        disagree.push((r, j, want, got));
                    }
                }
            }
            let who = debug::shard(family::SHA256_COMP, src.index);
            let checks = witness.len() * sh::STATE_WORDS;
            match disagree.first() {
            None => debug::line(&format!(
                "apogee deleg    {who:<22} compression agrees with the frame on {checks} state words"
            )),
            Some((r, j, want, got)) => debug::line(&format!(
                "apogee deleg    {who:<22} compression DISAGREES with the frame on {} of \
                 {checks} state words, first invocation {r} word {j}: recomputed {want:#010x}, \
                 the frame wrote {got:#010x}",
                disagree.len()
            )),
        }
        }
    );

    // A bit column from a per-row extractor. Padding rows are the zeros
    // `u32_column` pads with, which is what every gate wants of them.
    let bit_column = |out: &mut Vec<(PolyAddress, MultilinearPoly)>,
                      address: PolyAddress,
                      pick: &dyn Fn(&Row) -> u32,
                      t: usize| {
        let values: Vec<u32> = witness.iter().map(|row| (pick(row) >> t) & 1).collect();
        out.push((address, u32_column(values, h)));
    };

    for j in 0..sh::FRAME_WORDS {
        for t in 0..32 {
            let values: Vec<u32> = rows
                .clone()
                .map(|r| (frames.word(j).read_value[r] >> t) & 1)
                .collect();
            out.push((sh_circuit::in_bit(j, t), u32_column(values, h)));
        }
    }
    for j in 0..sh::STATE_WORDS {
        for t in 0..32 {
            let values: Vec<u32> = rows
                .clone()
                .map(|r| (frames.word(j).write_value[r] >> t) & 1)
                .collect();
            out.push((sh_circuit::out_bit(j, t), u32_column(values, h)));
        }
    }
    for j in 0..sh::STATE_WORDS {
        bit_column(&mut out, sh_circuit::out_carry(j), &|row| row.co[j], 0);
    }
    for i in sh::BLOCK_WORDS..sh::ROUNDS {
        for t in 0..32 {
            bit_column(&mut out, sh_circuit::sched_bit(i, t), &|row| row.w[i], t);
        }
    }
    for i in sh::BLOCK_WORDS..sh::ROUNDS {
        for t in 0..sh::CARRY_W_BITS {
            bit_column(
                &mut out,
                sh_circuit::sched_carry_bit(i, t),
                &|row| row.cw[i],
                t,
            );
        }
    }
    for i in 1..=sh::ROUNDS {
        for t in 0..32 {
            bit_column(
                &mut out,
                sh_circuit::a_bit(i as isize, t),
                &|row| row.a[i + 3],
                t,
            );
        }
    }
    for i in 1..=sh::ROUNDS {
        for t in 0..32 {
            bit_column(
                &mut out,
                sh_circuit::e_bit(i as isize, t),
                &|row| row.e[i + 3],
                t,
            );
        }
    }
    for i in 0..sh::ROUNDS {
        for t in 0..sh::CARRY_A_BITS {
            bit_column(&mut out, sh_circuit::ca_bit(i, t), &|row| row.ca[i], t);
        }
    }
    for i in 0..sh::ROUNDS {
        for t in 0..sh::CARRY_E_BITS {
            bit_column(&mut out, sh_circuit::ce_bit(i, t), &|row| row.ce[i], t);
        }
    }
    Ok(out)
}

/// `EC_ADD`'s fill: one third of a point addition a row.
///
/// The frame's own columns are **not** `delegation_frame`'s: this family
/// range-checks through `RANGE16` where the other five decompose into bits, so
/// its timestamp gap is two committed chunks rather than 38 booleans and its
/// two base decompositions are one column each. The `M` side is identical, so
/// only the witness side differs.
fn ec_add(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let inv = invocations(src, family::EC_ADD)?;
    debug_only!(deleg_frame_log(family::EC_ADD, src.index, &inv));
    let (frames, h) = (inv.frames, inv.height);
    let rows = 0..frames.len();

    let mut out = delegation_frame_range16(
        &inv,
        ea::FRAME_WORDS,
        ea::FRAME_BYTES as u64,
        ea_circuit::gap_chunk,
        [
            ea_circuit::base_low(),
            ea_circuit::base_low_hi(),
            ea_circuit::base_room(),
            ea_circuit::base_room_hi(),
        ],
    );
    // This family additionally bounds **every** frame word to 32 bits, because
    // its operands are linear combinations of frame limbs and the limb
    // identity's integer reasoning rests on each of them being below `2^32`.
    for j in 0..ea::FRAME_WORDS {
        let values: Vec<u32> = rows
            .clone()
            .map(|r| frames.word(j).read_value[r] >> 16)
            .collect();
        out.push((ea_circuit::word_high(j), u32_column(values, h)));
    }

    // --- one pass over the live rows ---------------------------------------
    let witness: Vec<EcAddRow> = rows.clone().map(|r| ec_add_row(frames, r)).collect();

    // The three scans this family's own failures need. `EC_ADD` is the newest
    // circuit and the peak-setting family in a block, and its S26c bug — a
    // gated conclusion written `b_7 = enable` instead of
    // `enable · (1 − b_7) = 0`, which made every row unprovable while every
    // shape test passed — is exactly what the canonicity line names.
    debug_only!(
        if debug::enabled_for(debug::Level::Detail, family::EC_ADD) {
            let who = debug::shard(family::EC_ADD, src.index);
            let live = witness.len();
            let mut tally = vec![0usize; ea::CODES.len()];
            for w in &witness {
                tally[w.code] += 1;
            }
            debug::line(&format!(
                "apogee deleg    {who:<22} {} of {live} live rows",
                debug::histogram("curve/group", &debug::EC_ADD_SELECTORS, &tally)
            ));
            // Each curve's three groups are one third of a point addition each, so
            // their counts must agree. Nothing else in the repository checks it.
            debug::line(&format!(
                "apogee deleg    {who:<22} {}",
                debug::ec_add_groups(&tally)
            ));
            // Canonicity, over the (row, value) pairs the row's group actually
            // reads — `debug::ec_add_reads` is why that restriction is not
            // optional.
            let mut bad: Vec<(usize, String, String)> = Vec::new();
            let mut pairs = 0usize;
            for (r, w) in witness.iter().enumerate() {
                let group = ea::CODE_GROUP[w.code];
                for (v, first) in EC_ADD_VALUE_WORDS.into_iter().enumerate() {
                    if !debug::ec_add_reads(group, v) {
                        continue;
                    }
                    pairs += 1;
                    if w.chains[v].1[ea::LIMBS - 1] == 1 {
                        continue;
                    }
                    let value: [u32; ea::LIMBS] =
                        core::array::from_fn(|k| frames.word(first + k).read_value[r]);
                    bad.push((
                        r,
                        format!("{}={}", debug::EC_ADD_VALUES[v], debug::limbs(&value)),
                        debug::limbs(&w.m.map(|x| x as u32)),
                    ));
                }
            }
            debug::line(&format!(
                "apogee deleg    {who:<22} {}",
                debug::canonical("values the group reads", pairs, &bad)
            ));
        }
    );

    for i in 0..ea::CODES.len() {
        let values: Vec<u32> = witness.iter().map(|w| u32::from(w.code == i)).collect();
        out.push((ea_circuit::selector(i), u32_column(values, h)));
    }
    for k in 0..ea::LIMBS {
        let values: Vec<u32> = witness.iter().map(|w| w.m[k] as u32).collect();
        out.push((ea_circuit::m_limb(k), u32_column(values, h)));
    }
    out.push((
        ea_circuit::b3(),
        u32_column(witness.iter().map(|w| w.b3).collect(), h),
    ));
    // The three curve-scaled helpers are limb-wise products, not reductions, so
    // `b3 * zz_k` reaches 21 * 2^32 and `byz3` is signed: `Fr` columns, not
    // `u32` ones.
    for (pick, address) in [
        (0usize, ea_circuit::bzz3_limb as fn(usize) -> PolyAddress),
        (1, ea_circuit::byz3_limb as fn(usize) -> PolyAddress),
        (2, ea_circuit::bxx9_limb as fn(usize) -> PolyAddress),
    ] {
        for k in 0..ea::LIMBS {
            let values: Vec<Fr> = witness.iter().map(|w| signed(w.helpers[pick][k])).collect();
            out.push((address(k), fr_column(values, h)));
        }
    }
    for v in 0..12 {
        for i in 0..ea::LIMBS {
            let values: Vec<u32> = witness.iter().map(|w| w.chains[v].0[i] as u32).collect();
            out.push((ea_circuit::diff(v, i), u32_column(values, h)));
        }
        for i in 0..ea::LIMBS {
            let values: Vec<u32> = witness
                .iter()
                .map(|w| (w.chains[v].0[i] >> 16) as u32)
                .collect();
            out.push((ea_circuit::diff_hi(v, i), u32_column(values, h)));
        }
        for i in 0..ea::LIMBS {
            let values: Vec<u32> = witness.iter().map(|w| w.chains[v].1[i] as u32).collect();
            out.push((ea_circuit::borrow(v, i), u32_column(values, h)));
        }
    }
    for r in 0..ea::GROUPS {
        for which in 0..4 {
            for k in 0..ea::LIMBS {
                let values: Vec<Fr> = witness
                    .iter()
                    .map(|w| signed(w.slots[r].operands[which][k]))
                    .collect();
                out.push((ea_circuit::operand(r, which, k), fr_column(values, h)));
            }
        }
        for k in 0..ea::LIMBS {
            let values: Vec<u32> = witness.iter().map(|w| w.slots[r].out[k] as u32).collect();
            out.push((ea_circuit::out_limb(r, k), u32_column(values, h)));
        }
        for k in 0..ea::LIMBS {
            let values: Vec<u32> = witness
                .iter()
                .map(|w| (w.slots[r].out[k] >> 16) as u32)
                .collect();
            out.push((ea_circuit::out_hi(r, k), u32_column(values, h)));
        }
        for i in 0..ea::QUOTIENT_LIMBS {
            let values: Vec<u32> = witness.iter().map(|w| w.slots[r].q[i] as u32).collect();
            out.push((ea_circuit::q_limb(r, i), u32_column(values, h)));
        }
        for i in 0..ea::QUOTIENT_LIMBS {
            let values: Vec<u32> = witness
                .iter()
                .map(|w| (w.slots[r].q[i] >> 16) as u32)
                .collect();
            out.push((ea_circuit::q_hi(r, i), u32_column(values, h)));
        }
        // The carry is committed as the **unsigned** `c + 2^46`, which reaches
        // 2^46 and so is an `Fr` column; its two chunks are halfwords.
        let offset = 1i128 << ea::CARRY_OFFSET_BITS;
        for c in 0..ea::CARRIES {
            let values: Vec<Fr> = witness
                .iter()
                .map(|w| signed(w.slots[r].carries[c] + offset))
                .collect();
            out.push((ea_circuit::carry(r, c), fr_column(values, h)));
        }
        for c in 0..ea::CARRIES {
            for j in 0..2 {
                let values: Vec<u32> = witness
                    .iter()
                    .map(|w| {
                        let u = w.slots[r].carries[c] + offset;
                        ((u >> (16 * (j as u32 + 1))) & 0xffff) as u32
                    })
                    .collect();
                out.push((ea_circuit::carry_chunk(r, c, j), u32_column(values, h)));
            }
        }
        for i in 0..ea::LIMBS {
            let values: Vec<u32> = witness
                .iter()
                .map(|w| w.slots[r].chain.0[i] as u32)
                .collect();
            out.push((ea_circuit::out_diff(r, i), u32_column(values, h)));
        }
        for i in 0..ea::LIMBS {
            let values: Vec<u32> = witness
                .iter()
                .map(|w| (w.slots[r].chain.0[i] >> 16) as u32)
                .collect();
            out.push((ea_circuit::out_diff_hi(r, i), u32_column(values, h)));
        }
        for i in 0..ea::LIMBS {
            let values: Vec<u32> = witness
                .iter()
                .map(|w| w.slots[r].chain.1[i] as u32)
                .collect();
            out.push((ea_circuit::out_borrow(r, i), u32_column(values, h)));
        }
    }
    Ok(out)
}

/// One `EC_ADD` row's witness.
struct EcAddRow {
    code: usize,
    m: [u64; ea::LIMBS],
    b3: u32,
    /// `bzz3`, `byz3` and `bxx9`, limb-wise and signed.
    helpers: [[i128; ea::LIMBS]; 3],
    /// The twelve frame values' `< m` chains, in `VALUES` order.
    chains: [([u64; ea::LIMBS], [u64; ea::LIMBS]); 12],
    slots: [EcAddSlot; ea::GROUPS],
}

/// One reduction slot's witness.
struct EcAddSlot {
    /// `A`, `B`, `C`, `D`, limb-wise and signed.
    operands: [[i128; ea::LIMBS]; 4],
    out: [u64; ea::LIMBS],
    q: [u64; ea::QUOTIENT_LIMBS],
    carries: [i128; ea::CARRIES],
    chain: ([u64; ea::LIMBS], [u64; ea::LIMBS]),
}

/// The twelve frame values' first words, in `constraints::ec_add::VALUES`
/// order. Hoisted out of [`ec_add_row`] so the `debug-info` canonicity scan
/// reads the same twelve words the witness does, rather than a second copy of
/// the list.
const EC_ADD_VALUE_WORDS: [usize; 12] = [
    ea::X1_WORD,
    ea::Y1_WORD,
    ea::Z1_WORD,
    ea::X2_WORD,
    ea::Y2_WORD,
    ea::Z2_WORD,
    ea::XX_WORD,
    ea::YY_WORD,
    ea::ZZ_WORD,
    ea::M4_WORD,
    ea::M5_WORD,
    ea::M6_WORD,
];

/// One row's witness: the selector, the curve's constants, the twelve values'
/// chains, and the three slots' operands, quotients and carries.
fn ec_add_row(frames: &FrameSlice, r: usize) -> EcAddRow {
    let read = |first: usize| -> [u64; ea::LIMBS] {
        core::array::from_fn(|k| frames.word(first + k).read_value[r] as u64)
    };
    let code_word = frames.word(ea::SELECTOR_WORD).read_value[r];
    let code = ea::code_index(code_word)
        .unwrap_or_else(|| panic!("ec_add: selector {code_word} names no curve and group"));
    let m: [u64; ea::LIMBS] = {
        let sel = ea::CURVE_MODULI[ea::CODE_CURVE[code]];
        core::array::from_fn(|k| sel[k] as u64)
    };
    let b3 = ea::CURVE_B3[ea::CODE_CURVE[code]];
    let g = ea::CODE_GROUP[code];

    let values: [[u64; ea::LIMBS]; 12] = core::array::from_fn(|v| read(EC_ADD_VALUE_WORDS[v]));
    // **Every value's chain is the honest one, on every row.** The chain's
    // sixteen `canonical` gates are *ungated* — they hold for any `v` — and only
    // the conclusion `below_modulus` is gated, to the groups that read the
    // value. So a non-reading value still owes a real chain, and the zeros this
    // wrote until the gated conclusion was corrected satisfy the canonical gates
    // only where `v = m`. `crates/checker/tests/ec_add.rs` is what says so.
    let chains: [([u64; ea::LIMBS], [u64; ea::LIMBS]); 12] = core::array::from_fn(|v| {
        let (d, b) = borrow_chain_against(&values[v], &m);
        (
            core::array::from_fn(|i| d[i]),
            core::array::from_fn(|i| b[i]),
        )
    });

    let (xx, yy, zz) = (values[6], values[7], values[8]);
    let m5 = values[10];
    let lim = |v: &[u64; ea::LIMBS], k: usize| v[k] as i128;
    // The three curve-scaled helpers, limb-wise and ungated: their gates hold
    // on every row, and only group 2's operand pins read them.
    let helpers: [[i128; ea::LIMBS]; 3] = [
        core::array::from_fn(|k| b3 as i128 * lim(&zz, k)),
        core::array::from_fn(|k| b3 as i128 * (lim(&m5, k) - lim(&yy, k) - lim(&zz, k))),
        core::array::from_fn(|k| 3 * b3 as i128 * lim(&xx, k)),
    ];

    // Each group's three slots, as `(A, B, C, D, the output's frame word)`.
    let zero = [0i128; ea::LIMBS];
    let lin = |terms: &[(usize, i128)]| -> [i128; ea::LIMBS] {
        core::array::from_fn(|k| terms.iter().map(|(v, c)| c * lim(&values[*v], k)).sum())
    };
    let xy = lin(&[(9, 1), (6, -1), (7, -1)]);
    let yz = lin(&[(10, 1), (7, -1), (8, -1)]);
    let xz = lin(&[(11, 1), (6, -1), (8, -1)]);
    let nxz = lin(&[(6, 1), (8, 1), (11, -1)]);
    let ym: [i128; ea::LIMBS] = core::array::from_fn(|k| lim(&yy, k) - helpers[0][k]);
    let yp: [i128; ea::LIMBS] = core::array::from_fn(|k| lim(&yy, k) + helpers[0][k]);
    let xx3: [i128; ea::LIMBS] = core::array::from_fn(|k| 3 * lim(&xx, k));
    let schedule: [[[i128; ea::LIMBS]; 4]; ea::GROUPS] = match g {
        0 => [
            [lin(&[(0, 1)]), lin(&[(3, 1)]), zero, zero],
            [lin(&[(1, 1)]), lin(&[(4, 1)]), zero, zero],
            [lin(&[(2, 1)]), lin(&[(5, 1)]), zero, zero],
        ],
        1 => [
            [lin(&[(0, 1), (1, 1)]), lin(&[(3, 1), (4, 1)]), zero, zero],
            [lin(&[(1, 1), (2, 1)]), lin(&[(4, 1), (5, 1)]), zero, zero],
            [lin(&[(0, 1), (2, 1)]), lin(&[(3, 1), (5, 1)]), zero, zero],
        ],
        _ => [
            [xy, ym, helpers[1], nxz],
            [yp, ym, helpers[2], xz],
            [yz, yp, xx3, xy],
        ],
    };
    let out_words = match g {
        0 => [ea::XX_WORD, ea::YY_WORD, ea::ZZ_WORD],
        1 => [ea::M4_WORD, ea::M5_WORD, ea::M6_WORD],
        _ => [ea::X1_WORD, ea::Y1_WORD, ea::Z1_WORD],
    };

    let slots: [EcAddSlot; ea::GROUPS] = core::array::from_fn(|slot| {
        let operands = schedule[slot];
        let result: [u64; ea::LIMBS] =
            core::array::from_fn(|k| frames.word(out_words[slot] + k).write_value[r] as u64);
        let (q, carries) = ec_add_witness(&m, &operands, &result);
        let (d, b) = borrow_chain_against(&result, &m);
        EcAddSlot {
            operands,
            out: result,
            q,
            carries,
            chain: (
                core::array::from_fn(|i| d[i]),
                core::array::from_fn(|i| b[i]),
            ),
        }
    });

    EcAddRow {
        code,
        m,
        b3,
        helpers,
        chains,
        slots,
    }
}

/// One slot's quotient and carries, from the limb identity
/// `A*B + C*D + 1024*m^2 = q*m + out`.
///
/// The positions are computed first as unnormalized signed sums — every one
/// below `2^80`, which an `i128` holds — then normalized into the non-negative
/// big integer `N = A*B + C*D + 1024*m^2 - out`, which is `q*m` exactly, and
/// divided. The carries then fall out of the identity position by position,
/// each an exact division by `2^32`.
fn ec_add_witness(
    m: &[u64; ea::LIMBS],
    operands: &[[i128; ea::LIMBS]; 4],
    result: &[u64; ea::LIMBS],
) -> ([u64; ea::QUOTIENT_LIMBS], [i128; ea::CARRIES]) {
    // `pos[k] = P_k + O_k - out_k`, the identity's left-hand side less the
    // quotient's product.
    let mut pos = [0i128; ea::POSITIONS];
    for i in 0..ea::LIMBS {
        for j in 0..ea::LIMBS {
            let at = i + j;
            pos[at] += operands[0][i] * operands[1][j];
            pos[at] += operands[2][i] * operands[3][j];
            pos[at] += ea::OFFSET_MULTIPLE as i128 * m[i] as i128 * m[j] as i128;
        }
    }
    for k in 0..ea::LIMBS {
        pos[k] -= result[k] as i128;
    }

    // `N`, normalized. It is non-negative because the `1024 * m^2` offset
    // dominates every negative term (`constraints::ec_add`'s
    // `the_carry_offset_covers_every_slot` is the same arithmetic).
    let mut limbs: Vec<u32> = Vec::with_capacity(ea::POSITIONS + 4);
    let mut carry = 0i128;
    for at in pos.iter() {
        let total = at + carry;
        let limb = total.rem_euclid(1i128 << 32);
        limbs.push(limb as u32);
        carry = (total - limb) >> 32;
    }
    while carry != 0 {
        let limb = carry.rem_euclid(1i128 << 32);
        limbs.push(limb as u32);
        carry = (carry - limb) >> 32;
    }
    assert!(
        carry == 0,
        "ec_add: the identity's left-hand side is negative"
    );

    let modulus: Vec<u32> = m.iter().map(|w| *w as u32).collect();
    let quotient = wide_div(&limbs, &modulus);
    for (i, w) in quotient.iter().enumerate().skip(ea::QUOTIENT_LIMBS) {
        assert_eq!(*w, 0, "ec_add: the quotient needs limb {i}");
    }
    let q: [u64; ea::QUOTIENT_LIMBS] = core::array::from_fn(|i| quotient[i] as u64);

    // The carries, from the identity: `c_k = (pos[k] - S_k + c_{k-1}) / 2^32`.
    let mut carries = [0i128; ea::CARRIES];
    let mut running = 0i128;
    for k in 0..ea::POSITIONS {
        let mut residue = pos[k] + running;
        for (i, qi) in q.iter().enumerate() {
            let Some(j) = k.checked_sub(i) else { continue };
            if j >= ea::LIMBS {
                continue;
            }
            residue -= *qi as i128 * m[j] as i128;
        }
        if k + 1 == ea::POSITIONS {
            assert_eq!(residue, 0, "ec_add: the identity does not close");
        } else {
            assert_eq!(residue % (1i128 << 32), 0, "ec_add: a carry is not exact");
            carries[k] = residue >> 32;
            running = carries[k];
        }
    }
    (q, carries)
}

/// Whether `x < y` over eight little-endian 32-bit limbs.
fn below(x: &[u64; mm::LIMBS], y: &[u64; mm::LIMBS]) -> bool {
    for k in (0..mm::LIMBS).rev() {
        if x[k] != y[k] {
            return x[k] < y[k];
        }
    }
    false
}

/// The quotient and the fifteen signed carries of `a * b = q * m + out`.
///
/// `q` is the schoolbook long division of the 512-bit product by `m`, computed
/// the same way `emulator::mod_mul_frame` computes the remainder, and the
/// carries are then read straight off the limb identity the circuit states:
/// `c_k = (P_k - S_k - out_k + c_{k-1}) / 2^32`, exactly, because the identity
/// holds over the integers.
///
/// Panics unless every division is exact and the last carry is zero, which is
/// the identity itself: a nonzero last carry would mean `a * b - q * m - out` is
/// a nonzero multiple of `2^480`.
fn mod_mul_witness(
    m: &[u64; mm::LIMBS],
    a: &[u64; mm::LIMBS],
    b: &[u64; mm::LIMBS],
    result: &[u64; mm::LIMBS],
) -> (Vec<u64>, Vec<i128>) {
    let big = |limbs: &[u64; mm::LIMBS]| -> Vec<u32> { limbs.iter().map(|w| *w as u32).collect() };
    let q = wide_div(&wide_mul(&big(a), &big(b)), &big(m));
    let q: [u64; mm::LIMBS] = core::array::from_fn(|k| q[k] as u64);

    let part = |x: &[u64; mm::LIMBS], y: &[u64; mm::LIMBS], k: usize| -> i128 {
        (0..mm::LIMBS)
            .filter_map(|i| k.checked_sub(i).filter(|j| *j < mm::LIMBS).map(|j| (i, j)))
            .map(|(i, j)| x[i] as i128 * y[j] as i128)
            .sum()
    };
    let mut carries: Vec<i128> = Vec::with_capacity(mm::CARRIES);
    let mut carry = 0i128;
    for k in 0..mm::POSITIONS {
        let mut lhs = part(a, b, k) - part(&q, m, k) + carry;
        // The result has eight limbs and there are fifteen positions, so the top
        // seven subtract nothing — which is what `result.get` says in one line.
        if let Some(limb) = result.get(k) {
            lhs -= *limb as i128;
        }
        let radix = 1i128 << 32;
        assert_eq!(
            lhs.rem_euclid(radix),
            0,
            "mod_mul: position {k}'s identity does not divide"
        );
        carry = lhs / radix;
        if k < mm::CARRIES {
            assert!(
                carry.unsigned_abs() < mm::CARRY_OFFSET as u128,
                "mod_mul: carry {k} is {carry}, outside the offset"
            );
            carries.push(carry);
        }
    }
    assert_eq!(carry, 0, "mod_mul: the identity leaves a carry");
    (q.to_vec(), carries)
}

/// `x * y` over eight 32-bit limbs, as sixteen.
fn wide_mul(x: &[u32], y: &[u32]) -> Vec<u32> {
    let mut out = vec![0u64; 2 * mm::LIMBS];
    for (i, xi) in x.iter().enumerate() {
        let mut carry = 0u64;
        for (j, yj) in y.iter().enumerate() {
            let total = out[i + j] + *xi as u64 * *yj as u64 + carry;
            out[i + j] = total & 0xffff_ffff;
            carry = total >> 32;
        }
        let mut at = i + y.len();
        while carry != 0 {
            let total = out[at] + carry;
            out[at] = total & 0xffff_ffff;
            carry = total >> 32;
            at += 1;
        }
    }
    out.into_iter().map(|w| w as u32).collect()
}

/// `x / m` over little-endian 32-bit limbs, by shift-and-subtract from the top.
///
/// The quotient has as many limbs as `x`; the caller takes the low eight,
/// which is exact for **every** frame the circuit accepts, not merely for an
/// honest prover's: `a < m` and `b < m` are gates since S26b, so
/// `q = (a·b − out)/m < m <= 2^256` and the high eight limbs are zero
/// (`crates/constraints/src/mod_mul.rs`' soundness note). The caller asserts
/// the two operand bounds before reaching here, so a truncation would be a
/// panic upstream and never a silent one.
fn wide_div(x: &[u32], m: &[u32]) -> Vec<u32> {
    let mut quotient = vec![0u32; x.len()];
    let mut rem = vec![0u64; m.len() + 1];
    for bit in (0..32 * x.len()).rev() {
        let mut carry = ((x[bit / 32] >> (bit % 32)) & 1) as u64;
        for word in rem.iter_mut() {
            let total = (*word << 1) | carry;
            *word = total & 0xffff_ffff;
            carry = total >> 32;
        }
        let fits = rem[m.len()] != 0
            || (0..m.len())
                .rev()
                .find(|k| rem[*k] != m[*k] as u64)
                .is_none_or(|k| rem[k] > m[k] as u64);
        if fits {
            let mut borrow = 0i64;
            for k in 0..m.len() {
                let diff = rem[k] as i64 - m[k] as i64 - borrow;
                borrow = i64::from(diff < 0);
                rem[k] = (diff + if diff < 0 { 1i64 << 32 } else { 0 }) as u64;
            }
            rem[m.len()] -= borrow as u64;
            quotient[bit / 32] |= 1 << (bit % 32);
        }
    }
    quotient
}

/// The borrow chain of `x - y` over eight 32-bit limbs: the difference limbs and
/// the borrows, the last of which is 1 exactly when `x < y`.
///
/// `delegation_frame`'s `borrow_chain` is the same computation against `p`'s
/// literal limbs, which is what `FR_ARITH`'s canonicity needs; this one takes
/// the subtrahend as data, because `MOD_MUL`'s modulus is one of four and the
/// row's selector says which. **Never substitute the other one here**: it
/// chains against `constants::FR_MODULUS`, which is right for exactly one of
/// the four selectors and silently wrong for the other three.
fn borrow_chain_against(
    x: &[u64; mm::LIMBS],
    y: &[u64; mm::LIMBS],
) -> ([u64; mm::LIMBS], [u64; mm::LIMBS]) {
    let (mut diff, mut borrow) = ([0u64; mm::LIMBS], [0u64; mm::LIMBS]);
    let mut carry = 0i64;
    for i in 0..mm::LIMBS {
        let d = x[i] as i64 - y[i] as i64 - carry;
        carry = i64::from(d < 0);
        diff[i] = if d < 0 {
            (d + (1i64 << 32)) as u64
        } else {
            d as u64
        };
        borrow[i] = carry as u64;
    }
    (diff, borrow)
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
/// words at the shard's opening point, so this is the one place the prover can
/// put the bytes and have the proof verify
/// (`docs/spec/public-values.md` §5).
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

fn u32_column(mut values: Vec<u32>, height: usize) -> MultilinearPoly {
    values.resize(height, 0);
    MultilinearPoly::new(PolyBacking::U32(values))
}

fn fr_column(mut values: Vec<Fr>, height: usize) -> MultilinearPoly {
    values.resize(height, Fr::ZERO);
    MultilinearPoly::new(PolyBacking::Fr(values))
}

/// A signed integer as a field element. Every value a fill hands to an `Fr`
/// column is a product or a sign-adjusted operand, so it fits an `i128` and is
/// far below the modulus either way.
fn signed(v: i128) -> Fr {
    let magnitude = |m: u128| {
        let shift = Fr::from_u64(1 << 32) * Fr::from_u64(1 << 32);
        Fr::from_u64((m >> 64) as u64) * shift + Fr::from_u64(m as u64)
    };
    match v < 0 {
        true => -magnitude(v.unsigned_abs()),
        false => magnitude(v as u128),
    }
}

/// An `ADD_SUB_LUI_AUIPC` shard, `docs/spec/shard-proof.md` §8.1: S14's frame
/// columns over the shard's cycles, the decoded row each cycle's pc claims, the
/// kind bits, the system split, the computed `rd` value with its wrap and high
/// halfword — written over the frame's `rd_selected`, which S14's builder
/// leaves 0 on an `x0` write — `next_pc`'s wrap and high halfword, and the
/// family's decoded table as `S[0..7]`.
///
/// Refuses, naming the cycle, an ecall other than `EXIT`: S16 proves no other.
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, an `rd` write or a `next_pc` that is not what the
/// instruction computes — which the emulator cannot produce.
fn add_sub(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::ADD_SUB_LUI_AUIPC;
    let rows = src.cycles(fam)?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no ADD_SUB_LUI_AUIPC table")?;
    let h = src.height;
    let width = frame_queries(fam).len();

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 6] = Default::default();
    let (mut is_ecall, mut is_fence, mut wrap) = (Vec::new(), Vec::new(), Vec::new());
    let mut is_deleg: [Vec<u32>; constraints::add_sub::IS_DELEGATION.len()] = Default::default();
    let (mut sel, mut rd_hi, mut next_pc_hi) = (Vec::new(), Vec::new(), Vec::new());
    for r in 0..rows.len() {
        let row = rows.row(r);
        let slot = row.pc as usize / 2;
        let field = |column: usize| {
            table.get(column, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the ADD_SUB_LUI_AUIPC table does not hold",
                    row.cycle, row.pc
                )
            })
        };
        // lookup_tuple: pc next_pc rs1 rs2 rd imm extra_mask.
        let row_values = [field(1), field(2), field(3), field(4), field(5), field(6)];
        let (fall, imm, mask) = (row_values[0], row_values[4], row_values[5]);
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        let (a, b) = (read(Role::Rs1), read(Role::Rs2));
        let bit = mask.trailing_zeros();
        let (mut ecall_row, mut fence_row) = (0, 0);
        // One selector per delegation type, in `IS_DELEGATION` order.
        let mut deleg_row = [0u32; constraints::add_sub::IS_DELEGATION.len()];
        let (value, carry) = match bit {
            kind::ADD => add(a, b),
            kind::ADDI => add(a, imm),
            kind::AUIPC => add(row.pc, imm),
            kind::SUB => (a.wrapping_sub(b), (a < b) as u32),
            kind::LUI => (imm, 0),
            kind::SYSTEM => match imm {
                system_code::ECALL if a == ecall::EXIT => {
                    ecall_row = 1;
                    (read(Role::Rd), 0)
                }
                // A delegation request: it writes no register, so its
                // `rd_selected` is 0, and its `next_pc` is the fall-through —
                // it is not an exit (`docs/spec/delegation.md` §5.2).
                system_code::ECALL if program::delegation_family(a).is_some() => {
                    let at = program::DELEGATIONS
                        .iter()
                        .position(|(_, n, ..)| *n == a)
                        .expect("just matched");
                    deleg_row[at] = 1;
                    (0, 0)
                }
                system_code::ECALL => {
                    return Err(format!(
                        "cycle {} calls ecall {a}, which no family proves",
                        row.cycle
                    ))
                }
                system_code::FENCE => {
                    fence_row = 1;
                    (0, 0)
                }
                other => panic!("cycle {} is a system row with code {other}", row.cycle),
            },
            other => panic!("cycle {} has kind bit {other}", row.cycle),
        };
        if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value, value,
                "cycle {}: the trace's rd write is not what the instruction computes",
                row.cycle
            );
        }
        let want_next = match ecall_row {
            1 => memory::HALT_PC,
            _ => fall,
        };
        assert_eq!(
            row.next_pc, want_next,
            "cycle {}: the trace's next_pc is not the family's",
            row.cycle
        );
        for (column, v) in decoded.iter_mut().zip(row_values) {
            column.push(v);
        }
        for (k, column) in kinds.iter_mut().enumerate() {
            column.push((k as u32 == bit) as u32);
        }
        let requests: u32 = deleg_row.iter().sum();
        is_ecall.push(ecall_row | requests);
        for (column, v) in is_deleg.iter_mut().zip(deleg_row) {
            column.push(v);
        }
        // `deleg_space`, the `M` column the mirror's leaf reads, is not this
        // fill's: `trace::build_memory_columns` writes it from the mirror
        // event's own address space. What ties the two together is the
        // registry — `deleg_space_rule` asks for `Σ tag_t·is_deleg_t`, and the
        // event's space is that family's tag — so a disagreement between them
        // is a disagreement inside `constants::delegation::TYPES`.
        is_fence.push(fence_row);
        wrap.push(carry);
        sel.push(value);
        rd_hi.push(value >> 16);
        next_pc_hi.push(row.next_pc >> 16);
    }

    let mut out = frame_columns(src, fam, rows);
    out.push((rd_selected(width), u32_column(sel, h)));
    for (address, values) in DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    // **The request side of the anchor pairing, counted.** An invocation's
    // partner is a request row in *this* family, and nothing else in the
    // repository counts them: a dropped invocation surfaces as
    // `MemoryArgument("the statement's roots do not reconcile")` over a
    // thirteen-shard product, naming no family and no row. Σ requests per type
    // over this family's shards must equal that delegation family's invocation
    // count (`apogee deleg … invocations=`), and Σ exit rows over the whole
    // execution is exactly 1 — the one row that writes `HALT_PC`.
    debug_only!(
        if debug::enabled_for(debug::Level::Detail, family::ADD_SUB_LUI_AUIPC) {
            let requests: Vec<usize> = is_deleg
                .iter()
                .map(|column| column.iter().filter(|v| **v == 1).count())
                .collect();
            let names: Vec<String> = program::DELEGATIONS
                .iter()
                .map(|(f, ..)| debug::family_name(*f))
                .collect();
            let labels: Vec<&str> = names.iter().map(String::as_str).collect();
            let ecalls: usize = is_ecall.iter().filter(|v| **v == 1).count();
            let total: usize = requests.iter().sum();
            debug::line(&format!(
                "apogee deleg    {:<22} {} exit-rows={}",
                debug::shard(family::ADD_SUB_LUI_AUIPC, src.index),
                debug::histogram("requests", &labels, &requests),
                ecalls.saturating_sub(total)
            ));
        }
    );
    out.push((IS_ECALL, u32_column(is_ecall, h)));
    out.push((IS_FENCE, u32_column(is_fence, h)));
    for (address, values) in constraints::add_sub::IS_DELEGATION.iter().zip(is_deleg) {
        out.push((*address, u32_column(values, h)));
    }
    out.push((WRAP, u32_column(wrap, h)));
    out.push((RD_HI, u32_column(rd_hi, h)));
    out.push((PC_WRAP, u32_column(Vec::new(), h)));
    out.push((NEXT_PC_HI, u32_column(next_pc_hi, h)));
    for j in 0..TABLE_WIDTH {
        out.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    Ok(out)
}

/// `a + b` mod `2^32`, and its carry.
fn add(a: u32, b: u32) -> (u32, u32) {
    let (sum, carry) = a.overflowing_add(b);
    (sum, carry as u32)
}

/// A `JUMP_BRANCH_SLT` shard, `docs/spec/jump-branch-slt.md` §2: S14's frame
/// columns over the shard's cycles; the decoded row each cycle's pc claims and
/// its kind bits; the comparison of `rs1` against `cmp_rhs` — the operands'
/// high halfwords and signs, `lt`, the gap and its high halfword; `eq` and the
/// inverse of `rs1 − cmp_rhs`; `taken`; `jalr`'s dropped bit, the wrap of
/// whichever sum `next_pc` is and its high halfword; the written `rd` value
/// over the frame's `rd_selected`, which S14's builder leaves 0 on an `x0`
/// write, and its high halfword; the family's decoded table as `S[0..7]` and
/// the packed generic table as `S[7..10]`.
///
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, an `rd` write or a `next_pc` that is not what the
/// instruction computes — which the emulator cannot produce.
fn jump_branch_slt(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::JUMP_BRANCH_SLT;
    let rows = src.cycles(fam)?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no JUMP_BRANCH_SLT table")?;
    let h = src.height;
    let width = frame_queries(fam).len();

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 12] = Default::default();
    // cmp_rhs rs1_hi rs1_sign cmp_rhs_hi cmp_rhs_sign lt cmp_gap cmp_gap_hi
    // eq taken jalr_drop pc_wrap next_pc_hi rd_hi, then rd_selected.
    let mut cells: [Vec<u32>; 15] = Default::default();
    let mut eq_inv = Vec::new();
    for r in 0..rows.len() {
        let row = rows.row(r);
        let slot = row.pc as usize / 2;
        let field = |column: usize| {
            table.get(column, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the JUMP_BRANCH_SLT table does not hold",
                    row.cycle, row.pc
                )
            })
        };
        // lookup_tuple: pc next_pc rs1 rs2 rd imm extra_mask.
        let row_values = [field(1), field(2), field(3), field(4), field(5), field(6)];
        let (seq, imm, mask) = (row_values[0], row_values[4], row_values[5]);
        let bit = mask.trailing_zeros();
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        let a = read(Role::Rs1);
        // An I-type comparison's absent rs2 reads 0, so its right operand is
        // the immediate; every other kind compares against rs2.
        let rhs = match bit {
            jbs::SLTI | jbs::SLTIU => read(Role::Rs2) + imm,
            _ => read(Role::Rs2),
        };
        let lt = match bit {
            jbs::SLTI | jbs::SLT | jbs::BLT | jbs::BGE => (a as i32) < (rhs as i32),
            _ => a < rhs,
        };
        let eq = a == rhs;
        let taken = match bit {
            jbs::BEQ => eq,
            jbs::BNE => !eq,
            jbs::BLT | jbs::BLTU => lt,
            jbs::BGE | jbs::BGEU => !lt,
            _ => false,
        };
        let (next, wrap, drop) = match bit {
            _ if bit == jbs::JAL || taken => {
                let (target, carry) = add(row.pc, imm);
                (target, carry, 0)
            }
            jbs::JALR => {
                let (sum, carry) = add(a, imm);
                (sum & !1, carry, sum & 1)
            }
            _ => (seq, 0, 0),
        };
        assert_eq!(
            row.next_pc, next,
            "cycle {}: the trace's next_pc is not the family's",
            row.cycle
        );
        let sel = match bit {
            jbs::JAL | jbs::JALR => seq,
            jbs::SLTI | jbs::SLTIU | jbs::SLT | jbs::SLTU => lt as u32,
            _ => 0,
        };
        if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value, sel,
                "cycle {}: the trace's rd write is not what the instruction computes",
                row.cycle
            );
        }
        let gap = a.wrapping_sub(rhs);
        let values = [
            rhs,
            a >> 16,
            a >> 31,
            rhs >> 16,
            rhs >> 31,
            lt as u32,
            gap,
            gap >> 16,
            eq as u32,
            taken as u32,
            drop,
            wrap,
            next >> 16,
            sel >> 16,
            sel,
        ];
        for (column, v) in cells.iter_mut().zip(values) {
            column.push(v);
        }
        eq_inv.push(
            (Fr::from_u64(a as u64) - Fr::from_u64(rhs as u64))
                .inverse()
                .unwrap_or(Fr::ZERO),
        );
        for (column, v) in decoded.iter_mut().zip(row_values) {
            column.push(v);
        }
        for (k, column) in kinds.iter_mut().enumerate() {
            column.push((k as u32 == bit) as u32);
        }
    }

    let mut out = frame_columns(src, fam, rows);
    let [cmp_rhs, rs1_hi, rs1_sign, rhs_hi, rhs_sign, lt, gap, gap_hi, eq, taken, drop, wrap, next_hi, rd_hi, sel] =
        cells;
    out.push((rd_selected(width), u32_column(sel, h)));
    for (address, values) in jbs_circuit::DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in jbs_circuit::KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in [
        (jbs_circuit::CMP_RHS, cmp_rhs),
        (jbs_circuit::RS1_HI, rs1_hi),
        (jbs_circuit::RS1_SIGN, rs1_sign),
        (jbs_circuit::CMP_RHS_HI, rhs_hi),
        (jbs_circuit::CMP_RHS_SIGN, rhs_sign),
        (jbs_circuit::LT, lt),
        (jbs_circuit::CMP_GAP, gap),
        (jbs_circuit::CMP_GAP_HI, gap_hi),
        (jbs_circuit::EQ, eq),
        (jbs_circuit::TAKEN, taken),
        (jbs_circuit::JALR_DROP, drop),
        (jbs_circuit::PC_WRAP, wrap),
        (jbs_circuit::NEXT_PC_HI, next_hi),
        (jbs_circuit::RD_HI, rd_hi),
    ] {
        out.push((address, u32_column(values, h)));
    }
    eq_inv.resize(h, Fr::ZERO);
    out.push((
        jbs_circuit::EQ_INV,
        MultilinearPoly::new(PolyBacking::Fr(eq_inv)),
    ));
    for j in 0..jbs_circuit::TABLE_WIDTH {
        out.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    let generic = generic_table(h.trailing_zeros());
    for (address, column) in jbs_circuit::GENERIC_TABLE.iter().zip(generic) {
        out.push((*address, column));
    }
    Ok(out)
}

/// A `SHIFT_BITWISE` shard, `docs/spec/shift-bitwise.md` §7: S14's frame
/// columns over the shard's cycles; the decoded row each cycle's pc claims and
/// its kind bits; the two half flags; `rs1`'s halfword and sign and the second
/// operand's halfword; the truncated shift amount with its powers and the bits
/// above it; the shared product with the sign-extension term, the overflow, the
/// residue and its scaling; both operands' bytes and their AND; the written
/// `rd` value over the frame's `rd_selected`, which S14's builder leaves 0 on an
/// `x0` write, and its high halfword; the family's decoded table as `S[0..7]`
/// and the packed generic table as `S[7..10]`.
///
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, an `rd` write or a `next_pc` that is not what the
/// instruction computes, or a row carrying both a register `rs2` and an
/// immediate — which the emulator cannot produce.
fn shift_bitwise(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::SHIFT_BITWISE;
    let rows = src.cycles(fam)?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no SHIFT_BITWISE table")?;
    let h = src.height;
    let width = frame_queries(fam).len();

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 12] = Default::default();
    // f_shift f_bitwise rs1_hi rs1_sign src2_hi amount pow copow high high_hi
    // se ovf ovf_hi residue residue_hi scaled scaled_hi rd_hi, then rd_selected.
    let mut cells: [Vec<u32>; 19] = Default::default();
    let mut bytes: [Vec<u32>; 12] = Default::default();
    let (mut shift_in, mut shift_prod) = (Vec::new(), Vec::new());
    for r in 0..rows.len() {
        let row = rows.row(r);
        let slot = row.pc as usize / 2;
        let field = |column: usize| {
            table.get(column, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the SHIFT_BITWISE table does not hold",
                    row.cycle, row.pc
                )
            })
        };
        // lookup_tuple: pc next_pc rs1 rs2 rd imm extra_mask.
        let row_values = [field(1), field(2), field(3), field(4), field(5), field(6)];
        let (fall, imm, mask) = (row_values[0], row_values[4], row_values[5]);
        let bit = mask.trailing_zeros();
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        let (a, b) = (read(Role::Rs1), read(Role::Rs2));
        // One of the two addends is always zero — an I-type row makes no rs2
        // query and an R-type row's decoded immediate is 0 — which is what
        // makes `rs2 + imm` one expression for both operand shapes and keeps
        // the field sum a 32-bit word.
        assert!(
            b == 0 || imm == 0,
            "cycle {}: a SHIFT_BITWISE row carries both a register rs2 and an immediate",
            row.cycle
        );
        let src2 = b + imm;
        let amount = src2 & 31;
        let (pow, copow) = (1u32 << amount, 1u32 << (31 - amount));
        let is_shift = matches!(
            bit,
            sb::SLLI | sb::SRLI | sb::SRAI | sb::SLL | sb::SRL | sb::SRA
        );
        let is_arithmetic = matches!(bit, sb::SRAI | sb::SRA);
        let se = (is_arithmetic && a >> 31 == 1) as u32;
        let value = match bit {
            sb::SLLI | sb::SLL => a << amount,
            sb::SRLI | sb::SRL => a >> amount,
            sb::SRAI | sb::SRA => ((a as i32) >> amount) as u32,
            sb::ANDI | sb::AND => a & src2,
            sb::ORI | sb::OR => a | src2,
            sb::XORI | sb::XOR => a ^ src2,
            other => panic!("cycle {} has kind bit {other}", row.cycle),
        };
        // The one product: `rs1·2^s` on a left shift, `rd_adj·2^s` on a right
        // one, and nothing on a bitwise row, whose looked-up pair is zero.
        let word = 1i64 << 32;
        let (input, ovf, residue) = match bit {
            sb::SLLI | sb::SLL => {
                let product = a as i64 * pow as i64;
                (a as i64, (product >> 32) as u32, 0)
            }
            sb::SRLI | sb::SRL | sb::SRAI | sb::SRA => {
                let rd_adj = value as i64 - se as i64 * word;
                let rs1_adj = a as i64 - se as i64 * word;
                let residue = rs1_adj - rd_adj * pow as i64;
                assert!(
                    (0..pow as i64).contains(&residue),
                    "cycle {}: the shift's residue is not below its power",
                    row.cycle
                );
                (rd_adj, 0, residue as u32)
            }
            _ => (0, 0, 0),
        };
        let (pow, copow) = match is_shift {
            true => (pow, copow),
            // A bitwise row looks nothing up, and `pow·copow = 2^31·f_shift`
            // holds there only at zero.
            false => (0, 0),
        };
        let product = input * pow as i64;
        let scaled = 2 * residue as u64 * copow as u64;
        if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value, value,
                "cycle {}: the trace's rd write is not what the instruction computes",
                row.cycle
            );
        }
        assert_eq!(
            row.next_pc, fall,
            "cycle {}: the trace's next_pc is not the decoded fall-through",
            row.cycle
        );
        let values = [
            is_shift as u32,
            !is_shift as u32,
            a >> 16,
            a >> 31,
            src2 >> 16,
            amount,
            pow,
            copow,
            src2 >> 5,
            (src2 >> 5) >> 16,
            se,
            ovf,
            ovf >> 16,
            residue,
            residue >> 16,
            scaled as u32,
            (scaled >> 16) as u32,
            value >> 16,
            value,
        ];
        for (column, v) in cells.iter_mut().zip(values) {
            column.push(v);
        }
        for j in 0..4 {
            let (byte_a, byte_b) = ((a >> (8 * j)) & 0xff, (src2 >> (8 * j)) & 0xff);
            bytes[j].push(byte_a);
            bytes[4 + j].push(byte_b);
            bytes[8 + j].push(byte_a & byte_b);
        }
        shift_in.push(signed(input as i128));
        shift_prod.push(signed(product as i128));
        for (column, v) in decoded.iter_mut().zip(row_values) {
            column.push(v);
        }
        for (k, column) in kinds.iter_mut().enumerate() {
            column.push((k as u32 == bit) as u32);
        }
    }

    let mut out = frame_columns(src, fam, rows);
    let [f_shift, f_bitwise, rs1_hi, rs1_sign, src2_hi, amount, pow, copow, high, high_hi, se, ovf, ovf_hi, residue, residue_hi, scaled, scaled_hi, rd_hi, sel] =
        cells;
    out.push((rd_selected(width), u32_column(sel, h)));
    for (address, values) in sb_circuit::DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in sb_circuit::KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in [
        (sb_circuit::F_SHIFT, f_shift),
        (sb_circuit::F_BITWISE, f_bitwise),
        (sb_circuit::RS1_HI, rs1_hi),
        (sb_circuit::RS1_SIGN, rs1_sign),
        (sb_circuit::SRC2_HI, src2_hi),
        (sb_circuit::AMOUNT, amount),
        (sb_circuit::POW, pow),
        (sb_circuit::COPOW, copow),
        (sb_circuit::HIGH, high),
        (sb_circuit::HIGH_HI, high_hi),
        (sb_circuit::SE, se),
        (sb_circuit::OVF, ovf),
        (sb_circuit::OVF_HI, ovf_hi),
        (sb_circuit::RESIDUE, residue),
        (sb_circuit::RESIDUE_HI, residue_hi),
        (sb_circuit::SCALED, scaled),
        (sb_circuit::SCALED_HI, scaled_hi),
        (sb_circuit::RD_HI, rd_hi),
    ] {
        out.push((address, u32_column(values, h)));
    }
    let mut bytes = bytes.into_iter();
    for group in [
        sb_circuit::BYTES_A,
        sb_circuit::BYTES_B,
        sb_circuit::BYTES_AND,
    ] {
        for address in group {
            let values = bytes.next().expect("twelve byte columns");
            out.push((address, u32_column(values, h)));
        }
    }
    out.push((sb_circuit::SHIFT_IN, fr_column(shift_in, h)));
    out.push((sb_circuit::SHIFT_PROD, fr_column(shift_prod, h)));
    for j in 0..sb_circuit::TABLE_WIDTH {
        out.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    let generic = generic_table(h.trailing_zeros());
    for (address, column) in sb_circuit::GENERIC_TABLE.iter().zip(generic) {
        out.push((*address, column));
    }
    Ok(out)
}

/// A `MUL_DIV` shard, `docs/spec/mul-div.md` §7: S14's frame columns over the
/// shard's cycles; the decoded row each cycle's pc claims — **five values, not
/// six**: this family's tuple has no immediate — and its kind bits; the
/// division flag; both operands' halfwords, top bits and sign adjustments; the
/// one product's multiplicands, its two halves and its sign; the division
/// witness with its two is-zero gadgets and the magnitude gap; the written `rd`
/// value over the frame's `rd_selected`, which S14's builder leaves 0 on an
/// `x0` write, and its high halfword; the family's decoded table as `S[0..6]`
/// and the packed generic table as `S[6..9]`.
///
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, an `rd` write or a `next_pc` that is not what the
/// instruction computes — which the emulator cannot produce.
fn mul_div(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::MUL_DIV;
    let rows = src.cycles(fam)?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no MUL_DIV table")?;
    let h = src.height;
    let width = frame_queries(fam).len();

    let mut decoded: [Vec<u32>; 5] = Default::default();
    let mut kinds: [Vec<u32>; 8] = Default::default();
    // f_div rs1_hi rs1_top rs2_hi rs2_top s1 s2 p_low p_low_hi p_high
    // p_high_hi p_sign q q_hi q_sign r r_hi r_sign rz d1 dz abs_r abs_d gap
    // gap_hi rd_hi, then rd_selected.
    let mut cells: [Vec<u32>; 27] = Default::default();
    let (mut mx_col, mut my_col) = (Vec::new(), Vec::new());
    let (mut r_inv_col, mut d_inv_col) = (Vec::new(), Vec::new());
    let word = 1i128 << 32;
    for row_index in 0..rows.len() {
        let row = rows.row(row_index);
        let slot = row.pc as usize / 2;
        let field = |column: usize| {
            table.get(column, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the MUL_DIV table does not hold",
                    row.cycle, row.pc
                )
            })
        };
        // lookup_tuple: pc next_pc rs1 rs2 rd extra_mask — six columns.
        let row_values = [field(1), field(2), field(3), field(4), field(5)];
        let (fall, mask) = (row_values[0], row_values[4]);
        let bit = mask.trailing_zeros();
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        let (a, b) = (read(Role::Rs1), read(Role::Rs2));

        // Each operand's sign adjustment: `mulhsu` is the asymmetric one, and
        // every unsigned position takes 0 whatever the operand's top bit.
        let lhs_signed = matches!(bit, md::MUL | md::MULH | md::MULHSU | md::DIV | md::REM);
        let rhs_signed = matches!(bit, md::MUL | md::MULH | md::DIV | md::REM);
        let s1 = (lhs_signed && a >> 31 == 1) as u32;
        let s2 = (rhs_signed && b >> 31 == 1) as u32;
        let rs1_adj = a as i128 - s1 as i128 * word;
        let rs2_adj = b as i128 - s2 as i128 * word;

        // The division witness, RV32M's exactly: a zero divisor gives a
        // quotient of all ones and the dividend back, and `−2^31 ÷ −1` gives
        // `−2^31` and 0, which `wrapping_div` and `wrapping_rem` are.
        let is_div = matches!(bit, md::DIV | md::DIVU | md::REM | md::REMU);
        let signed_div = matches!(bit, md::DIV | md::REM);
        let (q_word, r_word) = match (is_div, b, signed_div) {
            (false, _, _) => (0, 0),
            (true, 0, _) => (u32::MAX, a),
            (true, _, true) => (
                (a as i32).wrapping_div(b as i32) as u32,
                (a as i32).wrapping_rem(b as i32) as u32,
            ),
            (true, _, false) => (a / b, a % b),
        };
        let rz = (is_div && r_word == 0) as u32;
        let dz = (is_div && b == 0) as u32;
        let d1 = is_div as u32 * s1;
        // The remainder's sign is not its word's top bit: it is 1 exactly
        // where the dividend is negative and the remainder is not zero, which
        // is what makes the division truncated rather than floored.
        let r_sign = d1 * (1 - rz);
        let r_adj = r_word as i128 - r_sign as i128 * word;
        // On a zero divisor the identity says nothing about the quotient — the
        // pin fixes its word and leaves its sign free — and everywhere else
        // the identity determines it exactly.
        let q_adj = match (is_div, b) {
            (false, _) => 0,
            (true, 0) => q_word as i128,
            (true, _) => {
                let numerator = rs1_adj - r_adj;
                assert_eq!(
                    numerator % rs2_adj,
                    0,
                    "cycle {}: the division identity does not divide",
                    row.cycle
                );
                numerator / rs2_adj
            }
        };
        let q_sign = (q_adj < 0) as u32;
        assert_eq!(
            q_word as i128,
            q_adj + q_sign as i128 * word,
            "cycle {}: the quotient's word is not its adjusted value",
            row.cycle
        );

        // ONE product: the two operands on a multiply row, the divisor and the
        // quotient on a division one.
        let (mx, my) = match is_div {
            true => (rs2_adj, q_adj),
            false => (rs1_adj, rs2_adj),
        };
        let product = mx * my;
        let p_sign = (product < 0) as u32;
        let shifted = product + p_sign as i128 * (word * word);
        assert!(
            (0..word * word).contains(&shifted),
            "cycle {}: the product does not fit two words",
            row.cycle
        );
        let (p_low, p_high) = (shifted as u32, (shifted >> 32) as u32);

        let abs_r = r_adj.unsigned_abs() as u64;
        let abs_d = rs2_adj.unsigned_abs() as u64;
        let gap = match is_div {
            false => 0,
            true => abs_d + (dz as u64) * (1 << 32) - abs_r - 1,
        };
        let value = match bit {
            md::MUL => p_low,
            md::MULH | md::MULHSU | md::MULHU => p_high,
            md::DIV | md::DIVU => q_word,
            md::REM | md::REMU => r_word,
            other => panic!("cycle {} has kind bit {other}", row.cycle),
        };
        if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value, value,
                "cycle {}: the trace's rd write is not what the instruction computes",
                row.cycle
            );
        }
        assert_eq!(
            row.next_pc, fall,
            "cycle {}: the trace's next_pc is not the decoded fall-through",
            row.cycle
        );
        let values = [
            is_div as u32,
            a >> 16,
            a >> 31,
            b >> 16,
            b >> 31,
            s1,
            s2,
            p_low,
            p_low >> 16,
            p_high,
            p_high >> 16,
            p_sign,
            q_word,
            q_word >> 16,
            q_sign,
            r_word,
            r_word >> 16,
            r_sign,
            rz,
            d1,
            dz,
            abs_r as u32,
            abs_d as u32,
            gap as u32,
            (gap >> 16) as u32,
            value >> 16,
            value,
        ];
        for (column, v) in cells.iter_mut().zip(values) {
            column.push(v);
        }
        mx_col.push(signed(mx));
        my_col.push(signed(my));
        let unit = |on: bool, x: u32| match on {
            true => Fr::from_u64(x as u64).inverse().unwrap_or(Fr::ZERO),
            false => Fr::ZERO,
        };
        r_inv_col.push(unit(is_div, r_word));
        d_inv_col.push(unit(is_div, b));
        for (column, v) in decoded.iter_mut().zip(row_values) {
            column.push(v);
        }
        for (k, column) in kinds.iter_mut().enumerate() {
            column.push((k as u32 == bit) as u32);
        }
    }

    let mut out = frame_columns(src, fam, rows);
    let [f_div, rs1_hi, rs1_top, rs2_hi, rs2_top, s1, s2, p_low, p_low_hi, p_high, p_high_hi, p_sign, q, q_hi, q_sign, r, r_hi, r_sign, rz, d1, dz, abs_r, abs_d, gap, gap_hi, rd_hi, sel] =
        cells;
    out.push((rd_selected(width), u32_column(sel, h)));
    for (address, values) in md_circuit::DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in md_circuit::KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in [
        (md_circuit::F_DIV, f_div),
        (md_circuit::RS1_HI, rs1_hi),
        (md_circuit::RS1_TOP, rs1_top),
        (md_circuit::RS2_HI, rs2_hi),
        (md_circuit::RS2_TOP, rs2_top),
        (md_circuit::S1, s1),
        (md_circuit::S2, s2),
        (md_circuit::P_LOW, p_low),
        (md_circuit::P_LOW_HI, p_low_hi),
        (md_circuit::P_HIGH, p_high),
        (md_circuit::P_HIGH_HI, p_high_hi),
        (md_circuit::P_SIGN, p_sign),
        (md_circuit::Q, q),
        (md_circuit::Q_HI, q_hi),
        (md_circuit::Q_SIGN, q_sign),
        (md_circuit::R, r),
        (md_circuit::R_HI, r_hi),
        (md_circuit::R_SIGN, r_sign),
        (md_circuit::RZ, rz),
        (md_circuit::D1, d1),
        (md_circuit::DZ, dz),
        (md_circuit::ABS_R, abs_r),
        (md_circuit::ABS_D, abs_d),
        (md_circuit::GAP, gap),
        (md_circuit::GAP_HI, gap_hi),
        (md_circuit::RD_HI, rd_hi),
    ] {
        out.push((address, u32_column(values, h)));
    }
    for (address, values) in [
        (md_circuit::MX, mx_col),
        (md_circuit::MY, my_col),
        (md_circuit::R_INV, r_inv_col),
        (md_circuit::D_INV, d_inv_col),
    ] {
        out.push((address, fr_column(values, h)));
    }
    for j in 0..md_circuit::TABLE_WIDTH {
        out.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    let generic = generic_table(h.trailing_zeros());
    for (address, column) in md_circuit::GENERIC_TABLE.iter().zip(generic) {
        out.push((*address, column));
    }
    Ok(out)
}

/// The frame columns and the frame's own witness columns of a shard of
/// `family`, with `rd_selected` left out: every S19 fill writes the value the
/// instruction **computes** there, while S14's builder leaves 0 on an `x0`
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
        if address != rd_selected(width) {
            out.push((address, column));
        }
    }
    out
}

/// A `MEM_WORD` shard, `docs/spec/memory-ops.md` §3.5: S14's frame columns over
/// the shard's cycles; the decoded row each cycle's pc claims and its two kind
/// bits; the effective address split into `4·word_index` with its wrap bit; and
/// the written `rd` value with its high halfword. The family looks nothing up
/// in the packed generic table, so its setup columns are the decoded table
/// alone.
///
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, an `rd` write or a `next_pc` that is not what the
/// instruction computes, or an unaligned access, which the emulator refuses as
/// a fatal guest error before it stages an event.
fn mem_word(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::MEM_WORD;
    let rows = src.cycles(fam)?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no MEM_WORD table")?;
    let h = src.height;

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 2] = Default::default();
    // wrap word_index word_index_hi rd_hi, then rd_selected.
    let mut cells: [Vec<u32>; 5] = Default::default();
    for r in 0..rows.len() {
        let row = rows.row(r);
        let slot = row.pc as usize / 2;
        let field = |column: usize| {
            table.get(column, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the MEM_WORD table does not hold",
                    row.cycle, row.pc
                )
            })
        };
        // lookup_tuple: pc next_pc rs1 rs2 rd imm extra_mask.
        let row_values = [field(1), field(2), field(3), field(4), field(5), field(6)];
        let (seq, imm, mask) = (row_values[0], row_values[4], row_values[5]);
        let bit = mask.trailing_zeros();
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        let (address, wrap) = add(read(Role::Rs1), imm);
        assert_eq!(
            address % 4,
            0,
            "cycle {}: a MEM_WORD access at {address:#x} is not word-aligned",
            row.cycle
        );
        let sel = match bit == kind_mem::LW {
            true => read(Role::Load),
            false => 0,
        };
        assert_eq!(
            row.next_pc, seq,
            "cycle {}: the trace's next_pc is not the decoded fall-through",
            row.cycle
        );
        if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value, sel,
                "cycle {}: the trace's rd write is not what the instruction computes",
                row.cycle
            );
        }
        // `word_addr_rule` ties every RAM query's address to `4·word_index`,
        // so the fill holds the trace to it rather than to alignment alone.
        for role in [Role::Load, Role::Ram] {
            if let Some(q) = row.query(role) {
                assert_eq!(
                    q.addr, address,
                    "cycle {}: a {role:?} query's address is not the effective address",
                    row.cycle
                );
            }
        }
        if let Some(ram) = row.query(Role::Ram) {
            assert_eq!(
                ram.write_value,
                read(Role::Rs2),
                "cycle {}: the trace's stored word is not rs2",
                row.cycle
            );
        }
        let values = [wrap, address / 4, (address / 4) >> 16, sel >> 16, sel];
        for (column, v) in cells.iter_mut().zip(values) {
            column.push(v);
        }
        for (column, v) in decoded.iter_mut().zip(row_values) {
            column.push(v);
        }
        for (k, column) in kinds.iter_mut().enumerate() {
            column.push((k as u32 == bit) as u32);
        }
    }

    let mut out = frame_columns(src, fam, rows);
    let [wrap, word_index, word_index_hi, rd_hi, sel] = cells;
    out.push((rd_selected(frame_queries(fam).len()), u32_column(sel, h)));
    for (address, values) in mw_circuit::DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in mw_circuit::KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in [
        (mw_circuit::WRAP, wrap),
        (mw_circuit::WORD_INDEX, word_index),
        (mw_circuit::WORD_INDEX_HI, word_index_hi),
        (mw_circuit::RD_HI, rd_hi),
    ] {
        out.push((address, u32_column(values, h)));
    }
    for j in 0..mw_circuit::TABLE_WIDTH {
        out.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    Ok(out)
}

/// A `MEM_SUBWORD` shard, `docs/spec/memory-ops.md` §4.7: the frame columns;
/// the decoded row and its six kind bits; the effective address split into
/// `4·word_index + 2·bit1 + bit0` with its wrap bit; the splice's derived
/// constants and its three parts, each with the column its bound scales; the
/// truncated store source and the rest of `rs2`; the sign lookup's key, its
/// answer and the sign-extension term; and the written `rd` value.
///
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, an `rd` write, a written word or a `next_pc` that is
/// not what the instruction computes, or a halfword access at an odd address,
/// which the emulator refuses as a fatal guest error.
fn mem_subword(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::MEM_SUBWORD;
    let rows = src.cycles(fam)?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no MEM_SUBWORD table")?;
    let h = src.height;

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 6] = Default::default();
    // wrap word_index word_index_hi bit0 bit1 p pcopow wph p_ram word
    // high high_hi high_scaled high_scaled_hi sub sub_scaled sub_scaled_hi
    // low low_hi low_scaled low_scaled_hi
    // src_sub src_sub_scaled src_sub_scaled_hi src_high src_high_hi
    // sign_in sign se rd_hi, then rd_selected.
    let mut cells: [Vec<u32>; 31] = Default::default();
    for r in 0..rows.len() {
        let row = rows.row(r);
        let slot = row.pc as usize / 2;
        let field = |column: usize| {
            table.get(column, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the MEM_SUBWORD table does not hold",
                    row.cycle, row.pc
                )
            })
        };
        let row_values = [field(1), field(2), field(3), field(4), field(5), field(6)];
        let (seq, imm, mask) = (row_values[0], row_values[4], row_values[5]);
        let bit = mask.trailing_zeros();
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        let is_byte = matches!(bit, kind_sub::LB | kind_sub::LBU | kind_sub::SB);
        let is_load = matches!(
            bit,
            kind_sub::LB | kind_sub::LH | kind_sub::LBU | kind_sub::LHU
        );
        let sign_extends = matches!(bit, kind_sub::LB | kind_sub::LH);
        let (address, wrap) = add(read(Role::Rs1), imm);
        let (bit0, bit1) = (address & 1, (address >> 1) & 1);
        assert!(
            is_byte || bit0 == 0,
            "cycle {}: a halfword access at {address:#x} is not halfword-aligned",
            row.cycle
        );
        // The splice: p = 2^(8·offset), w the access width, and the word this
        // row decomposes — the one a load read, or the one a store rewrites.
        let p = 1u64 << (8 * (address & 3));
        let w = if is_byte { 1u64 << 8 } else { 1u64 << 16 };
        let word = match is_load {
            true => read(Role::Load),
            false => read(Role::Ram),
        } as u64;
        let (low, sub, high) = (word % p, (word / p) % w, word / (w * p));
        let (src_sub, src_high) = (read(Role::Rs2) as u64 % w, read(Role::Rs2) as u64 / w);
        let sign_in = sub * if is_byte { 1 << 8 } else { 1 };
        let sign = sign_in >> 15;
        let se = (sign_extends && sign == 1) as u64;
        let sel = match is_load {
            true => sub + se * ((1u64 << 32) - w),
            false => 0,
        };
        assert_eq!(
            row.next_pc, seq,
            "cycle {}: the trace's next_pc is not the decoded fall-through",
            row.cycle
        );
        if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value as u64, sel,
                "cycle {}: the trace's rd write is not what the instruction computes",
                row.cycle
            );
        }
        for role in [Role::Load, Role::Ram] {
            if let Some(q) = row.query(role) {
                assert_eq!(
                    q.addr,
                    address & !3,
                    "cycle {}: a {role:?} query's address is not the accessed word",
                    row.cycle
                );
            }
        }
        if let Some(ram) = row.query(Role::Ram) {
            assert_eq!(
                ram.write_value as u64,
                high * w * p + src_sub * p + low,
                "cycle {}: the trace's stored word is not the spliced one",
                row.cycle
            );
        }
        let p_ram = if is_load { 0 } else { p };
        let values = [
            wrap as u64,
            (address / 4) as u64,
            ((address / 4) >> 16) as u64,
            bit0 as u64,
            bit1 as u64,
            p,
            (1u64 << 31) / p,
            w * p / 2,
            p_ram,
            word,
            high,
            high >> 16,
            high * w * p,
            (high * w * p) >> 16,
            sub,
            sub * ((1u64 << 32) / w),
            (sub * ((1u64 << 32) / w)) >> 16,
            low,
            low >> 16,
            low * ((1u64 << 32) / p),
            (low * ((1u64 << 32) / p)) >> 16,
            src_sub,
            src_sub * ((1u64 << 32) / w),
            (src_sub * ((1u64 << 32) / w)) >> 16,
            src_high,
            src_high >> 16,
            sign_in,
            sign,
            se,
            sel >> 16,
            sel,
        ];
        for (column, v) in cells.iter_mut().zip(values) {
            column.push(v as u32);
        }
        for (column, v) in decoded.iter_mut().zip(row_values) {
            column.push(v);
        }
        for (k, column) in kinds.iter_mut().enumerate() {
            column.push((k as u32 == bit) as u32);
        }
    }

    let mut out = frame_columns(src, fam, rows);
    let [wrap, word_index, word_index_hi, bit0, bit1, p, pcopow, wph, p_ram, word, high, high_hi, high_scaled, high_scaled_hi, sub, sub_scaled, sub_scaled_hi, low, low_hi, low_scaled, low_scaled_hi, src_sub, src_sub_scaled, src_sub_scaled_hi, src_high, src_high_hi, sign_in, sign, se, rd_hi, sel] =
        cells;
    out.push((rd_selected(frame_queries(fam).len()), u32_column(sel, h)));
    for (address, values) in ms_circuit::DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in ms_circuit::KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in [
        (ms_circuit::WRAP, wrap),
        (ms_circuit::WORD_INDEX, word_index),
        (ms_circuit::WORD_INDEX_HI, word_index_hi),
        (ms_circuit::BIT0, bit0),
        (ms_circuit::BIT1, bit1),
        (ms_circuit::P, p),
        (ms_circuit::PCOPOW, pcopow),
        (ms_circuit::WPH, wph),
        (ms_circuit::P_RAM, p_ram),
        (ms_circuit::WORD, word),
        (ms_circuit::HIGH, high),
        (ms_circuit::HIGH_HI, high_hi),
        (ms_circuit::HIGH_SCALED, high_scaled),
        (ms_circuit::HIGH_SCALED_HI, high_scaled_hi),
        (ms_circuit::SUB, sub),
        (ms_circuit::SUB_SCALED, sub_scaled),
        (ms_circuit::SUB_SCALED_HI, sub_scaled_hi),
        (ms_circuit::LOW, low),
        (ms_circuit::LOW_HI, low_hi),
        (ms_circuit::LOW_SCALED, low_scaled),
        (ms_circuit::LOW_SCALED_HI, low_scaled_hi),
        (ms_circuit::SRC_SUB, src_sub),
        (ms_circuit::SRC_SUB_SCALED, src_sub_scaled),
        (ms_circuit::SRC_SUB_SCALED_HI, src_sub_scaled_hi),
        (ms_circuit::SRC_HIGH, src_high),
        (ms_circuit::SRC_HIGH_HI, src_high_hi),
        (ms_circuit::SIGN_IN, sign_in),
        (ms_circuit::SIGN, sign),
        (ms_circuit::SE, se),
        (ms_circuit::RD_HI, rd_hi),
    ] {
        out.push((address, u32_column(values, h)));
    }
    for j in 0..ms_circuit::TABLE_WIDTH {
        out.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    let generic = generic_table(h.trailing_zeros());
    for (address, column) in ms_circuit::GENERIC_TABLE.iter().zip(generic) {
        out.push((*address, column));
    }
    Ok(out)
}

/// An `ATOMICS` shard, `docs/spec/memory-ops.md` §6.7: the frame columns; the
/// decoded row — five columns, this family's tuple having no `imm` — and its
/// eleven kind bits; the word index, which is `rs1/4` with no offset at all;
/// `amoadd`'s reduced sum and carry; the bitwise selector with both operands'
/// bytes and their AND; the comparison of the old word against `rs2` and the
/// smaller of the two; and the written `rd` value, which is the **old** word on
/// every kind but `sc.w`.
///
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, a written word, an `rd` write or a `next_pc` that is
/// not what the instruction computes, or a misaligned access, which the
/// emulator refuses as a fatal guest error.
fn atomics(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::ATOMICS;
    let rows = src.cycles(fam)?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no ATOMICS table")?;
    let h = src.height;

    let mut decoded: [Vec<u32>; 5] = Default::default();
    let mut kinds: [Vec<u32>; 11] = Default::default();
    // word_index word_index_hi sum sum_hi add_wrap f_bitwise
    // old_hi old_sign src_hi src_sign lt cmp_gap cmp_gap_hi lo, then rd_selected.
    let mut cells: [Vec<u32>; 15] = Default::default();
    let mut bytes: [Vec<u32>; 12] = Default::default();
    for r in 0..rows.len() {
        let row = rows.row(r);
        let slot = row.pc as usize / 2;
        let field = |column: usize| {
            table.get(column, slot).unwrap_or_else(|| {
                panic!(
                    "cycle {} runs pc {:#x}, which the ATOMICS table does not hold",
                    row.cycle, row.pc
                )
            })
        };
        // lookup_tuple: pc next_pc rs1 rs2 rd extra_mask — six, no imm.
        let row_values = [field(1), field(2), field(3), field(4), field(5)];
        let (seq, mask) = (row_values[0], row_values[4]);
        let bit = mask.trailing_zeros();
        let read = |role: Role| row.query(role).map_or(0, |q| q.read_value);
        let (address, old, b) = (read(Role::Rs1), read(Role::Ram), read(Role::Rs2));
        assert_eq!(
            address % 4,
            0,
            "cycle {}: an atomic at {address:#x} is not word-aligned",
            row.cycle
        );
        let (sum, add_wrap) = add(old, b);
        let signed_order = matches!(bit, at::AMOMIN_W | at::AMOMAX_W);
        let lt = match signed_order {
            true => (old as i32) < (b as i32),
            false => old < b,
        };
        let lo = if lt { old } else { b };
        let gap = old.wrapping_sub(b);
        let and: Vec<u32> = (0..4)
            .map(|j| (old >> (8 * j)) & 0xff & (b >> (8 * j)))
            .collect();
        let accumulator: u32 = (0..4).map(|j| and[j] << (8 * j)).sum();
        let new = match bit {
            at::LR_W => old,
            at::SC_W | at::AMOSWAP_W => b,
            at::AMOADD_W => sum,
            at::AMOAND_W => accumulator,
            // `or` and `xor` are `a + b − and` and `a + b − 2·and` byte by
            // byte, each below 2^32, but the sum on its own can pass it.
            at::AMOOR_W => old.wrapping_add(b).wrapping_sub(accumulator),
            at::AMOXOR_W => old
                .wrapping_add(b)
                .wrapping_sub(accumulator)
                .wrapping_sub(accumulator),
            at::AMOMIN_W | at::AMOMINU_W => lo,
            at::AMOMAX_W | at::AMOMAXU_W => old.wrapping_add(b).wrapping_sub(lo),
            other => panic!("cycle {}: kind bit {other} is not an atomic", row.cycle),
        };
        let sel = match bit == at::SC_W {
            true => 0,
            false => old,
        };
        assert_eq!(
            row.next_pc, seq,
            "cycle {}: the trace's next_pc is not the decoded fall-through",
            row.cycle
        );
        assert_eq!(
            row.query(Role::Ram).map(|q| (q.addr, q.write_value)),
            Some((address, new)),
            "cycle {}: the trace's RAM query is not the word the instruction rewrites",
            row.cycle
        );
        if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
            assert_eq!(
                rd.write_value, sel,
                "cycle {}: the trace's rd write is not the old word",
                row.cycle
            );
        }
        let values = [
            address / 4,
            (address / 4) >> 16,
            sum,
            sum >> 16,
            add_wrap,
            matches!(bit, at::AMOAND_W | at::AMOOR_W | at::AMOXOR_W) as u32,
            old >> 16,
            old >> 31,
            b >> 16,
            b >> 31,
            lt as u32,
            gap,
            gap >> 16,
            lo,
            sel,
        ];
        for (column, v) in cells.iter_mut().zip(values) {
            column.push(v);
        }
        for j in 0..4 {
            bytes[j].push((old >> (8 * j)) & 0xff);
            bytes[4 + j].push((b >> (8 * j)) & 0xff);
            bytes[8 + j].push(and[j]);
        }
        for (column, v) in decoded.iter_mut().zip(row_values) {
            column.push(v);
        }
        for (k, column) in kinds.iter_mut().enumerate() {
            column.push((k as u32 == bit) as u32);
        }
    }

    let mut out = frame_columns(src, fam, rows);
    let [word_index, word_index_hi, sum, sum_hi, add_wrap, f_bitwise, old_hi, old_sign, src_hi, src_sign, lt, cmp_gap, cmp_gap_hi, lo, sel] =
        cells;
    out.push((rd_selected(frame_queries(fam).len()), u32_column(sel, h)));
    for (address, values) in at_circuit::DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in at_circuit::KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in [
        (at_circuit::WORD_INDEX, word_index),
        (at_circuit::WORD_INDEX_HI, word_index_hi),
        (at_circuit::SUM, sum),
        (at_circuit::SUM_HI, sum_hi),
        (at_circuit::ADD_WRAP, add_wrap),
        (at_circuit::F_BITWISE, f_bitwise),
        (at_circuit::OLD_HI, old_hi),
        (at_circuit::OLD_SIGN, old_sign),
        (at_circuit::SRC_HI, src_hi),
        (at_circuit::SRC_SIGN, src_sign),
        (at_circuit::LT, lt),
        (at_circuit::CMP_GAP, cmp_gap),
        (at_circuit::CMP_GAP_HI, cmp_gap_hi),
        (at_circuit::LO, lo),
    ] {
        out.push((address, u32_column(values, h)));
    }
    let mut columns = bytes.into_iter();
    for group in [
        at_circuit::BYTES_A,
        at_circuit::BYTES_B,
        at_circuit::BYTES_AND,
    ] {
        for address in group {
            let values = columns.next().expect("twelve byte columns");
            out.push((address, u32_column(values, h)));
        }
    }
    for j in 0..at_circuit::TABLE_WIDTH {
        out.push((PolyAddress::Setup(j as u32), table.column_poly(j)));
    }
    let generic = generic_table(h.trailing_zeros());
    for (address, column) in at_circuit::GENERIC_TABLE.iter().zip(generic) {
        out.push((*address, column));
    }
    Ok(out)
}
