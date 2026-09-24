//! The family fills: how each family's trace buffer becomes its circuit's
//! committed columns. `docs/spec/shard-proof.md` §8.1 and §11.
//!
//! A fill returns every `M`, `W` and `S` column but the multiplicities, which
//! the common path counts over the family's channels.

use constants::extra_mask::add_sub_lui_auipc as kind;
use constants::extra_mask::atomics as at;
use constants::extra_mask::jump_branch_slt as jbs;
use constants::extra_mask::mem_subword as kind_sub;
use constants::extra_mask::mem_word as kind_mem;
use constants::extra_mask::mul_div as md;
use constants::extra_mask::shift_bitwise as sb;
use constants::extra_mask::system_code;
use constants::fr_arith as fa;
use constants::poseidon2 as p2;
use constants::{delegation, ecall, family, guest_memory, keccak, memory};
use constraints::add_sub::{
    DECODED, IS_ECALL, IS_FENCE, IS_READ, IS_WRITE, KINDS, NEXT_PC_HI, PC_WRAP, RAM_VALUE_HI,
    RD_HI, TABLE_WIDTH, WRAP,
};
use constraints::atomics as at_circuit;
use constraints::delegation as deleg;
use constraints::fr_arith as fa_circuit;
use constraints::jump_branch_slt as jbs_circuit;
use constraints::keccak as kec_circuit;
use constraints::mem_subword as ms_circuit;
use constraints::mem_word as mw_circuit;
use constraints::memory::{frame_queries, rd_selected};
use constraints::mul_div as md_circuit;
use constraints::poseidon2 as p2_circuit;
use constraints::shift_bitwise as sb_circuit;
use constraints::PolyAddress;
use field::Fr;
use poly::{MultilinearPoly, PolyBacking};
use program::lookup_tables::generic_table;
use program::FamilyId;
use trace::{
    build_frame_witness, build_init_teardown_columns, build_memory_columns, Role, TraceArchive,
};

use crate::Program;

/// What a fill reads: the program, the archived execution, and which shard —
/// its family, its index, its height, and for a RAM window family its window.
pub struct ShardSource<'a> {
    pub program: &'a Program,
    pub archive: &'a TraceArchive,
    pub family: FamilyId,
    pub index: u32,
    pub height: usize,
    pub window: u32,
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
        family::INIT_TEARDOWN | family::ZERO_WINDOWS => Some(window),
        family::KECCAK_F => Some(keccak_f),
        family::POSEIDON2 => Some(poseidon2),
        family::FR_ARITH => Some(fr_arith),
        _ => None,
    }
}

/// A delegation shard's rows: the buffer, the slice of invocations this shard
/// holds, and the height to pad to.
struct Invocations<'a> {
    trace: &'a trace::DelegationTrace,
    rows: core::ops::Range<usize>,
    height: usize,
}

/// The invocations a delegation shard proves.
fn invocations<'a>(src: &'a ShardSource, family: FamilyId) -> Result<Invocations<'a>, String> {
    let trace = src
        .archive
        .family_traces()
        .delegation(family)
        .ok_or_else(|| format!("the archive has no {} buffer", program::family_name(family)))?;
    let start = src.index as usize * src.height;
    let end = (start + src.height).min(trace.len());
    Ok(Invocations {
        trace,
        rows: start..end,
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
/// `witness_base` is where the family's circuit starts the frame's **witness**
/// columns, and it is not always 0. `constraints::delegation` puts the gap and
/// base bits at `W[0]` and a family's own bits above them, which is what S23's
/// two circuits do; S21's `keccak` predates that module and puts its 1,600
/// state bits first, so its frame's bits begin at `W[1600]`. The `M` layout is
/// the same in both — four head columns then four a word — so only the witness
/// side needs shifting, and getting this wrong writes the frame's bits over
/// the state's and leaves the top of `W` unfilled, which is a `gkr_part` panic
/// on "a witness column" and not a wrong proof.
fn delegation_frame(
    inv: &Invocations,
    words: usize,
    frame_bytes: u64,
    witness_base: usize,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let (trace, rows, h) = (inv.trace, inv.rows.clone(), inv.height);
    let wit = |a: PolyAddress| match a {
        PolyAddress::Witness(i) => PolyAddress::Witness(i + witness_base as u32),
        other => other,
    };
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    let cycles: Vec<Fr> = rows.clone().map(|r| Fr::from_u64(trace.cycle[r])).collect();
    out.push((deleg::CYCLE, fr_column(cycles, h)));
    out.push((
        deleg::LIVE,
        u32_column(rows.clone().map(|_| 1).collect(), h),
    ));
    out.push((
        deleg::BASE,
        u32_column(rows.clone().map(|r| trace.base[r]).collect(), h),
    ));
    // The value the request wrote back on its mirror query. Free on both
    // sides, and 0 on both in an honest fill (`docs/spec/delegation.md` §5.2).
    out.push((deleg::ANCHOR_VALUE, u32_column(Vec::new(), h)));

    for j in 0..words {
        let w = &trace.words[j];
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
                    let ts = memory::TS_STEP * trace.cycle[r] + delegation::FRAME_DELTA;
                    let gap = ts - w.read_ts[r] - 1;
                    ((gap >> bit) & 1) as u32
                })
                .collect();
            out.push((wit(deleg::gap_bit(j, bit)), u32_column(values, h)));
        }
    }
    for bit in 0..deleg::BASE_LOW_BITS {
        let values: Vec<u32> = rows
            .clone()
            .map(|r| (((trace.base[r] - guest_memory::RAM_ORIGIN) / 4) >> bit) & 1)
            .collect();
        out.push((wit(deleg::base_low_bit(words, bit)), u32_column(values, h)));
    }
    for bit in 0..deleg::BASE_ROOM_BITS {
        let values: Vec<u32> = rows
            .clone()
            .map(|r| {
                let room = (1u64 << 31) - frame_bytes - trace.base[r] as u64;
                ((room >> bit) & 1) as u32
            })
            .collect();
        out.push((wit(deleg::base_room_bit(words, bit)), u32_column(values, h)));
    }
    out
}

/// A frame value's eight words on row `r`, from the field its circuit reads.
fn value_words(trace: &trace::DelegationTrace, first: usize, field: u32, r: usize) -> [u32; 8] {
    core::array::from_fn(|k| {
        let w = &trace.words[first + k];
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
    let (trace, rows, h) = (inv.trace, inv.rows.clone(), inv.height);
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    for k in 0..8 {
        for t in 0..32 {
            let values: Vec<u32> = rows
                .clone()
                .map(|r| (value_words(trace, first, field, r)[k] >> t) & 1)
                .collect();
            out.push((bits(k, t), u32_column(values, h)));
        }
    }
    for k in 0..8 {
        for t in 0..32 {
            let values: Vec<u32> = rows
                .clone()
                .map(|r| {
                    ((borrow_chain(&value_words(trace, first, field, r)).0[k] >> t) & 1) as u32
                })
                .collect();
            out.push((diffs(k, t), u32_column(values, h)));
        }
    }
    for k in 0..8 {
        let values: Vec<u32> = rows
            .clone()
            .map(|r| borrow_chain(&value_words(trace, first, field, r)).1[k] as u32)
            .collect();
        out.push((borrows(k), u32_column(values, h)));
    }
    out
}

/// A `KECCAK_F` shard, `docs/spec/delegation.md` §6.1: the delegation frame,
/// plus the input state's 1600 bits.
fn keccak_f(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let inv = invocations(src, family::KECCAK_F)?;
    // S21's circuit puts the state's 1,600 bits at `W[0]`, so the frame's own
    // bits start above them (`constraints::keccak::gap_bit`).
    let mut out = delegation_frame(
        &inv,
        keccak::FRAME_WORDS,
        keccak::STATE_BYTES as u64,
        keccak::STATE_BITS,
    );
    let (trace, rows, h) = (inv.trace, inv.rows.clone(), inv.height);
    // The state's bits: frame word `2i + half` is lane `i`'s half, so bit `t`
    // of word `j` is state bit `64·(j/2) + 32·(j%2) + t`.
    for b in 0..keccak::STATE_BITS {
        let (j, t) = (2 * (b / 64) + (b % 64) / 32, b % 32);
        let values: Vec<u32> = rows
            .clone()
            .map(|r| (trace.words[j].read_value[r] >> t) & 1)
            .collect();
        out.push((kec_circuit::in_bit(b), u32_column(values, h)));
    }
    Ok(out)
}

/// A `POSEIDON2` shard, `docs/spec/delegation.md` §12.1: the delegation frame,
/// plus the six lane values' word and canonicity bits — three read, three
/// written.
fn poseidon2(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let inv = invocations(src, family::POSEIDON2)?;
    let mut out = delegation_frame(&inv, p2::FRAME_WORDS, p2::FRAME_BYTES as u64, 0);
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
    Ok(out)
}

/// An `FR_ARITH` shard, `docs/spec/delegation.md` §13.1: the delegation frame,
/// the three values' bits, the operation selectors, and the three witnessed
/// scalars — the product helper, the inverse and the is-zero flag.
fn fr_arith(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let inv = invocations(src, family::FR_ARITH)?;
    let mut out = delegation_frame(&inv, fa::FRAME_WORDS, fa::FRAME_BYTES as u64, 0);
    let (trace, rows, h) = (inv.trace, inv.rows.clone(), inv.height);
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
    let opcode = |r: usize| trace.words[fa::OPCODE_WORD].read_value[r];
    for (i, op) in fa::OPS.iter().enumerate() {
        let values: Vec<u32> = rows.clone().map(|r| u32::from(opcode(r) == *op)).collect();
        out.push((fa_circuit::selector(i), u32_column(values, h)));
    }
    // The three `Fr`-valued witnesses. `a` and `b` are the frame's own words
    // read as `Fr`'s in-memory representation; every one is canonical, which
    // the emulator refused to run without.
    let value = |first: usize, field: u32, r: usize| -> Fr {
        let words = value_words(trace, first, field, r);
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

/// A RAM window shard: `trace::build_init_teardown_columns` over its window,
/// with `S[0]`, the image column, for window 0.
fn window(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    Ok(build_init_teardown_columns(
        src.archive.memory_log(),
        &src.program.image,
        src.window,
        src.height,
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
/// Refuses, naming the cycle, an ecall this family does not prove, and an I/O
/// ecall the circuit cannot admit: a `read` or a `write` on a descriptor
/// outside its call's pair, which the executor answered `-EBADF`, and a `read`
/// that moved no word. Each is a refusal rather than a call, and the S25a
/// gates hold every row that claims one to what a call does
/// (`docs/spec/shard-proof.md` §8.5).
///
/// Panics if the trace and the decoded table disagree — a cycle at a pc the
/// table does not hold, an `rd` write or a `next_pc` that is not what the
/// instruction computes, a `read` answering more than one word or a `write`
/// answering a count other than the one it was asked for — which the emulator
/// cannot produce.
fn add_sub(src: &ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String> {
    let fam = family::ADD_SUB_LUI_AUIPC;
    let traces = src.archive.family_traces();
    let trace = traces
        .family(fam)
        .ok_or("the archive has no ADD_SUB_LUI_AUIPC buffer")?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no ADD_SUB_LUI_AUIPC table")?;
    let h = src.height;
    let start = src.index as usize * h;
    let end = (start + h).min(trace.len());
    let cycles = &trace.cycle[start..end];
    let width = frame_queries(fam).len();

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 6] = Default::default();
    let (mut is_ecall, mut is_fence, mut wrap) = (Vec::new(), Vec::new(), Vec::new());
    let mut is_deleg: [Vec<u32>; constraints::add_sub::IS_DELEGATION.len()] = Default::default();
    let (mut is_read, mut is_write, mut ram_value_hi) = (Vec::new(), Vec::new(), Vec::new());
    let mut fd_uncommitted_column = Vec::new();
    let (mut sel, mut rd_hi, mut next_pc_hi) = (Vec::new(), Vec::new(), Vec::new());
    for r in start..end {
        let row = trace.row(r);
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
        // What a query **wrote**, which is not what it read. On every row but
        // an ecall's the two differ only at `rd`, and there the fill computes
        // the written value rather than copying it. On an ecall's row `a0` is
        // read *and* written by one query — the ABI puts the call's first
        // argument and its answer in the same register — so a `read` or a
        // `write` reads a descriptor and writes a byte count, and the
        // frame's `rd_selected` must carry the second
        // (`docs/spec/execution-trace.md` §7).
        let written = |role: Role| row.query(role).map_or(0, |q| q.write_value);
        let (a, b) = (read(Role::Rs1), read(Role::Rs2));
        let bit = mask.trailing_zeros();
        let (mut ecall_row, mut fence_row) = (0, 0);
        // One selector per delegation type, in `IS_DELEGATION` order.
        let mut deleg_row = [0u32; constraints::add_sub::IS_DELEGATION.len()];
        // S25's two: `read` and `write`, the provable I/O ecalls.
        let (mut read_row, mut write_row) = (0u32, 0u32);
        // 1 where an I/O ecall names the uncommitted one of its two
        // descriptors — fd 3 for a `read`, fd 2 for a `write` — and 0 where it
        // names fd 0 or fd 1. `read_descriptor` and `write_descriptor` read it
        // (`docs/spec/shard-proof.md` §8.2).
        let mut fd_uncommitted = 0u32;
        let (value, carry) = match bit {
            kind::ADD => add(a, b),
            kind::ADDI => add(a, imm),
            kind::AUIPC => add(row.pc, imm),
            kind::SUB => (a.wrapping_sub(b), (a < b) as u32),
            kind::LUI => (imm, 0),
            kind::SYSTEM => match imm {
                // A `read` carries the word it delivers on this very row, so
                // `ram_mask_rule` demands the RAM query. A refusal — a
                // descriptor the ABI does not give the call — makes none, and
                // is therefore not provable: say so here rather than let the
                // shard fail as a `Constraint` on bytes a verifier was handed
                // (`docs/spec/shard-proof.md` §8.5).
                system_code::ECALL if a == ecall::READ => {
                    // The two refusals a `read` row can carry, each by name.
                    // A descriptor outside the call's pair is refused by
                    // `read_descriptor` and moves no word besides; the
                    // executor answers `-EBADF` and stages no RAM query, which
                    // `ram_mask_rule` also demands. Neither shape is provable,
                    // so say so here rather than hand a verifier a shard that
                    // fails as a `Constraint` (`docs/spec/shard-proof.md`
                    // §8.5).
                    if !matches!(b, ecall::FD_PUBLIC_INPUT | ecall::FD_HINT) {
                        return Err(format!(
                            "cycle {} is a `read` from fd {b}, which is neither fd {} nor \
                             fd {}, so it is a refusal, which no family proves",
                            row.cycle,
                            ecall::FD_PUBLIC_INPUT,
                            ecall::FD_HINT
                        ));
                    }
                    if row.query(Role::Ram).is_none() {
                        return Err(format!(
                            "cycle {} is a `read` that moved no word, so it is a refusal \
                             (a descriptor fd 0 and fd 3 do not name), which no family proves",
                            row.cycle
                        ));
                    }
                    // A short read is a real answer and stays provable; a
                    // count above the one word asked for is not, and
                    // `read_count_gap_range` is what refuses it.
                    assert!(
                        written(Role::Rd) <= ecall::READ_WORD_BYTES,
                        "cycle {}: a `read` answered {} bytes, more than the one word it asked \
                         for",
                        row.cycle,
                        written(Role::Rd)
                    );
                    read_row = 1;
                    fd_uncommitted = (b == ecall::FD_HINT) as u32;
                    // The byte count the executor answered with, which is
                    // `a0`'s **write** and not the fd it read. No gate fixes
                    // it: what a `read` delivers and what it reports are fd
                    // 0's content, bound by the guest's own `io_digest` and
                    // by no row (`docs/spec/memory.md` §10), so there is
                    // nothing to hold it against and the check below skips
                    // this row.
                    (written(Role::Rd), 0)
                }
                system_code::ECALL if a == ecall::WRITE => {
                    // Its refusal, the sibling of a `read`'s: the executor
                    // answers `-EBADF` and appends nothing, and since S25a
                    // `write_descriptor` refuses the row, where before it
                    // proved a `write` that had not happened.
                    if !matches!(b, ecall::FD_PUBLIC_OUTPUT | ecall::FD_STDERR) {
                        return Err(format!(
                            "cycle {} is a `write` to fd {b}, which is neither fd {} nor \
                             fd {}, so it is a refusal, which no family proves",
                            row.cycle,
                            ecall::FD_PUBLIC_OUTPUT,
                            ecall::FD_STDERR
                        ));
                    }
                    if row.query(Role::Ram).is_some() {
                        return Err(format!(
                            "cycle {} is a `write` carrying a RAM query, which `ram_mask_rule` \
                             forbids: a `write` moves no memory event",
                            row.cycle
                        ));
                    }
                    // Unlike a `read`'s, a `write`'s answer is fixed: the
                    // executor appends every byte or refuses the descriptor,
                    // and `write_count_is_the_request` holds the row to that.
                    assert_eq!(
                        written(Role::Rd),
                        read(Role::Arg2),
                        "cycle {}: a `write` answered a count other than the one it was asked \
                         for",
                        row.cycle
                    );
                    write_row = 1;
                    fd_uncommitted = (b == ecall::FD_STDERR) as u32;
                    // Likewise fd 1's: the count written back, bound by
                    // `io_digest` and by no row.
                    (written(Role::Rd), 0)
                }
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
        // Every row whose `rd` write the circuit fixes: the trace's write is
        // held to what the family computes. A `read`'s and a `write`'s is
        // **not** one of those — `value` was taken from that very write above,
        // so the comparison would be vacuous, and no gate constrains it — but
        // an exit's is (it writes back the status it read) and a delegation
        // request's is (it writes 0 over the frame base,
        // `docs/spec/delegation.md` §5.2), and both are checked here.
        if read_row | write_row == 0 {
            if let Some(rd) = row.query(Role::Rd).filter(|q| q.addr != 0) {
                assert_eq!(
                    rd.write_value, value,
                    "cycle {}: the trace's rd write is not what the instruction computes",
                    row.cycle
                );
            }
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
        is_ecall.push(ecall_row | requests | read_row | write_row);
        is_read.push(read_row);
        is_write.push(write_row);
        fd_uncommitted_column.push(fd_uncommitted);
        // The word a `read` delivers, whose 16+16 pair bounds it. A row that
        // makes no RAM query carries 0, which is what the frame's own fill
        // writes into the query's columns and what the pair then holds.
        ram_value_hi.push(row.query(Role::Ram).map_or(0, |q| q.write_value >> 16));
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

    let mut out = frame_columns(src, fam, cycles);
    out.push((rd_selected(width), u32_column(sel, h)));
    for (address, values) in DECODED.iter().zip(decoded) {
        out.push((*address, u32_column(values, h)));
    }
    for (address, values) in KINDS.iter().zip(kinds) {
        out.push((*address, u32_column(values, h)));
    }
    out.push((IS_ECALL, u32_column(is_ecall, h)));
    out.push((IS_FENCE, u32_column(is_fence, h)));
    for (address, values) in constraints::add_sub::IS_DELEGATION.iter().zip(is_deleg) {
        out.push((*address, u32_column(values, h)));
    }
    out.push((IS_READ, u32_column(is_read, h)));
    out.push((IS_WRITE, u32_column(is_write, h)));
    out.push((
        constraints::add_sub::FD_UNCOMMITTED,
        u32_column(fd_uncommitted_column, h),
    ));
    out.push((RAM_VALUE_HI, u32_column(ram_value_hi, h)));
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
    let traces = src.archive.family_traces();
    let trace = traces
        .family(fam)
        .ok_or("the archive has no JUMP_BRANCH_SLT buffer")?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no JUMP_BRANCH_SLT table")?;
    let h = src.height;
    let start = src.index as usize * h;
    let end = (start + h).min(trace.len());
    let cycles = &trace.cycle[start..end];
    let width = frame_queries(fam).len();

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 12] = Default::default();
    // cmp_rhs rs1_hi rs1_sign cmp_rhs_hi cmp_rhs_sign lt cmp_gap cmp_gap_hi
    // eq taken jalr_drop pc_wrap next_pc_hi rd_hi, then rd_selected.
    let mut cells: [Vec<u32>; 15] = Default::default();
    let mut eq_inv = Vec::new();
    for r in start..end {
        let row = trace.row(r);
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

    let mut out = frame_columns(src, fam, cycles);
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
    let traces = src.archive.family_traces();
    let trace = traces
        .family(fam)
        .ok_or("the archive has no SHIFT_BITWISE buffer")?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no SHIFT_BITWISE table")?;
    let h = src.height;
    let start = src.index as usize * h;
    let end = (start + h).min(trace.len());
    let cycles = &trace.cycle[start..end];
    let width = frame_queries(fam).len();

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 12] = Default::default();
    // f_shift f_bitwise rs1_hi rs1_sign src2_hi amount pow copow high high_hi
    // se ovf ovf_hi residue residue_hi scaled scaled_hi rd_hi, then rd_selected.
    let mut cells: [Vec<u32>; 19] = Default::default();
    let mut bytes: [Vec<u32>; 12] = Default::default();
    let (mut shift_in, mut shift_prod) = (Vec::new(), Vec::new());
    for r in start..end {
        let row = trace.row(r);
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

    let mut out = frame_columns(src, fam, cycles);
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
    let traces = src.archive.family_traces();
    let trace = traces
        .family(fam)
        .ok_or("the archive has no MUL_DIV buffer")?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no MUL_DIV table")?;
    let h = src.height;
    let start = src.index as usize * h;
    let end = (start + h).min(trace.len());
    let cycles = &trace.cycle[start..end];
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
    for row_index in start..end {
        let row = trace.row(row_index);
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

    let mut out = frame_columns(src, fam, cycles);
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
    cycles: &[u64],
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let log = src.archive.memory_log();
    let queries = frame_queries(family);
    let width = queries.len();
    let mut out = build_memory_columns(log, queries, cycles, src.height);
    for (address, column) in build_frame_witness(log, queries, cycles, src.height) {
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
    let traces = src.archive.family_traces();
    let trace = traces
        .family(fam)
        .ok_or("the archive has no MEM_WORD buffer")?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no MEM_WORD table")?;
    let h = src.height;
    let start = src.index as usize * h;
    let end = (start + h).min(trace.len());
    let cycles = &trace.cycle[start..end];

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 2] = Default::default();
    // wrap word_index word_index_hi is_advice word_index_hi_rest rd_hi, then
    // rd_selected. `is_advice` is bit 13 of `word_index_hi`, which is bit 31
    // of the byte address (`docs/spec/advice.md` §3.1).
    let mut cells: [Vec<u32>; 7] = Default::default();
    for r in start..end {
        let row = trace.row(r);
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
        let word_index_hi = (address / 4) >> 16;
        let values = [
            wrap,
            address / 4,
            word_index_hi,
            word_index_hi >> 13,
            word_index_hi & ((1 << 13) - 1),
            sel >> 16,
            sel,
        ];
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

    let mut out = frame_columns(src, fam, cycles);
    let [wrap, word_index, word_index_hi, is_advice, word_index_hi_rest, rd_hi, sel] = cells;
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
        (mw_circuit::IS_ADVICE, is_advice),
        (mw_circuit::WORD_INDEX_HI_REST, word_index_hi_rest),
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
    let traces = src.archive.family_traces();
    let trace = traces
        .family(fam)
        .ok_or("the archive has no MEM_SUBWORD buffer")?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no MEM_SUBWORD table")?;
    let h = src.height;
    let start = src.index as usize * h;
    let end = (start + h).min(trace.len());
    let cycles = &trace.cycle[start..end];

    let mut decoded: [Vec<u32>; 6] = Default::default();
    let mut kinds: [Vec<u32>; 6] = Default::default();
    // wrap word_index word_index_hi is_advice word_index_hi_rest
    // bit0 bit1 p pcopow wph p_ram word
    // high high_hi high_scaled high_scaled_hi sub sub_scaled sub_scaled_hi
    // low low_hi low_scaled low_scaled_hi
    // src_sub src_sub_scaled src_sub_scaled_hi src_high src_high_hi
    // sign_in sign se rd_hi, then rd_selected.
    // `from_fn` rather than `Default::default()`: the standard library stops
    // implementing `Default` for arrays at 32, and S25b's two advice columns
    // took this one past it.
    let mut cells: [Vec<u32>; 33] = core::array::from_fn(|_| Vec::new());
    for r in start..end {
        let row = trace.row(r);
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
        let word_index_hi = ((address / 4) >> 16) as u64;
        let values = [
            wrap as u64,
            (address / 4) as u64,
            word_index_hi,
            word_index_hi >> 13,
            word_index_hi & ((1 << 13) - 1),
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

    let mut out = frame_columns(src, fam, cycles);
    let [wrap, word_index, word_index_hi, is_advice, word_index_hi_rest, bit0, bit1, p, pcopow, wph, p_ram, word, high, high_hi, high_scaled, high_scaled_hi, sub, sub_scaled, sub_scaled_hi, low, low_hi, low_scaled, low_scaled_hi, src_sub, src_sub_scaled, src_sub_scaled_hi, src_high, src_high_hi, sign_in, sign, se, rd_hi, sel] =
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
        (ms_circuit::IS_ADVICE, is_advice),
        (ms_circuit::WORD_INDEX_HI_REST, word_index_hi_rest),
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
    let traces = src.archive.family_traces();
    let trace = traces
        .family(fam)
        .ok_or("the archive has no ATOMICS buffer")?;
    let table = src
        .program
        .tables
        .family(fam)
        .ok_or("the program has no ATOMICS table")?;
    let h = src.height;
    let start = src.index as usize * h;
    let end = (start + h).min(trace.len());
    let cycles = &trace.cycle[start..end];

    let mut decoded: [Vec<u32>; 5] = Default::default();
    let mut kinds: [Vec<u32>; 11] = Default::default();
    // word_index word_index_hi sum sum_hi add_wrap f_bitwise
    // old_hi old_sign src_hi src_sign lt cmp_gap cmp_gap_hi lo, then rd_selected.
    let mut cells: [Vec<u32>; 15] = Default::default();
    let mut bytes: [Vec<u32>; 12] = Default::default();
    for r in start..end {
        let row = trace.row(r);
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

    let mut out = frame_columns(src, fam, cycles);
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
