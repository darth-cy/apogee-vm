//! The SHA-256 four-round circuit, gate by gate and obligation by obligation.
//!
//! `docs/spec/delegation-circuits.md` §6 is what this suite restates: the 25-word
//! frame, the anchor's two tuples, the one-hot round-group selector, four rounds
//! over two sequences, four derived schedule words, and the window that carries
//! the schedule from one call to the next.
//!
//! **There is no forward pass here, and since S26e there cannot be.** This
//! family carries the `RANGE16` and `XOR8` channels, whose tables each need
//! sixteen variables, so its circuit cannot be built at a height a whole-shard
//! pass would afford. So the arithmetic is checked row by row, exactly as
//! `tests/keccak.rs` checks keccak's: each row is built from **`u32` host
//! arithmetic in this file** and evaluated alone — the gates through
//! `checker::violated_relations`, the `RANGE16` obligations through
//! `checker::violated_lookups` and the `XOR8` ones through [`violated_xor8`],
//! which states what the table means rather than looking a row up in it.
//!
//! The call this file computes is written from FIPS 180-4 in `u32` primitives
//! and shares no line with `crates/prover`'s fill or `crates/emulator`'s
//! executor, so a circuit stating anything but four SHA-256 rounds and the
//! schedule words they unlock would reject an honest witness.
//! [`the_call_is_the_executors`] ties it to the executor, and
//! [`sixteen_calls_are_one_compression`] to the standard's published digest.
//!
//! Every negative control corrupts one cell of an otherwise honest witness, or
//! supplies an honest witness for a claim the circuit must refuse, and names the
//! relation or the obligation that must catch it.

use constants::{
    challenge_slot, delegation, guest_memory, lookup_channel, memory as mem, sha256 as f,
};
use constraints::sha256::{self, Round, Sched};
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress};
use field::Fr;
use gkr::{gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use poly::{MultilinearPoly, PolyBacking};

#[path = "../../prover/tests/common/mod.rs"]
mod common;

/// The circuit's own height, `constants::family::DEFAULT_HEIGHTS`' entry: the
/// fill test builds a program config at it, and the two must agree.
const VARS: u32 = common::SHA256_VARS;

/// The rows this suite builds and evaluates: one compression's sixteen calls,
/// four corners, and padding to a power of two. The other rows of the circuit
/// are never materialized — a relation is row-local.
const ROWS: usize = 32;

/// Rows the honest set fills.
const LIVE_ROWS: usize = f::GROUPS + 4;

/// Rounds a call runs.
const R: usize = f::ROUNDS_PER_CALL;

// ---------------------------------------------------------------------------
// FIPS 180-4, one call of it, written here
// ---------------------------------------------------------------------------

/// One invocation as a witness builder sees it.
#[derive(Clone, Copy)]
struct Invocation {
    cycle: u64,
    base: u32,
    group: usize,
    /// `a..h` going in.
    state: [u32; 8],
    /// `W_{4r}..W_{4r+15}` going in.
    window: [u32; 16],
}

/// Everything one call computes, in the circuit's own decomposition.
struct Call {
    /// `A_{-3}..A_4` and `E_{-3}..E_4`: index `j + 3` is `A_j`.
    a: [u32; 8],
    e: [u32; 8],
    /// The window, then the four words this call derives.
    x: [u32; 20],
    carry_a: [u32; R],
    carry_e: [u32; R],
    /// `Σ0`'s `y` and `x`, `Σ1`'s, `e ^ f`, `e ^ g`, `a ^ b`, `c ^ a ^ b`.
    bs0: [(u32, u32); R],
    bs1: [(u32, u32); R],
    ch: [(u32, u32); R],
    maj: [(u32, u32); R],
    /// `sigma0`'s `y`, its shift and `z`; `sigma1`'s.
    ss0: [(u32, u32, u32); R],
    ss1: [(u32, u32, u32); R],
    carry_w: [u32; R],
    /// The frame's state words and window after the call.
    state_out: [u32; 8],
}

fn call_of(i: &Invocation) -> Call {
    let mut a = [0u32; 8];
    let mut e = [0u32; 8];
    for j in 0..4 {
        a[3 - j] = i.state[j];
        e[3 - j] = i.state[4 + j];
    }
    let mut call = Call {
        a,
        e,
        x: [0; 20],
        carry_a: [0; R],
        carry_e: [0; R],
        bs0: [(0, 0); R],
        bs1: [(0, 0); R],
        ch: [(0, 0); R],
        maj: [(0, 0); R],
        ss0: [(0, 0, 0); R],
        ss1: [(0, 0, 0); R],
        carry_w: [0; R],
        state_out: [0; 8],
    };
    for k in 0..R {
        let (a, b, c, d) = (call.a[k + 3], call.a[k + 2], call.a[k + 1], call.a[k]);
        let (e, g_, h_, hh) = (call.e[k + 3], call.e[k + 2], call.e[k + 1], call.e[k]);
        // Σ0(a) = ROTR2(a ^ ROTR11(a ^ ROTR9(a))), and Σ1 likewise.
        let y0 = a ^ a.rotate_right(9);
        let x0 = a ^ y0.rotate_right(11);
        let y1 = e ^ e.rotate_right(14);
        let x1 = e ^ y1.rotate_right(5);
        let big0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let big1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        assert_eq!(x0.rotate_right(2), big0, "the nested Σ0");
        assert_eq!(x1.rotate_right(6), big1, "the nested Σ1");
        let ch = (e & g_) ^ (!e & h_);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t1 = hh as u64
            + big1 as u64
            + ch as u64
            + f::ROUND_CONSTANTS[R * i.group + k] as u64
            + i.window[k] as u64;
        let t2 = big0 as u64 + maj as u64;
        call.a[k + 4] = (t1 + t2) as u32;
        call.e[k + 4] = (d as u64 + t1) as u32;
        call.carry_a[k] = ((t1 + t2) >> 32) as u32;
        call.carry_e[k] = ((d as u64 + t1) >> 32) as u32;
        call.bs0[k] = (y0, x0);
        call.bs1[k] = (y1, x1);
        call.ch[k] = (e ^ g_, e ^ h_);
        call.maj[k] = (a ^ b, c ^ a ^ b);
    }
    call.x[..16].copy_from_slice(&i.window);
    for m in 0..R {
        let t = 16 + m;
        let (p, q) = (call.x[t - 15], call.x[t - 2]);
        let y0 = p ^ p.rotate_right(11);
        let z0 = y0.rotate_right(7) ^ (p >> 3);
        let y1 = q ^ q.rotate_right(2);
        let z1 = y1.rotate_right(17) ^ (q >> 10);
        assert_eq!(
            z0,
            p.rotate_right(7) ^ p.rotate_right(18) ^ (p >> 3),
            "sigma0"
        );
        assert_eq!(
            z1,
            q.rotate_right(17) ^ q.rotate_right(19) ^ (q >> 10),
            "sigma1"
        );
        let total = z1 as u64 + call.x[t - 7] as u64 + z0 as u64 + call.x[t - 16] as u64;
        call.x[t] = total as u32;
        call.carry_w[m] = (total >> 32) as u32;
        call.ss0[m] = (y0, p >> 3, z0);
        call.ss1[m] = (y1, q >> 10, z1);
    }
    for j in 0..4 {
        call.state_out[j] = call.a[7 - j];
        call.state_out[4 + j] = call.e[7 - j];
    }
    call
}

/// The frame's read and written words for one invocation.
fn read_words(i: &Invocation) -> [u32; f::FRAME_WORDS] {
    let mut out = [0u32; f::FRAME_WORDS];
    out[f::GROUP_WORD] = i.group as u32;
    out[f::STATE_WORD..f::WINDOW_WORD].copy_from_slice(&i.state);
    out[f::WINDOW_WORD..].copy_from_slice(&i.window);
    out
}

fn written_words(i: &Invocation, c: &Call) -> [u32; f::FRAME_WORDS] {
    let mut out = [0u32; f::FRAME_WORDS];
    out[f::GROUP_WORD] = i.group as u32;
    out[f::STATE_WORD..f::WINDOW_WORD].copy_from_slice(&c.state_out);
    out[f::WINDOW_WORD..].copy_from_slice(&c.x[4..]);
    out
}

fn byte(v: u32, b: usize) -> u64 {
    ((v >> (8 * b)) & 0xff) as u64
}

/// Each byte of `v` XORed with `2^s − 1`.
fn masked(v: u32, s: u32) -> u32 {
    v ^ u32::from_le_bytes([((1u32 << s) - 1) as u8; 4])
}

/// The word round `k`'s byte block `block` holds.
fn round_word(c: &Call, k: usize, block: Round) -> u32 {
    match block {
        Round::Bs0M1 => masked(c.a[k + 3], 1),
        Round::Bs0Y => c.bs0[k].0,
        Round::Bs0M3 => masked(c.bs0[k].0, 3),
        Round::Bs0X => c.bs0[k].1,
        Round::Bs1M6 => masked(c.e[k + 3], 6),
        Round::Bs1Y => c.bs1[k].0,
        Round::Bs1M5 => masked(c.bs1[k].0, 5),
        Round::Bs1X => c.bs1[k].1,
        Round::ChEf => c.ch[k].0,
        Round::ChEg => c.ch[k].1,
        Round::MajAb => c.maj[k].0,
        Round::MajCab => c.maj[k].1,
        other => panic!("{other:?} is not a byte block"),
    }
}

/// The word derived schedule word `m`'s byte block `block` holds.
fn sched_word(c: &Call, m: usize, block: Sched) -> u32 {
    match block {
        Sched::Ss0M3 => masked(c.x[1 + m], 3),
        Sched::Ss0Y => c.ss0[m].0,
        Sched::Ss0M7 => masked(c.ss0[m].0, 7),
        Sched::Ss0Shr => c.ss0[m].1,
        Sched::Ss0Z => c.ss0[m].2,
        Sched::Ss1M2 => masked(c.x[14 + m], 2),
        Sched::Ss1Y => c.ss1[m].0,
        Sched::Ss1M1 => masked(c.ss1[m].0, 1),
        Sched::Ss1Shr => c.ss1[m].1,
        Sched::Ss1Z => c.ss1[m].2,
        Sched::CarryW => panic!("a carry is not a byte block"),
    }
}

fn column(values: Vec<u64>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(
        values.into_iter().map(Fr::from_u64).collect(),
    ))
}

/// The honest witness of `live`, padded to [`ROWS`] with zero rows.
fn witness(live: &[Invocation]) -> Vec<(PolyAddress, MultilinearPoly)> {
    let calls: Vec<Call> = live.iter().map(call_of).collect();
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    let mut push = |address: PolyAddress, of: &dyn Fn(&Invocation, &Call) -> u64| {
        let values = (0..ROWS)
            .map(|r| match live.get(r) {
                Some(i) => of(i, &calls[r]),
                None => 0,
            })
            .collect();
        out.push((address, column(values)));
    };
    push(sha256::CYCLE, &|i, _| i.cycle);
    push(sha256::LIVE, &|_, _| 1);
    push(sha256::BASE, &|i, _| i.base as u64);
    push(sha256::ANCHOR_VALUE, &|_, _| 0);
    for j in 0..f::FRAME_WORDS {
        push(sha256::word(j, sha256::WORD_ADDR), &move |i, _| {
            i.base as u64 + 4 * j as u64
        });
        // The read each word consumed: the previous cycle's frame write.
        push(sha256::word(j, sha256::WORD_READ_TS), &|i, _| {
            mem::TS_STEP * (i.cycle - 1) + delegation::FRAME_DELTA
        });
        push(sha256::word(j, sha256::WORD_READ_VALUE), &move |i, _| {
            read_words(i)[j] as u64
        });
        push(sha256::word(j, sha256::WORD_WRITE_VALUE), &move |i, c| {
            written_words(i, c)[j] as u64
        });
    }
    for j in 0..f::FRAME_WORDS {
        for c in 0..constraints::delegation::GAP_CHUNKS {
            push(sha256::gap_chunk(j, c), &move |_, _| {
                // `4·cycle − 1 − (4·(cycle − 1))` is 3, whose chunks above the
                // derived low one are zero.
                (3u64 >> (16 * (c as u32 + 1))) & 0xffff
            });
        }
    }
    let low = |i: &Invocation| ((i.base - guest_memory::RAM_ORIGIN) / 4) as u64;
    let room = |i: &Invocation| (1u64 << 31) - f::FRAME_BYTES as u64 - i.base as u64;
    push(sha256::base_low(), &move |i, _| low(i));
    push(sha256::base_low_hi(), &move |i, _| low(i) >> 16);
    push(sha256::base_room(), &move |i, _| room(i));
    push(sha256::base_room_hi(), &move |i, _| room(i) >> 16);
    for g in 0..f::GROUPS {
        push(sha256::group_sel(g), &move |i, _| u64::from(i.group == g));
    }
    for j in -2..=3isize {
        for b in 0..4 {
            push(sha256::a_byte(j, b), &move |_, c| {
                byte(c.a[(j + 3) as usize], b)
            });
            push(sha256::e_byte(j, b), &move |_, c| {
                byte(c.e[(j + 3) as usize], b)
            });
        }
    }
    for i in [1usize, 2, 3, 4, 14, 15] {
        for b in 0..4 {
            push(sha256::w_byte(i, b), &move |inv, _| byte(inv.window[i], b));
        }
    }
    for m in 0..2 {
        for b in 0..4 {
            push(sha256::n_byte(m, b), &move |_, c| byte(c.x[16 + m], b));
        }
    }
    for k in 0..R {
        for block in [
            Round::Bs0M1,
            Round::Bs0Y,
            Round::Bs0M3,
            Round::Bs0X,
            Round::Bs1M6,
            Round::Bs1Y,
            Round::Bs1M5,
            Round::Bs1X,
            Round::ChEf,
            Round::ChEg,
            Round::MajAb,
            Round::MajCab,
        ] {
            for b in 0..4 {
                push(sha256::round_col(k, block, b), &move |_, c| {
                    byte(round_word(c, k, block), b)
                });
            }
        }
        push(sha256::round_col(k, Round::Bs0Mx, 0), &move |_, c| {
            byte(c.bs0[k].1, 0) ^ 0x03
        });
        push(sha256::round_col(k, Round::Bs1Mx, 0), &move |_, c| {
            byte(c.bs1[k].1, 0) ^ 0x3f
        });
        push(sha256::round_col(k, Round::CarryA, 0), &move |_, c| {
            c.carry_a[k] as u64
        });
        push(sha256::round_col(k, Round::CarryE, 0), &move |_, c| {
            c.carry_e[k] as u64
        });
    }
    for m in 0..R {
        for (block, width) in [
            (Sched::Ss0M3, 4),
            (Sched::Ss0Y, 4),
            (Sched::Ss0M7, 4),
            (Sched::Ss0Shr, 4),
            (Sched::Ss0Z, 4),
            (Sched::Ss1M2, 4),
            (Sched::Ss1Y, 4),
            (Sched::Ss1M1, 4),
            (Sched::Ss1Shr, 3),
            (Sched::Ss1Z, 3),
        ] {
            for b in 0..width {
                push(sha256::sched_col(m, block, b), &move |_, c| {
                    byte(sched_word(c, m, block), b)
                });
            }
        }
        push(sha256::sched_col(m, Sched::CarryW, 0), &move |_, c| {
            c.carry_w[m] as u64
        });
    }
    push(sha256::written_hi(0), &|_, c| (c.a[7] >> 16) as u64);
    push(sha256::written_hi(1), &|_, c| (c.e[7] >> 16) as u64);
    push(sha256::written_hi(2), &|_, c| (c.x[18] >> 16) as u64);
    push(sha256::written_hi(3), &|_, c| (c.x[19] >> 16) as u64);
    // A channel's multiplicity is `crates/trace`'s and no gate reads it — but
    // `a.committed()` names it, so the column has to exist.
    out.push((sha256::range16_multiplicity(), column(vec![0; ROWS])));
    out.push((sha256::xor8_multiplicity(), column(vec![0; ROWS])));
    out
}

// ---------------------------------------------------------------------------
// Evaluation, row by row
// ---------------------------------------------------------------------------

/// The memory challenges, the channels' `g` and the `beta` powers.
fn challenges_for(a: &CircuitArtifact) -> ExternalChallenges {
    let mut ch = ExternalChallenges::new();
    for (slot, value) in [
        (challenge_slot::MEM_GAMMA, 3u64),
        (challenge_slot::MEM_ALPHA_ADDR, 5),
        (challenge_slot::MEM_ALPHA_TS, 7),
        (challenge_slot::MEM_ALPHA_VAL, 11),
    ] {
        ch.insert(slot, Fr::from_u64(value));
    }
    insert_lookup_challenges(&mut ch, Fr::from_u64(13), Fr::from_u64(17), a);
    ch
}

fn corrupt(
    mut columns: Vec<(PolyAddress, MultilinearPoly)>,
    address: PolyAddress,
    row: usize,
    value: Fr,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let slot = columns
        .iter_mut()
        .find(|(a, _)| *a == address)
        .unwrap_or_else(|| panic!("{address} is not a committed column"));
    let mut values: Vec<Fr> = (0..slot.1.len()).map(|r| slot.1.get(r)).collect();
    values[row] = value;
    slot.1 = MultilinearPoly::new(PolyBacking::Fr(values));
    columns
}

fn cell(columns: &[(PolyAddress, MultilinearPoly)], address: PolyAddress, row: usize) -> Fr {
    columns
        .iter()
        .find(|(a, _)| *a == address)
        .unwrap_or_else(|| panic!("{address} is not a committed column"))
        .1
        .get(row)
}

/// One row of a column set as a witness row of `a`, its scratch computed
/// row-locally by the engine's own gate kernel.
fn witness_row(
    a: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    row: usize,
) -> checker::WitnessRow {
    let committed: Vec<Fr> = a
        .committed()
        .into_iter()
        .map(|address| cell(columns, address, row))
        .collect();
    let virtuals: Vec<Fr> = a
        .virtuals
        .iter()
        .map(|(kind, _)| virtual_at_row(*kind, row))
        .collect();
    let ch = challenges_for(a);
    let mut scratch = vec![Fr::ZERO; a.scratch.len()];
    let mut lower = committed.clone();
    for k in 0..a.depth() {
        if a.layers[k].halving {
            break;
        }
        let v: &[Fr] = if k == 0 { &virtuals } else { &[] };
        let values = gate_values(a, k, &lower, &[], v, &ch);
        let produced = values[..a.layers[k].producing.len()].to_vec();
        for (j, value) in produced.iter().enumerate() {
            let address = PolyAddress::Inner {
                layer: k as u32 + 1,
                offset: j as u32,
            };
            let slot = a
                .scratch
                .iter()
                .position(|s| s.address == address)
                .expect("every inner column has a scratch slot");
            scratch[slot] = *value;
        }
        lower = produced;
    }
    checker::WitnessRow {
        committed,
        row,
        scratch,
    }
}

/// The relation the corrupted witness breaks first, or a panic.
fn refusal(a: &CircuitArtifact, columns: Vec<(PolyAddress, MultilinearPoly)>) -> String {
    for row in 0..ROWS {
        let violated =
            checker::violated_relations(a, &witness_row(a, &columns, row), &challenges_for(a));
        if let Some(name) = violated.first() {
            return name.clone();
        }
    }
    panic!("the corrupted witness satisfies every gate")
}

/// A field element as the byte it must be, or `None`.
fn as_byte(x: Fr) -> Option<u64> {
    let bytes = x.to_bytes();
    match bytes[1..].iter().all(|b| *b == 0) {
        true => Some(bytes[0] as u64),
        false => None,
    }
}

/// One tuple expression of a lookup, evaluated over one row.
fn expression(e: &GateDef, columns: &[(PolyAddress, MultilinearPoly)], row: usize) -> Fr {
    let GateDef::Linear { terms, constant } = e else {
        panic!("a lookup expression is a Linear gate")
    };
    let Coeff::Literal(mut acc) = *constant else {
        panic!("a lookup expression's constant is a literal")
    };
    for (c, address) in terms {
        let Coeff::Literal(c) = c else {
            panic!("a lookup expression's coefficient is a literal")
        };
        acc += *c * cell(columns, *address, row);
    }
    acc
}

/// Every `XOR8` obligation of `a` that row `row` does not satisfy, by name.
///
/// The table **is** `(a, b, a ^ b)` over every pair of bytes, and this states
/// that rather than looking a row up — the native reading of the obligation and
/// the same statement LogUp proves. A row whose selector is 0 contributes the
/// all-zero tuple, a real entry, so a padding row satisfies every obligation by
/// construction.
fn violated_xor8(
    a: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    row: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    for l in &a.lookups {
        if l.channel != lookup_channel::XOR8 || cell(columns, l.selector, row) == Fr::ZERO {
            continue;
        }
        let values: Vec<Option<u64>> = l
            .tuple
            .iter()
            .map(|e| as_byte(expression(e, columns, row)))
            .collect();
        let held = match values.as_slice() {
            [Some(x), Some(y), Some(z)] => *z == (*x ^ *y),
            _ => false,
        };
        if !held {
            out.push(l.name.clone());
        }
    }
    out
}

/// Every gate, every `RANGE16` obligation and every `XOR8` obligation of
/// every row, or a panic naming the first that fails.
fn assert_every_row_holds(a: &CircuitArtifact, columns: &[(PolyAddress, MultilinearPoly)]) {
    for row in 0..ROWS {
        let w = witness_row(a, columns, row);
        let violated = checker::violated_relations(a, &w, &challenges_for(a));
        assert!(violated.is_empty(), "row {row} breaks {violated:?}");
        let ranges = checker::violated_lookups(a, &w);
        assert!(ranges.is_empty(), "row {row} breaks {ranges:?}");
        let xor = violated_xor8(a, columns, row);
        assert!(xor.is_empty(), "row {row} breaks {xor:?}");
    }
}

/// The `XOR8` obligations the corrupted witness breaks, or a panic.
fn xor8_refusal(a: &CircuitArtifact, columns: &[(PolyAddress, MultilinearPoly)]) -> Vec<String> {
    for row in 0..ROWS {
        let violated = violated_xor8(a, columns, row);
        if !violated.is_empty() {
            return violated;
        }
    }
    panic!("the corrupted witness satisfies every XOR8 obligation")
}

// ---------------------------------------------------------------------------
// The honest set
// ---------------------------------------------------------------------------

/// FIPS 180-4's `"abc"`, padded into its one block.
fn abc_block() -> [u32; 16] {
    let mut block = [0u32; 16];
    block[0] = 0x6162_6380;
    block[15] = 24;
    block
}

/// The 20 live invocations: **one whole compression** — groups 0 to 15, each
/// reading the frame the one before it wrote, at one frame base — then four
/// corners: the all-zero frame, the all-ones frame, and two random frames at the
/// last group and a middle one, so the selector's two ends are both exercised
/// outside the chain.
///
/// The compression is `"abc"` from the initial hash value, which is what lets
/// [`sixteen_calls_are_one_compression`] hold the chain to the published
/// digest.
fn honest() -> Vec<Invocation> {
    let mut live: Vec<Invocation> = Vec::with_capacity(LIVE_ROWS);
    let mut state = f::IV;
    let mut window = abc_block();
    for group in 0..f::GROUPS {
        let inv = Invocation {
            cycle: 7 + group as u64,
            base: guest_memory::RAM_ORIGIN + 4 * 1024,
            group,
            state,
            window,
        };
        let c = call_of(&inv);
        state = c.state_out;
        window.copy_from_slice(&c.x[4..]);
        live.push(inv);
    }
    let mut rng = test_support::Rng::new(0x5ba2_5626);
    let mut random = |cycle: u64, group: usize| Invocation {
        cycle,
        base: guest_memory::RAM_ORIGIN + 4 * 4096 * cycle as u32,
        group,
        state: core::array::from_fn(|_| rng.next_u64() as u32),
        window: core::array::from_fn(|_| rng.next_u64() as u32),
    };
    let (last, middle) = (random(101, f::GROUPS - 1), random(103, 6));
    live.push(Invocation {
        cycle: 105,
        base: guest_memory::RAM_ORIGIN + 4 * 9000,
        group: 0,
        state: [0; 8],
        window: [0; 16],
    });
    live.push(Invocation {
        cycle: 107,
        base: guest_memory::RAM_ORIGIN + 4 * 9100,
        group: 3,
        state: [u32::MAX; 8],
        window: [u32::MAX; 16],
    });
    live.push(last);
    live.push(middle);
    live
}

// ---------------------------------------------------------------------------
// The circuit
// ---------------------------------------------------------------------------

#[test]
fn the_circuit_keeps_every_rule() {
    let a = sha256::artifact(VARS);
    a.validate().expect("the circuit is a circuit");
    checker::check_laws(&a).expect("the standalone validators agree");
    checker::check_padding(&a).expect("the padding contract holds");
    checker::check_padding_identity(&a).expect("the padding identity clause holds");
    constraints::memory::check_memory(&a).expect("the memory provenance rules hold");
    checker::check_lookup_discharge(&a, &sha256::channels())
        .expect("every obligation is discharged exactly once, in its own channel");
}

/// The shape `docs/spec/delegation-circuits.md` §6 accounts for.
#[test]
fn the_shape_is_the_manifests() {
    let a = sha256::artifact(VARS);
    assert_eq!(a.memory.len(), 4 + 4 * f::FRAME_WORDS);
    assert_eq!(a.memory.len(), sha256::MEMORY_COLUMNS);
    assert_eq!(a.witness.len(), sha256::WITNESS_COLUMNS);
    assert_eq!(a.memory.len() + a.witness.len(), 624);
    assert!(a.setup.is_empty(), "no setup column, so nothing to bind");
    assert_eq!(a.virtuals.len(), 4, "range16, and XOR8's three columns");

    // 114 on `RANGE16` — four a frame gap, three a base decomposition, two for
    // each of the four written words that carry a pair — and 336 on `XOR8`:
    // 52 a round and 32 a derived word.
    let count = |channel: u32| a.lookups.iter().filter(|l| l.channel == channel).count();
    assert_eq!(count(lookup_channel::RANGE16), 114);
    assert_eq!(count(lookup_channel::XOR8), 336);
    assert_eq!(a.lookups.len(), 450);

    // Flat: one list of enforcing gates, everything above it a tree.
    assert!(a.layers[1..].iter().all(|l| l.enforcing.is_empty()));
    let enforcing = a.layers[0].enforcing.len();
    assert_eq!(
        enforcing,
        // the frame: live_boolean, 25 addr_w, base_aligned, base_in_window
        1 + f::FRAME_WORDS + 2
            // the selector: 16 booleanity, group_rule, one_group_a_live_row
            + f::GROUPS + 2
            // writes_back_w0; A and E's six decodes and encodes each; the six
            // window decodes, the two derived encodes and the twelve shifts
            + 1 + 12 + 6 + 2 + 12
            // two sums a round and one a derived word
            + 2 * R + R
            // the small sigmas' shifted bytes: four and three a derived word
            + 7 * R,
        "the enforcing gates are the manifest's"
    );
    assert_eq!(enforcing, 119);
    assert_eq!(a.outputs.len(), 6, "two memory roots and two channels");
    // One gate list, nine row-wise reductions — the XOR8 tree's depth — and one
    // halving list a variable.
    assert_eq!(a.depth(), 1 + 9 + VARS as usize);
}

/// A height adds one halving list per variable and changes no gate.
#[test]
fn a_height_moves_only_the_halving_layers() {
    let (low, high) = (sha256::artifact(16), sha256::artifact(18));
    assert_eq!(low.memory, high.memory);
    assert_eq!(low.witness, high.witness);
    assert_eq!(low.lookups.len(), high.lookups.len());
    assert_eq!(
        low.layers[0].enforcing.len(),
        high.layers[0].enforcing.len()
    );
    assert_eq!(high.depth() - low.depth(), 2);
    assert_eq!(
        high.relations.len() - low.relations.len(),
        2 * low.outputs.len()
    );
}

/// Both channels' tables need sixteen variables, which is the family's floor;
/// `2^8`, where S26c's row lived, is not a height it has any more.
#[test]
fn the_channels_set_the_family_floor() {
    use constants::family::SHA256_COMP as SHA;
    assert!(constraints::family_circuit(SHA, 8).is_none());
    assert!(constraints::family_circuit(SHA, 14).is_none());
    assert!(constraints::family_circuit(SHA, 16).is_some());
    assert_eq!(
        constants::family::DEFAULT_HEIGHTS[SHA as usize],
        1 << VARS,
        "the suite's height is the family's"
    );
}

// ---------------------------------------------------------------------------
// The call
// ---------------------------------------------------------------------------

/// The call this file computes is the call the executor computes, at every
/// group, over random frames.
#[test]
fn the_call_is_the_executors() {
    let mut rng = test_support::Rng::new(0x0d26_5ba2);
    for group in 0..f::GROUPS {
        let inv = Invocation {
            cycle: 1,
            base: guest_memory::RAM_ORIGIN,
            group,
            state: core::array::from_fn(|_| rng.next_u64() as u32),
            window: core::array::from_fn(|_| rng.next_u64() as u32),
        };
        let mine = call_of(&inv);
        let (mut state, mut window) = (inv.state, inv.window);
        emulator::sha256_call(group, &mut state, &mut window);
        assert_eq!(
            mine.state_out, state,
            "group {group}: the working variables"
        );
        assert_eq!(&mine.x[4..], &window, "group {group}: the window");
    }
}

/// The honest set's sixteen rows **are** `sha256("abc")`: the initial hash value
/// plus the working variables the sixteenth call writes is FIPS 180-4's
/// published digest. This is the one line that ties the chain to the standard
/// rather than to another implementation in this repository.
#[test]
fn sixteen_calls_are_one_compression() {
    let live = honest();
    let last = call_of(&live[f::GROUPS - 1]);
    let digest: Vec<u32> = (0..8)
        .map(|j| f::IV[j].wrapping_add(last.state_out[j]))
        .collect();
    assert_eq!(
        digest,
        [
            0xba78_16bf,
            0x8f01_cfea,
            0x4141_40de,
            0x5dae_2223,
            0xb003_61a3,
            0x9617_7a9c,
            0xb410_ff61,
            0xf200_15ad
        ]
    );
}

/// **Acceptance: the circuit computes four SHA-256 rounds and four schedule
/// words, at every group.** Sixteen rows are one whole compression, so every
/// round constant and every selector is exercised; four corners and padding
/// follow, so the padding row's own satisfaction is part of what passes.
#[test]
fn an_honest_witness_satisfies_every_gate_and_obligation() {
    let a = sha256::artifact(VARS);
    assert_every_row_holds(&a, &witness(&honest()));
}

/// The sixteen rows chain through the frame: call `r`'s written frame is call
/// `r + 1`'s read one, at one base — what the memory multiset proves in a real
/// block, and what makes sixteen invocations one compression.
#[test]
fn the_sixteen_rows_chain_through_the_frame() {
    let columns = witness(&honest());
    for row in 0..f::GROUPS - 1 {
        for j in f::STATE_WORD..f::FRAME_WORDS {
            assert_eq!(
                cell(&columns, sha256::word(j, sha256::WORD_WRITE_VALUE), row),
                cell(&columns, sha256::word(j, sha256::WORD_READ_VALUE), row + 1),
                "call {row} word {j}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The negative controls: the gates
// ---------------------------------------------------------------------------

/// A byte that is not its frame word's: a decode is the word's byte split and
/// its 32-bit bound at once.
#[test]
fn a_changed_input_byte_is_refused() {
    let a = sha256::artifact(VARS);
    for (address, gate) in [
        (sha256::a_byte(0, 2), "a0_decode"),
        (sha256::e_byte(-2, 0), "em2_decode"),
        (sha256::w_byte(14, 1), "w14_decode"),
    ] {
        let columns = witness(&honest());
        let was = cell(&columns, address, 3);
        assert_eq!(
            refusal(&a, corrupt(columns, address, 3, was + Fr::ONE)),
            gate
        );
    }
}

/// A written word that is not the call's result: `A_1..A_3` are encoded from
/// their bytes, and `A_4` is the round equation's.
#[test]
fn a_changed_written_word_is_refused() {
    let a = sha256::artifact(VARS);
    for (j, gate) in [
        (f::STATE_WORD + 3, "a1_encode"),
        (f::STATE_WORD + 5, "e3_encode"),
        (f::STATE_WORD, "r3_a"),
        (f::WINDOW_WORD + 13, "n1_encode"),
        (f::WINDOW_WORD + 15, "s3_sum"),
    ] {
        let columns = witness(&honest());
        let address = sha256::word(j, sha256::WORD_WRITE_VALUE);
        let was = cell(&columns, address, 5);
        assert_eq!(
            refusal(&a, corrupt(columns, address, 5, was + Fr::ONE)),
            gate,
            "frame word {j}"
        );
    }
}

/// A window word not moved down four: `w{i}_shift`.
#[test]
fn a_window_not_shifted_is_refused() {
    let a = sha256::artifact(VARS);
    let columns = witness(&honest());
    let address = sha256::word(f::WINDOW_WORD + 7, sha256::WORD_WRITE_VALUE);
    let was = cell(&columns, address, 2);
    assert_eq!(
        refusal(&a, corrupt(columns, address, 2, was + Fr::ONE)),
        "w7_shift"
    );
}

/// A group word the call rewrote: `writes_back_w0`. The guest's loop advances
/// the group, and a call that could rewrite it would be naming the next call's
/// round constants itself.
#[test]
fn a_group_word_the_call_rewrote_is_refused() {
    let a = sha256::artifact(VARS);
    let columns = witness(&honest());
    let address = sha256::word(f::GROUP_WORD, sha256::WORD_WRITE_VALUE);
    let was = cell(&columns, address, 9);
    assert_eq!(
        refusal(&a, corrupt(columns, address, 9, was + Fr::ONE)),
        "writes_back_w0"
    );
}

/// A selector the group word does not name: `group_rule`. A row claiming another
/// group would add the wrong round constants — correct arithmetic and the wrong
/// answer.
#[test]
fn a_selector_the_group_word_does_not_name_is_refused() {
    let a = sha256::artifact(VARS);
    let columns = witness(&honest());
    assert_eq!(
        refusal(&a, corrupt(columns, sha256::group_sel(11), 11, Fr::ZERO)),
        "group_rule"
    );
}

/// Two selectors at once, spelling a third group: `one_group_a_live_row`.
/// `group_rule` cannot refuse it — `1 + 2 = 3` — and the sum gate is the only
/// thing that does.
#[test]
fn two_groups_at_once_is_refused() {
    let a = sha256::artifact(VARS);
    let mut columns = witness(&honest());
    for (g, value) in [(3usize, Fr::ZERO), (1, Fr::ONE), (2, Fr::ONE)] {
        columns = corrupt(columns, sha256::group_sel(g), 3, value);
    }
    assert_eq!(refusal(&a, columns), "one_group_a_live_row");
}

/// A carry that is not the sum's: the round equation it closes.
#[test]
fn a_changed_carry_is_refused() {
    let a = sha256::artifact(VARS);
    for (address, gate) in [
        (sha256::round_col(1, Round::CarryA, 0), "r1_a"),
        (sha256::round_col(2, Round::CarryE, 0), "r2_e"),
        (sha256::sched_col(0, Sched::CarryW, 0), "s0_sum"),
    ] {
        let columns = witness(&honest());
        let was = cell(&columns, address, 4);
        assert_eq!(
            refusal(&a, corrupt(columns, address, 4, was + Fr::ONE)),
            gate
        );
    }
}

/// A shifted byte that is not the shift: the small sigmas' committed shifts are
/// pinned by `s{m}_shr3_b{b}` and `s{m}_shr10_b{b}`.
#[test]
fn a_changed_shift_byte_is_refused() {
    let a = sha256::artifact(VARS);
    for (address, gate) in [
        (sha256::sched_col(2, Sched::Ss0Shr, 1), "s2_shr3_b1"),
        (sha256::sched_col(3, Sched::Ss1Shr, 2), "s3_shr10_b2"),
    ] {
        let columns = witness(&honest());
        let was = cell(&columns, address, 8);
        assert_eq!(
            refusal(&a, corrupt(columns, address, 8, was + Fr::ONE)),
            gate
        );
    }
}

/// A frame word at the wrong address, and a misaligned base with every address
/// moved with it, which leaves `base_aligned` the only thing to refuse it.
#[test]
fn a_frame_off_its_base_is_refused() {
    let a = sha256::artifact(VARS);
    let columns = witness(&honest());
    let address = sha256::word(12, sha256::WORD_ADDR);
    let was = cell(&columns, address, 2);
    assert_eq!(
        refusal(&a, corrupt(columns, address, 2, was + Fr::from_u64(4))),
        "addr_w12"
    );

    let mut columns = witness(&honest());
    let two = Fr::from_u64(2);
    let was = cell(&columns, sha256::BASE, 4);
    columns = corrupt(columns, sha256::BASE, 4, was + two);
    for j in 0..f::FRAME_WORDS {
        let address = sha256::word(j, sha256::WORD_ADDR);
        let was = cell(&columns, address, 4);
        columns = corrupt(columns, address, 4, was + two);
    }
    assert_eq!(refusal(&a, columns), "base_aligned");
}

// ---------------------------------------------------------------------------
// The negative controls: the obligations
// ---------------------------------------------------------------------------

/// Some stages are pinned by the `XOR8` channel **alone**: no gate reads the
/// big sigmas' inner `y` and masks, `a ^ b`, or the small sigma's inner `y` and
/// `ROTR7` mask, so a wrong value breaks no relation and is refused by the
/// obligation that writes it. The round **is** its obligations; the gates only
/// tie those to the frame.
#[test]
fn a_stage_no_gate_reads_is_refused_by_the_channel_alone() {
    let a = sha256::artifact(VARS);
    let honest_columns = witness(&honest());
    let row = 6;
    let cases: [(PolyAddress, &str); 7] = [
        (sha256::round_col(0, Round::Bs0M1, 2), "r0_bs0_m1_b2_xor"),
        (sha256::round_col(1, Round::Bs0Y, 3), "r1_bs0_y_b3_xor"),
        (sha256::round_col(2, Round::Bs1M6, 0), "r2_bs1_m6_b0_xor"),
        (sha256::round_col(3, Round::Bs1M5, 1), "r3_bs1_m5_b1_xor"),
        (sha256::round_col(1, Round::MajAb, 0), "r1_maj_ab_b0_xor"),
        (sha256::sched_col(1, Sched::Ss0Y, 2), "s1_ss0_y_b2_xor"),
        (sha256::sched_col(0, Sched::Ss0M7, 3), "s0_ss0_m7_b3_xor"),
    ];
    for (address, obligation) in cases {
        let was = cell(&honest_columns, address, row);
        let columns = corrupt(honest_columns.clone(), address, row, was + Fr::ONE);
        for r in 0..ROWS {
            let violated =
                checker::violated_relations(&a, &witness_row(&a, &columns, r), &challenges_for(&a));
            assert!(
                violated.is_empty(),
                "{address} broke the gate {violated:?}, so the channel is not its only bound"
            );
        }
        assert!(
            xor8_refusal(&a, &columns).contains(&obligation.to_string()),
            "{address} is not refused by `{obligation}`"
        );
    }
}

/// The stages a sum reads are refused **twice**: by the round or schedule
/// equation whose linear form reads them, and by the obligation that writes
/// them. Which list a stage is in is a property of the circuit's shape, and a
/// stage moving from one to the other would be a real change in what pins it.
#[test]
fn a_stage_a_sum_reads_is_refused_twice() {
    let a = sha256::artifact(VARS);
    let honest_columns = witness(&honest());
    let row = 6;
    for (address, gate, obligation) in [
        (
            sha256::round_col(0, Round::Bs0X, 1),
            "r0_a",
            "r0_bs0_x_b1_xor",
        ),
        (
            sha256::round_col(2, Round::Bs1Mx, 0),
            "r2_a",
            "r2_bs1_mx_xor",
        ),
        (
            sha256::round_col(1, Round::ChEg, 3),
            "r1_a",
            "r1_ch_eg_b3_xor",
        ),
        (
            sha256::round_col(3, Round::MajCab, 2),
            "r3_a",
            "r3_maj_cab_b2_xor",
        ),
        (
            sha256::sched_col(2, Sched::Ss0Z, 0),
            "s2_sum",
            "s2_ss0_z_b0_xor",
        ),
        (
            sha256::sched_col(1, Sched::Ss1Y, 1),
            "s1_sum",
            "s1_ss1_y_b1_xor",
        ),
    ] {
        let was = cell(&honest_columns, address, row);
        let columns = corrupt(honest_columns.clone(), address, row, was + Fr::ONE);
        assert_eq!(refusal(&a, columns.clone()), gate, "{address}");
        assert!(
            xor8_refusal(&a, &columns).contains(&obligation.to_string()),
            "{address} is not refused by `{obligation}`"
        );
    }
}

/// A carry that is not a byte is refused by its range obligation, `(0, c, c)`,
/// even when the sum it closes is rebalanced to hold: what makes every round
/// equation an integer equation is that bound.
///
/// The twin moves `A_4` up by `2^32` and its carry down by one, which keeps
/// `r{k}_a` true over `Fr`. Two things refuse it: the written word's own
/// `RANGE16` pair, `A_4` no longer being below `2^32`, and — where the honest
/// carry was 0 — the carry's byte range.
#[test]
fn a_rebalanced_sum_is_refused_by_its_ranges() {
    let a = sha256::artifact(VARS);
    let columns = witness(&honest());
    let row = (0..f::GROUPS)
        .find(|r| cell(&columns, sha256::round_col(3, Round::CarryA, 0), *r) != Fr::ZERO)
        .expect("a row whose last round carries");
    let write = sha256::word(f::STATE_WORD, sha256::WORD_WRITE_VALUE);
    let carry = sha256::round_col(3, Round::CarryA, 0);
    let two32 = Fr::from_u64(1 << 32);
    let (w, c) = (cell(&columns, write, row), cell(&columns, carry, row));
    let broken = corrupt(
        corrupt(columns, write, row, w + two32),
        carry,
        row,
        c - Fr::ONE,
    );
    for r in 0..ROWS {
        let violated =
            checker::violated_relations(&a, &witness_row(&a, &broken, r), &challenges_for(&a));
        assert!(violated.is_empty(), "the sum still holds: {violated:?}");
    }
    let ranges = checker::violated_lookups(&a, &witness_row(&a, &broken, row));
    assert!(
        ranges.iter().any(|n| n.starts_with("w1_written")),
        "A_4's RANGE16 pair refuses a word above 2^32: {ranges:?}"
    );
}

/// A gap chunk is refused by `RANGE16` alone: there is no `gap_w{j}` gate, the
/// obligations being the bound and the decomposition at once.
#[test]
fn a_changed_gap_chunk_is_refused_by_the_channel_alone() {
    let a = sha256::artifact(VARS);
    let columns = witness(&honest());
    let broken = corrupt(columns, sha256::gap_chunk(3, 0), 10, Fr::from_u64(2));
    for r in 0..ROWS {
        let violated =
            checker::violated_relations(&a, &witness_row(&a, &broken, r), &challenges_for(&a));
        assert!(
            violated.is_empty(),
            "a gap chunk broke the gate {violated:?}"
        );
    }
    let violated = checker::violated_lookups(&a, &witness_row(&a, &broken, 10));
    assert!(
        violated.contains(&"gap3_lo_range".to_string()),
        "the gap's derived low part is what sees it: {violated:?}"
    );
}

/// The padding row is free where every gate and obligation carries `live`, and
/// **not** free where a gate is ungated: a byte decode is, and a padding row's
/// words are 0.
#[test]
fn a_padding_row_is_free_only_where_the_mask_reaches() {
    let a = sha256::artifact(VARS);
    let columns = witness(&honest());
    let padding = LIVE_ROWS;
    assert_eq!(cell(&columns, sha256::LIVE, padding), Fr::ZERO);

    let mut free = columns.clone();
    for address in [
        sha256::gap_chunk(5, 1),
        sha256::base_room_hi(),
        sha256::round_col(1, Round::Bs0M3, 0),
    ] {
        free = corrupt(free, address, padding, Fr::ONE);
    }
    assert_every_row_holds(&a, &free);

    assert_eq!(
        refusal(
            &a,
            corrupt(columns, sha256::a_byte(-1, 3), padding, Fr::ONE)
        ),
        "am1_decode"
    );
}

// ---------------------------------------------------------------------------
// The prover's own fill, over a real trace
// ---------------------------------------------------------------------------

/// **`prover::fill::sha256_comp` writes the values this circuit's relations and
/// obligations expect**, over `guests/sha256-ops`' real execution.
///
/// Everything above builds its own columns, so nothing above can see a
/// disagreement between the fill's layout and the circuit's — a byte read at
/// the wrong offset or a block transposed is a silently wrong proof, and
/// `crates/prover/tests/fills.rs` only checks that every address is written
/// once. `trace::build_multiplicities` is part of what passes: it refuses a
/// gated tuple no row of the channel's table answers.
#[test]
fn the_fill_satisfies_every_gate_and_every_obligation() {
    let program = common::sha256_program();
    let archive = common::sha256_archive(&program);
    let circuit = constraints::family_circuit(constants::family::SHA256_COMP, VARS)
        .expect("the registry has the circuit");
    let a = &circuit.artifact;
    let fill = prover::family_fill(constants::family::SHA256_COMP).expect("the family's fill");
    let source = prover::ShardSource::archived(
        &program,
        &archive,
        constants::family::SHA256_COMP,
        0,
        1 << VARS,
        0,
    )
    .expect("the shard's rows");
    let mut columns = fill(&source).expect("the fill");
    let counts = trace::build_multiplicities(a, &columns, &circuit.channels)
        .unwrap_or_else(|e| panic!("sha256 multiplicities: {e}"));
    columns.extend(counts);
    assert_eq!(columns.len(), a.committed().len());

    let live = archive
        .family_traces()
        .delegation(constants::family::SHA256_COMP)
        .expect("the archive has the delegation buffer")
        .len();
    // One raw call, `sha256-ops`' first check, then whole compressions of
    // sixteen calls each.
    assert_eq!(
        (live - 1) % f::GROUPS,
        0,
        "a raw call, then whole compressions"
    );

    let rows: Vec<usize> = (0..live + 2).chain([(1usize << VARS) - 1]).collect();
    for row in rows {
        let w = witness_row(a, &columns, row);
        let violated = checker::violated_relations(a, &w, &challenges_for(a));
        assert!(violated.is_empty(), "row {row} breaks {violated:?}");
        let ranges = checker::violated_lookups(a, &w);
        assert!(ranges.is_empty(), "row {row} breaks {ranges:?}");
        let xor = violated_xor8(a, &columns, row);
        assert!(xor.is_empty(), "row {row} breaks {xor:?}");
    }
    // After the raw call, the groups run 0..16 in order, which is the guest's
    // loop seen from the prover's side.
    for row in 1..live {
        let group = (row - 1) % f::GROUPS;
        assert_eq!(
            cell(&columns, sha256::group_sel(group), row),
            Fr::ONE,
            "invocation {row} claims group {group}"
        );
    }
}
