//! The memory argument's gates through the kernel, and its verifier functions,
//! `docs/spec/memory.md` §2.2, §3.3 and §4: every leaf of every execution
//! family's frame and of the two window artifacts against the tuple written out
//! in plain field arithmetic, the boundary factors against the same, the window
//! constant against a hand computation, the reconciliation, and an honest proof
//! of each artifact.
//!
//! The address spaces, the slots `Δ`, the column positions **and each family's
//! query list** are written here again rather than read from
//! `constraints::memory`. A family's frame holds only the queries its
//! instructions can make, so a leaf's `AS` and `Δ` come from its **global query
//! id** while its columns come from its **slot** — its position in that
//! family's list — and the two agree only for the pc query. Every table below
//! is indexed by whichever of the two the document says it is.

mod common;

use common::{committed_columns, discharge, fr_base, output_claims};
use constants::challenge_slot::{
    MEM_ALPHA_ADDR, MEM_ALPHA_TS, MEM_ALPHA_VAL, MEM_GAMMA, MEM_WINDOW_CONSTANT,
};
use constants::family;
use constants::transcript_tags;
use constants::{address_space, guest_memory};
use constraints::memory::{
    advice_window_artifact, family_frame_artifact, frame_artifact, image_window_artifact,
    zero_window_artifact,
};
use constraints::{CircuitArtifact, VirtualKind};
use field::Fr;
use gkr::{
    boundary_factors, forward, gate_values, prove, reconciles, self_check, verify, virtual_at_row,
    window_challenges, BaseLayer, BoundaryFinals, ExternalChallenges, GkrError, SelfCheckError,
};
use sumcheck::{absorb_witness_digest, witness_digest};
use test_support::Rng;
use transcript::Transcript;

/// The query table, by **global query id**: pc, rs1, rs2, arg1, arg2, load,
/// ram, rd, and — S21's eighth role — deleg, a delegation request's mirror, in
/// the keccak family's own address space 4 (`docs/spec/delegation.md` §5.1).
/// No family holds all nine.
const SPACE: [u64; 9] = [3, 1, 1, 1, 1, 2, 2, 1, 4];
const DELTA: [u64; 9] = [0, 1, 2, 2, 2, 2, 3, 3, 3];

/// The query ids, in the table's frozen order.
const PC: usize = 0;
const RS1: usize = 1;
const RS2: usize = 2;
const ARG1: usize = 3;
const ARG2: usize = 4;
const LOAD: usize = 5;
const RAM: usize = 6;
const RD: usize = 7;
const DELEG: usize = 8;

/// The queries that write back what they read, `docs/spec/memory.md` §2.4.
const READ_ONLY: [usize; 5] = [RS1, RS2, ARG1, ARG2, LOAD];

/// Every execution family and the queries its frame holds, `docs/spec/memory.md`
/// §2.1's table written out, with `deleg` on the family that owns ecall rows
/// (`docs/spec/delegation.md` §5.1). Widths 8, 4, 6 and 5: the two that are not
/// powers of two carry constant-1 pad leaves, and the 8- and the 4-wide ones
/// carry none.
const FAMILIES: [(u32, &[usize]); 7] = [
    (
        family::ADD_SUB_LUI_AUIPC,
        &[PC, RS1, RS2, ARG1, ARG2, RAM, RD, DELEG],
    ),
    (family::JUMP_BRANCH_SLT, &[PC, RS1, RS2, RD]),
    (family::SHIFT_BITWISE, &[PC, RS1, RS2, RD]),
    (family::MUL_DIV, &[PC, RS1, RS2, RD]),
    (family::MEM_WORD, &[PC, RS1, RS2, LOAD, RAM, RD]),
    (family::MEM_SUBWORD, &[PC, RS1, RS2, LOAD, RAM, RD]),
    (family::ATOMICS, &[PC, RS1, RS2, RAM, RD]),
];

/// The address space of a RAM tuple, which the window artifacts are all of.
const RAM_SPACE: u64 = 2;

/// The layout position of the query at **slot** `s`, field `f`: 0 mask, 1 addr,
/// 2 read_ts, 3 read_value, 4 write_value. `M[1 + 5s + f]`, and the `1 + 5w`
/// memory columns come first in the committed row.
fn column(slot: usize, field: usize) -> usize {
    1 + 5 * slot + field
}

/// `M[1 + 5w]`, the per-row address-space tag, on the frames that carry one:
/// the delegation mirror's requested type (`docs/spec/delegation.md` §5.1) or
/// a load's `RAM`-or-`ADVICE` (`docs/spec/advice.md` §3.2). One column serves
/// both, no frame holding both queries; a frame with neither does not carry it.
fn space_column(queries: &[usize]) -> Option<usize> {
    (queries.contains(&DELEG) || queries.contains(&LOAD)).then(|| 1 + 5 * queries.len())
}

/// The memory columns of a frame over `queries`: `1 + 5w`, and one more where
/// a per-row address-space tag rides.
fn memory_columns(queries: &[usize]) -> usize {
    1 + 5 * queries.len() + usize::from(space_column(queries).is_some())
}

/// `W[s]`, the gap's high chunk of the query at slot `s`, in a frame over
/// `queries`: the witness columns follow the memory ones.
fn gap_hi(queries: &[usize], slot: usize) -> usize {
    memory_columns(queries) + slot
}

/// `W[w]`, `W[w + 1]`, `W[w + 2]`: the x0 gadget's three witnesses, after the
/// `w` gap columns.
fn rd_inv(queries: &[usize]) -> usize {
    memory_columns(queries) + queries.len()
}
fn rd_is_zero(queries: &[usize]) -> usize {
    rd_inv(queries) + 1
}
fn rd_selected(queries: &[usize]) -> usize {
    rd_inv(queries) + 2
}

/// A frame's committed columns: its memory ones and `w + 3` witness.
fn committed(queries: &[usize]) -> usize {
    memory_columns(queries) + queries.len() + 3
}

/// A pseudo-random field element below `2^252`.
fn fr(rng: &mut Rng) -> Fr {
    let mut b = rng.next_le32();
    b[31] &= 0x0f;
    Fr::from_bytes(&b).expect("below 2^252")
}

fn int(v: u64) -> Fr {
    Fr::from_u64(v)
}

/// Random `γ_M, α_addr, α_ts, α_val`, as values and as slots 1–4.
fn random_memory(rng: &mut Rng) -> ([Fr; 4], ExternalChallenges) {
    let c = [fr(rng), fr(rng), fr(rng), fr(rng)];
    let mut slots = ExternalChallenges::new();
    for (slot, value) in [MEM_GAMMA, MEM_ALPHA_ADDR, MEM_ALPHA_TS, MEM_ALPHA_VAL]
        .into_iter()
        .zip(c)
    {
        slots.insert(slot, value);
    }
    (c, slots)
}

/// `T(AS, ADDR, TS, VAL) = γ_M + AS + α_addr·ADDR + α_ts·TS + α_val·VAL`.
/// `constants::address_space::ADVICE`, as a `u64` for the arithmetic below.
const ADVICE_SPACE: u64 = address_space::ADVICE as u64;

fn t(c: &[Fr; 4], space: Fr, addr: Fr, ts: Fr, value: Fr) -> Fr {
    c[0] + space + c[1] * addr + c[2] * ts + c[3] * value
}

/// **An advice tuple and a RAM tuple are never equal, whatever their address,
/// timestamp and value.** This is the "cannot alias" half of
/// `docs/spec/advice.md` §1.1 stated arithmetically: the multiset matches
/// tuples, and the space term is what keeps a query of one region from being
/// answered by a write in the other.
///
/// It holds unconditionally because `γ_M` is additive and the space is added to
/// it **unweighted** (`docs/spec/memory.md` §2): two tuples that agree in
/// `addr`, `ts` and `value` differ by exactly `ADVICE − RAM = 5`, which is not
/// zero in `Fr`. So the separation does not rest on the addresses being
/// disjoint, and disjoint addresses buy something else — they stop a guest
/// **pointer** walking from one region into the other, which is arithmetic and
/// not a tuple.
///
/// Swept over random challenges and random field values in every position,
/// including the degenerate ones a real trace cannot produce.
#[test]
fn an_advice_tuple_is_never_a_ram_tuple() {
    let mut rng = Rng::new(0x5714_3106);
    let (ram, advice) = (int(address_space::RAM as u64), int(ADVICE_SPACE));
    for trial in 0..64 {
        let (c, _) = random_memory(&mut rng);
        let (addr, ts, value) = (fr(&mut rng), fr(&mut rng), fr(&mut rng));
        assert_ne!(
            t(&c, ram, addr, ts, value),
            t(&c, advice, addr, ts, value),
            "trial {trial}: one address, one timestamp, one value, two spaces"
        );
        // And the difference is the constant 5, whatever the challenges: the
        // space is not weighted by one.
        assert_eq!(
            t(&c, advice, addr, ts, value) - t(&c, ram, addr, ts, value),
            int(ADVICE_SPACE - address_space::RAM as u64),
            "trial {trial}"
        );
        // Degenerate rows too: a tuple of zeros in every other position.
        assert_ne!(
            t(&c, ram, Fr::ZERO, Fr::ZERO, Fr::ZERO),
            t(&c, advice, Fr::ZERO, Fr::ZERO, Fr::ZERO),
            "trial {trial}: the all-zero tuple"
        );
    }
}

/// Every frame leaf of every execution family is exactly 1 at `m = 0`, whatever
/// the other columns and challenges are, and at `m = 1` the read leaf is
/// `T(AS, addr, read_ts, read_value)` and the write leaf `T(AS, addr, 4·cycle +
/// Δ, write_value)` — with `AS` and `Δ` the **query's**, from the global table,
/// and every column the **slot's**. Each slot's mask is tried alone at 1 among
/// zeros and alone at 0 among ones, beside all zeros and all ones, so leaves `s`
/// and `side + s` must read slot `s`'s own mask. The pad leaves that fill each
/// side out to a power of two are 1 on every one of those rows.
///
/// Kills a wrong AS, Δ, timestamp step, column position or mask term, a leaf
/// masked by another query's mask, a pad leaf that reads anything, and — the
/// mutant the per-family frames add — a leaf taking its AS or Δ from its slot
/// instead of its query id, which differs at `ATOMICS`' slot 3 (`ram`, AS 2,
/// Δ 3, against `arg1`'s AS 1, Δ 2) and at `ADD_SUB_LUI_AUIPC`'s slots 5, 6 and
/// 7 — the last of them `deleg`, whose AS is the row's `deleg_space` column
/// against slot 7's `rd` AS 1 (`docs/spec/delegation.md` §5.1).
/// Each family's query list is the test's own; `frame_artifact` over it is
/// asserted equal to `family_frame_artifact`, so a changed `frame_queries` fails
/// here rather than quietly moving what is swept.
#[test]
fn frame_leaves_are_one_when_masked_and_the_tuple_when_live() {
    let mut rng = Rng::new(0x5714_3101);
    for (id, queries) in FAMILIES {
        let a = family_frame_artifact(id, 4);
        assert_eq!(a, frame_artifact(queries, 4), "family {id}'s query list");
        let width = queries.len();
        let side = width.next_power_of_two();

        let mut patterns = vec![vec![false; width], vec![true; width]];
        for s in 0..width {
            let mut alone = vec![false; width];
            alone[s] = true;
            patterns.push(alone.iter().map(|live| !live).collect());
            patterns.push(alone);
        }
        for live in patterns {
            let (c, slots) = random_memory(&mut rng);
            let mut row: Vec<Fr> = (0..committed(queries)).map(|_| fr(&mut rng)).collect();
            for (s, &m) in live.iter().enumerate() {
                row[column(s, 0)] = if m { Fr::ONE } else { Fr::ZERO };
            }
            let values = gate_values(&a, 0, &row, &[], &[], &slots);
            let cycle = row[0];
            for (s, &q) in queries.iter().enumerate() {
                let (addr, read_ts) = (row[column(s, 1)], row[column(s, 2)]);
                let (read_value, write_value) = (row[column(s, 3)], row[column(s, 4)]);
                let write_ts = int(4) * cycle + int(DELTA[q]);
                // Two queries' `AS` is not a literal of the table: the
                // delegation mirror's type and, since S25b, a load's space,
                // each riding the frame's one extra column
                // (`docs/spec/delegation.md` §5.1, `docs/spec/advice.md`
                // §3.2). Here that column is one more random cell, which is
                // exactly the sweep this test wants of it.
                let space = match q {
                    DELEG | LOAD => row[space_column(queries).expect("the frame carries one")],
                    _ => int(SPACE[q]),
                };
                let (read, write) = if live[s] {
                    (
                        t(&c, space, addr, read_ts, read_value),
                        t(&c, space, addr, write_ts, write_value),
                    )
                } else {
                    (Fr::ONE, Fr::ONE)
                };
                let at = format!("family {id}, masks {live:?}, slot {s} (query {q})");
                assert_eq!(values[s], read, "{at}: read leaf");
                assert_eq!(values[side + s], write, "{at}: write leaf");
            }
            for i in width..side {
                let at = format!("family {id}, masks {live:?}, pad leaf {i}");
                assert_eq!(values[i], Fr::ONE, "{at}: read side");
                assert_eq!(values[side + i], Fr::ONE, "{at}: write side");
            }
        }
    }
}

/// The window leaves at rows either side of `2^14` and at the ends of the
/// window: `INIT_TEARDOWN`'s two leaves are 1 below `2^14`, and from it the
/// teardown tuple `T(RAM, 4y, ts, value)` and the init tuple
/// `T(RAM, 4y, 0, init_value)`; `ZERO_WINDOWS`' leaves at window `w` are
/// `T(RAM, 4h·w + 4y, ts, value)` and `T(RAM, 4h·w + 4y, 0, 0)` on every row;
/// and `ADVICE_WINDOWS`' are the same pair one space over, with `M[2]` where
/// the literal 0 was: `T(ADVICE, A + 4h·w + 4y, ts, value)` and
/// `T(ADVICE, A + 4h·w + 4y, 0, init_value)`, `A` being `ADVICE_ORIGIN`. All
/// three through `window_challenges`. Kills a wrong window constant, address
/// step, mask, timestamp or space — and, for advice, an init leaf that read
/// the teardown column instead of its own.
#[test]
fn window_leaves_are_the_tuples_of_their_rows() {
    let (vars, h) = (16u32, 1u64 << 16);
    let image = image_window_artifact(vars);
    let zero = zero_window_artifact(vars);
    let advice = advice_window_artifact(vars);
    let mut rng = Rng::new(0x5714_3102);
    let rows = [
        0usize,
        1,
        (1 << 14) - 1,
        1 << 14,
        (1 << 14) + 1,
        (1 << 16) - 1,
    ];
    for trial in 0..4 {
        let (c, slots) = random_memory(&mut rng);
        let window = 1 + (rng.next_u64() % ((1 << 29) / h - 1)) as u32;
        let random_row = (rng.next_u64() % h) as usize;
        for y in rows.into_iter().chain([random_row]) {
            let (ts, value, init) = (fr(&mut rng), fr(&mut rng), fr(&mut rng));
            let row_index = virtual_at_row(VirtualKind::RowIndex, y);
            let live = virtual_at_row(VirtualKind::RamLive, y);

            let values = gate_values(
                &image,
                0,
                &[ts, value, init],
                &[],
                &[row_index, live],
                &window_challenges(&slots, address_space::RAM, 0, vars),
            );
            let expected = if y < 1 << 14 {
                vec![Fr::ONE, Fr::ONE]
            } else {
                let addr = int(4 * y as u64);
                vec![
                    t(&c, int(RAM_SPACE), addr, ts, value),
                    t(&c, int(RAM_SPACE), addr, Fr::ZERO, init),
                ]
            };
            assert_eq!(values, expected, "trial {trial}, image window row {y}");

            let values = gate_values(
                &zero,
                0,
                &[ts, value],
                &[],
                &[row_index],
                &window_challenges(&slots, address_space::RAM, window, vars),
            );
            let addr = int(4 * h * window as u64 + 4 * y as u64);
            let expected = vec![
                t(&c, int(RAM_SPACE), addr, ts, value),
                t(&c, int(RAM_SPACE), addr, Fr::ZERO, Fr::ZERO),
            ];
            assert_eq!(values, expected, "trial {trial}, window {window} row {y}");

            // The advice window's three columns, and a window id of its own:
            // advice windows are numbered from 0 at `ADVICE_ORIGIN`, so the
            // whole range `[0, 2^29/h)` is available to it where RAM reserves
            // 0 for `INIT_TEARDOWN`.
            let advice_window = (rng.next_u64() % ((1 << 29) / h)) as u32;
            let values = gate_values(
                &advice,
                0,
                &[ts, value, init],
                &[],
                &[row_index],
                &window_challenges(&slots, address_space::ADVICE, advice_window, vars),
            );
            let addr = int(guest_memory::ADVICE_ORIGIN as u64
                + 4 * h * advice_window as u64
                + 4 * y as u64);
            let expected = vec![
                t(&c, int(address_space::ADVICE as u64), addr, ts, value),
                t(&c, int(address_space::ADVICE as u64), addr, Fr::ZERO, init),
            ];
            assert_eq!(
                values, expected,
                "trial {trial}, advice window {advice_window} row {y}"
            );
        }
    }
}

/// Slot 5 at RAM window 3 of height `2^16`, `γ_M = 11`, `α_addr = 7`:
/// `11 + 2 + 7·(4·65536·3) = 13 + 7·786432 = 5505037`. Slots 1–4 are copied,
/// slot 0 is not; the top RAM window of height `2^22` against its integer; and
/// the advice region's own windows, whose space term and origin both differ.
#[test]
fn the_window_constant_is_pinned() {
    let mut memory = ExternalChallenges::new();
    for (slot, v) in [
        (MEM_GAMMA, 11),
        (MEM_ALPHA_ADDR, 7),
        (MEM_ALPHA_TS, 5),
        (MEM_ALPHA_VAL, 3),
    ] {
        memory.insert(slot, int(v));
    }
    let w = window_challenges(&memory, address_space::RAM, 3, 16);
    assert_eq!(w.get(MEM_WINDOW_CONSTANT), Some(int(5_505_037)));
    for (slot, v) in [
        (MEM_GAMMA, 11),
        (MEM_ALPHA_ADDR, 7),
        (MEM_ALPHA_TS, 5),
        (MEM_ALPHA_VAL, 3),
    ] {
        assert_eq!(w.get(slot), Some(int(v)), "slot {slot}");
    }
    assert_eq!(w.get(0), None);
    // Window 127 of 128 at 2^22: its first address is 0x7F00_0000.
    let top = window_challenges(&memory, address_space::RAM, 127, 22);
    assert_eq!(
        top.get(MEM_WINDOW_CONSTANT),
        Some(int(13 + 7 * 0x7F00_0000))
    );
    // The same window id one space over is a different constant twice: the
    // space term is 7 rather than 2, and the address is offset by
    // `ADVICE_ORIGIN`. Advice window 0 is the first advice word, not address 0.
    let advice = window_challenges(&memory, address_space::ADVICE, 3, 16);
    assert_eq!(
        advice.get(MEM_WINDOW_CONSTANT),
        Some(int(11 + 7 + 7 * (0x8000_0000 + 4 * 65536 * 3)))
    );
    let first = window_challenges(&memory, address_space::ADVICE, 0, 16);
    assert_eq!(
        first.get(MEM_WINDOW_CONSTANT),
        Some(int(18 + 7 * 0x8000_0000))
    );
}

/// Only the two spaces windows initialize may be named. A delegation anchor's
/// space has no windows — its tuples are written by the requesting row, not by
/// an init family — and asking for one is a caller bug, not a soundness hole
/// to be papered over with a constant.
#[test]
#[should_panic(expected = "address space 4 is not initialized in windows")]
fn the_window_constant_refuses_a_space_with_no_windows() {
    let mut memory = ExternalChallenges::new();
    for slot in [MEM_GAMMA, MEM_ALPHA_ADDR, MEM_ALPHA_TS, MEM_ALPHA_VAL] {
        memory.insert(slot, Fr::ONE);
    }
    window_challenges(&memory, address_space::DELEGATION_KECCAK_F, 0, 16);
}

#[test]
#[should_panic(expected = "window_challenges: slot 4 (mem_alpha_val) has no value")]
fn the_window_constant_needs_every_drawn_slot() {
    let mut memory = ExternalChallenges::new();
    for slot in [MEM_GAMMA, MEM_ALPHA_ADDR, MEM_ALPHA_TS] {
        memory.insert(slot, Fr::ONE);
    }
    window_challenges(&memory, address_space::RAM, 1, 16);
}

/// `(W_b, R_b)` against §4.2's products written out: 32 register inits and the
/// pc's init at `entry_pc`; `x0`'s final value 0, `x_1..x_31`'s from
/// `reg_values[r − 1]`, the pc's `HALT_PC = 1`. Then `x10`'s final value moved
/// changes `R_b` alone. Kills an off-by-one in `reg_values`, a pc final that is
/// not 1, a swapped AS, and a swapped pair.
#[test]
fn the_boundary_factors_are_the_documents_products() {
    let mut rng = Rng::new(0x5714_3103);
    for trial in 0..4 {
        let (c, slots) = random_memory(&mut rng);
        let mut finals = BoundaryFinals {
            reg_ts: [0; 32],
            pc_ts: rng.next_u64() >> 26,
            reg_values: [0; 31],
        };
        for ts in finals.reg_ts.iter_mut() {
            *ts = rng.next_u64() >> 26;
        }
        for v in finals.reg_values.iter_mut() {
            *v = rng.next_u64() as u32;
        }
        let entry_pc = rng.next_u64() as u32 & !1;

        let mut w_b = t(&c, int(3), Fr::ZERO, Fr::ZERO, int(entry_pc as u64));
        let mut r_b = t(&c, int(3), Fr::ZERO, int(finals.pc_ts), Fr::ONE);
        w_b *= t(&c, int(1), Fr::ZERO, Fr::ZERO, Fr::ZERO);
        r_b *= t(&c, int(1), Fr::ZERO, int(finals.reg_ts[0]), Fr::ZERO);
        for r in 1..32 {
            w_b *= t(&c, int(1), int(r as u64), Fr::ZERO, Fr::ZERO);
            let value = int(finals.reg_values[r - 1] as u64);
            r_b *= t(&c, int(1), int(r as u64), int(finals.reg_ts[r]), value);
        }
        let (w, r) = boundary_factors(&slots, entry_pc, &finals);
        assert_eq!((w, r), (w_b, r_b), "trial {trial}");

        finals.reg_values[9] ^= 1;
        let (w2, r2) = boundary_factors(&slots, entry_pc, &finals);
        assert_eq!(w2, w, "trial {trial}: W_b does not read the finals");
        assert_ne!(r2, r, "trial {trial}: R_b reads x10's final value");
    }
}

/// Balanced roots reconcile; one changed root does not; a zero root on both
/// sides balances, and is still refused. Kills a check that swaps the factors
/// or omits the nonzero clause.
#[test]
fn reconciles_is_the_product_equation_and_nonzero() {
    let mut rng = Rng::new(0x5714_3104);
    let (r1, r2, w_b, r_b) = (fr(&mut rng), fr(&mut rng), fr(&mut rng), fr(&mut rng));
    let w1 = r1 * r2 * r_b * w_b.inverse().expect("nonzero");
    assert!(reconciles(&[r1, r2], &[w1], (w_b, r_b)));
    assert!(!reconciles(&[r1, r2], &[w1], (r_b, w_b)), "swapped factors");
    assert!(!reconciles(&[r1, r2 + Fr::ONE], &[w1], (w_b, r_b)));
    assert!(!reconciles(&[r1], &[w1], (w_b, r_b)));
    assert!(!reconciles(&[r1, Fr::ZERO], &[w1, Fr::ZERO], (w_b, r_b)));
}

/// Bind the base's digest, then draw slots 1–4 after it — and, for a window
/// shard, derive slot 5 from them at that shard's `(space, window)`.
fn bind(
    a: &CircuitArtifact,
    base: &BaseLayer,
    window: Option<(u8, u32)>,
) -> (Transcript, ExternalChallenges) {
    let mut t = Transcript::new();
    absorb_witness_digest(&mut t, witness_digest(&committed_columns(a, base)));
    let mut memory = ExternalChallenges::new();
    for slot in MEM_GAMMA..=MEM_ALPHA_VAL {
        memory.insert(
            slot,
            t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE),
        );
    }
    let challenges = match window {
        Some((space, w)) => window_challenges(&memory, space, w, a.trace_vars),
        None => memory,
    };
    (t, challenges)
}

/// Forward, self-check, prove and verify on separate transcripts, discharge.
fn prove_and_verify(
    a: &CircuitArtifact,
    base: &BaseLayer,
    window: Option<(u8, u32)>,
) -> Result<(), GkrError> {
    let (mut prover, challenges) = bind(a, base, window);
    let values = forward(a, base, &challenges);
    let proof = prove(a, &values, &challenges, &mut prover);
    let (mut verifier, challenges) = bind(a, base, window);
    let claims = verify(
        a,
        &proof,
        &output_claims(a, &values),
        &challenges,
        &mut verifier,
    )?;
    discharge(base, &claims).expect("an honest proof's base claims discharge");
    Ok(())
}

/// All three window artifacts at `2^16` rows over random columns — every row
/// of a window is an address, so any columns are a witness — prove, verify and
/// discharge, each at a window of its own.
///
/// The advice one is here because nothing else proves it: no committed guest
/// reads advice, so the honest-statement suites over real guests' logs never
/// build an `ADVICE_WINDOWS` shard, and its only other coverage would be a
/// deferred proof. It has three columns rather than two, and its third is the
/// free init value, so "any columns are a witness" is if anything more true of
/// it than of its siblings.
#[test]
fn window_artifacts_prove_and_verify() {
    let mut rng = Rng::new(0x5714_3105);
    let rows = 1usize << 16;
    let mut random = |n: usize| -> Vec<Vec<Fr>> {
        (0..n)
            .map(|_| (0..rows).map(|_| int(rng.next_u64() >> 26)).collect())
            .collect()
    };
    let ram = address_space::RAM;
    let image = image_window_artifact(16);
    let base = fr_base(&image, random(3));
    assert_eq!(prove_and_verify(&image, &base, Some((ram, 0))), Ok(()));

    let zero = zero_window_artifact(16);
    let base = fr_base(&zero, random(2));
    assert_eq!(prove_and_verify(&zero, &base, Some((ram, 5000))), Ok(()));

    let advice = advice_window_artifact(16);
    let base = fr_base(&advice, random(3));
    for window in [0u32, 1, 8191] {
        assert_eq!(
            prove_and_verify(&advice, &base, Some((address_space::ADVICE, window))),
            Ok(()),
            "advice window {window}"
        );
    }
}

/// A satisfying base for the frame holding `queries`, over 16 rows, in layout
/// order: random masks, rows 0 and 1 live in every query; a masked query is 0 in
/// every column; a read-only query writes back; `rd` is at address 0 on row 0
/// and wherever a coin says, with its x0 witnesses consistent. Every column is
/// addressed by the query's **slot** in this family, its behaviour chosen by the
/// query's id: `ram` and `deleg` fall through to the last arm and write what
/// they like, the frame constraining neither — the mirror's three zeroings are
/// the requesting family's own circuit, not its frame
/// (`docs/spec/delegation.md` §5.2).
fn frame_columns(queries: &[usize], rng: &mut Rng) -> Vec<Vec<Fr>> {
    let n = committed(queries);
    let (inv, is_zero, selected) = (rd_inv(queries), rd_is_zero(queries), rd_selected(queries));
    let mut cols: Vec<Vec<Fr>> = vec![Vec::new(); n];
    for y in 0..16 {
        let mut row = vec![Fr::ZERO; n];
        row[0] = int(rng.next_u64() >> 32);
        for (s, &q) in queries.iter().enumerate() {
            if y > 1 && rng.next_u64() & 1 == 0 {
                continue;
            }
            row[column(s, 0)] = Fr::ONE;
            let read_value = int(rng.next_u64() >> 32);
            row[column(s, 2)] = int(rng.next_u64() >> 26);
            row[column(s, 3)] = read_value;
            row[gap_hi(queries, s)] = int(rng.next_u64() >> 45);
            let (addr, write_value) = if READ_ONLY.contains(&q) {
                (int(rng.next_u64() >> 59), read_value)
            } else if q == RD {
                let sel = int(rng.next_u64() >> 32);
                row[selected] = sel;
                if y == 0 || rng.next_u64() & 1 == 0 {
                    row[is_zero] = Fr::ONE;
                    (Fr::ZERO, Fr::ZERO)
                } else {
                    let addr = int(1 + rng.next_u64() % 31);
                    row[inv] = addr.inverse().expect("nonzero");
                    (addr, sel)
                }
            } else {
                (int(rng.next_u64() >> 32), int(rng.next_u64() >> 32))
            };
            row[column(s, 1)] = addr;
            row[column(s, 4)] = write_value;
            // A leaf whose `AS` rides the frame's space column needs that
            // column set; any tag the query may name will do here, the frame
            // constraining none of them (`docs/spec/delegation.md` §5.1,
            // `docs/spec/advice.md` §3.2).
            if q == DELEG || q == LOAD {
                let at = space_column(queries).expect("the frame carries one");
                row[at] = int(match q {
                    DELEG => constants::address_space::DELEGATION_KECCAK_F,
                    _ => constants::address_space::RAM,
                } as u64);
            }
        }
        for (column, value) in cols.iter_mut().zip(row) {
            column.push(value);
        }
    }
    cols
}

/// Every execution family's frame at `2^4` rows over a satisfying base proves
/// and verifies — the four widths, 8, 6, 5 and 4, so both a padded and an
/// unpadded gate list 0 are proven. Then row 0's `rd` write, at address 0, is
/// set to 5: the self-check names `rd_write_masked` and `verify` rejects at
/// transition 0. `rd`'s **slot** is its position in that family's own ascending
/// list — the last one for every family but `ADD_SUB_LUI_AUIPC`, where S21's
/// `deleg` query follows it — so it is looked up rather than assumed.
#[test]
fn every_frame_proves_and_verifies_and_rejects_a_write_to_x0() {
    let mut rng = Rng::new(0x5714_3106);
    for (id, queries) in FAMILIES {
        let a = family_frame_artifact(id, 4);
        let rd = queries
            .iter()
            .position(|&q| q == RD)
            .unwrap_or_else(|| panic!("family {id}: every execution family writes rd"));

        let mut cols = frame_columns(queries, &mut rng);
        let base = fr_base(&a, cols.clone());
        let (_, challenges) = bind(&a, &base, None);
        assert_eq!(
            self_check(&a, &forward(&a, &base, &challenges), &challenges),
            Ok(()),
            "family {id}"
        );
        assert_eq!(prove_and_verify(&a, &base, None), Ok(()), "family {id}");

        assert_eq!(cols[column(rd, 1)][0], Fr::ZERO, "family {id}");
        cols[column(rd, 4)][0] = int(5);
        let base = fr_base(&a, cols);
        let (_, challenges) = bind(&a, &base, None);
        assert_eq!(
            self_check(&a, &forward(&a, &base, &challenges), &challenges),
            Err(SelfCheckError {
                layer: 0,
                row: 0,
                relation: "rd_write_masked".into(),
            }),
            "family {id}"
        );
        assert_eq!(
            prove_and_verify(&a, &base, None),
            Err(GkrError::LayerInconsistency { layer: 0 }),
            "family {id}"
        );
    }
}
