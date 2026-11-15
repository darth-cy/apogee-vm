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

use common::{base_layer, committed_columns, discharge, output_claims};
use constants::challenge_slot::{
    MEM_ALPHA_ADDR, MEM_ALPHA_HI, MEM_ALPHA_TS, MEM_ALPHA_VAL, MEM_GAMMA, MEM_WINDOW_CONSTANT,
};
use constants::family;
use constants::transcript_tags;
use constraints::memory::{
    family_frame_artifact, frame_artifact, image_window_artifact, zero_window_artifact,
};
use constraints::{CircuitArtifact, VirtualKind};
use field::{Fp, Fp2};
use gkr::{
    boundary_factors, forward, gate_values, prove, reconciles, self_check, verify, virtual_at_row,
    window_challenges, BaseLayer, BoundaryFinals, ExternalChallenges, GkrError, SelfCheckError,
};
use sumcheck::{absorb_witness_digest, witness_digest};
use test_support::Rng;
use transcript::Transcript;

/// The query table, by **global query id**: pc, rs1, rs2, load, ram, rd.
/// No family holds all six.
const SPACE: [u64; 6] = [3, 1, 1, 2, 2, 1];
const DELTA: [u64; 6] = [0, 1, 2, 2, 3, 3];

/// The query ids, in the table's order.
const PC: usize = 0;
const RS1: usize = 1;
const RS2: usize = 2;
const LOAD: usize = 3;
const RAM: usize = 4;
const RD: usize = 5;

/// The queries that write back what they read, `docs/spec/memory.md` §2.4.
const READ_ONLY: [usize; 2] = [RS1, RS2];

/// The register queries, which carry a high word.
const REG: [usize; 3] = [RS1, RS2, RD];

/// Every execution family and the queries its frame holds, `docs/spec/memory.md`
/// §2.1's table written out. Widths 4 and 6: the 6-wide frame carries
/// constant-1 pad leaves, the 4-wide one none.
const FAMILIES: [(u32, &[usize]); 7] = [
    (family::ADD_SUB_LUI_AUIPC, &[PC, RS1, RS2, RD]),
    (family::JUMP_BRANCH_SLT, &[PC, RS1, RS2, RD]),
    (family::BITWISE, &[PC, RS1, RS2, RD]),
    (family::MUL_DIV, &[PC, RS1, RS2, RD]),
    (family::MEM_WORD, &[PC, RS1, RS2, LOAD, RAM, RD]),
    (family::MEM_SUBWORD, &[PC, RS1, RS2, LOAD, RAM, RD]),
    (family::ATOMICS, &[PC, RS1, RS2, LOAD, RAM, RD]),
];

/// The address space of a RAM tuple, which the window artifacts are all of.
const RAM_SPACE: u64 = 2;

/// The layout position of the query at **slot** `s`, field `f`: 0 mask, 1 addr,
/// 2 read_ts, 3 read_value, 4 write_value. `M[1 + 5s + f]`, and the `1 + 5w`
/// memory columns come first in the committed row.
fn column(slot: usize, field: usize) -> usize {
    1 + 5 * slot + field
}

/// The memory columns of a frame over `queries`: `1 + 5w`, then two per
/// register query.
fn memory_columns(queries: &[usize]) -> usize {
    1 + 5 * queries.len() + 2 * queries.iter().filter(|q| REG.contains(q)).count()
}

/// The high word read (`write` false) or written by the register query at
/// slot `s`: `M[1 + 5w + 2r + write]`, `r` its position among the frame's
/// register queries.
fn hi(queries: &[usize], slot: usize, write: bool) -> usize {
    let r = queries[..slot].iter().filter(|q| REG.contains(q)).count();
    1 + 5 * queries.len() + 2 * r + write as usize
}

/// `W[s]`, the gap's high chunk of the query at slot `s`, in a frame over
/// `queries`: the witness columns follow the memory ones.
fn gap_hi(queries: &[usize], slot: usize) -> usize {
    memory_columns(queries) + slot
}

/// `W[w]` to `W[w + 3]`: the x0 gadget's four witnesses, after the `w` gap
/// columns.
fn rd_inv(queries: &[usize]) -> usize {
    memory_columns(queries) + queries.len()
}
fn rd_is_zero(queries: &[usize]) -> usize {
    rd_inv(queries) + 1
}
fn rd_selected(queries: &[usize]) -> usize {
    rd_inv(queries) + 2
}
fn rd_selected_hi(queries: &[usize]) -> usize {
    rd_inv(queries) + 3
}

/// A frame's committed columns: its memory ones and `w + 4` witness.
fn committed(queries: &[usize]) -> usize {
    memory_columns(queries) + queries.len() + 4
}

/// A pseudo-random `Fp2` element, both coordinates drawn.
fn fp2(rng: &mut Rng) -> Fp2 {
    Fp2 {
        c0: Fp::from_u64(rng.next_u64()),
        c1: Fp::from_u64(rng.next_u64()),
    }
}

/// An integer, embedded in `Fp2`.
fn int(v: u64) -> Fp2 {
    Fp::from_u64(v).into()
}

/// The five memory challenges' slots, `γ_M, α_addr, α_ts, α_val, α_hi`.
const MEMORY_SLOTS: [u32; 5] = [
    MEM_GAMMA,
    MEM_ALPHA_ADDR,
    MEM_ALPHA_TS,
    MEM_ALPHA_VAL,
    MEM_ALPHA_HI,
];

/// Random `γ_M, α_addr, α_ts, α_val, α_hi`, as values and as their slots.
fn random_memory(rng: &mut Rng) -> ([Fp2; 5], ExternalChallenges) {
    let c = [fp2(rng), fp2(rng), fp2(rng), fp2(rng), fp2(rng)];
    let mut slots = ExternalChallenges::new();
    for (slot, value) in MEMORY_SLOTS.into_iter().zip(c) {
        slots.insert(slot, value);
    }
    (c, slots)
}

/// `T(AS, ADDR, TS, VAL, HI) = γ_M + AS + α_addr·ADDR + α_ts·TS + α_val·VAL + α_hi·HI`.
fn t(c: &[Fp2; 5], space: Fp2, addr: Fp2, ts: Fp2, value: Fp2, high: Fp2) -> Fp2 {
    c[0] + space + c[1] * addr + c[2] * ts + c[3] * value + c[4] * high
}

/// Every frame leaf of every execution family is exactly 1 at `m = 0`, whatever
/// the other columns and challenges are, and at `m = 1` the read leaf is
/// `T(AS, addr, read_ts, read_value, read_hi)` and the write leaf `T(AS, addr,
/// 4·cycle + Δ, write_value, write_hi)`, a high word only for a register query
/// — with `AS` and `Δ` the **query's**, from the global table, and every column
/// the **slot's**. Each slot's mask is tried alone at 1 among
/// zeros and alone at 0 among ones, beside all zeros and all ones, so leaves `s`
/// and `side + s` must read slot `s`'s own mask. The pad leaves that fill each
/// side out to a power of two are 1 on every one of those rows.
///
/// Kills a wrong AS, Δ, timestamp step, column position or mask term, a leaf
/// masked by another query's mask, a pad leaf that reads anything, and — the
/// mutant the per-family frames add — a leaf taking its AS or Δ from its slot
/// instead of its query id, which differs at every 4-wide frame's slot 3
/// (`rd`, AS 1, Δ 3, against slot 3's `load`, AS 2, Δ 2).
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
            let mut row: Vec<Fp2> = (0..committed(queries)).map(|_| fp2(&mut rng)).collect();
            for (s, &m) in live.iter().enumerate() {
                row[column(s, 0)] = if m { Fp2::ONE } else { Fp2::ZERO };
            }
            let values = gate_values(&a, 0, &row, &[], &[], &slots);
            let cycle = row[0];
            for (s, &q) in queries.iter().enumerate() {
                let (addr, read_ts) = (row[column(s, 1)], row[column(s, 2)]);
                let (read_value, write_value) = (row[column(s, 3)], row[column(s, 4)]);
                let write_ts = int(4) * cycle + int(DELTA[q]);
                let space = int(SPACE[q]);
                let high = |write| match REG.contains(&q) {
                    true => row[hi(queries, s, write)],
                    false => Fp2::ZERO,
                };
                let (read, write) = if live[s] {
                    (
                        t(&c, space, addr, read_ts, read_value, high(false)),
                        t(&c, space, addr, write_ts, write_value, high(true)),
                    )
                } else {
                    (Fp2::ONE, Fp2::ONE)
                };
                let at = format!("family {id}, masks {live:?}, slot {s} (query {q})");
                assert_eq!(values[s], read, "{at}: read leaf");
                assert_eq!(values[side + s], write, "{at}: write leaf");
            }
            for i in width..side {
                let at = format!("family {id}, masks {live:?}, pad leaf {i}");
                assert_eq!(values[i], Fp2::ONE, "{at}: read side");
                assert_eq!(values[side + i], Fp2::ONE, "{at}: write side");
            }
        }
    }
}

/// The window leaves at rows either side of `2^14` and at the ends of the
/// window: `INIT_TEARDOWN`'s two leaves are 1 below `2^14`, and from it the
/// teardown tuple `T(RAM, 4y, ts, value)` and the init tuple
/// `T(RAM, 4y, 0, init_value)`; `ZERO_WINDOWS`' leaves at window `w` are
/// `T(RAM, 4h·w + 4y, ts, value)` and `T(RAM, 4h·w + 4y, 0, 0)` on every row.
/// Both through `window_challenges`. Kills a wrong window constant, address
/// step, mask or timestamp.
#[test]
fn window_leaves_are_the_tuples_of_their_rows() {
    let (vars, h) = (16u32, 1u64 << 16);
    let image = image_window_artifact(vars);
    let zero = zero_window_artifact(vars);
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
            let (ts, value, init) = (fp2(&mut rng), fp2(&mut rng), fp2(&mut rng));
            let row_index = virtual_at_row(VirtualKind::RowIndex, y).into();
            let live = virtual_at_row(VirtualKind::RamLive, y).into();

            let values = gate_values(
                &image,
                0,
                &[ts, value, init],
                &[],
                &[row_index, live],
                &window_challenges(&slots, 0, vars),
            );
            let expected = if y < 1 << 14 {
                vec![Fp2::ONE, Fp2::ONE]
            } else {
                let addr = int(4 * y as u64);
                vec![
                    t(&c, int(RAM_SPACE), addr, ts, value, Fp2::ZERO),
                    t(&c, int(RAM_SPACE), addr, Fp2::ZERO, init, Fp2::ZERO),
                ]
            };
            assert_eq!(values, expected, "trial {trial}, image window row {y}");

            let values = gate_values(
                &zero,
                0,
                &[ts, value],
                &[],
                &[row_index],
                &window_challenges(&slots, window, vars),
            );
            let addr = int(4 * h * window as u64 + 4 * y as u64);
            let expected = vec![
                t(&c, int(RAM_SPACE), addr, ts, value, Fp2::ZERO),
                t(&c, int(RAM_SPACE), addr, Fp2::ZERO, Fp2::ZERO, Fp2::ZERO),
            ];
            assert_eq!(values, expected, "trial {trial}, window {window} row {y}");
        }
    }
}

/// Slot 5 at window 3 of height `2^16`, `γ_M = 11`, `α_addr = 7`:
/// `11 + 2 + 7·(4·65536·3) = 13 + 7·786432 = 5505037`. Slots 1–4 are copied,
/// slot 0 is not; and the top window of height `2^22` against its integer.
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
    let w = window_challenges(&memory, 3, 16);
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
    let top = window_challenges(&memory, 127, 22);
    assert_eq!(
        top.get(MEM_WINDOW_CONSTANT),
        Some(int(13 + 7 * 0x7F00_0000))
    );
}

#[test]
#[should_panic(expected = "window_challenges: slot 4 (mem_alpha_val) has no value")]
fn the_window_constant_needs_every_drawn_slot() {
    let mut memory = ExternalChallenges::new();
    for slot in [MEM_GAMMA, MEM_ALPHA_ADDR, MEM_ALPHA_TS] {
        memory.insert(slot, Fp2::ONE);
    }
    window_challenges(&memory, 1, 16);
}

/// `(W_b, R_b)` against §4.2's products written out: 32 register inits and the
/// pc's init at `entry_pc`; `x0`'s final value 0, `x_1..x_31`'s from
/// `reg_values[r − 1]`, its low word at `α_val` and its high word at `α_hi`,
/// the pc's `HALT_PC = 1`. Then `x10`'s final value moved
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
            *v = rng.next_u64();
        }
        let entry_pc = rng.next_u64() as u32 & !1;

        let zero = Fp2::ZERO;
        let mut w_b = t(&c, int(3), zero, zero, int(entry_pc as u64), zero);
        let mut r_b = t(&c, int(3), zero, int(finals.pc_ts), Fp2::ONE, zero);
        w_b *= t(&c, int(1), zero, zero, zero, zero);
        r_b *= t(&c, int(1), zero, int(finals.reg_ts[0]), zero, zero);
        for r in 1..32 {
            w_b *= t(&c, int(1), int(r as u64), zero, zero, zero);
            let v = finals.reg_values[r - 1];
            let (low, high) = (int(v & u32::MAX as u64), int(v >> 32));
            r_b *= t(&c, int(1), int(r as u64), int(finals.reg_ts[r]), low, high);
        }
        let (w, r) = boundary_factors(&slots, entry_pc, &finals);
        assert_eq!((w, r), (w_b, r_b), "trial {trial}");

        for bit in [1, 1 << 32] {
            let mut moved = finals;
            moved.reg_values[9] ^= bit;
            let (w2, r2) = boundary_factors(&slots, entry_pc, &moved);
            assert_eq!(w2, w, "trial {trial}: W_b does not read the finals");
            assert_ne!(r2, r, "trial {trial}: R_b reads both of x10's words");
        }
    }
}

/// Balanced roots reconcile; one changed root does not; a zero root on both
/// sides balances, and is still refused. Kills a check that swaps the factors
/// or omits the nonzero clause.
#[test]
fn reconciles_is_the_product_equation_and_nonzero() {
    let mut rng = Rng::new(0x5714_3104);
    let (r1, r2, w_b, r_b) = (fp2(&mut rng), fp2(&mut rng), fp2(&mut rng), fp2(&mut rng));
    let w1 = r1 * r2 * r_b * w_b.inverse().expect("nonzero");
    assert!(reconciles(&[r1, r2], &[w1], (w_b, r_b)));
    assert!(!reconciles(&[r1, r2], &[w1], (r_b, w_b)), "swapped factors");
    assert!(!reconciles(&[r1, r2 + Fp2::ONE], &[w1], (w_b, r_b)));
    assert!(!reconciles(&[r1], &[w1], (w_b, r_b)));
    assert!(!reconciles(&[r1, Fp2::ZERO], &[w1, Fp2::ZERO], (w_b, r_b)));
}

/// Bind the base's digest, then draw the memory slots after it — and, for a
/// window shard, derive slot 5 from them.
fn bind(
    a: &CircuitArtifact,
    base: &BaseLayer,
    window: Option<u32>,
) -> (Transcript, ExternalChallenges) {
    let mut t = Transcript::new();
    absorb_witness_digest(&mut t, &witness_digest(&committed_columns(a, base)));
    let mut memory = ExternalChallenges::new();
    for slot in MEMORY_SLOTS {
        memory.insert(slot, t.challenge(transcript_tags::SUMCHECK_CHALLENGE));
    }
    let challenges = match window {
        Some(w) => window_challenges(&memory, w, a.trace_vars),
        None => memory,
    };
    (t, challenges)
}

/// Forward, self-check, prove and verify on separate transcripts, discharge.
fn prove_and_verify(
    a: &CircuitArtifact,
    base: &BaseLayer,
    window: Option<u32>,
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

/// Both window artifacts at `2^16` rows over random columns — every row of a
/// window is an address, so any columns are a witness — prove, verify and
/// discharge, `ZERO_WINDOWS` at a random window.
#[test]
fn window_artifacts_prove_and_verify() {
    let mut rng = Rng::new(0x5714_3105);
    let rows = 1usize << 16;
    let mut random = |n: usize| -> Vec<Vec<Fp>> {
        (0..n)
            .map(|_| {
                (0..rows)
                    .map(|_| Fp::from_u64(rng.next_u64() >> 26))
                    .collect()
            })
            .collect()
    };
    let image = image_window_artifact(16);
    let base = base_layer(&image, random(3));
    assert_eq!(prove_and_verify(&image, &base, Some(0)), Ok(()));

    let zero = zero_window_artifact(16);
    let base = base_layer(&zero, random(2));
    assert_eq!(prove_and_verify(&zero, &base, Some(5000)), Ok(()));
}

/// A satisfying base for the frame holding `queries`, over 16 rows, in layout
/// order: random masks, rows 0 and 1 live in every query; a masked query is 0 in
/// every column; a read-only query writes back both words; `rd` is at address
/// 0 on row 0 and wherever a coin says, with its x0 witnesses consistent.
/// Every column is addressed by the query's **slot** in this family, its
/// behaviour chosen by the query's id: `load` and `ram` fall through to the
/// last arm and write what they like, the frame not constraining them.
fn frame_columns(queries: &[usize], rng: &mut Rng) -> Vec<Vec<Fp>> {
    let n = committed(queries);
    let (inv, is_zero) = (rd_inv(queries), rd_is_zero(queries));
    let (selected, selected_hi) = (rd_selected(queries), rd_selected_hi(queries));
    let mut cols: Vec<Vec<Fp>> = vec![Vec::new(); n];
    for y in 0..16 {
        let mut row = vec![Fp::ZERO; n];
        row[0] = Fp::from_u64(rng.next_u64() >> 32);
        for (s, &q) in queries.iter().enumerate() {
            if y > 1 && rng.next_u64() & 1 == 0 {
                continue;
            }
            row[column(s, 0)] = Fp::ONE;
            let read_value = Fp::from_u64(rng.next_u64() >> 32);
            row[column(s, 2)] = Fp::from_u64(rng.next_u64() >> 26);
            row[column(s, 3)] = read_value;
            row[gap_hi(queries, s)] = Fp::from_u64(rng.next_u64() >> 45);
            let read_hi = Fp::from_u64(rng.next_u64() >> 32);
            if REG.contains(&q) {
                row[hi(queries, s, false)] = read_hi;
            }
            let (addr, write_value) = if READ_ONLY.contains(&q) {
                row[hi(queries, s, true)] = read_hi;
                (Fp::from_u64(rng.next_u64() >> 59), read_value)
            } else if q == RD {
                let (sel, sel_hi) = (
                    Fp::from_u64(rng.next_u64() >> 32),
                    Fp::from_u64(rng.next_u64() >> 32),
                );
                row[selected] = sel;
                row[selected_hi] = sel_hi;
                if y == 0 || rng.next_u64() & 1 == 0 {
                    row[is_zero] = Fp::ONE;
                    (Fp::ZERO, Fp::ZERO)
                } else {
                    let addr = Fp::from_u64(1 + rng.next_u64() % 31);
                    row[inv] = addr.inverse().expect("nonzero");
                    row[hi(queries, s, true)] = sel_hi;
                    (addr, sel)
                }
            } else {
                (
                    Fp::from_u64(rng.next_u64() >> 32),
                    Fp::from_u64(rng.next_u64() >> 32),
                )
            };
            row[column(s, 1)] = addr;
            row[column(s, 4)] = write_value;
        }
        for (column, value) in cols.iter_mut().zip(row) {
            column.push(value);
        }
    }
    cols
}

/// Every execution family's frame at `2^4` rows over a satisfying base proves
/// and verifies — the two widths, 6 and 4, so both a padded and an unpadded
/// gate list 0 are proven. Then row 0's `rd` write, at address 0, is set to 5,
/// in its low word and then in its high word: the self-check names
/// `rd_write_masked` and `rd_write_masked_hi`, and `verify` rejects at
/// transition 0. `rd`'s **slot** is its position in that family's own ascending
/// list, so it is looked up rather than assumed.
#[test]
fn every_frame_proves_and_verifies_and_rejects_a_write_to_x0() {
    let mut rng = Rng::new(0x5714_3106);
    for (id, queries) in FAMILIES {
        let a = family_frame_artifact(id, 4);
        let rd = queries
            .iter()
            .position(|&q| q == RD)
            .unwrap_or_else(|| panic!("family {id}: every execution family writes rd"));

        let cols = frame_columns(queries, &mut rng);
        let base = base_layer(&a, cols.clone());
        let (_, challenges) = bind(&a, &base, None);
        assert_eq!(
            self_check(&a, &forward(&a, &base, &challenges), &challenges),
            Ok(()),
            "family {id}"
        );
        assert_eq!(prove_and_verify(&a, &base, None), Ok(()), "family {id}");

        assert_eq!(cols[column(rd, 1)][0], Fp::ZERO, "family {id}");
        for (at, relation) in [
            (column(rd, 4), "rd_write_masked"),
            (hi(queries, rd, true), "rd_write_masked_hi"),
        ] {
            let mut cols = cols.clone();
            cols[at][0] = Fp::from_u64(5);
            let base = base_layer(&a, cols);
            let (_, challenges) = bind(&a, &base, None);
            assert_eq!(
                self_check(&a, &forward(&a, &base, &challenges), &challenges),
                Err(SelfCheckError {
                    layer: 0,
                    row: 0,
                    relation: relation.into(),
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
}
