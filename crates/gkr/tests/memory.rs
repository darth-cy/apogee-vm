//! The memory argument's gates through the kernel, and its verifier functions,
//! `docs/spec/memory.md` §2.2, §3.3 and §4: every leaf of the three artifacts
//! against the tuple written out in plain field arithmetic, the boundary
//! factors against the same, the window constant against a hand computation,
//! the reconciliation, and an honest proof of each artifact.
//!
//! The address spaces, the slots `Δ` and the column positions are written here
//! again rather than read from `constraints::memory`.

mod common;

use common::{committed_columns, discharge, fr_base, output_claims};
use constants::challenge_slot::{
    MEM_ALPHA_ADDR, MEM_ALPHA_TS, MEM_ALPHA_VAL, MEM_GAMMA, MEM_WINDOW_CONSTANT,
};
use constants::transcript_tags;
use constraints::memory::{frame_artifact, image_window_artifact, zero_window_artifact};
use constraints::{CircuitArtifact, VirtualKind};
use field::Fr;
use gkr::{
    boundary_factors, forward, gate_values, prove, reconciles, self_check, verify, virtual_at_row,
    window_challenges, BaseLayer, BoundaryFinals, ExternalChallenges, GkrError, SelfCheckError,
};
use sumcheck::{absorb_witness_digest, witness_digest};
use test_support::Rng;
use transcript::Transcript;

/// Per query: pc, rs1, rs2, arg1, arg2, load, ram, rd.
const SPACE: [u64; 8] = [3, 1, 1, 1, 1, 2, 2, 1];
const DELTA: [u64; 8] = [0, 1, 2, 2, 2, 2, 3, 3];
/// 41 memory columns, then 11 witness columns.
const FRAME_COLUMNS: usize = 52;
const RAM: u64 = 2;

/// The layout position of query `q`'s field `f`: 0 mask, 1 addr, 2 read_ts,
/// 3 read_value, 4 write_value.
fn column(q: usize, f: usize) -> usize {
    1 + 5 * q + f
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
fn t(c: &[Fr; 4], space: u64, addr: Fr, ts: Fr, value: Fr) -> Fr {
    c[0] + int(space) + c[1] * addr + c[2] * ts + c[3] * value
}

/// Every frame leaf is exactly 1 at `m = 0`, whatever the other columns and
/// challenges are, and at `m = 1` the read leaf is `T(AS, addr, read_ts,
/// read_value)` and the write leaf `T(AS, addr, 4·cycle + Δ, write_value)`.
/// Each query's mask is tried alone at 1 among zeros and alone at 0 among
/// ones, beside all zeros and all ones, so leaves `q` and `8 + q` must read
/// query `q`'s own mask. Kills a wrong AS, Δ, timestamp step, column position
/// or mask term, and a leaf masked by another query's mask.
#[test]
fn frame_leaves_are_one_when_masked_and_the_tuple_when_live() {
    let a = frame_artifact(4);
    let mut rng = Rng::new(0x5714_3101);
    let mut patterns = vec![[false; 8], [true; 8]];
    for q in 0..8 {
        let mut alone = [false; 8];
        alone[q] = true;
        patterns.push(alone);
        patterns.push(alone.map(|live| !live));
    }
    for live in patterns {
        let (c, slots) = random_memory(&mut rng);
        let mut row: Vec<Fr> = (0..FRAME_COLUMNS).map(|_| fr(&mut rng)).collect();
        for q in 0..8 {
            row[column(q, 0)] = if live[q] { Fr::ONE } else { Fr::ZERO };
        }
        let values = gate_values(&a, 0, &row, &[], &[], &slots);
        let cycle = row[0];
        for q in 0..8 {
            let (addr, read_ts) = (row[column(q, 1)], row[column(q, 2)]);
            let (read_value, write_value) = (row[column(q, 3)], row[column(q, 4)]);
            let write_ts = int(4) * cycle + int(DELTA[q]);
            let (read, write) = if live[q] {
                (
                    t(&c, SPACE[q], addr, read_ts, read_value),
                    t(&c, SPACE[q], addr, write_ts, write_value),
                )
            } else {
                (Fr::ONE, Fr::ONE)
            };
            assert_eq!(values[q], read, "masks {live:?}, read leaf {q}");
            assert_eq!(values[8 + q], write, "masks {live:?}, write leaf {q}");
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
            let (ts, value, init) = (fr(&mut rng), fr(&mut rng), fr(&mut rng));
            let row_index = virtual_at_row(VirtualKind::RowIndex, y);
            let live = virtual_at_row(VirtualKind::RamLive, y);

            let values = gate_values(
                &image,
                0,
                &[ts, value, init],
                &[],
                &[row_index, live],
                &window_challenges(&slots, 0, vars),
            );
            let expected = if y < 1 << 14 {
                vec![Fr::ONE, Fr::ONE]
            } else {
                let addr = int(4 * y as u64);
                vec![
                    t(&c, RAM, addr, ts, value),
                    t(&c, RAM, addr, Fr::ZERO, init),
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
                t(&c, RAM, addr, ts, value),
                t(&c, RAM, addr, Fr::ZERO, Fr::ZERO),
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
        memory.insert(slot, Fr::ONE);
    }
    window_challenges(&memory, 1, 16);
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

        let mut w_b = t(&c, 3, Fr::ZERO, Fr::ZERO, int(entry_pc as u64));
        let mut r_b = t(&c, 3, Fr::ZERO, int(finals.pc_ts), Fr::ONE);
        w_b *= t(&c, 1, Fr::ZERO, Fr::ZERO, Fr::ZERO);
        r_b *= t(&c, 1, Fr::ZERO, int(finals.reg_ts[0]), Fr::ZERO);
        for r in 1..32 {
            w_b *= t(&c, 1, int(r as u64), Fr::ZERO, Fr::ZERO);
            let value = int(finals.reg_values[r - 1] as u64);
            r_b *= t(&c, 1, int(r as u64), int(finals.reg_ts[r]), value);
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
/// shard, derive slot 5 from them.
fn bind(
    a: &CircuitArtifact,
    base: &BaseLayer,
    window: Option<u32>,
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
    let mut random = |n: usize| -> Vec<Vec<Fr>> {
        (0..n)
            .map(|_| (0..rows).map(|_| int(rng.next_u64() >> 26)).collect())
            .collect()
    };
    let image = image_window_artifact(16);
    let base = fr_base(&image, random(3));
    assert_eq!(prove_and_verify(&image, &base, Some(0)), Ok(()));

    let zero = zero_window_artifact(16);
    let base = fr_base(&zero, random(2));
    assert_eq!(prove_and_verify(&zero, &base, Some(5000)), Ok(()));
}

/// A satisfying frame base over 16 rows, in layout order: random masks, rows 0
/// and 1 live in every query; a masked query is 0 in every column; a read-only
/// query writes back; `rd` is at address 0 on row 0 and wherever a coin says,
/// with its x0 witnesses consistent.
fn frame_columns(rng: &mut Rng) -> Vec<Vec<Fr>> {
    let (inv, is_zero, selected) = (49, 50, 51);
    let mut cols: Vec<Vec<Fr>> = vec![Vec::new(); FRAME_COLUMNS];
    for y in 0..16 {
        let mut row = vec![Fr::ZERO; FRAME_COLUMNS];
        row[0] = int(rng.next_u64() >> 32);
        for q in 0..8 {
            if y > 1 && rng.next_u64() & 1 == 0 {
                continue;
            }
            row[column(q, 0)] = Fr::ONE;
            let read_value = int(rng.next_u64() >> 32);
            row[column(q, 2)] = int(rng.next_u64() >> 26);
            row[column(q, 3)] = read_value;
            row[41 + q] = int(rng.next_u64() >> 45);
            let (addr, write_value) = match q {
                1..=5 => (int(rng.next_u64() >> 59), read_value),
                7 => {
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
                }
                _ => (int(rng.next_u64() >> 32), int(rng.next_u64() >> 32)),
            };
            row[column(q, 1)] = addr;
            row[column(q, 4)] = write_value;
        }
        for (column, value) in cols.iter_mut().zip(row) {
            column.push(value);
        }
    }
    cols
}

/// The frame at `2^4` rows over a satisfying base proves and verifies. Then
/// row 0's `rd` write, at address 0, is set to 5: the self-check names
/// `rd_write_masked` and `verify` rejects at transition 0.
#[test]
fn the_frame_proves_and_verifies_and_rejects_a_write_to_x0() {
    let a = frame_artifact(4);
    let mut rng = Rng::new(0x5714_3106);
    let mut cols = frame_columns(&mut rng);
    let base = fr_base(&a, cols.clone());
    let (_, challenges) = bind(&a, &base, None);
    assert_eq!(
        self_check(&a, &forward(&a, &base, &challenges), &challenges),
        Ok(())
    );
    assert_eq!(prove_and_verify(&a, &base, None), Ok(()));

    assert_eq!(cols[column(7, 1)][0], Fr::ZERO);
    cols[column(7, 4)][0] = int(5);
    let base = fr_base(&a, cols);
    let (_, challenges) = bind(&a, &base, None);
    assert_eq!(
        self_check(&a, &forward(&a, &base, &challenges), &challenges),
        Err(SelfCheckError {
            layer: 0,
            row: 0,
            relation: "rd_write_masked".into(),
        })
    );
    assert_eq!(
        prove_and_verify(&a, &base, None),
        Err(GkrError::LayerInconsistency { layer: 0 })
    );
}
