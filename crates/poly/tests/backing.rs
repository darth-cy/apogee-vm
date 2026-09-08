//! Acceptance 3 and 5: the five backings are one polynomial in five costumes,
//! and the lift is lazy in the sense that is observable — bind-triggered, never
//! read-triggered.

mod common;

use common::{next_fr, pack_bits};
use field::Fr;
use poly::{MultilinearPoly, PolyBacking};
use test_support::Rng;

/// Every way of storing `values`, in every width they fit in. `fr` is always
/// last, and is the reference the others are compared against.
fn backings(values: &[u64]) -> Vec<(&'static str, PolyBacking)> {
    let mut out: Vec<(&'static str, PolyBacking)> = Vec::new();
    if values.iter().all(|v| *v <= 1) {
        let bits: Vec<bool> = values.iter().map(|v| *v == 1).collect();
        out.push(("u1", pack_bits(&bits)));
    }
    if values.iter().all(|v| *v <= u8::MAX as u64) {
        out.push((
            "u8",
            PolyBacking::U8(values.iter().map(|v| *v as u8).collect()),
        ));
    }
    if values.iter().all(|v| *v <= u16::MAX as u64) {
        out.push((
            "u16",
            PolyBacking::U16(values.iter().map(|v| *v as u16).collect()),
        ));
    }
    if values.iter().all(|v| *v <= u32::MAX as u64) {
        out.push((
            "u32",
            PolyBacking::U32(values.iter().map(|v| *v as u32).collect()),
        ));
    }
    out.push((
        "fr",
        PolyBacking::Fr(values.iter().map(|v| Fr::from_u64(*v)).collect()),
    ));
    out
}

/// `get`, `evaluate`, and every table a full bind chain leaves behind, compared
/// across all the widths `values` fits in.
fn assert_backings_agree(values: &[u64], point: &[Fr]) {
    let all = backings(values);
    assert!(
        all.len() >= 2,
        "a corpus stored only one way checks nothing"
    );
    assert_eq!(all.last().expect("fr is always present").0, "fr");

    // The reference: the same values in the field, which needs no lift at all.
    let reference = MultilinearPoly::new(all[all.len() - 1].1.clone());
    let reference_gets: Vec<Fr> = (0..reference.len()).map(|i| reference.get(i)).collect();
    for (i, v) in values.iter().enumerate() {
        assert_eq!(
            reference_gets[i],
            Fr::from_u64(*v),
            "the lift must be the canonical embedding"
        );
    }
    let reference_eval = reference.evaluate(point);
    let mut chain: Vec<PolyBacking> = Vec::new();
    let mut folding = reference.clone();
    for r in point {
        folding.bind(*r);
        chain.push(folding.backing().clone());
    }

    for (name, backing) in &all {
        let p = MultilinearPoly::new(backing.clone());
        assert_eq!(p.num_vars(), reference.num_vars(), "{name}: num_vars");
        let gets: Vec<Fr> = (0..p.len()).map(|i| p.get(i)).collect();
        assert_eq!(gets, reference_gets, "{name}: get");
        assert_eq!(p.evaluate(point), reference_eval, "{name}: evaluate");
        // Must-be-exact 3: neither read touched the backing.
        assert_eq!(p.backing(), backing, "{name}: a read mutated the backing");

        let mut q = p;
        for (step, r) in point.iter().enumerate() {
            q.bind(*r);
            assert_eq!(q.backing(), &chain[step], "{name}: bind step {step}");
        }
    }
}

// ---------------------------------------------------------------------------
// Acceptance 3
// ---------------------------------------------------------------------------

/// All 256 three-variable 0/1 tables, exhaustively: `U1` against every wider
/// width. Eight entries fit in one limb, so this also pins the bit order.
#[test]
fn every_three_variable_bit_table_agrees_across_backings() {
    let mut rng = Rng::new(20260911);
    let point: Vec<Fr> = (0..3).map(|_| next_fr(&mut rng)).collect();
    for table in 0u64..256 {
        let values: Vec<u64> = (0..8).map(|i| (table >> i) & 1).collect();
        // The bitset is the byte itself: entry i is bit i, little-endian.
        assert_eq!(
            backings(&values)[0].1,
            PolyBacking::U1(vec![table], 8),
            "table {table:#010b} did not pack to itself"
        );
        assert_backings_agree(&values, &point);
    }
}

/// The wider widths, on seeded random tables. Every table is expressed in every
/// width it fits in, so a `u8` table is checked four ways.
#[test]
fn wider_backings_agree_on_seeded_tables() {
    let mut rng = Rng::new(20260912);
    for num_vars in [0usize, 1, 2, 4, 6, 8] {
        for bits in [8u32, 16, 32] {
            let ceiling = if bits == 32 {
                u32::MAX as u64
            } else {
                (1u64 << bits) - 1
            };
            let values: Vec<u64> = (0..1usize << num_vars)
                .map(|_| rng.next_u64() & ceiling)
                .collect();
            let point: Vec<Fr> = (0..num_vars).map(|_| next_fr(&mut rng)).collect();
            assert_backings_agree(&values, &point);
        }
    }
}

/// The extremes of each width, which a random table will never produce.
#[test]
fn backings_agree_at_the_edges_of_their_width() {
    let mut rng = Rng::new(20260913);
    let point: Vec<Fr> = (0..2).map(|_| next_fr(&mut rng)).collect();
    for values in [
        vec![0u64, 0, 0, 0],
        vec![1, 1, 1, 1],
        vec![0, u8::MAX as u64, 0, u8::MAX as u64],
        vec![u16::MAX as u64, 0, u16::MAX as u64, 1],
        vec![u32::MAX as u64, 0, 1, u32::MAX as u64 - 1],
    ] {
        assert_backings_agree(&values, &point);
    }
}

// ---------------------------------------------------------------------------
// Acceptance 5
// ---------------------------------------------------------------------------

/// Lazy means bind-triggered. `backing()` is the discriminant accessor the
/// stage asks for: it is the only way to tell, and it says `U16` until a
/// challenge arrives.
#[test]
fn the_lift_is_lazy_and_one_way() {
    let mut rng = Rng::new(20260914);
    let values: Vec<u16> = (0..16).map(|_| rng.next_u64() as u16).collect();
    let point: Vec<Fr> = (0..4).map(|_| next_fr(&mut rng)).collect();

    let mut p = MultilinearPoly::new(PolyBacking::U16(values.clone()));
    assert!(matches!(p.backing(), PolyBacking::U16(_)));

    for i in 0..p.len() {
        let _ = p.get(i);
    }
    let _ = p.evaluate(&point);
    assert_eq!(
        p.backing(),
        &PolyBacking::U16(values),
        "reads must not lift, and must not disturb the table"
    );

    p.bind(point[0]);
    assert!(
        matches!(p.backing(), PolyBacking::Fr(_)),
        "the first bind lifts"
    );
    p.bind(point[1]);
    assert!(
        matches!(p.backing(), PolyBacking::Fr(_)),
        "and it stays lifted"
    );
    let _ = p.get(0);
    let _ = p.evaluate(&point[2..]);
    assert!(matches!(p.backing(), PolyBacking::Fr(_)));
}

/// The same, for the other three small widths: no read of any kind lifts.
#[test]
fn no_read_lifts_any_backing() {
    let mut rng = Rng::new(20260915);
    let point: Vec<Fr> = (0..3).map(|_| next_fr(&mut rng)).collect();
    let bits: Vec<bool> = (0..8).map(|_| rng.next_u64() & 1 == 1).collect();
    for backing in [
        pack_bits(&bits),
        PolyBacking::U8((0..8).map(|_| rng.next_u64() as u8).collect()),
        PolyBacking::U32((0..8).map(|_| rng.next_u64() as u32).collect()),
    ] {
        let p = MultilinearPoly::new(backing.clone());
        for i in 0..p.len() {
            let _ = p.get(i);
        }
        let _ = p.evaluate(&point);
        let _ = p.clone().evaluate(&point);
        assert_eq!(p.backing(), &backing);
    }
}
