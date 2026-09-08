//! Acceptance 4, 6, 7 and 8: the index convention, bind/evaluate consistency,
//! the eq machinery, and every loud error.

mod common;

use common::{next_fr, vertex};
use field::Fr;
use poly::{eq_eval, eq_table, MultilinearPoly, PolyBacking};
use test_support::Rng;

// ---------------------------------------------------------------------------
// Acceptance 7: the index convention, pinned by a literal
// ---------------------------------------------------------------------------

/// `get(0b011)` reads the evaluation at `y0 = 1, y1 = 1, y2 = 0`. The table is
/// built so that each value spells its own vertex — `110` is `y0 = 1, y1 = 1,
/// y2 = 0` — which makes an endianness flip visible in the assertion itself.
#[test]
fn the_index_convention_is_little_endian() {
    let values: Vec<u16> = (0..8u16)
        .map(|i| 100 * (i & 1) + 10 * ((i >> 1) & 1) + ((i >> 2) & 1))
        .collect();
    let p = MultilinearPoly::new(PolyBacking::U16(values));

    assert_eq!(p.get(0b011), Fr::from_u64(110));
    assert_eq!(p.get(0b001), Fr::from_u64(100), "0b001 is y0 = 1");
    assert_eq!(p.get(0b010), Fr::from_u64(10), "0b010 is y1 = 1");
    assert_eq!(p.get(0b100), Fr::from_u64(1), "0b100 is y2 = 1");
    assert_eq!(p.get(0b111), Fr::from_u64(111));
    assert_eq!(p.get(0b000), Fr::ZERO);

    // `point[j]` is variable `j`, so the same vertex as a point agrees.
    assert_eq!(p.evaluate(&[Fr::ONE, Fr::ONE, Fr::ZERO]), Fr::from_u64(110));
    for y in 0..8 {
        assert_eq!(p.evaluate(&vertex(y, 3)), p.get(y), "vertex {y}");
    }

    // `bind` fixes variable 0: binding 1 keeps the odd indices, binding 0 the
    // even ones, and the old variable 1 becomes the new variable 0.
    let mut one = p.clone();
    one.bind(Fr::ONE);
    let mut zero = p.clone();
    zero.bind(Fr::ZERO);
    assert_eq!(one.num_vars(), 2);
    for y in 0..4 {
        assert_eq!(one.get(y), p.get(2 * y + 1), "bind(1) at {y}");
        assert_eq!(zero.get(y), p.get(2 * y), "bind(0) at {y}");
    }
}

// ---------------------------------------------------------------------------
// Acceptance 4: binding every variable is evaluating
// ---------------------------------------------------------------------------

#[test]
fn binding_every_variable_equals_evaluate() {
    let mut rng = Rng::new(20260916);
    for round in 0..10 {
        let entries = 1usize << 10;
        let backing = if round % 2 == 0 {
            PolyBacking::U32((0..entries).map(|_| rng.next_u64() as u32).collect())
        } else {
            PolyBacking::Fr((0..entries).map(|_| next_fr(&mut rng)).collect())
        };
        let point: Vec<Fr> = (0..10).map(|_| next_fr(&mut rng)).collect();

        let p = MultilinearPoly::new(backing);
        let expected = p.evaluate(&point);

        let mut q = p.clone();
        for (step, r) in point.iter().enumerate() {
            q.bind(*r);
            assert_eq!(q.num_vars(), 9 - step);
            assert_eq!(q.len(), 1usize << (9 - step));
        }
        assert_eq!(q.get(0), expected, "round {round}");
        assert_eq!(q.evaluate(&[]), expected, "a 0-variable evaluate is get(0)");

        // Binding a prefix and evaluating the rest is the same thing again.
        let mut half = p.clone();
        for r in &point[..4] {
            half.bind(*r);
        }
        assert_eq!(half.evaluate(&point[4..]), expected, "round {round}");
    }
}

// ---------------------------------------------------------------------------
// Acceptance 6: the eq machinery
// ---------------------------------------------------------------------------

#[test]
fn the_eq_machinery_agrees_with_itself() {
    let mut rng = Rng::new(20260917);
    for _ in 0..10 {
        let r: Vec<Fr> = (0..6).map(|_| next_fr(&mut rng)).collect();
        let table = eq_table(&r);
        assert_eq!(table.len(), 64);

        let mut sum = Fr::ZERO;
        for (y, entry) in table.iter().enumerate() {
            assert_eq!(*entry, eq_eval(&r, &vertex(y, 6)), "vertex {y}");
            sum += *entry;
        }
        assert_eq!(sum, Fr::ONE, "eq(r, .) sums to one over the cube");

        let other: Vec<Fr> = (0..6).map(|_| next_fr(&mut rng)).collect();
        assert_eq!(eq_eval(&r, &other), eq_eval(&other, &r), "eq is symmetric");

        // The table is the multilinear extension of `eq_eval`, off the cube as
        // well as on it — which is the property later stages lean on when they
        // treat `eq` as a virtual column.
        let table_poly = MultilinearPoly::new(PolyBacking::Fr(table));
        assert_eq!(table_poly.evaluate(&other), eq_eval(&r, &other));
    }

    assert_eq!(eq_table(&[]), vec![Fr::ONE], "the empty product is one");
    assert_eq!(eq_eval(&[], &[]), Fr::ONE);
    assert_eq!(eq_table(&[Fr::ZERO]), vec![Fr::ONE, Fr::ZERO]);
    assert_eq!(eq_table(&[Fr::ONE]), vec![Fr::ZERO, Fr::ONE]);
}

// ---------------------------------------------------------------------------
// Acceptance 8: every loud error
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "is not a power of two")]
fn new_rejects_a_non_power_of_two_table() {
    MultilinearPoly::new(PolyBacking::U8(vec![1, 2, 3]));
}

#[test]
#[should_panic(expected = "is not a power of two")]
fn new_rejects_an_empty_table() {
    MultilinearPoly::new(PolyBacking::U32(Vec::new()));
}

#[test]
#[should_panic(expected = "is not a power of two")]
fn new_rejects_a_non_power_of_two_bitset() {
    MultilinearPoly::new(PolyBacking::U1(vec![0b101], 3));
}

#[test]
#[should_panic(expected = "entries need")]
fn new_rejects_a_bitset_with_the_wrong_limb_count() {
    MultilinearPoly::new(PolyBacking::U1(vec![0, 0], 8));
}

#[test]
#[should_panic(expected = "must be zero")]
fn new_rejects_a_bitset_with_a_dirty_tail() {
    MultilinearPoly::new(PolyBacking::U1(vec![1 << 9], 8));
}

#[test]
#[should_panic(expected = "no variables left to bind")]
fn bind_rejects_a_constant() {
    MultilinearPoly::new(PolyBacking::Fr(vec![Fr::ONE])).bind(Fr::ONE);
}

#[test]
#[should_panic(expected = "no variables left to bind")]
fn bind_rejects_one_binding_too_many() {
    let mut p = MultilinearPoly::new(PolyBacking::U8(vec![1, 2]));
    p.bind(Fr::ONE);
    p.bind(Fr::ONE);
}

#[test]
#[should_panic(expected = "point has 2 coordinates, expected 3")]
fn evaluate_rejects_a_short_point() {
    MultilinearPoly::new(PolyBacking::U8(vec![0; 8])).evaluate(&[Fr::ONE, Fr::ONE]);
}

#[test]
#[should_panic(expected = "point has 4 coordinates, expected 3")]
fn evaluate_rejects_a_long_point() {
    MultilinearPoly::new(PolyBacking::U8(vec![0; 8])).evaluate(&[Fr::ONE; 4]);
}

#[test]
#[should_panic(expected = "point has 1 coordinates, expected 0")]
fn evaluate_rejects_a_point_for_a_constant() {
    MultilinearPoly::new(PolyBacking::U8(vec![7])).evaluate(&[Fr::ONE]);
}

#[test]
#[should_panic(expected = "is out of range")]
fn get_rejects_an_index_past_the_table() {
    MultilinearPoly::new(PolyBacking::U8(vec![0; 4])).get(4);
}

#[test]
#[should_panic(expected = "is out of range")]
fn get_rejects_an_index_past_a_bound_table() {
    let mut p = MultilinearPoly::new(PolyBacking::U8(vec![0; 4]));
    p.bind(Fr::ONE);
    p.get(2);
}

#[test]
#[should_panic(expected = "eq_eval: r has 3 coordinates, y has 2")]
fn eq_eval_rejects_a_length_mismatch() {
    eq_eval(&[Fr::ONE; 3], &[Fr::ONE; 2]);
}

/// The controls above are only meaningful if the shapes they reject are the
/// only ones rejected: every legal edge has to be accepted.
#[test]
fn the_legal_edges_are_accepted() {
    let one_var = MultilinearPoly::new(PolyBacking::U1(vec![0b10], 2));
    assert_eq!(one_var.num_vars(), 1);
    assert_eq!((one_var.get(0), one_var.get(1)), (Fr::ZERO, Fr::ONE));

    let constant = MultilinearPoly::new(PolyBacking::U1(vec![1], 1));
    assert_eq!(constant.num_vars(), 0);
    assert_eq!(constant.len(), 1);
    assert_eq!(constant.evaluate(&[]), Fr::ONE);

    // Exactly one full limb, and one entry past it: the two places the tail
    // check has to not fire.
    let full = MultilinearPoly::new(PolyBacking::U1(vec![u64::MAX], 64));
    assert_eq!(full.num_vars(), 6);
    assert_eq!(full.get(63), Fr::ONE);
    let two_limbs = MultilinearPoly::new(PolyBacking::U1(vec![0, u64::MAX], 128));
    assert_eq!(two_limbs.num_vars(), 7);
    assert_eq!((two_limbs.get(63), two_limbs.get(64)), (Fr::ZERO, Fr::ONE));
}
