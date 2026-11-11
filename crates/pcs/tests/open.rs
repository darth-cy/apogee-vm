//! Akita's openings, end to end at small shapes: an honest opening verifies,
//! and an opening of anything else does not.

use field::{Fp, Fp2};
use pcs::sample::setup_prefix;
use pcs::{commit, open, setup_need, verify, Commitment, Opener, Schedule, Source};
use poly::{MultilinearPoly, PolyBacking};
use transcript::Transcript;

fn fp2(rng: &mut test_support::Rng) -> Fp2 {
    Fp2 {
        c0: Fp::from_u64(rng.next_u64()),
        c1: Fp::from_u64(rng.next_u64()),
    }
}

/// `cols` columns of `2^n` entries, cycling through the backings a shard
/// holds: bits, bytes, words and full field elements.
fn columns(rng: &mut test_support::Rng, n: u32, cols: usize) -> Vec<MultilinearPoly> {
    (0..cols)
        .map(|c| {
            let len = 1usize << n;
            let backing = match c % 4 {
                0 => PolyBacking::U8((0..len).map(|_| rng.next_u64() as u8).collect()),
                1 => PolyBacking::U32((0..len).map(|_| rng.next_u64() as u32).collect()),
                2 => PolyBacking::Fp((0..len).map(|_| Fp::from_u64(rng.next_u64())).collect()),
                _ => PolyBacking::U16((0..len).map(|_| rng.next_u64() as u16).collect()),
            };
            MultilinearPoly::new(backing)
        })
        .collect()
}

struct Case {
    setup: Vec<Fp>,
    groups: Vec<Vec<MultilinearPoly>>,
    openers: Vec<Opener>,
    point: Vec<Fp2>,
    values: Vec<Fp2>,
}

fn case(seed: u64, n: u32, groups: &[usize]) -> Case {
    let mut rng = test_support::Rng::new(seed);
    let schedule = Schedule::new(n, groups);
    let setup = setup_prefix(setup_need(&schedule));
    let cols: Vec<Vec<MultilinearPoly>> = groups.iter().map(|&g| columns(&mut rng, n, g)).collect();
    let openers = cols
        .iter()
        .map(|g| {
            let refs: Vec<&MultilinearPoly> = g.iter().collect();
            commit(&setup, &schedule.levels[0], &Source::Columns(&refs))
        })
        .collect();
    let point: Vec<Fp2> = (0..n).map(|_| fp2(&mut rng)).collect();
    let values = cols.iter().flatten().map(|c| c.evaluate(&point)).collect();
    Case {
        setup,
        groups: cols,
        openers,
        point,
        values,
    }
}

fn prove(c: &Case) -> pcs::Proof {
    let refs: Vec<Vec<&MultilinearPoly>> = c.groups.iter().map(|g| g.iter().collect()).collect();
    let inputs: Vec<(&Opener, Source)> = c
        .openers
        .iter()
        .zip(&refs)
        .map(|(o, r)| (o, Source::Columns(r)))
        .collect();
    open(
        &mut Transcript::new(),
        &c.setup,
        &inputs,
        &c.point,
        &c.values,
    )
}

fn check(
    c: &Case,
    commitments: &[Commitment],
    values: &[Fp2],
    proof: &pcs::Proof,
) -> Result<(), pcs::Error> {
    let groups: Vec<(&Commitment, usize)> = commitments
        .iter()
        .zip(&c.groups)
        .map(|(k, g)| (k, g.len()))
        .collect();
    verify(
        &mut Transcript::new(),
        &c.setup,
        &groups,
        &c.point,
        values,
        proof,
    )
}

#[test]
fn an_honest_opening_verifies_and_a_false_value_does_not() {
    let c = case(1, 12, &[2, 1]);
    let proof = prove(&c);
    let commitments: Vec<Commitment> = c.openers.iter().map(|o| o.commitment.clone()).collect();
    assert_eq!(check(&c, &commitments, &c.values, &proof), Ok(()));
    let mut wrong = c.values.clone();
    wrong[1] += Fp2::ONE;
    assert!(
        check(&c, &commitments, &wrong, &proof).is_err(),
        "a false value is refused"
    );
    let mut other = commitments.clone();
    other[0].0[0][0] += Fp::ONE;
    assert!(
        check(&c, &other, &c.values, &proof).is_err(),
        "another commitment is refused"
    );
}

/// Every fold kind: the packing root, packing level 1, evaluation-trace folds
/// on the Euclidean route with and without compression, multi-stage range
/// trees, and the terminal.
#[test]
fn a_full_schedule_verifies() {
    let c = case(2, 16, &[2, 1]);
    let s = Schedule::new(16, &[2, 1]);
    assert!(s
        .levels
        .iter()
        .any(|l| l.method == pcs::params::Method::Trace && l.s_max.is_some()));
    assert!(s.levels.iter().any(|l| !l.compress));
    let proof = prove(&c);
    let commitments: Vec<Commitment> = c.openers.iter().map(|o| o.commitment.clone()).collect();
    assert_eq!(check(&c, &commitments, &c.values, &proof), Ok(()));
}

/// Every message the verifier reads is bound: changing any one field of an
/// honest proof — a payload, a round, a claim, a partial, the response — is
/// refused.
#[test]
fn every_proof_field_is_bound() {
    let c = case(3, 12, &[2, 1]);
    let proof = prove(&c);
    let commitments: Vec<Commitment> = c.openers.iter().map(|o| o.commitment.clone()).collect();
    let refused = |p: &pcs::Proof| check(&c, &commitments, &c.values, p).is_err();
    type Edit = fn(&mut pcs::Proof);
    let cases: [(&str, Edit); 15] = [
        ("opening payload", |p| p.folds[0].opening[0] += Fp::ONE),
        ("nonce", |p| p.folds[0].nonce ^= 1),
        ("successor image", |p| p.folds[0].successor[0][0] += Fp::ONE),
        ("successor digest", |p| {
            p.folds.last_mut().unwrap().digest.as_mut().unwrap()[0] += Fp::ONE
        }),
        ("terminal inner image", |p| {
            p.folds.last_mut().unwrap().successor[0][0] += Fp::ONE
        }),
        ("range round", |p| {
            p.folds[0].range[0].rounds[0][0] += Fp2::ONE
        }),
        ("range claim", |p| p.folds[0].range[0].claims[0] += Fp2::ONE),
        ("fused round", |p| p.folds[0].fused[0][0] += Fp2::ONE),
        ("fused value", |p| p.folds[0].value += Fp2::ONE),
        ("terminal column partial", |p| {
            p.terminal.tensor.partials[1] += Fp2::ONE
        }),
        ("terminal tensor round", |p| {
            p.terminal.tensor.rounds[0][0] += Fp2::ONE
        }),
        ("terminal partial", |p| p.terminal.partials[0][0] += Fp::ONE),
        ("terminal digest", |p| p.terminal.digest[0] += Fp::ONE),
        ("terminal nonce", |p| p.terminal.nonce ^= 1),
        ("terminal response", |p| p.terminal.response[0] ^= 4),
    ];
    for (name, edit) in cases {
        let mut p = proof.clone();
        edit(&mut p);
        assert!(refused(&p), "a changed {name} is refused");
    }
}
