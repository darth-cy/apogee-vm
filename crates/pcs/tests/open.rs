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

/// Every other entry a word on a balanced base-`2^16` digit carry, the rest
/// random.
fn word(rng: &mut test_support::Rng, i: usize) -> u32 {
    const CARRIES: [u32; 8] = [
        0x7fff,
        0x8000,
        0xffff,
        0x1_8000,
        0x7fff_8000,
        0xffff_7fff,
        0xffff_8000,
        u32::MAX,
    ];
    if i.is_multiple_of(2) {
        CARRIES[i / 2 % CARRIES.len()]
    } else {
        rng.next_u64() as u32
    }
}

/// Columns `first..first + cols` of `2^n` entries, column `c` of the `c`th
/// backing a shard holds, the most digit planes first: field elements, 32-
/// and 16-bit words on their carries, bytes, packed bits, and a setup column's
/// `MINUS_ONE` padding. Every other ring of `d` entries is zero, offset by
/// column, so the root's scratch digits meet a nonzero ring and then a zero
/// one in both the commitment's order and the response's, and the response's
/// meet a backing of fewer digit planes after a wider one.
fn columns(
    rng: &mut test_support::Rng,
    n: u32,
    d: usize,
    first: usize,
    cols: usize,
) -> Vec<MultilinearPoly> {
    let len = 1usize << n;
    (first..first + cols)
        .map(|c| {
            let zero = |i: usize| (i / d + c) % 2 == 1;
            let backing = match c % 6 {
                0 => PolyBacking::Fp(
                    (0..len)
                        .map(|i| match zero(i) {
                            true => Fp::ZERO,
                            false => Fp::from_u64(rng.next_u64()),
                        })
                        .collect(),
                ),
                1 => PolyBacking::U32(
                    (0..len)
                        .map(|i| if zero(i) { 0 } else { word(rng, i) })
                        .collect(),
                ),
                2 => PolyBacking::U16(
                    (0..len)
                        .map(|i| if zero(i) { 0 } else { word(rng, i) as u16 })
                        .collect(),
                ),
                3 => PolyBacking::U8(
                    (0..len)
                        .map(|i| if zero(i) { 0 } else { rng.next_u64() as u8 })
                        .collect(),
                ),
                4 => {
                    let mut limbs = vec![0u64; len / 64];
                    for i in (0..len).filter(|&i| !zero(i) && !rng.next_u64().is_multiple_of(3)) {
                        limbs[i / 64] |= 1 << (i % 64);
                    }
                    PolyBacking::U1(limbs, len)
                }
                _ => PolyBacking::Fp(
                    (0..len)
                        .map(|i| match i < len / 3 {
                            true => Fp::from_u64(rng.next_u64() % 4096),
                            false => Fp::MINUS_ONE,
                        })
                        .collect(),
                ),
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
    let d = schedule.levels[0].d_a;
    let mut first = 0;
    let cols: Vec<Vec<MultilinearPoly>> = groups
        .iter()
        .map(|&g| {
            first += g;
            columns(&mut rng, n, d, first - g, g)
        })
        .collect();
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
    let c = case(1, 12, &[4, 2]);
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
    let c = case(2, 16, &[4, 2]);
    let s = Schedule::new(16, &[4, 2]);
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
    let c = case(3, 12, &[4, 2]);
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
