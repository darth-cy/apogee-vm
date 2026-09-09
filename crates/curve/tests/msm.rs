//! `curve::msm`: the committed corpus, the live differential, the small path,
//! and totality on every degenerate input S07 must-be-exact 1 names.

mod common;

use std::fs;
use std::path::PathBuf;

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField};
use common::next_fr;
use curve::msm::{msm, msm_small_u32, MsmError};
use curve::{G1Affine, G1Projective};
use field::Fr;
use test_support::{sha256, to_hex, Rng};

/// The committed corpus, pinned. Refresh deliberately:
/// `cargo run -p kat-gen -- msm`, then paste the digest it prints.
const KAT_SHA256: &str = "f6c5c90caf8fd84dabdaa6b9fd128b79064cb00475f8a81abd1eca8fc6e640c0";

fn vectors() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/msm_kats.txt");
    let text = fs::read_to_string(path).expect("reading msm_kats.txt");
    assert_eq!(
        to_hex(&sha256(text.as_bytes())),
        KAT_SHA256,
        "msm_kats.txt does not match its pin; regenerate it deliberately"
    );
    text
}

// ---------------------------------------------------------------------------
// The expansion the fixtures encode.
//
// This is deliberately a second implementation of `tools/kat-gen/src/msm.rs`'s
// `case`, written against `curve` rather than arkworks. If the two drift, the
// expected points stop matching and both sides say so. `common::next_fr` is
// the same draw-mask-reject rule kat-gen spells out over arkworks.
// ---------------------------------------------------------------------------

fn case(pattern: &str, n: usize, seed: u64) -> (Vec<G1Affine>, Vec<Fr>) {
    let mut rng = Rng::new(seed);

    let bases: Vec<G1Affine> = (0..n)
        .map(|i| {
            let k = next_fr(&mut rng);
            if pattern == "infinity" && i % 3 == 0 {
                G1Affine::IDENTITY
            } else {
                G1Projective::GENERATOR.mul(&k).to_affine()
            }
        })
        .collect();

    let scalars: Vec<Fr> = match pattern {
        "zeros" => (0..n)
            .map(|_| next_fr(&mut rng))
            .map(|_| Fr::ZERO)
            .collect(),
        "identical" => {
            let all: Vec<Fr> = (0..n).map(|_| next_fr(&mut rng)).collect();
            let one = all.first().copied().unwrap_or(Fr::ZERO);
            vec![one; n]
        }
        _ => (0..n).map(|_| next_fr(&mut rng)).collect(),
    };

    (bases, scalars)
}

// ---------------------------------------------------------------------------
// Acceptance 1 — the committed arkworks vectors
// ---------------------------------------------------------------------------

#[test]
fn committed_vectors_match() {
    let text = vectors();
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 5, "malformed line: {line}");
        assert_eq!(f[0], "msm");
        let (pattern, n, seed) = (f[1], f[2].parse().unwrap(), f[3].parse().unwrap());

        let (bases, scalars) = case(pattern, n, seed);
        let got = msm(&bases, &scalars).expect("equal lengths");
        assert_eq!(
            to_hex(&got.to_affine().to_bytes()),
            f[4],
            "{pattern} at n = {n}"
        );
        checked += 1;
    }
    assert_eq!(checked, 13, "every committed case ran");
}

/// The negative control S07 acceptance 11 asks for: one corrupted byte in the
/// corpus has to fail, or the corpus is not being read.
#[test]
fn a_corrupted_vector_fails() {
    let text = vectors();
    let line = text
        .lines()
        .find(|l| l.starts_with("msm random 100"))
        .expect("the n = 100 case");
    let f: Vec<&str> = line.split_whitespace().collect();

    let mut corrupted: Vec<u8> = f[4].bytes().collect();
    corrupted[0] ^= b'0' ^ b'1';
    let corrupted = String::from_utf8(corrupted).unwrap();
    assert_ne!(corrupted, f[4]);

    let (bases, scalars) = case(f[1], f[2].parse().unwrap(), f[3].parse().unwrap());
    let got = msm(&bases, &scalars).expect("equal lengths");
    assert_ne!(to_hex(&got.to_affine().to_bytes()), corrupted);
}

// ---------------------------------------------------------------------------
// Acceptance 2 — the live differential
// ---------------------------------------------------------------------------

/// 100 random MSMs of mixed sizes against `ark_ec::VariableBaseMSM`, plus the
/// sizes where the window heuristic changes width. Sizes 31/32/33, 128/129,
/// 255/256/257 and 1023/1024/1025 straddle every threshold the rule has below
/// 2^12, so every window width this test can reach is exercised.
#[test]
fn live_differential_against_arkworks() {
    let mut rng = Rng::new(20260931);
    let boundaries = [
        0usize, 1, 2, 3, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023,
        1024, 1025, 2047, 2048, 4095, 4096,
    ];

    let mut runs = 0;
    for size in boundaries {
        check_against_arkworks(size, &mut rng);
        runs += 1;
    }
    while runs < 100 {
        let n = (rng.next_u64() % 4097) as usize;
        check_against_arkworks(n, &mut rng);
        runs += 1;
    }
    assert!(runs >= 100);
}

fn check_against_arkworks(n: usize, rng: &mut Rng) {
    let mut bases = Vec::with_capacity(n);
    let mut scalars = Vec::with_capacity(n);
    let mut ark_bases = Vec::with_capacity(n);
    let mut ark_scalars = Vec::with_capacity(n);

    for _ in 0..n {
        let k = next_fr(rng);
        let s = next_fr(rng);
        let base = G1Projective::GENERATOR.mul(&k).to_affine();
        bases.push(base);
        scalars.push(s);
        ark_bases.push(common::to_ark_g1(&base));
        ark_scalars.push(common::to_ark_fr(&s));
    }

    let ours = msm(&bases, &scalars).expect("equal lengths").to_affine();
    let theirs = ark_bn254::G1Projective::msm(&ark_bases, &ark_scalars)
        .expect("equal lengths")
        .into_affine();

    assert_eq!(ours.to_bytes(), common::ark_g1_bytes(&theirs), "n = {n}");
}

// ---------------------------------------------------------------------------
// Acceptance 3 — the small path
// ---------------------------------------------------------------------------

/// `msm_small_u32(b, s) == msm(b, lift(s))` on u16-range, u32-range, all-zero
/// and single-bit scalar sets, at sizes through 2^14.
#[test]
fn small_path_matches_the_general_one() {
    let mut rng = Rng::new(20260932);

    for n in [0usize, 1, 2, 31, 32, 33, 100, 1024, 4096, 16384] {
        let bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine())
            .collect();

        for kind in ["u16", "u32", "zero", "one-bit", "max"] {
            let small: Vec<u32> = (0..n)
                .map(|i| match kind {
                    "u16" => (rng.next_u64() as u32) & 0xffff,
                    "u32" => rng.next_u64() as u32,
                    "zero" => 0,
                    "one-bit" => 1u32 << (i % 32),
                    _ => u32::MAX,
                })
                .collect();
            let lifted: Vec<Fr> = small.iter().map(|s| Fr::from_u64(*s as u64)).collect();

            assert_eq!(
                msm_small_u32(&bases, &small).expect("equal lengths"),
                msm(&bases, &lifted).expect("equal lengths"),
                "{kind} at n = {n}"
            );
        }
    }
}

/// The small path against arkworks directly, not only against our own general
/// path: two of our functions agreeing proves less than either agreeing with
/// an outside implementation.
#[test]
fn small_path_against_arkworks() {
    let mut rng = Rng::new(20260933);
    for n in [1usize, 7, 100, 1024, 5000] {
        let mut bases = Vec::with_capacity(n);
        let mut ark_bases = Vec::with_capacity(n);
        let mut small = Vec::with_capacity(n);
        let mut ark_scalars = Vec::with_capacity(n);

        for _ in 0..n {
            let base = G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();
            let s = rng.next_u64() as u32;
            bases.push(base);
            ark_bases.push(common::to_ark_g1(&base));
            small.push(s);
            ark_scalars.push(ark_bn254::Fr::from(s));
        }

        let ours = msm_small_u32(&bases, &small)
            .expect("equal lengths")
            .to_affine();
        let theirs = ark_bn254::G1Projective::msm(&ark_bases, &ark_scalars)
            .expect("equal lengths")
            .into_affine();
        assert_eq!(ours.to_bytes(), common::ark_g1_bytes(&theirs), "n = {n}");
    }
}

// ---------------------------------------------------------------------------
// Must-be-exact 1 — totality
// ---------------------------------------------------------------------------

/// Every degenerate input answers, and none of them panics. The naive
/// reference is `sum_i s_i * B_i` one point at a time, which shares no code
/// with the bucket machinery.
#[test]
fn degenerate_inputs_are_total() {
    let mut rng = Rng::new(20260934);

    let bases: Vec<G1Affine> = (0..40)
        .map(|i| {
            if i % 7 == 0 {
                G1Affine::IDENTITY
            } else {
                G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine()
            }
        })
        .collect();

    let all_infinity = vec![G1Affine::IDENTITY; 40];
    let one = next_fr(&mut rng);

    let scalar_sets: Vec<Vec<Fr>> = vec![
        vec![Fr::ZERO; 40],
        vec![Fr::ONE; 40],
        vec![Fr::MINUS_ONE; 40],
        vec![one; 40],
        (0..40).map(|_| next_fr(&mut rng)).collect(),
    ];

    for base_set in [&bases, &all_infinity] {
        for scalars in &scalar_sets {
            let got = msm(base_set, scalars).expect("equal lengths");
            assert_eq!(got, naive(base_set, scalars));
        }
    }

    // Empty input is the identity, in both entry points.
    assert_eq!(msm(&[], &[]).unwrap(), G1Projective::IDENTITY);
    assert_eq!(msm_small_u32(&[], &[]).unwrap(), G1Projective::IDENTITY);

    // One element, in every combination that matters.
    for base in [G1Affine::GENERATOR, G1Affine::IDENTITY] {
        for s in [Fr::ZERO, Fr::ONE, Fr::MINUS_ONE, one] {
            assert_eq!(msm(&[base], &[s]).unwrap(), naive(&[base], &[s]));
        }
    }
}

/// The one error, in both directions and in both entry points.
#[test]
fn length_mismatch_is_an_error() {
    let b = [G1Affine::GENERATOR; 3];
    let s = [Fr::ONE; 2];
    assert_eq!(
        msm(&b, &s),
        Err(MsmError::LengthMismatch {
            bases: 3,
            scalars: 2
        })
    );
    assert_eq!(
        msm(&b[..1], &s),
        Err(MsmError::LengthMismatch {
            bases: 1,
            scalars: 2
        })
    );
    assert_eq!(
        msm_small_u32(&b, &[1u32, 2]),
        Err(MsmError::LengthMismatch {
            bases: 3,
            scalars: 2
        })
    );
    assert_eq!(
        msm(&[], &s),
        Err(MsmError::LengthMismatch {
            bases: 0,
            scalars: 2
        })
    );
}

/// The signed recoding is where a windowed MSM goes wrong, and it goes wrong
/// at the ends. Every scalar here sits on a window boundary or a carry
/// boundary for some width, and the sizes sweep the width heuristic.
#[test]
fn boundary_scalars_agree_with_the_naive_sum() {
    let mut rng = Rng::new(20260935);
    let boundary: Vec<Fr> = [
        Fr::ZERO,
        Fr::ONE,
        Fr::MINUS_ONE,
        Fr::from_u64(u64::MAX),
        Fr::from_u64(1 << 16),
        Fr::from_u64((1 << 17) - 1),
        Fr::from_u64(1 << 17),
        Fr::from_u64(1 << 32),
        Fr::from_u64(u32::MAX as u64),
    ]
    .into_iter()
    .collect();

    for n in [1usize, 2, 31, 32, 33, 129, 257, 600] {
        let bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine())
            .collect();
        for s in &boundary {
            let scalars = vec![*s; n];
            assert_eq!(
                msm(&bases, &scalars).expect("equal lengths"),
                naive(&bases, &scalars),
                "scalar {s:?} at n = {n}"
            );
        }
        // And the whole boundary set interleaved, so one window's carry meets
        // a different scalar's in the same bucket pass.
        let mixed: Vec<Fr> = (0..n).map(|i| boundary[i % boundary.len()]).collect();
        assert_eq!(
            msm(&bases, &mixed).expect("equal lengths"),
            naive(&bases, &mixed),
            "mixed at n = {n}"
        );
    }
}

/// The result must not depend on how many cores ran it.
///
/// `pippenger` splits the input into chunks whose count comes from
/// `rayon::current_num_threads()`, so the decomposition genuinely differs
/// between machines. Bucket sums are group elements and addition is
/// associative, so the *value* must not — and a proof that verifies on the
/// prover's machine and not the verifier's would be the worst kind of bug to
/// find later. Every size here is also checked against the naive sum, so this
/// doubles as the totality sweep across every window width the heuristic
/// reaches below 2^14.
#[test]
fn the_answer_does_not_depend_on_the_thread_count() {
    let sizes = [
        1usize, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 40, 63, 64, 65, 100, 127, 128, 129, 200,
        255, 256, 257, 511, 512, 513, 1000, 1023, 1024, 1025, 2047, 2048, 4095, 4096, 5000, 8191,
        8192,
    ];

    for n in sizes {
        let mut rng = Rng::new(20260937 + n as u64);
        // Every seventh base is the point at infinity, so the degenerate
        // mixed-add path is inside the parallel sweep rather than beside it.
        let bases: Vec<G1Affine> = (0..n)
            .map(|i| {
                if i % 7 == 3 {
                    G1Affine::IDENTITY
                } else {
                    G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine()
                }
            })
            .collect();
        let scalars: Vec<Fr> = (0..n).map(|_| next_fr(&mut rng)).collect();
        let small: Vec<u32> = (0..n).map(|i| (rng.next_u64() as u32) ^ i as u32).collect();
        let lifted: Vec<Fr> = small.iter().map(|s| Fr::from_u64(*s as u64)).collect();

        let expected = naive(&bases, &scalars);
        let expected_small = naive(&bases, &lifted);

        // Well past this machine's core count in both directions: one thread
        // makes `chunks` collapse to 1, and 128 makes it hit the density clamp.
        for threads in [1usize, 2, 3, 5, 8, 13, 16, 32, 64, 128] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("building a rayon pool");
            let (general, small_path) = pool.install(|| {
                (
                    msm(&bases, &scalars).expect("equal lengths"),
                    msm_small_u32(&bases, &small).expect("equal lengths"),
                )
            });
            assert_eq!(general, expected, "general, n = {n}, {threads} threads");
            assert_eq!(
                small_path, expected_small,
                "small path, n = {n}, {threads} threads"
            );
        }
    }
}

/// `sum_i scalars[i] * bases[i]`, one scalar multiplication at a time.
fn naive(bases: &[G1Affine], scalars: &[Fr]) -> G1Projective {
    bases
        .iter()
        .zip(scalars)
        .fold(G1Projective::IDENTITY, |acc, (b, s)| {
            acc.add(&G1Projective::from(*b).mul(s))
        })
}

/// A guard on the arkworks bridge itself: if `ark_g1_bytes` and `to_bytes`
/// disagreed on encoding, every differential above would compare two
/// spellings of nothing.
#[test]
fn the_arkworks_bridge_round_trips() {
    let mut rng = Rng::new(20260936);
    for _ in 0..32 {
        let p = G1Projective::GENERATOR.mul(&next_fr(&mut rng)).to_affine();
        assert_eq!(common::ark_g1_bytes(&common::to_ark_g1(&p)), p.to_bytes());
    }
    assert_eq!(
        common::ark_g1_bytes(&ark_bn254::G1Affine::zero()),
        G1Affine::IDENTITY.to_bytes()
    );
    // And the scalar bridge, which the differential leans on just as hard.
    for _ in 0..32 {
        let s = next_fr(&mut rng);
        assert_eq!(
            common::to_ark_fr(&s).into_bigint().to_bytes_le(),
            s.to_bytes().to_vec()
        );
    }
}
