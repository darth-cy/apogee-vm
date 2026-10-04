//! `verifier_core::fold`'s MSM against `curve`'s (`docs/spec/recursion.md`
//! §8.3): the templates replayed natively, every inversion a hole
//! `fold::simulate` fills, give `Σ s_i·P_i` exactly — and the two constants
//! the templates carry are the points they say they are.
//!
//! `verifier-core` is `no_std` and has no curve, so this suite lives where
//! both are linked.

use curve::{msm::msm, G1Affine, G1Projective};
use field::Fr;
use test_support::Rng;
use transcript::g1_limbs;
use verifier_core::fold::{
    finish, load_point, point_template, prelude, simulate, split, FoldPoint, Layout, Phase, Side,
    BETA, CORRECTION, LAMBDA, OFFSET, WINDOWS,
};
use verifier_core::tape::{infinity_sentinel, run, Memory};

/// A point's coordinates as 64-bit limbs, `x` then `y`.
fn limbs(p: &G1Affine) -> [[u64; 4]; 2] {
    let bytes = p.to_bytes();
    core::array::from_fn(|c| {
        core::array::from_fn(|k| {
            u64::from_le_bytes(
                bytes[32 * c + 8 * k..32 * c + 8 * k + 8]
                    .try_into()
                    .unwrap(),
            )
        })
    })
}

fn scalar(rng: &mut Rng) -> Fr {
    let mut b = rng.next_le32();
    b[31] &= 0x1f;
    Fr::from_bytes(&b).expect("below 2^253")
}

/// `R = k·G` and `−R'' = −(Σ_w 256^w)·(Σ_b b·(b + 1))·R`, both mod r.
#[test]
fn the_offset_and_the_correction_are_their_points() {
    let k = Fr::from_hex("0x0000000000000100000000000000000000000000000000524543555253494f4e")
        .expect("k is a scalar");
    let r = G1Projective::GENERATOR.mul(&k).to_affine();
    assert_eq!(limbs(&r), OFFSET);
    let mut powers = Fr::ZERO;
    let mut p = Fr::ONE;
    for _ in 0..WINDOWS {
        powers += p;
        p *= Fr::from_u64(256);
    }
    let s = powers * Fr::from_u64((1..256u64).map(|b| b * (b + 1)).sum());
    let neg = G1Projective::GENERATOR.mul(&(-(k * s))).to_affine();
    assert_eq!(limbs(&neg), CORRECTION);
}

/// `φ(x, y) = (β·x, y)` is `λ` on G1: on the generator and on a random point.
#[test]
fn the_endomorphism_is_lambda() {
    let lambda = Fr::from_hex(LAMBDA).expect("a canonical literal");
    let fq = |limbs: [u64; 4]| {
        let bytes: Vec<u8> = limbs.iter().flat_map(|l| l.to_le_bytes()).collect();
        curve::Fq::from_bytes(&bytes.try_into().unwrap()).expect("below q")
    };
    let mut rng = Rng::new(0x474c_5631);
    for p in [
        G1Projective::GENERATOR.to_affine(),
        G1Projective::GENERATOR.mul(&scalar(&mut rng)).to_affine(),
    ] {
        let mut bytes = p.to_bytes();
        bytes[..32].copy_from_slice(&(fq(limbs(&p)[0]) * fq(BETA)).to_bytes());
        let phi = G1Affine::from_bytes(&bytes).expect("on the curve");
        assert_eq!(phi, G1Projective::from(p).mul(&lambda).to_affine());
    }
}

/// Each phase replayed as many times as it says.
fn phases(phases: &[Phase], memory: &mut Memory) {
    for (i, (template, times)) in phases.iter().enumerate() {
        for r in 0..*times {
            simulate(template, memory)
                .unwrap_or_else(|op| panic!("phase {i}, replay {r}: op {op} refuses"));
        }
    }
}

/// Twelve random points and scalars, each put in place by `load_point` from
/// its transcript limbs as a guest's are, through the prelude, one point
/// template each and the finish: the result is `curve::msm`'s. A thirteenth,
/// the point at infinity, is held to the sentinel and adds nothing — and a
/// real point said to be infinity is refused, since that would drop it.
#[test]
fn the_fold_msm_is_the_curve_msm() {
    let l = Layout::at(1 << 16);
    let (limbs_at, sentinel) = (l.end(), l.end() + 8);
    let mut memory = Memory::default();
    memory.set(sentinel, infinity_sentinel());
    phases(&prelude(&l), &mut memory);
    let point = point_template(&l);
    let at = FoldPoint {
        limbs: limbs_at,
        scalar: limbs_at + 4,
        side: Side::A,
    };
    let place = |memory: &mut Memory, bytes: &[u8; 64], s: Fr| {
        for (k, v) in g1_limbs(bytes).into_iter().enumerate() {
            memory.set(limbs_at + k as u32, v);
        }
        memory.set(at.scalar, s);
    };
    let mut rng = Rng::new(0x4d53_4d31);
    let (mut points, mut scalars) = (Vec::new(), Vec::new());
    for _ in 0..12 {
        let p = G1Projective::GENERATOR.mul(&scalar(&mut rng)).to_affine();
        let s = scalar(&mut rng);
        place(&mut memory, &p.to_bytes(), s);
        let mut said_infinity = memory.clone();
        assert!(
            run(
                &load_point(&at, &l, sentinel, true),
                &mut said_infinity,
                &[]
            )
            .is_err(),
            "a real point said to be infinity is dropped"
        );
        run(&load_point(&at, &l, sentinel, false), &mut memory, &[]).expect("the point loads");
        for (k, v) in split(s).into_iter().enumerate() {
            memory.set(l.split + k as u32, v);
        }
        simulate(&point, &mut memory)
            .unwrap_or_else(|op| panic!("op {op} of the point template: {:?}", point.ops[op]));
        points.push(p);
        scalars.push(s);
    }
    place(&mut memory, &[0; 64], scalar(&mut rng));
    run(&load_point(&at, &l, sentinel, true), &mut memory, &[]).expect("infinity is the sentinel");

    phases(&finish(&l), &mut memory);
    let got: [[u64; 4]; 2] = core::array::from_fn(|c| {
        core::array::from_fn(|k| {
            let v = memory.get(l.result + 4 * c as u32 + k as u32).to_bytes();
            u64::from_le_bytes(v[..8].try_into().unwrap())
        })
    });
    let want = msm(&points, &scalars)
        .expect("one scalar a point")
        .to_affine();
    // `run` writes the reduced representative, as the executor does.
    assert_eq!(got, limbs(&want), "the fold's MSM is not curve's");
}
