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
use verifier_core::fold::{
    finish_template, point_template, prelude, simulate, Layout, CORRECTION, OFFSET, WINDOWS,
};

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

/// Twelve random points and scalars through the prelude, one point template
/// each and the finish: the result is `curve::msm`'s.
#[test]
fn the_fold_msm_is_the_curve_msm() {
    let l = Layout::at(1 << 16);
    let mut memory: Vec<Fr> = Vec::new();
    simulate(&prelude(&l), &mut memory).expect("the prelude runs");
    let point = point_template(&l);
    let mut rng = Rng::new(0x4d53_4d31);
    let (mut points, mut scalars) = (Vec::new(), Vec::new());
    for _ in 0..12 {
        let p = G1Projective::GENERATOR.mul(&scalar(&mut rng)).to_affine();
        let s = scalar(&mut rng);
        let coordinates = limbs(&p);
        for (c, limbs) in coordinates.iter().enumerate() {
            for (k, limb) in limbs.iter().enumerate() {
                let cell = (l.point + 4 * c as u32 + k as u32) as usize;
                if memory.len() <= cell {
                    memory.resize(cell + 1, Fr::ZERO);
                }
                memory[cell] = Fr::from_u64(*limb);
            }
        }
        memory[l.scalar as usize] = s;
        simulate(&point, &mut memory).expect("the point template runs");
        points.push(p);
        scalars.push(s);
    }
    simulate(&finish_template(&l), &mut memory).expect("the finish runs");
    let got: [[u64; 4]; 2] = core::array::from_fn(|c| {
        core::array::from_fn(|k| {
            let v = memory[(l.result + 4 * c as u32 + k as u32) as usize].to_bytes();
            u64::from_le_bytes(v[..8].try_into().unwrap())
        })
    });
    let want = msm(&points, &scalars)
        .expect("one scalar a point")
        .to_affine();
    // `run` writes the reduced representative, as the executor does.
    assert_eq!(got, limbs(&want), "the fold's MSM is not curve's");
}
