//! The Mercury fixtures: `crates/pcs/tests/vectors/`.
//!
//! Two files, and they are two different kinds of thing.
//!
//! * `g1_absorb_kats.txt` — the `Fr` limbs an affine G1 point absorbs as.
//!   **A genuine oracle.** Every point and every limb comes from arkworks:
//!   the point is arkworks' scalar multiplication, the limbs are its own
//!   little-endian serialization split at byte 16, and the infinity sentinel is
//!   `2^128` computed as an integer here. Nothing in this file is
//!   `crates/pcs`'s answer read back.
//!
//! * `mercury_proof.txt` — a full opening proof at `n = 2^4`.
//!   **A regression pin, not an oracle.** There is no second Mercury
//!   implementation to ask, so the proof bytes come from `pcs::open`; what they
//!   freeze is the transcript schedule, which any change to the absorb order,
//!   the tags or the encodings moves. The half of it that *is* independent is
//!   the SRS: the powers of the toy `tau` are computed with arkworks and handed
//!   to `Srs::load` as an archive, while `crates/pcs`'s own suite builds the
//!   same SRS with `crates/curve`. The two constructions have to agree or the
//!   committed proof does not replay.

use std::fmt::Write as _;

use ark_bn254::{Fq, Fq2, Fr as ArkFr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

use field::Fr;
use pcs::{commit, open};
use poly::{MultilinearPoly, PolyBacking};
use test_support::{to_hex, Rng};
use transcript::Transcript;

/// The toy SRS secret, mirroring `crates/pcs/tests/common/mod.rs::TOY_TAU`.
/// Written down on purpose: this SRS exists to exercise the protocol.
const TOY_TAU: u64 = 0x00ab_cdef;

/// The fixture instance. Small enough that the whole witness fits in the file.
const NUM_VARS: usize = 4;
const SEED: u64 = 20260913;

pub fn generate() {
    crate::write_vectors(
        "crates/pcs/tests/vectors/g1_absorb_kats.txt",
        &absorb_kats(),
    );
    crate::write_vectors("crates/pcs/tests/vectors/mercury_proof.txt", &proof_kat());
    crate::write_vectors(
        "crates/pcs/tests/vectors/z_pow_b_alpha.txt",
        &z_pow_b_alpha_kat(),
    );
    crate::write_vectors(
        "crates/pcs/tests/vectors/accumulator.txt",
        &accumulator_kat(),
    );
    crate::write_vectors("crates/pcs/tests/vectors/mercury_batch.txt", &batch_kat());
}

/// The toy SRS of `2^vars` powers, built with **arkworks** and handed to
/// `Srs::load` as an archive.
///
/// The independent half of every fixture below: `crates/pcs`'s own suite builds
/// the same SRS with `crates/curve`, so a committed vector only replays if the
/// two constructions agree.
fn toy_srs(vars: usize) -> (srs::Srs, ArkFr) {
    let count = 1usize << vars;
    let tau = ArkFr::from(TOY_TAU);
    let mut scalars = Vec::with_capacity(count);
    let mut acc = ArkFr::from(1u64);
    for _ in 0..count {
        scalars.push(acc);
        acc *= tau;
    }
    let mut archive = Vec::new();
    archive.extend_from_slice(b"APOGESRS");
    archive.extend_from_slice(&1u32.to_le_bytes());
    archive.extend_from_slice(&(vars as u32).to_le_bytes());
    archive.extend_from_slice(&(count as u64).to_le_bytes());
    archive.extend_from_slice(&g2_bytes(&G2Affine::generator()));
    archive.extend_from_slice(&g2_bytes(&(G2Projective::generator() * tau).into_affine()));
    for s in &scalars {
        archive.extend_from_slice(&g1_bytes(&(G1Projective::generator() * s).into_affine()));
    }
    let path =
        std::env::temp_dir().join(format!("apogee-kat-gen-{}-{vars}.srs", std::process::id()));
    std::fs::write(&path, &archive).expect("writing the toy archive");
    let loaded = srs::Srs::load(&path).expect("the toy archive loads");
    std::fs::remove_file(&path).ok();
    (loaded, tau)
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

fn fq_bytes(x: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_le());
    out
}

fn g1_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if p.is_zero() {
        return out;
    }
    out[..32].copy_from_slice(&fq_bytes(&p.x));
    out[32..].copy_from_slice(&fq_bytes(&p.y));
    out
}

fn g2_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if p.is_zero() {
        return out;
    }
    let (x, y): (Fq2, Fq2) = (p.x, p.y);
    out[..32].copy_from_slice(&fq_bytes(&x.c0));
    out[32..64].copy_from_slice(&fq_bytes(&x.c1));
    out[64..96].copy_from_slice(&fq_bytes(&y.c0));
    out[96..].copy_from_slice(&fq_bytes(&y.c1));
    out
}

/// The four `Fr` limbs a point absorbs as, computed from arkworks alone:
/// `x` low, `x` high, `y` low, `y` high, each half a coordinate's canonical
/// little-endian encoding zero-extended to 32 bytes.
///
/// Infinity is four copies of `2^128`, the smallest value no 128-bit half can
/// take. That is `constants::G1_INFINITY_SENTINEL`, derived here rather than
/// read, so the fixture would catch the constant changing.
fn limbs(p: &G1Affine) -> [[u8; 32]; 4] {
    if p.is_zero() {
        let sentinel = BigUint::from(1u32) << 128u32;
        let mut limb = [0u8; 32];
        for (slot, byte) in limb.iter_mut().zip(sentinel.to_bytes_le()) {
            *slot = byte;
        }
        return [limb; 4];
    }
    let raw = g1_bytes(p);
    let mut out = [[0u8; 32]; 4];
    for (i, half) in raw.chunks_exact(16).enumerate() {
        out[i][..16].copy_from_slice(half);
    }
    out
}

fn limb_tokens(p: &G1Affine) -> String {
    limbs(p)
        .iter()
        .map(|l| to_hex(l))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// g1_absorb_kats.txt
// ---------------------------------------------------------------------------

fn absorb_kats() -> String {
    let mut out = String::new();
    out.push_str(
        "\
# G1 transcript absorption -- docs/spec/mercury.md section 4.
# Generated by `cargo run -p kat-gen -- pcs`, from ark-bn254. Do not edit.
#
# A point absorbs as four Fr limbs: x low, x high, y low, y high, where the
# halves are the 128-bit halves of the coordinate's canonical little-endian
# encoding. Infinity absorbs four copies of 2^128.
#
# Records, one token per value, all hex, all canonical little-endian:
#   single <G1 64B> <limb0> <limb1> <limb2> <limb3>
#   pair   <G1 64B> <G1 64B> <limb0> .. <limb7>
# A `pair` is ONE typed message of eight limbs, not two messages of four.
",
    );

    let mut rng = Rng::new(SEED);
    let mut points = vec![G1Affine::identity(), G1Affine::generator()];
    for _ in 0..6 {
        let k = ArkFr::from_le_bytes_mod_order(&rng.next_le32());
        points.push((G1Projective::generator() * k).into_affine());
    }

    for p in &points {
        writeln!(out, "single {} {}", to_hex(&g1_bytes(p)), limb_tokens(p))
            .expect("writing to a String");
    }

    // The list case: a real pair, and a pair containing infinity, so the
    // sentinel is exercised inside a list as well as alone.
    for (a, b) in [(points[1], points[2]), (points[0], points[3])] {
        writeln!(
            out,
            "pair {} {} {} {}",
            to_hex(&g1_bytes(&a)),
            to_hex(&g1_bytes(&b)),
            limb_tokens(&a),
            limb_tokens(&b)
        )
        .expect("writing to a String");
    }

    out
}

// ---------------------------------------------------------------------------
// mercury_proof.txt
// ---------------------------------------------------------------------------

fn proof_kat() -> String {
    let n = 1usize << NUM_VARS;
    let (srs, tau) = toy_srs(NUM_VARS);

    // The witness and the point, from the seeded stream.
    let mut rng = Rng::new(SEED + 1);
    let values: Vec<Fr> = (0..n).map(|_| next_fr(&mut rng)).collect();
    let point: Vec<Fr> = (0..NUM_VARS).map(|_| next_fr(&mut rng)).collect();

    let f = MultilinearPoly::new(PolyBacking::Fr(values.clone()));
    let cm = commit(&srs, &f).expect("commit");
    let mut tr = Transcript::new();
    let (v, proof) = open(&srs, &f, &cm, &point, &mut tr).expect("open");

    // The raw duplex sample the transcript yields once the opening is over. It
    // is a function of the terminal sponge state, so it pins every step of the
    // schedule — including the squeeze positions of challenges nothing reads
    // back, which the proof bytes alone cannot see.
    let probe = tr.sample();

    let mut out = String::new();
    out.push_str(
        "\
# A full Mercury opening proof at n = 2^4 -- docs/spec/mercury.md section 8.
# Generated by `cargo run -p kat-gen -- pcs`. Do not edit.
#
# A REGRESSION PIN, not an oracle: the proof bytes are `pcs::open`'s own
# output, and what they freeze is the transcript schedule. The SRS is the
# independent half -- its powers are arkworks', while the test rebuilds the
# same SRS with `crates/curve`.
#
# Records, one token per value, all hex, all canonical little-endian:
#   tau        <Fr 32B>          the toy SRS secret; the archive is 2^numvars powers of it
#   numvars    <decimal>
#   value      <index> <Fr 32B>  one evaluation of f, in index order
#   point      <index> <Fr 32B>  one coordinate of u, in variable order
#   claim      <Fr 32B>          v = fhat(u)
#   commitment <G1 64B>
#   proof      <704B>            8 G1 points then 6 Fr values, in field order
",
    );
    writeln!(out, "tau {}", to_hex(&fr_bytes(&tau))).expect("writing to a String");
    writeln!(out, "numvars {NUM_VARS}").expect("writing to a String");
    for (i, x) in values.iter().enumerate() {
        writeln!(out, "value {i} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    for (i, x) in point.iter().enumerate() {
        writeln!(out, "point {i} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    writeln!(out, "claim {}", to_hex(&v.to_bytes())).expect("writing to a String");
    writeln!(out, "commitment {}", to_hex(&cm.0.to_bytes())).expect("writing to a String");
    writeln!(out, "proof {}", to_hex(&proof.to_bytes())).expect("writing to a String");
    writeln!(out, "probe {}", to_hex(&probe.to_bytes())).expect("writing to a String");
    out
}

fn fr_bytes(x: &ArkFr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_le());
    out
}

/// The same canonical sampler `crates/pcs`'s suite uses: 32 little-endian
/// bytes with the top two bits cleared, rejected rather than reduced.
fn next_fr(rng: &mut Rng) -> Fr {
    loop {
        let mut b = rng.next_le32();
        b[31] &= 0x3f;
        if let Some(x) = Fr::from_bytes(&b) {
            return x;
        }
    }
}

// ---------------------------------------------------------------------------
// z_pow_b_alpha.txt
// ---------------------------------------------------------------------------

/// A Mercury instance with `alpha` forced equal to `z^b` — S09 acceptance 6.
///
/// **A harness-constructed instance, not an opening.** `alpha` is squeezed four
/// steps before `z` in the real schedule, so no honest run reaches `z^b = alpha`
/// except with probability about `2^-254`; the only way to exercise the case is
/// to bypass the draws. So this fixture picks `z` and *defines* `alpha := z^b`,
/// then builds all eight polynomials from their definitions in
/// `docs/spec/mercury.md` §3 — schoolbook multiplication, one Horner division
/// per column, `eq` from its product form — and commits each with S07's KZG.
/// Nothing here calls `pcs::open`, and the production path is untouched.
///
/// What the case shows is that `(z^b - alpha) q` vanishes and the protocol is
/// unharmed: check A loses its `q` term entirely and everything else is
/// unchanged. `crates/pcs/tests/edge_cases.rs` reads this file back and puts the
/// instance through the real `pcs::discharge`.
fn z_pow_b_alpha_kat() -> String {
    // t = 2, b = 4: the smallest instance where `S` and the degree check have
    // room to exist and `b` is not the whole polynomial.
    const VARS: usize = 4;
    let n = 1usize << VARS;
    let t = VARS / 2;
    let b = 1usize << t;

    let (srs, tau) = toy_srs(VARS);
    let mut rng = Rng::new(SEED + 2);
    let values: Vec<Fr> = (0..n).map(|_| next_fr(&mut rng)).collect();
    let u: Vec<Fr> = (0..VARS).map(|_| next_fr(&mut rng)).collect();
    let (u1, u2) = (&u[..t], &u[t..]);

    // The forced challenge set. `z` is drawn; `alpha` is *defined* as `z^b`.
    let z = next_fr(&mut rng);
    let alpha = pow(z, b);
    let gamma = next_fr(&mut rng);
    let delta = next_fr(&mut rng);
    let z_prime = next_fr(&mut rng);
    let rho = next_fr(&mut rng);
    let z_inv = z.inverse().expect("a drawn challenge is nonzero");
    assert_eq!(alpha, pow(z, b), "the whole point of this fixture");
    assert!(
        z != Fr::ZERO && z.square() != Fr::ONE && z != alpha && z * alpha != Fr::ONE,
        "the forced set must still be non-degenerate"
    );

    // -- the polynomials, from docs/spec/mercury.md section 3 ---------------
    let v = (0..n)
        .map(|k| eq_at(k, &u) * values[k])
        .fold(Fr::ZERO, |a, x| a + x);
    let h: Vec<Fr> = (0..b)
        .map(|j| {
            (0..b)
                .map(|i| eq_at(i, u1) * values[i + j * b])
                .fold(Fr::ZERO, |a, x| a + x)
        })
        .collect();

    let mut g = vec![Fr::ZERO; b];
    let mut q = vec![Fr::ZERO; n - b];
    for i in 0..b {
        let column: Vec<Fr> = (0..b).map(|j| values[i + j * b]).collect();
        let (qi, remainder) = divide(&column, alpha);
        g[i] = remainder;
        for (j, c) in qi.iter().enumerate() {
            q[i + j * b] = *c;
        }
    }

    let h_alpha = eval(&h, alpha);
    let p1 = tensor(u1);
    let p2 = tensor(u2);
    let big = add(
        &add(&mul(&g, &rev(&p1)), &mul(&rev(&g), &p1)),
        &scale(&add(&mul(&h, &rev(&p2)), &mul(&rev(&h), &p2)), gamma),
    );
    assert_eq!(big[b - 1], (h_alpha + gamma * v) + (h_alpha + gamma * v));
    let s: Vec<Fr> = big[b..].to_vec();
    let d = rev(&g);

    // The fold's opening at z. With `alpha = z^b` the quotient term is zero,
    // which is exactly the case under test.
    let z_pow_b = pow(z, b);
    assert_eq!(z_pow_b - alpha, Fr::ZERO, "the q term vanishes");
    let g_z = eval(&g, z);
    let numerator = add(&add(&values, &scale(&q, -(z_pow_b - alpha))), &[-g_z]);
    let (big_h, remainder) = divide(&numerator, z);
    assert_eq!(remainder, Fr::ZERO, "the fold numerator vanishes at z");

    // -- the BDFG20 batch, section 6 ---------------------------------------
    let d_z = pow(z, b - 1) * eval(&g, z_inv);
    let items: [(Vec<Fr>, Vec<Fr>, Vec<Fr>); 4] = [
        (
            g.clone(),
            vanishing(&[alpha]),
            interpolate(&[(z, g_z), (z_inv, eval(&g, z_inv))]),
        ),
        (
            h.clone(),
            vec![Fr::ONE],
            interpolate(&[(z, eval(&h, z)), (z_inv, eval(&h, z_inv)), (alpha, h_alpha)]),
        ),
        (
            s.clone(),
            vanishing(&[alpha]),
            interpolate(&[(z, eval(&s, z)), (z_inv, eval(&s, z_inv))]),
        ),
        (d.clone(), vanishing(&[z_inv, alpha]), vec![d_z]),
    ];
    let mut batched = vec![Fr::ZERO];
    for (i, (poly, complement, r)) in items.iter().enumerate() {
        let shifted = add(poly, &scale(r, -Fr::ONE));
        batched = add(&batched, &scale(&mul(complement, &shifted), pow(delta, i)));
    }
    let mut w_poly = batched;
    for root in [z, z_inv, alpha] {
        let (quotient, remainder) = divide(&w_poly, root);
        assert_eq!(remainder, Fr::ZERO, "F is divisible by Z_T");
        w_poly = quotient;
    }
    let z_t = eval(&vanishing(&[z, z_inv, alpha]), z_prime);
    let mut l = scale(&w_poly, -z_t);
    for (i, (poly, complement, r)) in items.iter().enumerate() {
        let c = pow(delta, i) * eval(complement, z_prime);
        l = add(&l, &scale(poly, c));
        l = add(&l, &[-(c * eval(r, z_prime))]);
    }
    let (w_prime_poly, remainder) = divide(&l, z_prime);
    assert_eq!(remainder, Fr::ZERO, "L vanishes at z'");

    // -- the proof, in the frozen field order -------------------------------
    let com = |c: &[Fr]| {
        srs::kzg::kzg_commit(&srs, c)
            .expect("the toy SRS covers every polynomial here")
            .to_bytes()
    };
    let mut proof = Vec::with_capacity(704);
    for poly in [&h, &q, &g, &s, &d, &big_h, &w_poly, &w_prime_poly] {
        proof.extend_from_slice(&com(poly));
    }
    for value in [
        g_z,
        eval(&g, z_inv),
        eval(&h, z),
        eval(&h, z_inv),
        eval(&s, z),
        eval(&s, z_inv),
    ] {
        proof.extend_from_slice(&value.to_bytes());
    }
    assert_eq!(proof.len(), 704);

    let mut out = String::new();
    out.push_str(
        "\
# A Mercury instance with alpha = z^b -- S09 acceptance 6.
# Generated by `cargo run -p kat-gen -- pcs`. Do not edit.
#
# HARNESS-CONSTRUCTED, not an opening. The real schedule squeezes alpha four
# steps before z, so no honest run reaches z^b = alpha; this file picks z and
# defines alpha := z^b, then builds every polynomial from its definition in
# docs/spec/mercury.md section 3 and commits it with S07's KZG. `pcs::open` is
# not called and the production challenge draw is untouched.
#
# The case is legal because (z^b - alpha) q vanishes: check A loses its q term
# and every other equation is unchanged. crates/pcs/tests/edge_cases.rs reads
# this back, rebuilds the verifier's twelve accumulator terms from the forced
# challenges, and puts them through the real `pcs::discharge`.
#
# Records, one token per value, all hex, all canonical little-endian:
#   tau        <Fr 32B>          the toy SRS secret; the archive is 2^numvars powers of it
#   numvars    <decimal>
#   value      <index> <Fr 32B>  one evaluation of f, in index order
#   point      <index> <Fr 32B>  one coordinate of u, in variable order
#   claim      <Fr 32B>          v = fhat(u)
#   challenge  <name> <Fr 32B>   alpha, gamma, z, delta, zprime, rho -- all forced
#   derived    <name> <Fr 32B>   halpha = h(alpha), dz = D(z), from the polynomials
#   commitment <G1 64B>
#   proof      <704B>            8 G1 points then 6 Fr values, in field order
",
    );
    writeln!(out, "tau {}", to_hex(&fr_bytes(&tau))).expect("writing to a String");
    writeln!(out, "numvars {VARS}").expect("writing to a String");
    for (i, x) in values.iter().enumerate() {
        writeln!(out, "value {i} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    for (i, x) in u.iter().enumerate() {
        writeln!(out, "point {i} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    writeln!(out, "claim {}", to_hex(&v.to_bytes())).expect("writing to a String");
    for (name, x) in [
        ("alpha", alpha),
        ("gamma", gamma),
        ("z", z),
        ("delta", delta),
        ("zprime", z_prime),
        ("rho", rho),
    ] {
        writeln!(out, "challenge {name} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    for (name, x) in [("halpha", h_alpha), ("dz", d_z)] {
        writeln!(out, "derived {name} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    writeln!(out, "commitment {}", to_hex(&com(&values))).expect("writing to a String");
    writeln!(out, "proof {}", to_hex(&proof)).expect("writing to a String");
    out
}

// ---------------------------------------------------------------------------
// mercury_batch.txt
// ---------------------------------------------------------------------------

/// A `k = 1` batched opening at `n = 2^4` — S09 acceptance 3.
///
/// **A regression pin on the batch transcript schedule.** A batch of one is the
/// smallest thing that runs `docs/spec/mercury.md` §11's preamble, and it is
/// deliberately *not* the same transcript as a bare single opening: the
/// commitment list and the claimed value are absorbed and `rho` is squeezed
/// before the opening begins, so every challenge inside the opening moves. The
/// `probe` record is one raw duplex sample past the end, which pins the
/// terminal sponge state and therefore every squeeze position, including ones
/// nothing reads back.
fn batch_kat() -> String {
    const VARS: usize = 4;
    let n = 1usize << VARS;
    let (srs, tau) = toy_srs(VARS);
    let mut rng = Rng::new(SEED + 4);

    let values: Vec<Fr> = (0..n).map(|_| next_fr(&mut rng)).collect();
    let point: Vec<Fr> = (0..VARS).map(|_| next_fr(&mut rng)).collect();
    let f = MultilinearPoly::new(PolyBacking::Fr(values.clone()));
    let cm = commit(&srs, &f).expect("commit");

    let mut tr = Transcript::new();
    let (vs, proof) = pcs::batch_open(&srs, std::slice::from_ref(&f), &[cm], &point, &mut tr)
        .expect("batch_open");
    let probe = tr.sample();

    let mut out = String::new();
    out.push_str(
        "\
# A k = 1 batched Mercury opening at n = 2^4 -- docs/spec/mercury.md section 11.
# Generated by `cargo run -p kat-gen -- pcs`. Do not edit.
#
# A REGRESSION PIN on the batch transcript schedule, not an oracle: the proof
# bytes are `pcs::batch_open`'s own output. A batch of one is the smallest thing
# that runs the preamble, and it is NOT the same transcript as a bare single
# opening -- the commitment list and the claimed value are absorbed and rho is
# squeezed first, which moves every challenge inside the opening. Any change to
# the preamble's absorb order, its tags or its encodings moves every byte here.
#
# Records, one token per value, all hex, all canonical little-endian:
#   tau        <Fr 32B>          the toy SRS secret
#   numvars    <decimal>
#   value      <index> <Fr 32B>  one evaluation of the single column
#   point      <index> <Fr 32B>  one coordinate of u
#   claim      <Fr 32B>          the value batch_open returned
#   commitment <G1 64B>
#   proof      <704B>            8 G1 points then 6 Fr values, in field order
#   probe      <Fr 32B>          Transcript::sample() after the batched opening
",
    );
    writeln!(out, "tau {}", to_hex(&fr_bytes(&tau))).expect("writing to a String");
    writeln!(out, "numvars {VARS}").expect("writing to a String");
    for (i, x) in values.iter().enumerate() {
        writeln!(out, "value {i} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    for (i, x) in point.iter().enumerate() {
        writeln!(out, "point {i} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    writeln!(out, "claim {}", to_hex(&vs[0].to_bytes())).expect("writing to a String");
    writeln!(out, "commitment {}", to_hex(&cm.0.to_bytes())).expect("writing to a String");
    writeln!(out, "proof {}", to_hex(&proof.to_bytes())).expect("writing to a String");
    writeln!(out, "probe {}", to_hex(&probe.to_bytes())).expect("writing to a String");
    out
}

// ---------------------------------------------------------------------------
// accumulator.txt
// ---------------------------------------------------------------------------

/// Two independent deferred verifications, their concatenated accumulator, and
/// its digest — S09 acceptance 9.
///
/// **A regression pin on `docs/spec/accumulator.md`'s layout.** The entries are
/// `pcs::verify_deferred`'s and `pcs::batch_verify_deferred`'s own output —
/// there is no second Mercury to ask — so what the words freeze is the wire
/// form: the group count word, the six words an entry occupies, the side tags,
/// the limb split, and the order of all twelve entries. Any change to any of
/// them moves this file, and the digest moves with it.
///
/// The two verifications are deliberately of different kinds: one single
/// opening and one three-column batch, so the fixture shows that a batch defers
/// the same twelve entries a single opening does.
fn accumulator_kat() -> String {
    const VARS: usize = 4;
    const COLUMNS: usize = 3;
    let n = 1usize << VARS;
    let (srs, tau) = toy_srs(VARS);
    let vsrs = srs.verifier();
    let mut rng = Rng::new(SEED + 3);

    // -- the single instance ------------------------------------------------
    let single_values: Vec<Fr> = (0..n).map(|_| next_fr(&mut rng)).collect();
    let single_point: Vec<Fr> = (0..VARS).map(|_| next_fr(&mut rng)).collect();
    let f = MultilinearPoly::new(PolyBacking::Fr(single_values.clone()));
    let single_cm = commit(&srs, &f).expect("commit");
    let mut tr = Transcript::new();
    let (single_v, single_proof) =
        open(&srs, &f, &single_cm, &single_point, &mut tr).expect("open");

    // -- the batched instance -----------------------------------------------
    let batch_values: Vec<Vec<Fr>> = (0..COLUMNS)
        .map(|_| (0..n).map(|_| next_fr(&mut rng)).collect())
        .collect();
    let batch_point: Vec<Fr> = (0..VARS).map(|_| next_fr(&mut rng)).collect();
    let cols: Vec<MultilinearPoly> = batch_values
        .iter()
        .map(|v| MultilinearPoly::new(PolyBacking::Fr(v.clone())))
        .collect();
    let batch_cms: Vec<pcs::MercuryCommitment> = cols
        .iter()
        .map(|c| commit(&srs, c).expect("commit"))
        .collect();
    let mut tr = Transcript::new();
    let (batch_vs, batch_proof) =
        pcs::batch_open(&srs, &cols, &batch_cms, &batch_point, &mut tr).expect("batch_open");

    // -- the two deferred checks, concatenated ------------------------------
    let mut tr = Transcript::new();
    let first = pcs::verify_deferred(
        &vsrs,
        &single_cm,
        &single_point,
        single_v,
        &single_proof,
        &mut tr,
    )
    .expect("verify_deferred");
    let mut tr = Transcript::new();
    let second = pcs::batch_verify_deferred(
        &vsrs,
        &batch_cms,
        &batch_point,
        &batch_vs,
        &batch_proof,
        &mut tr,
    )
    .expect("batch_verify_deferred");

    let entries: Vec<pcs::AccumulatorEntry> = [first, second].concat();
    let checks = [pcs::ENTRIES_PER_CHECK, pcs::ENTRIES_PER_CHECK];
    let words = pcs::accumulator_words(&entries, &checks).expect("the frozen layout");
    let digest = pcs::accumulator_digest(&words);
    pcs::discharge(&vsrs, &entries, &checks).expect("the concatenation discharges");

    let mut out = String::new();
    out.push_str(
        "\
# A concatenated accumulator and its digest -- docs/spec/accumulator.md.
# Generated by `cargo run -p kat-gen -- pcs`. Do not edit.
#
# A REGRESSION PIN on the wire layout, not an oracle: the entries are
# `pcs::verify_deferred`'s and `pcs::batch_verify_deferred`'s own output. What
# the words freeze is the format -- the per-group count word, the six words an
# entry occupies, the side tags, the 128-bit limb split and the entry order --
# and the digest, which any change to any of them moves.
#
# Two independent verifications of different kinds: a single opening, then a
# three-column batch. Both emit twelve entries.
#
# Records, one token per value, all hex, all canonical little-endian:
#   tau              <Fr 32B>            the toy SRS secret
#   numvars          <decimal>
#   single_value     <index> <Fr 32B>
#   single_point     <index> <Fr 32B>
#   single_claim     <Fr 32B>
#   single_cm        <G1 64B>
#   single_proof     <704B>
#   batch_value      <column> <index> <Fr 32B>
#   batch_point      <index> <Fr 32B>
#   batch_claim      <column> <Fr 32B>
#   batch_cm         <column> <G1 64B>
#   batch_proof      <704B>
#   word             <index> <Fr 32B>    the concatenated accumulator, in order
#   digest           <Fr 32B>            Poseidon2 over exactly those words
",
    );
    writeln!(out, "tau {}", to_hex(&fr_bytes(&tau))).expect("writing to a String");
    writeln!(out, "numvars {VARS}").expect("writing to a String");
    for (i, x) in single_values.iter().enumerate() {
        writeln!(out, "single_value {i} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    for (i, x) in single_point.iter().enumerate() {
        writeln!(out, "single_point {i} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    writeln!(out, "single_claim {}", to_hex(&single_v.to_bytes())).expect("writing to a String");
    writeln!(out, "single_cm {}", to_hex(&single_cm.0.to_bytes())).expect("writing to a String");
    writeln!(out, "single_proof {}", to_hex(&single_proof.to_bytes()))
        .expect("writing to a String");
    for (c, column) in batch_values.iter().enumerate() {
        for (i, x) in column.iter().enumerate() {
            writeln!(out, "batch_value {c} {i} {}", to_hex(&x.to_bytes()))
                .expect("writing to a String");
        }
    }
    for (i, x) in batch_point.iter().enumerate() {
        writeln!(out, "batch_point {i} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    for (c, x) in batch_vs.iter().enumerate() {
        writeln!(out, "batch_claim {c} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    for (c, cm) in batch_cms.iter().enumerate() {
        writeln!(out, "batch_cm {c} {}", to_hex(&cm.0.to_bytes())).expect("writing to a String");
    }
    writeln!(out, "batch_proof {}", to_hex(&batch_proof.to_bytes())).expect("writing to a String");
    for (i, x) in words.iter().enumerate() {
        writeln!(out, "word {i} {}", to_hex(&x.to_bytes())).expect("writing to a String");
    }
    writeln!(out, "digest {}", to_hex(&digest.to_bytes())).expect("writing to a String");
    out
}

// ---------------------------------------------------------------------------
// Naive univariate arithmetic, written from the definitions
// ---------------------------------------------------------------------------

fn eval(c: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::ZERO;
    let mut power = Fr::ONE;
    for a in c {
        acc += *a * power;
        power *= x;
    }
    acc
}

fn mul(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::ZERO; a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            out[i + j] += *x * *y;
        }
    }
    out
}

fn add(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::ZERO; a.len().max(b.len())];
    for (i, x) in a.iter().enumerate() {
        out[i] += *x;
    }
    for (i, y) in b.iter().enumerate() {
        out[i] += *y;
    }
    out
}

fn scale(a: &[Fr], c: Fr) -> Vec<Fr> {
    a.iter().map(|x| *x * c).collect()
}

fn rev(a: &[Fr]) -> Vec<Fr> {
    a.iter().rev().copied().collect()
}

/// `(quotient, remainder)` of `c(X) / (X - r)`, by long division from the top.
fn divide(c: &[Fr], r: Fr) -> (Vec<Fr>, Fr) {
    let mut work = c.to_vec();
    let mut q = vec![Fr::ZERO; c.len().saturating_sub(1)];
    for i in (1..c.len()).rev() {
        let lead = work[i];
        q[i - 1] = lead;
        work[i] = Fr::ZERO;
        work[i - 1] += lead * r;
    }
    (q, work.first().copied().unwrap_or(Fr::ZERO))
}

fn vanishing(roots: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::ONE];
    for r in roots {
        out = mul(&out, &[-*r, Fr::ONE]);
    }
    out
}

fn interpolate(points: &[(Fr, Fr)]) -> Vec<Fr> {
    let mut out = vec![Fr::ZERO; points.len()];
    for (i, (xi, yi)) in points.iter().enumerate() {
        let mut num = vec![Fr::ONE];
        let mut den = Fr::ONE;
        for (j, (xj, _)) in points.iter().enumerate() {
            if i != j {
                num = mul(&num, &[-*xj, Fr::ONE]);
                den *= *xi - *xj;
            }
        }
        out = add(&out, &scale(&num, *yi * den.inverse().expect("distinct")));
    }
    out
}

fn pow(x: Fr, e: usize) -> Fr {
    let mut acc = Fr::ONE;
    for _ in 0..e {
        acc *= x;
    }
    acc
}

/// `eq(i, u)` from `prod_k (u_k i_k + (1 - u_k)(1 - i_k))`, `i` little-endian.
fn eq_at(i: usize, u: &[Fr]) -> Fr {
    let mut acc = Fr::ONE;
    for (k, uk) in u.iter().enumerate() {
        let bit = Fr::from_u64(((i >> k) & 1) as u64);
        acc *= *uk * bit + (Fr::ONE - *uk) * (Fr::ONE - bit);
    }
    acc
}

/// `P_u(X) = sum_i eq(i, u) X^i`, as a coefficient vector.
fn tensor(u: &[Fr]) -> Vec<Fr> {
    (0..1usize << u.len()).map(|i| eq_at(i, u)).collect()
}
