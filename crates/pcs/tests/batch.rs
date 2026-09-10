//! Acceptance 1, 2, 3 and 7, and Must-be-exact 6: batching `k` columns opened
//! at one point.
//!
//! The batch is one Mercury instance, not `k` of them: `cm* = sum rho^i cm_i`
//! and `f* = sum rho^i f_i` go through one ordinary opening, and what the
//! batching buys is that the proof is the same 704 bytes however many columns
//! there are. What it costs is one Schwartz–Zippel term, `(k-1)/|Fr|`.
//!
//! Three of the four rejections here are about *binding* rather than about
//! arithmetic. `rho` is squeezed after the commitment list and the value list
//! are absorbed, so reordering the list, shortening it, or moving one claimed
//! value all move `rho` — and `cm*` and `v*` with it.

mod common;

use field::Fr;
use pcs::{batch_open, batch_verify, commit, verify, MercuryCommitment, MercuryProof, PcsError};
use poly::{MultilinearPoly, PolyBacking};
use srs::Srs;
use test_support::{sha256, to_hex, Rng};
use transcript::Transcript;

const BATCH_KAT: &str = include_str!("vectors/mercury_batch.txt");

/// A batch of `k` random columns on `num_vars` variables, and its commitments.
struct Batch {
    srs: Srs,
    values: Vec<Vec<Fr>>,
    cols: Vec<MultilinearPoly>,
    cms: Vec<MercuryCommitment>,
    u: Vec<Fr>,
}

fn batch(num_vars: usize, k: usize, seed: u64) -> Batch {
    let srs = common::toy_srs(num_vars as u32);
    let mut rng = Rng::new(seed);
    let values: Vec<Vec<Fr>> = (0..k)
        .map(|_| {
            (0..1usize << num_vars)
                .map(|_| common::next_fr(&mut rng))
                .collect()
        })
        .collect();
    let cols: Vec<MultilinearPoly> = values
        .iter()
        .map(|v| MultilinearPoly::new(PolyBacking::Fr(v.clone())))
        .collect();
    let cms: Vec<MercuryCommitment> = cols
        .iter()
        .map(|f| commit(&srs, f).expect("commit"))
        .collect();
    let u = common::random_point(&mut rng, num_vars);
    Batch {
        srs,
        values,
        cols,
        cms,
        u,
    }
}

impl Batch {
    fn open(&self) -> (Vec<Fr>, MercuryProof) {
        let mut tr = Transcript::new();
        batch_open(&self.srs, &self.cols, &self.cms, &self.u, &mut tr).expect("batch_open")
    }

    fn check(
        &self,
        cms: &[MercuryCommitment],
        vs: &[Fr],
        proof: &MercuryProof,
    ) -> Result<(), PcsError> {
        let mut tr = Transcript::new();
        batch_verify(&self.srs.verifier(), cms, &self.u, vs, proof, &mut tr)
    }
}

/// Acceptance 1: eight random `2^16` columns at one random point.
#[test]
fn a_batch_of_eight_round_trips_at_two_to_the_sixteen() {
    let it = batch(16, 8, 0x5009_0001);
    let (vs, proof) = it.open();

    assert_eq!(vs.len(), 8);
    for (i, col) in it.cols.iter().enumerate() {
        assert_eq!(
            vs[i],
            col.evaluate(&it.u),
            "column {i}'s returned value is its multilinear evaluation"
        );
    }
    // A round trip rather than a length: `to_bytes` returns `[u8; PROOF_BYTES]`,
    // so its length is a fact about the type, but `from_bytes` validates every
    // point and every value and can fail.
    assert_eq!(
        MercuryProof::from_bytes(&proof.to_bytes()),
        Some(proof),
        "a batched proof is a MercuryProof and decodes as one"
    );
    it.check(&it.cms, &vs, &proof).expect("batch_verify");
}

/// The two sides leave the transcript in the same state, so a batched opening
/// composes inside a larger transcript exactly as a single one does.
#[test]
fn the_two_sides_stay_in_step() {
    let it = batch(8, 5, 0x5009_0002);

    let mut prover = Transcript::new();
    let (vs, proof) =
        batch_open(&it.srs, &it.cols, &it.cms, &it.u, &mut prover).expect("batch_open");
    let mut verifier = Transcript::new();
    batch_verify(
        &it.srs.verifier(),
        &it.cms,
        &it.u,
        &vs,
        &proof,
        &mut verifier,
    )
    .expect("batch_verify");

    assert_eq!(prover.snapshot(), verifier.snapshot());
    assert_eq!(
        prover.challenge_scalar(constants::transcript_tags::SUMCHECK_CHALLENGE),
        verifier.challenge_scalar(constants::transcript_tags::SUMCHECK_CHALLENGE)
    );
}

/// Acceptance 3: a batch of one verifies. It is **not** the same transcript as
/// a bare single opening, and the two are not interchangeable: a `k = 1` batch
/// absorbs the commitment list and squeezes `rho` before the opening begins.
#[test]
fn a_batch_of_one_verifies_and_is_not_a_single_opening() {
    let it = batch(8, 1, 0x5009_0003);
    let (vs, proof) = it.open();
    assert_eq!(vs[0], it.cols[0].evaluate(&it.u));
    it.check(&it.cms, &vs, &proof).expect("batch_verify");

    // The single-polynomial verifier is handed the same statement and the same
    // proof and rejects it, because its schedule is a different schedule.
    let mut tr = Transcript::new();
    assert_eq!(
        verify(
            &it.srs.verifier(),
            &it.cms[0],
            &it.u,
            vs[0],
            &proof,
            &mut tr
        ),
        Err(PcsError::VerificationFailed),
        "a k = 1 batch is not a bare single opening"
    );
}

/// Acceptance 2: the witness twin, and the three binding twins.
#[test]
fn every_batch_twin_is_rejected() {
    let it = batch(8, 4, 0x5009_0004);
    let (vs, proof) = it.open();
    it.check(&it.cms, &vs, &proof)
        .expect("the control verifies");

    // 1. Flip one evaluation in one column, open honestly against the ORIGINAL
    //    commitments, and verify with the values that honest opening returned.
    //    The prover is not cheating; `cm*` simply no longer commits to `f*`.
    for column in [0usize, 3] {
        let mut values = it.values.clone();
        values[column][7] += Fr::ONE;
        let cols: Vec<MultilinearPoly> = values
            .into_iter()
            .map(|v| MultilinearPoly::new(PolyBacking::Fr(v)))
            .collect();

        let mut tr = Transcript::new();
        let (tampered_vs, tampered_proof) =
            batch_open(&it.srs, &cols, &it.cms, &it.u, &mut tr).expect("batch_open");
        assert_ne!(tampered_vs[column], vs[column], "the value must have moved");
        assert_eq!(
            it.check(&it.cms, &tampered_vs, &tampered_proof),
            Err(PcsError::VerificationFailed),
            "column {column} flipped"
        );
        // And with the honest values, so the rejection is not about `vs` alone.
        assert_eq!(
            it.check(&it.cms, &vs, &tampered_proof),
            Err(PcsError::VerificationFailed),
            "column {column} flipped, honest values"
        );
    }

    // 2. One claimed value perturbed.
    for i in 0..vs.len() {
        let mut perturbed = vs.clone();
        perturbed[i] += Fr::ONE;
        assert_eq!(
            it.check(&it.cms, &perturbed, &proof),
            Err(PcsError::VerificationFailed),
            "value {i} perturbed"
        );
    }

    // 3. Two commitments swapped: order binding.
    let mut swapped = it.cms.clone();
    swapped.swap(0, 2);
    let mut swapped_vs = vs.clone();
    swapped_vs.swap(0, 2);
    assert_ne!(swapped, it.cms);
    assert_eq!(
        it.check(&swapped, &vs, &proof),
        Err(PcsError::VerificationFailed),
        "two commitments swapped"
    );
    // Swapping the values to match does not rescue it: the list order is what
    // fixes which power of `rho` each commitment carries.
    assert_eq!(
        it.check(&swapped, &swapped_vs, &proof),
        Err(PcsError::VerificationFailed),
        "two commitments and their values swapped"
    );

    // 4. `k` reported as `k - 1`, one commitment dropped: length binding.
    assert_eq!(
        it.check(&it.cms[..3], &vs[..3], &proof),
        Err(PcsError::VerificationFailed),
        "one commitment dropped"
    );
}

/// Acceptance 7: the zero polynomial commits to the point at infinity, whose
/// wire form is S05's all-zero 64 bytes, and it opens and verifies — alone and
/// inside a batch.
#[test]
fn the_zero_polynomial_commits_to_infinity_and_opens() {
    let num_vars = 8;
    let srs = common::toy_srs(num_vars as u32);
    let zero = MultilinearPoly::new(PolyBacking::Fr(vec![Fr::ZERO; 1 << num_vars]));

    let cm = commit(&srs, &zero).expect("commit");
    assert!(cm.0.infinity, "the zero polynomial commits to infinity");
    assert_eq!(
        cm.0.to_bytes(),
        [0u8; 64],
        "infinity is 64 zero bytes on the wire"
    );
    assert_eq!(
        curve::G1Affine::from_bytes(&[0u8; 64]).expect("all-zero decodes"),
        curve::G1Affine::IDENTITY
    );

    // The single opening: the true claim is zero, and any other claim fails.
    let mut rng = Rng::new(0x5009_0005);
    let u = common::random_point(&mut rng, num_vars);
    let mut tr = Transcript::new();
    let (v, proof) = pcs::open(&srs, &zero, &cm, &u, &mut tr).expect("open");
    assert_eq!(v, Fr::ZERO);
    let mut tr = Transcript::new();
    verify(&srs.verifier(), &cm, &u, v, &proof, &mut tr).expect("verify");
    let mut tr = Transcript::new();
    assert_eq!(
        verify(&srs.verifier(), &cm, &u, Fr::ONE, &proof, &mut tr),
        Err(PcsError::VerificationFailed),
        "the zero polynomial does not open to one"
    );

    // And inside a batch, beside two ordinary columns.
    let others: Vec<MultilinearPoly> = (0..2)
        .map(|_| common::random_poly(&mut rng, num_vars))
        .collect();
    let cols = vec![others[0].clone(), zero, others[1].clone()];
    let cms: Vec<MercuryCommitment> = cols
        .iter()
        .map(|f| commit(&srs, f).expect("commit"))
        .collect();
    assert!(cms[1].0.infinity, "the zero column is still infinity");

    let mut tr = Transcript::new();
    let (vs, proof) = batch_open(&srs, &cols, &cms, &u, &mut tr).expect("batch_open");
    assert_eq!(vs[1], Fr::ZERO);
    let mut tr = Transcript::new();
    batch_verify(&srs.verifier(), &cms, &u, &vs, &proof, &mut tr).expect("batch_verify");

    // A batch of nothing but zero columns is the same story: everything is
    // infinity, every value is zero, and the true statement verifies.
    let zeros: Vec<MultilinearPoly> = (0..3)
        .map(|_| MultilinearPoly::new(PolyBacking::Fr(vec![Fr::ZERO; 1 << num_vars])))
        .collect();
    let zero_cms: Vec<MercuryCommitment> = zeros
        .iter()
        .map(|f| commit(&srs, f).expect("commit"))
        .collect();
    let mut tr = Transcript::new();
    let (vs, proof) = batch_open(&srs, &zeros, &zero_cms, &u, &mut tr).expect("batch_open");
    assert_eq!(vs, vec![Fr::ZERO; 3]);
    let mut tr = Transcript::new();
    batch_verify(&srs.verifier(), &zero_cms, &u, &vs, &proof, &mut tr).expect("batch_verify");
    let mut tr = Transcript::new();
    assert_eq!(
        batch_verify(
            &srs.verifier(),
            &zero_cms,
            &u,
            &[Fr::ZERO, Fr::ONE, Fr::ZERO],
            &proof,
            &mut tr
        ),
        Err(PcsError::VerificationFailed),
        "an all-infinity batch still rejects a false claim"
    );
}

/// Acceptance 7's negative control: a corrupted infinity encoding does not
/// decode, on every wire a G1 point crosses.
#[test]
fn a_corrupted_infinity_encoding_does_not_decode() {
    // The 64-byte affine form: all-zero is infinity, and `(0, y)` for any other
    // `y` is off the curve.
    for byte in [0usize, 31, 32, 63] {
        let mut bad = [0u8; 64];
        bad[byte] = 1;
        assert_eq!(
            curve::G1Affine::from_bytes(&bad),
            None,
            "byte {byte} of an infinity encoding"
        );
    }

    // Inside a proof: an infinity point in a proof decodes, a corrupted one
    // does not.
    let it = batch(4, 2, 0x5009_0006);
    let (_, proof) = it.open();
    let mut bytes = proof.to_bytes();
    bytes[..64].copy_from_slice(&[0u8; 64]);
    assert!(
        MercuryProof::from_bytes(&bytes).is_some(),
        "an infinity proof point decodes"
    );
    bytes[3] = 1;
    assert_eq!(
        MercuryProof::from_bytes(&bytes),
        None,
        "a corrupted infinity proof point does not"
    );
}

/// Must-be-exact 6: every degenerate batch input is an error, and none of them
/// is a panic. `k = 0`, mismatched list lengths, and mixed column sizes.
#[test]
fn degenerate_batch_inputs_are_errors() {
    let it = batch(8, 3, 0x5009_0007);
    let (vs, proof) = it.open();
    let vsrs = it.srs.verifier();
    let mut tr = Transcript::new();

    // k = 0, on both sides.
    assert_eq!(
        batch_open(&it.srs, &[], &[], &it.u, &mut tr),
        Err(PcsError::EmptyBatch)
    );
    assert_eq!(
        pcs::batch_verify(&vsrs, &[], &it.u, &[], &proof, &mut tr),
        Err(PcsError::EmptyBatch)
    );
    assert_eq!(
        tr.snapshot(),
        Transcript::new().snapshot(),
        "a rejected batch absorbs nothing"
    );

    // Columns and commitments disagree.
    assert_eq!(
        batch_open(&it.srs, &it.cols, &it.cms[..2], &it.u, &mut tr),
        Err(PcsError::BatchLengthMismatch {
            commitments: 2,
            paired: 3
        })
    );
    // Commitments and claimed values disagree.
    assert_eq!(
        pcs::batch_verify(&vsrs, &it.cms, &it.u, &vs[..2], &proof, &mut tr),
        Err(PcsError::BatchLengthMismatch {
            commitments: 3,
            paired: 2
        })
    );

    // Mixed column sizes.
    let mut rng = Rng::new(0x5009_0008);
    let mut mixed = it.cols.clone();
    mixed[1] = common::random_poly(&mut rng, 6);
    assert_eq!(
        batch_open(&it.srs, &mixed, &it.cms, &it.u, &mut tr),
        Err(PcsError::MixedColumnSizes {
            expected: 8,
            found: 6
        })
    );

    // An unsupported instance size, and a point whose length is not the
    // columns' variable count.
    let odd: Vec<MultilinearPoly> = vec![common::random_poly(&mut rng, 7)];
    assert_eq!(
        batch_open(&it.srs, &odd, &it.cms[..1], &it.u, &mut tr),
        Err(PcsError::UnsupportedNumVars { num_vars: 7 })
    );
    assert_eq!(
        batch_open(&it.srs, &it.cols, &it.cms, &it.u[..7], &mut tr),
        Err(PcsError::PointLengthMismatch {
            point: 7,
            num_vars: 8
        })
    );
    assert_eq!(
        pcs::batch_verify(&vsrs, &it.cms, &it.u[..7], &vs, &proof, &mut tr),
        Err(PcsError::UnsupportedNumVars { num_vars: 7 })
    );

    // An SRS that cannot hold the instance.
    let small = common::toy_srs(4);
    assert_eq!(
        batch_open(&small, &it.cols, &it.cms, &it.u, &mut tr),
        Err(PcsError::SrsTooSmall {
            needed: 256,
            available: 16
        })
    );

    // A commitment that is not a point: `cm*` is a sum of these.
    let off_curve = curve::G1Affine {
        x: curve::Fq::ONE,
        y: curve::Fq::ONE,
        infinity: false,
    };
    let mut bad = it.cms.clone();
    bad[1] = MercuryCommitment(off_curve);
    assert_eq!(
        pcs::batch_verify(&vsrs, &bad, &it.u, &vs, &proof, &mut tr),
        Err(PcsError::InvalidPoint { field: "cm" })
    );

    // Nothing above touched the transcript.
    assert_eq!(tr.snapshot(), Transcript::new().snapshot());
}

/// Two identical columns batch correctly — `rho^i` still separates them — and a
/// commitment that does not match its column fails, which is the same failure
/// `open` has when handed a commitment it did not produce.
#[test]
fn aliased_and_mismatched_columns_behave() {
    let num_vars = 6;
    let srs = common::toy_srs(num_vars as u32);
    let mut rng = Rng::new(0x5009_0009);
    let f = common::random_poly(&mut rng, num_vars);
    let cm = commit(&srs, &f).expect("commit");

    let cols = vec![f.clone(), f.clone()];
    let cms = vec![cm, cm];
    let u = common::random_point(&mut rng, num_vars);
    let mut tr = Transcript::new();
    let (vs, proof) = batch_open(&srs, &cols, &cms, &u, &mut tr).expect("batch_open");
    assert_eq!(vs[0], vs[1]);
    let mut tr = Transcript::new();
    batch_verify(&srs.verifier(), &cms, &u, &vs, &proof, &mut tr).expect("batch_verify");

    // A commitment to something else, in position 1.
    let other = commit(&srs, &common::random_poly(&mut rng, num_vars)).expect("commit");
    let wrong = vec![cm, other];
    let mut tr = Transcript::new();
    let (vs, proof) = batch_open(&srs, &cols, &wrong, &u, &mut tr).expect("batch_open");
    let mut tr = Transcript::new();
    assert_eq!(
        batch_verify(&srs.verifier(), &wrong, &u, &vs, &proof, &mut tr),
        Err(PcsError::VerificationFailed),
        "a commitment that does not match its column fails"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 3 — the committed batch schedule
// ---------------------------------------------------------------------------

/// The `k = 1` fixture, replayed. Every byte of the proof, and the terminal
/// sponge state past it, comes back from the committed instance — so a change
/// to §11's preamble, its tags or its encodings shows up here.
fn replay_batch_kat(text: &str) -> Result<(), String> {
    let mut tau = None;
    let mut num_vars = None;
    let mut values: Vec<Fr> = Vec::new();
    let mut point: Vec<Fr> = Vec::new();
    let mut claim = None;
    let mut commitment = None;
    let mut proof: Option<Vec<u8>> = None;
    let mut probe = None;

    for fields in common::records(text) {
        match (fields[0].as_str(), fields.len()) {
            ("tau", 2) => tau = Some(common::parse_fr(&fields[1])?),
            ("numvars", 2) => {
                num_vars = Some(fields[1].parse::<usize>().map_err(|e| e.to_string())?)
            }
            ("value", 3) => {
                if fields[1].parse::<usize>() != Ok(values.len()) {
                    return Err("values must be in index order".to_string());
                }
                values.push(common::parse_fr(&fields[2])?);
            }
            ("point", 3) => {
                if fields[1].parse::<usize>() != Ok(point.len()) {
                    return Err("coordinates must be in variable order".to_string());
                }
                point.push(common::parse_fr(&fields[2])?);
            }
            ("claim", 2) => claim = Some(common::parse_fr(&fields[1])?),
            ("commitment", 2) => {
                commitment = Some(MercuryCommitment(common::parse_g1(&fields[1])?))
            }
            ("proof", 2) => {
                proof = Some(test_support::hex_to_bytes(&fields[1]).map_err(|e| e.to_string())?)
            }
            ("probe", 2) => probe = Some(common::parse_fr(&fields[1])?),
            (other, n) => return Err(format!("unknown record `{other}` with {n} fields")),
        }
    }

    let num_vars = num_vars.ok_or("no numvars record")?;
    if values.len() != 1usize << num_vars || point.len() != num_vars {
        return Err("the witness does not match numvars".to_string());
    }
    if tau.ok_or("no tau record")? != Fr::from_hex(common::TOY_TAU).expect("canonical") {
        return Err("the fixture's tau is not the toy tau".to_string());
    }
    let claim = claim.ok_or("no claim record")?;
    let commitment = commitment.ok_or("no commitment record")?;
    let expected = proof.ok_or("no proof record")?;
    let probe = probe.ok_or("no probe record")?;

    let srs = common::toy_srs(num_vars as u32);
    let f = MultilinearPoly::new(PolyBacking::Fr(values));
    if commit(&srs, &f).map_err(|e| format!("{e:?}"))? != commitment {
        return Err("the commitment does not match the witness".to_string());
    }

    let mut prover = Transcript::new();
    let (vs, proof) = batch_open(
        &srs,
        std::slice::from_ref(&f),
        &[commitment],
        &point,
        &mut prover,
    )
    .map_err(|e| format!("{e:?}"))?;
    if vs != vec![claim] {
        return Err("the claimed value does not match".to_string());
    }
    if proof.to_bytes().as_slice() != expected.as_slice() {
        return Err("the batched proof bytes do not match".to_string());
    }
    if prover.sample() != probe {
        return Err("the prover's terminal transcript state does not match".to_string());
    }

    let mut verifier = Transcript::new();
    batch_verify(
        &srs.verifier(),
        &[commitment],
        &point,
        &vs,
        &proof,
        &mut verifier,
    )
    .map_err(|e| format!("{e:?}"))?;
    if verifier.sample() != probe {
        return Err("the verifier's terminal transcript state does not match".to_string());
    }
    Ok(())
}

/// Acceptance 3: the committed `k = 1` batch replays byte for byte.
#[test]
fn the_committed_batch_replays() {
    replay_batch_kat(BATCH_KAT).expect("the committed batch replays");
    assert_eq!(
        to_hex(&sha256(BATCH_KAT.as_bytes())),
        "a211203ceb980ee9689516486a0e46d88a253433368505f242a3cbf4b774576f"
    );
}

/// Master rule 8: the replayer must be able to fail.
#[test]
fn a_corrupted_batch_fixture_is_rejected() {
    let body: String = BATCH_KAT
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(replay_batch_kat(&body).is_ok(), "the control");

    let damaged = |from: &str, to: &str| {
        let text = body.replacen(from, to, 1);
        assert_ne!(text, body, "the edit must land");
        assert!(replay_batch_kat(&text).is_err(), "{from} -> {to}");
    };

    for record in [
        "proof ",
        "probe ",
        "value 0 ",
        "point 0 ",
        "claim ",
        "commitment ",
    ] {
        let line = body
            .lines()
            .find(|l| l.starts_with(record))
            .unwrap_or_else(|| panic!("the {record} record"))
            .to_string();
        let token = line.split_whitespace().last().expect("a token");
        damaged(token, &flip_first_digit(token));
    }
    damaged("numvars 4", "numvars 6");
    damaged("value 1 ", "value 7 ");
    damaged("probe ", "# probe ");
    damaged("tau ", "tao ");
}

fn flip_first_digit(token: &str) -> String {
    let mut bytes = token.to_string().into_bytes();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).expect("hex is ASCII")
}
