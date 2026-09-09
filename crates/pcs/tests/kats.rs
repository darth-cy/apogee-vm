//! Acceptance 8, 9 and 12: the transcript schedule, pinned three ways.
//!
//! * The G1 absorption vectors are an **oracle**: arkworks' points, arkworks'
//!   limbs. `append_g1` matching them is a statement about this repository's
//!   encoding, not about its own arithmetic.
//! * The proof vectors are a **regression pin**: `pcs::open`'s own bytes at
//!   `n = 2^4`. Any change to the absorb order, a tag, or an encoding moves
//!   every challenge and therefore every byte.
//! * The binding tests are properties: two openings of one instance agree byte
//!   for byte, and moving any absorbed input moves `alpha`.
//!
//! Both files are pinned by SHA-256 below, and `cargo run -p kat-gen -- pcs`
//! regenerates them.

mod common;

use constants::transcript_tags as tags;
use curve::G1Affine;
use field::Fr;
use pcs::{append_g1, append_g1_list, commit, open, verify, MercuryCommitment, MercuryProof};
use poly::{MultilinearPoly, PolyBacking};
use test_support::{hex_to_bytes, sha256, to_hex, Rng};
use transcript::Transcript;

const ABSORB_KATS: &str = include_str!("vectors/g1_absorb_kats.txt");
const PROOF_KAT: &str = include_str!("vectors/mercury_proof.txt");

const ABSORB_SHA256: &str = "9ee465300bd28bd596dcaf463280d0b330d9e5004d624d4e9b592f84681391f6";
const PROOF_SHA256: &str = "0f6c03662c2d0bc03f3cfbfc651ab7fa8c7981f8523089aedeab779705c95308";

#[test]
fn the_committed_files_are_the_pinned_ones() {
    assert_eq!(to_hex(&sha256(ABSORB_KATS.as_bytes())), ABSORB_SHA256);
    assert_eq!(to_hex(&sha256(PROOF_KAT.as_bytes())), PROOF_SHA256);
}

// ---------------------------------------------------------------------------
// Acceptance 12 — G1 absorption
// ---------------------------------------------------------------------------

/// A transcript that absorbed `limbs` under `tag` as one typed message.
fn by_limbs(tag: u64, limbs: &[Fr]) -> transcript::TranscriptSnapshot {
    let mut tr = Transcript::new();
    tr.append_scalars(tag, limbs);
    tr.snapshot()
}

fn replay_absorb_kats(text: &str) -> Result<usize, String> {
    let mut cases = 0;
    let mut singles = 0;
    let mut pairs = 0;

    for fields in common::records(text) {
        let kind = fields[0].as_str();
        let (points, limb_start) = match kind {
            "single" => (1usize, 2usize),
            "pair" => (2usize, 3usize),
            other => return Err(format!("unknown record `{other}`")),
        };
        if fields.len() != limb_start + 4 * points {
            return Err(format!("record `{kind}` has {} fields", fields.len()));
        }

        let mut ps = Vec::new();
        for token in &fields[1..1 + points] {
            let raw = hex_to_bytes(token).map_err(|e| e.to_string())?;
            let raw: [u8; 64] = raw.try_into().map_err(|_| "a G1 token is 64 bytes")?;
            ps.push(G1Affine::from_bytes(&raw).ok_or("a G1 token must be a valid point")?);
        }
        let mut limbs = Vec::new();
        for token in &fields[limb_start..] {
            let raw = hex_to_bytes(token).map_err(|e| e.to_string())?;
            let raw: [u8; 32] = raw.try_into().map_err(|_| "a limb token is 32 bytes")?;
            limbs.push(Fr::from_bytes(&raw).ok_or("a limb must be canonical")?);
        }

        let mut tr = Transcript::new();
        if points == 1 {
            append_g1(&mut tr, tags::COMMITMENT, &ps[0]);
            singles += 1;
        } else {
            append_g1_list(&mut tr, tags::COMMITMENT, &ps);
            pairs += 1;
        }
        if tr.snapshot() != by_limbs(tags::COMMITMENT, &limbs) {
            return Err(format!("record {cases} does not absorb to its limbs"));
        }
        cases += 1;
    }

    if singles < 3 || pairs < 2 {
        return Err("the fixture must keep both record kinds".to_string());
    }
    Ok(cases)
}

/// Acceptance 12: every committed case replays byte-exact.
#[test]
fn every_committed_absorption_replays() {
    let cases = replay_absorb_kats(ABSORB_KATS).expect("the committed absorption cases replay");
    assert!(cases >= 10, "the fixture must not shrink silently");
}

/// The fixture covers what acceptance 12 names: a real point, the point at
/// infinity, and a two-point list that is one message of eight limbs.
#[test]
fn the_absorption_fixture_covers_what_it_claims() {
    let records = common::records(ABSORB_KATS);
    let infinity = to_hex(&[0u8; 64]);
    assert!(
        records.iter().any(|r| r[0] == "single" && r[1] == infinity),
        "the point at infinity must be a case"
    );
    assert!(
        records
            .iter()
            .any(|r| r[0] == "single" && r[1] == to_hex(&G1Affine::GENERATOR.to_bytes())),
        "a known point must be a case"
    );
    assert!(
        records.iter().any(|r| r[0] == "pair" && r.len() == 3 + 8),
        "a two-point list of eight limbs must be a case"
    );
}

/// `append_g1` is exactly the one-element list, and a list is one message
/// rather than several.
#[test]
fn a_list_is_one_message() {
    let mut rng = Rng::new(0x5008_0600);
    let srs = common::toy_srs(4);
    let a = commit(&srs, &common::random_poly(&mut rng, 4))
        .expect("commit")
        .0;
    let b = commit(&srs, &common::random_poly(&mut rng, 4))
        .expect("commit")
        .0;

    let mut one = Transcript::new();
    append_g1(&mut one, tags::COMMITMENT, &a);
    let mut listed = Transcript::new();
    append_g1_list(&mut listed, tags::COMMITMENT, &[a]);
    assert_eq!(one.snapshot(), listed.snapshot());

    let mut together = Transcript::new();
    append_g1_list(&mut together, tags::COMMITMENT, &[a, b]);
    let mut apart = Transcript::new();
    append_g1(&mut apart, tags::COMMITMENT, &a);
    append_g1(&mut apart, tags::COMMITMENT, &b);
    assert_ne!(
        together.snapshot(),
        apart.snapshot(),
        "one message of two points must differ from two messages of one"
    );

    // The empty list is its own message, and the typed layer records it.
    let mut empty = Transcript::new();
    append_g1_list(&mut empty, tags::COMMITMENT, &[]);
    assert_eq!(
        empty.event_log(),
        &[transcript::TranscriptEvent::Absorb {
            tag: tags::COMMITMENT,
            n_scalars: 0
        }]
    );
}

/// Master rule 8: the replayer must be able to fail.
#[test]
fn a_corrupted_absorption_fixture_is_rejected() {
    assert!(replay_absorb_kats(ABSORB_KATS).is_ok(), "the control");

    // One flipped hex digit in an expected limb.
    let mut damaged = ABSORB_KATS.to_string();
    let line = damaged
        .lines()
        .find(|l| l.starts_with("single 01"))
        .expect("the generator's case")
        .to_string();
    let mut fields: Vec<&str> = line.split_whitespace().collect();
    let bumped = flip_first_digit(fields[2]);
    fields[2] = &bumped;
    damaged = damaged.replace(&line, &fields.join(" "));
    assert!(replay_absorb_kats(&damaged).is_err(), "a flipped limb");

    // A flipped digit in the *input* point.
    let mut damaged = ABSORB_KATS.to_string();
    let bumped = flip_first_digit(line.split_whitespace().nth(1).expect("the point token"));
    damaged = damaged.replace(
        line.split_whitespace().nth(1).expect("the point token"),
        &bumped,
    );
    assert!(replay_absorb_kats(&damaged).is_err(), "a flipped point");

    // A dropped field, an unknown record, and a thinned fixture.
    assert!(replay_absorb_kats(&ABSORB_KATS.replace("single 01", "single")).is_err());
    assert!(replay_absorb_kats(&ABSORB_KATS.replace("pair ", "triple ")).is_err());
    assert!(
        replay_absorb_kats(&ABSORB_KATS.replace("pair ", "# pair ")).is_err(),
        "dropping every list case must fail"
    );
}

fn flip_first_digit(token: &str) -> String {
    let mut bytes = token.to_string().into_bytes();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).expect("hex is ASCII")
}

// ---------------------------------------------------------------------------
// Acceptance 9 — the committed proof
// ---------------------------------------------------------------------------

/// The fixture instance, parsed.
struct ProofKat {
    tau: Fr,
    values: Vec<Fr>,
    point: Vec<Fr>,
    claim: Fr,
    commitment: G1Affine,
    proof: Vec<u8>,
    probe: Fr,
}

fn parse_proof_kat(text: &str) -> Result<ProofKat, String> {
    let mut tau = None;
    let mut num_vars = None;
    let mut values: Vec<Fr> = Vec::new();
    let mut point: Vec<Fr> = Vec::new();
    let mut claim = None;
    let mut commitment = None;
    let mut proof = None;
    let mut probe = None;

    let fr = |s: &str| -> Result<Fr, String> {
        let raw = hex_to_bytes(s).map_err(|e| e.to_string())?;
        let raw: [u8; 32] = raw.try_into().map_err(|_| "an Fr token is 32 bytes")?;
        Fr::from_bytes(&raw).ok_or_else(|| "an Fr token must be canonical".to_string())
    };

    for fields in common::records(text) {
        match (fields[0].as_str(), fields.len()) {
            ("tau", 2) => tau = Some(fr(&fields[1])?),
            ("numvars", 2) => {
                num_vars = Some(fields[1].parse::<usize>().map_err(|e| e.to_string())?)
            }
            ("value", 3) => {
                if fields[1].parse::<usize>() != Ok(values.len()) {
                    return Err("values must be in index order".to_string());
                }
                values.push(fr(&fields[2])?);
            }
            ("point", 3) => {
                if fields[1].parse::<usize>() != Ok(point.len()) {
                    return Err("coordinates must be in variable order".to_string());
                }
                point.push(fr(&fields[2])?);
            }
            ("claim", 2) => claim = Some(fr(&fields[1])?),
            ("commitment", 2) => {
                let raw = hex_to_bytes(&fields[1]).map_err(|e| e.to_string())?;
                let raw: [u8; 64] = raw.try_into().map_err(|_| "a G1 token is 64 bytes")?;
                commitment =
                    Some(G1Affine::from_bytes(&raw).ok_or("the commitment must be a valid point")?);
            }
            ("proof", 2) => proof = Some(hex_to_bytes(&fields[1]).map_err(|e| e.to_string())?),
            ("probe", 2) => probe = Some(fr(&fields[1])?),
            (other, n) => return Err(format!("unknown record `{other}` with {n} fields")),
        }
    }

    let num_vars = num_vars.ok_or("no numvars record")?;
    if values.len() != 1usize << num_vars || point.len() != num_vars {
        return Err("the witness does not match numvars".to_string());
    }
    Ok(ProofKat {
        tau: tau.ok_or("no tau record")?,
        values,
        point,
        claim: claim.ok_or("no claim record")?,
        commitment: commitment.ok_or("no commitment record")?,
        proof: proof.ok_or("no proof record")?,
        probe: probe.ok_or("no probe record")?,
    })
}

fn replay_proof_kat(text: &str) -> Result<(), String> {
    let kat = parse_proof_kat(text)?;
    if kat.tau != Fr::from_hex(common::TOY_TAU).expect("the toy tau is canonical") {
        return Err("the fixture's tau is not the toy tau".to_string());
    }

    let num_vars = kat.point.len();
    let srs = common::toy_srs(num_vars as u32);
    let f = MultilinearPoly::new(PolyBacking::Fr(kat.values.clone()));

    let cm = commit(&srs, &f).map_err(|e| format!("{e:?}"))?;
    if cm.0 != kat.commitment {
        return Err("the commitment does not match".to_string());
    }

    let mut tr = Transcript::new();
    let (v, proof) = open(&srs, &f, &cm, &kat.point, &mut tr).map_err(|e| format!("{e:?}"))?;
    if v != kat.claim {
        return Err("the claimed value does not match".to_string());
    }
    if proof.to_bytes().as_slice() != kat.proof.as_slice() {
        return Err("the proof bytes do not match".to_string());
    }
    // The terminal sponge state, which the proof bytes cannot see: a squeeze
    // moved within the schedule, or one the prover stops drawing, changes this
    // and nothing else.
    if tr.sample() != kat.probe {
        return Err("the prover's terminal transcript state does not match".to_string());
    }

    // And the committed bytes really are a proof.
    let decoded = MercuryProof::from_bytes(
        &kat.proof
            .clone()
            .try_into()
            .map_err(|_| "the proof token is the wrong length")?,
    )
    .ok_or("the committed proof must decode")?;
    let mut tr = Transcript::new();
    verify(
        &srs.verifier(),
        &MercuryCommitment(kat.commitment),
        &kat.point,
        kat.claim,
        &decoded,
        &mut tr,
    )
    .map_err(|e| format!("{e:?}"))?;
    if tr.sample() != kat.probe {
        return Err("the verifier's terminal transcript state does not match".to_string());
    }
    Ok(())
}

/// Acceptance 9: the committed proof replays byte for byte.
#[test]
fn the_committed_proof_replays() {
    replay_proof_kat(PROOF_KAT).expect("the committed proof replays");
}

/// Master rule 8, again: the replayer must be able to fail.
#[test]
fn a_corrupted_proof_fixture_is_rejected() {
    // The header documents the record names, so damage is applied to the body
    // alone: a replacement that landed in a comment would change nothing.
    let body: String = PROOF_KAT
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(replay_proof_kat(&body).is_ok(), "the control");

    let damaged = |from: &str, to: &str| {
        let text = body.replacen(from, to, 1);
        assert_ne!(text, body, "the edit must land");
        assert!(replay_proof_kat(&text).is_err(), "{from} -> {to}");
    };

    // One flipped digit in the expected proof, in the witness, in the point,
    // in the claim and in the commitment.
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
            .expect("the record")
            .to_string();
        let token = line.split_whitespace().last().expect("a token");
        damaged(token, &flip_first_digit(token));
    }

    // Structural damage.
    damaged("probe ", "# probe ");
    damaged("numvars 4", "numvars 5");
    damaged("value 1 ", "value 7 ");
    damaged("tau ", "tao ");
    damaged("claim ", "# claim ");
}

// ---------------------------------------------------------------------------
// Acceptance 8 — transcript binding
// ---------------------------------------------------------------------------

/// `alpha`, from the prefix of the schedule that precedes it.
fn alpha_of(cm: &MercuryCommitment, u: &[Fr], v: Fr, h: &G1Affine) -> Fr {
    let mut tr = Transcript::new();
    tr.append_scalar(tags::MERCURY_INSTANCE, Fr::from_u64(1u64 << u.len()));
    append_g1(&mut tr, tags::COMMITMENT, &cm.0);
    let mut claim = u.to_vec();
    claim.push(v);
    tr.append_scalars(tags::EVALUATION_CLAIM, &claim);
    append_g1(&mut tr, tags::PCS_OPENING, h);
    tr.challenge_scalar(tags::MERCURY_ALPHA)
}

/// Acceptance 8: opening the same instance twice is byte-identical, and moving
/// any absorbed input moves `alpha`.
#[test]
fn the_transcript_binds_the_statement() {
    let srs = common::toy_srs(8);
    let mut rng = Rng::new(0x5008_0601);
    let f = common::random_poly(&mut rng, 8);
    let u = common::random_point(&mut rng, 8);
    let cm = commit(&srs, &f).expect("commit");

    let mut first = Transcript::new();
    let (v, a) = open(&srs, &f, &cm, &u, &mut first).expect("open");
    let mut second = Transcript::new();
    let (v2, b) = open(&srs, &f, &cm, &u, &mut second).expect("open");
    assert_eq!(v, v2);
    assert_eq!(a.to_bytes(), b.to_bytes(), "opening is deterministic");
    assert_eq!(first.snapshot(), second.snapshot());

    let base = alpha_of(&cm, &u, v, &a.h);

    let other = commit(&srs, &common::random_poly(&mut rng, 8)).expect("commit");
    assert_ne!(base, alpha_of(&other, &u, v, &a.h), "cm binds alpha");

    let mut moved = u.clone();
    moved[3] += Fr::ONE;
    assert_ne!(base, alpha_of(&cm, &moved, v, &a.h), "u binds alpha");

    assert_ne!(base, alpha_of(&cm, &u, v + Fr::ONE, &a.h), "v binds alpha");

    let shifted = curve::G1Projective::from(a.h)
        .add(&curve::G1Projective::GENERATOR)
        .to_affine();
    assert_ne!(base, alpha_of(&cm, &u, v, &shifted), "h binds alpha");

    // And the size, which is the first thing absorbed: the same u, v and cm at
    // a different declared n gives a different alpha.
    let mut tr = Transcript::new();
    tr.append_scalar(tags::MERCURY_INSTANCE, Fr::from_u64(1u64 << 10));
    append_g1(&mut tr, tags::COMMITMENT, &cm.0);
    let mut claim = u.clone();
    claim.push(v);
    tr.append_scalars(tags::EVALUATION_CLAIM, &claim);
    append_g1(&mut tr, tags::PCS_OPENING, &a.h);
    assert_ne!(
        base,
        tr.challenge_scalar(tags::MERCURY_ALPHA),
        "n binds alpha"
    );
}

/// A transcript with history in it still works, and the two sides stay in step
/// through it: this is how S09 will call `open` and `verify`.
#[test]
fn a_transcript_with_a_prefix_stays_in_step() {
    let srs = common::toy_srs(6);
    let mut rng = Rng::new(0x5008_0602);
    let f = common::random_poly(&mut rng, 6);
    let u = common::random_point(&mut rng, 6);
    let cm = commit(&srs, &f).expect("commit");

    let prefix = |tr: &mut Transcript| {
        tr.append_bytes(tags::PUBLIC_INPUTS, b"an earlier phase");
        tr.append_scalar(tags::PROTOCOL_SUITE, Fr::from_u64(7));
    };

    let mut prover = Transcript::new();
    prefix(&mut prover);
    let (v, proof) = open(&srs, &f, &cm, &u, &mut prover).expect("open");

    let mut verifier = Transcript::new();
    prefix(&mut verifier);
    verify(&srs.verifier(), &cm, &u, v, &proof, &mut verifier).expect("verify");

    assert_eq!(
        prover.snapshot(),
        verifier.snapshot(),
        "prover and verifier must leave the transcript in the same state"
    );
    assert_eq!(
        prover.challenge_scalar(tags::SUMCHECK_CHALLENGE),
        verifier.challenge_scalar(tags::SUMCHECK_CHALLENGE),
        "and the next challenge must agree"
    );

    // A proof made without the prefix does not verify against one with it.
    let mut bare = Transcript::new();
    let (v2, bare_proof) = open(&srs, &f, &cm, &u, &mut bare).expect("open");
    assert_eq!(v, v2);
    assert_ne!(proof.to_bytes(), bare_proof.to_bytes());
    let mut verifier = Transcript::new();
    prefix(&mut verifier);
    assert!(verify(&srs.verifier(), &cm, &u, v, &bare_proof, &mut verifier).is_err());
}
