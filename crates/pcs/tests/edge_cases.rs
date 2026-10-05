//! The committed `z^b = alpha` instance.
//!
//! `z^b = alpha` is legal and must verify, because the `(z^b - alpha) q` term
//! vanishes. No honest run reaches it — `alpha` is squeezed four steps before
//! `z`, so the coincidence has probability about
//! `2^-254` — and `Fr` has no `b`-th root to grind toward. So the instance is
//! **harness-constructed**: `tools/kat-gen` picks `z`, *defines* `alpha := z^b`,
//! and builds every polynomial from its definition. Nothing bypasses the
//! challenge draw in the production path, which is untouched.
//!
//! What this file does with the fixture is put it through the real verifier.
//! The twelve accumulator terms are rebuilt from the forced challenges — the
//! same `tests/common` code `accumulator.rs` checks against a live schedule
//! replay — and handed to `pcs::discharge`, which is the production MSM and the
//! production pairing check. So the equations that pass here are the equations
//! that run in `verify`.

mod common;

use field::Fr;
use pcs::{commit, discharge, AccumulatorEntry, MercuryCommitment, ENTRIES_PER_CHECK};
use poly::{MultilinearPoly, PolyBacking};
use test_support::{sha256, to_hex};

const KAT: &str = include_str!("vectors/z_pow_b_alpha.txt");

/// The fixture instance, parsed.
struct Kat {
    tau: Fr,
    values: Vec<Fr>,
    u: Vec<Fr>,
    v: Fr,
    challenges: common::Challenges,
    h_alpha: Fr,
    d_z: Fr,
    cm: MercuryCommitment,
    proof: pcs::MercuryProof,
}

fn parse(text: &str) -> Result<Kat, String> {
    let mut tau = None;
    let mut num_vars = None;
    let mut values: Vec<Fr> = Vec::new();
    let mut u: Vec<Fr> = Vec::new();
    let mut v = None;
    let mut named: Vec<(String, Fr)> = Vec::new();
    let mut cm = None;
    let mut proof = None;

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
                if fields[1].parse::<usize>() != Ok(u.len()) {
                    return Err("coordinates must be in variable order".to_string());
                }
                u.push(common::parse_fr(&fields[2])?);
            }
            ("claim", 2) => v = Some(common::parse_fr(&fields[1])?),
            ("challenge", 3) | ("derived", 3) => {
                named.push((fields[1].clone(), common::parse_fr(&fields[2])?))
            }
            ("commitment", 2) => cm = Some(MercuryCommitment(common::parse_g1(&fields[1])?)),
            ("proof", 2) => proof = Some(common::parse_proof(&fields[1])?),
            (other, n) => return Err(format!("unknown record `{other}` with {n} fields")),
        }
    }

    let num_vars = num_vars.ok_or("no numvars record")?;
    if values.len() != 1usize << num_vars || u.len() != num_vars {
        return Err("the witness does not match numvars".to_string());
    }
    let pick = |name: &str| -> Result<Fr, String> {
        named
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, x)| *x)
            .ok_or_else(|| format!("no `{name}` record"))
    };
    Ok(Kat {
        tau: tau.ok_or("no tau record")?,
        values,
        u,
        v: v.ok_or("no claim record")?,
        challenges: common::Challenges {
            alpha: pick("alpha")?,
            gamma: pick("gamma")?,
            z: pick("z")?,
            delta: pick("delta")?,
            z_prime: pick("zprime")?,
            rho: pick("rho")?,
        },
        h_alpha: pick("halpha")?,
        d_z: pick("dz")?,
        cm: cm.ok_or("no commitment record")?,
        proof: proof.ok_or("no proof record")?,
    })
}

/// The whole check, as one fallible routine so a corrupted fixture has
/// something to fail.
fn replay(text: &str) -> Result<Vec<AccumulatorEntry>, String> {
    let kat = parse(text)?;
    if kat.tau != Fr::from_hex(common::TOY_TAU).expect("the toy tau is canonical") {
        return Err("the fixture's tau is not the toy tau".to_string());
    }
    let num_vars = kat.u.len();
    let b = 1usize << (num_vars / 2);
    let c = kat.challenges;

    // The property under test, and the degeneracy rule it must still satisfy.
    if c.alpha != common::pow(c.z, b) {
        return Err("this fixture exists to have alpha = z^b".to_string());
    }
    if c.z == Fr::ZERO || c.z.square() == Fr::ONE || c.z == c.alpha || c.z * c.alpha == Fr::ONE {
        return Err("the forced challenge set must not be degenerate".to_string());
    }

    // The statement is real: the commitment is `crates/pcs`'s commitment of the
    // witness, and the claim is the multilinear evaluation at `u`.
    let srs = common::toy_srs(num_vars as u32);
    let f = MultilinearPoly::new(PolyBacking::Fr(kat.values.clone()));
    if commit(&srs, &f).map_err(|e| format!("{e:?}"))? != kat.cm {
        return Err("the commitment does not match the witness".to_string());
    }
    if f.evaluate(&kat.u) != kat.v {
        return Err("the claim is not fhat(u)".to_string());
    }

    // The two values `docs/spec/mercury.md` §3.4 derives rather than receives,
    // recomputed from the six sent evaluations and checked against the ones the
    // harness read straight off the polynomials.
    let (h_alpha, d_z) = common::derived(&kat.u, kat.v, &kat.proof, &c);
    if h_alpha != kat.h_alpha {
        return Err("the verifier's route to h(alpha) disagrees".to_string());
    }
    if d_z != kat.d_z {
        return Err("the verifier's route to D(z) disagrees".to_string());
    }

    // The twelve terms, and the production pairing check over them.
    let vsrs = srs.verifier();
    let entries = common::deferred_entries(&vsrs.g1_gen, &kat.cm, &kat.u, kat.v, &kat.proof, &c);
    if entries[2].scalar != Fr::ZERO {
        return Err("with alpha = z^b the q term must carry a zero scalar".to_string());
    }
    discharge(&vsrs, &entries, &[ENTRIES_PER_CHECK]).map_err(|e| format!("{e:?}"))?;
    Ok(entries)
}

/// The committed instance passes every verifier equation.
#[test]
fn the_committed_z_pow_b_equals_alpha_instance_verifies() {
    let entries = replay(KAT).expect("the committed instance verifies");
    assert_eq!(entries.len(), ENTRIES_PER_CHECK);

    // The q term is the only scalar that is zero, so the vanishing is the
    // documented one and not a collapse of the whole relation.
    let zeros: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.scalar == Fr::ZERO)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(zeros, vec![2], "only the q term vanishes");
}

/// The replayer must be able to fail.
#[test]
fn a_corrupted_z_pow_b_fixture_is_rejected() {
    let body: String = KAT
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(replay(&body).is_ok(), "the control");

    let damaged = |from: &str, to: &str| {
        let text = body.replacen(from, to, 1);
        assert_ne!(text, body, "the edit must land");
        assert!(replay(&text).is_err(), "{from} -> {to}");
    };

    // One flipped digit in each load-bearing record.
    for record in [
        "proof ",
        "value 0 ",
        "point 0 ",
        "claim ",
        "commitment ",
        "challenge alpha ",
        "challenge gamma ",
        "challenge z ",
        "challenge delta ",
        "challenge zprime ",
        "derived halpha ",
        "derived dz ",
    ] {
        let line = body
            .lines()
            .find(|l| l.starts_with(record))
            .unwrap_or_else(|| panic!("the {record} record"))
            .to_string();
        let token = line.split_whitespace().last().expect("a token");
        damaged(token, &flip_first_digit(token));
    }

    // Structural damage.
    damaged("numvars 4", "numvars 6");
    damaged("value 1 ", "value 7 ");
    damaged("tau ", "tao ");
    damaged("derived dz ", "# derived dz ");

    // `rho` is deliberately absent from the list above, and its absence is the
    // point of the next test.
    let line = body
        .lines()
        .find(|l| l.starts_with("challenge rho "))
        .expect("the rho record")
        .to_string();
    let token = line.split_whitespace().last().expect("a token");
    assert!(
        replay(&body.replacen(token, &flip_first_digit(token), 1)).is_ok(),
        "a moved merge challenge must NOT break an honest instance"
    );
}

fn flip_first_digit(token: &str) -> String {
    let mut bytes = token.to_string().into_bytes();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).expect("hex is ASCII")
}

/// The fixture is the committed one.
#[test]
fn the_committed_file_is_the_pinned_one() {
    assert_eq!(
        to_hex(&sha256(KAT.as_bytes())),
        "fdf5183bb1aab3dd87b33d6a83d5b41c5a65af9f8bc6c5be38405978e8dbc72a"
    );
}
