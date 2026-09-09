//! Known-answer tests against the committed arkworks-generated vector files.
//!
//! The files are data, never inline literals, and each is pinned by SHA-256.
//! Refresh them with `cargo run -p kat-gen`, then update the digests below
//! deliberately.
//!
//! [`evaluate`] is the single place a vector can fail. That is what makes the
//! negative control meaningful: it corrupts one field at a time and asserts
//! that this function notices.
//!
//! The edge lines carry a *name*, and the evaluator checks that the line
//! really is the case its name claims — that `p_plus_neg_p`'s second point is
//! the negation of its first, that `k_one`'s scalar is one. A fixture that
//! silently stopped covering a branch would otherwise still pass.

mod common;

use common::{
    fq2_to_hex, fq_from_hex, fq_to_hex, fr_from_hex, g1_bytes_from_hex, g1_raw, g1_to_hex,
    g2_bytes_from_hex, g2_raw, g2_to_hex,
};
use constants::FR_MODULUS;
use curve::{Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use field::Fr;
use std::collections::BTreeMap;
use test_support::{hex_to_32, sha256, to_hex};

/// Every committed file, with the digest that pins it.
const FILES: [(&str, &str); 3] = [
    (
        "tests/vectors/fq_kats.txt",
        "230f6e09738fec8b39fbc891534149a86520db5282b4723b4a27c959152c81ec",
    ),
    (
        "tests/vectors/g1_kats.txt",
        "3eaf2b1493a0d231d0a79826a5b6c68d3839ca5b16ccac5f77b0b13cc449c4c9",
    ),
    (
        "tests/vectors/g2_kats.txt",
        "42c37efa30ef8908803ac791cc73d3c60a2c55bd5cb4f17a3ccb01560d9634bb",
    ),
];

/// Each line kind and exactly how many lines of it the corpus holds. A
/// truncated or half-regenerated file fails here rather than passing quietly
/// with less coverage than it claims.
const EXPECTED_KINDS: [(&str, usize); 17] = [
    ("fq_ops", 1_049),
    ("fq2_ops", 1_081),
    ("fq_pow", 75),
    ("fq_bytes", 15),
    ("fq_u64", 9),
    ("g1_generator", 1),
    ("g1_ops", 1_000),
    ("g1_add_edge", 6),
    ("g1_madd_edge", 1),
    ("g1_scalar_edge", 4),
    ("g1_reject", 10),
    ("g2_generator", 1),
    ("g2_ops", 1_000),
    ("g2_add_edge", 6),
    ("g2_madd_edge", 1),
    ("g2_scalar_edge", 4),
    ("g2_reject", 14),
];

/// One parsed line: where it came from, its kind, and its fields.
struct Kat {
    file: &'static str,
    line_no: usize,
    op: String,
    fields: Vec<String>,
}

fn read_kats() -> Vec<Kat> {
    let mut all = Vec::new();
    for (path, digest) in FILES {
        let text = std::fs::read_to_string(path).expect("committed vector file must be readable");
        assert_eq!(
            to_hex(&sha256(text.as_bytes())),
            digest,
            "{path} does not match its pinned digest; refresh it deliberately"
        );
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let op = it.next().expect("a non-empty line has an operator");
            all.push(Kat {
                file: path,
                line_no: i + 1,
                op: op.to_string(),
                fields: it.map(|s| s.to_string()).collect(),
            });
        }
    }
    all
}

// ---------------------------------------------------------------------------
// Comparison helpers. Everything is compared in the wire form, so `to_bytes`
// is exercised on every result and a failure message is readable.
// ---------------------------------------------------------------------------

fn fq2_from_hex(s: &str) -> Result<Fq2, String> {
    if s.len() != 128 {
        return Err(format!(
            "expected 128 hex characters of Fq2, got {}",
            s.len()
        ));
    }
    Ok(Fq2::new(fq_from_hex(&s[..64])?, fq_from_hex(&s[64..])?))
}

fn want(expected: &str, ours: &str, what: &str) -> Result<(), String> {
    if expected == ours {
        Ok(())
    } else {
        Err(format!("{what}: expected {expected}, got {ours}"))
    }
}

fn require(condition: bool, what: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(what.to_string())
    }
}

fn arity(kat: &Kat, n: usize) -> Result<(), String> {
    require(
        kat.fields.len() == n,
        &format!("{} takes {n} fields, got {}", kat.op, kat.fields.len()),
    )
}

/// `Fq` and `Fq2` square roots are two-valued and arkworks' choice of sign is
/// not always ours, so the fixture is checked up to negation — and the root we
/// produced is squared back, which pins it absolutely. Written twice rather
/// than once over a trait: the crate has exactly two field types.
fn check_fq_sqrt(expected: &str, a: Fq) -> Result<(), String> {
    match (expected, a.sqrt()) {
        ("none", None) => Ok(()),
        ("none", Some(v)) => Err(format!(
            "fq sqrt: expected a nonresidue, got {}",
            fq_to_hex(&v)
        )),
        (expected, None) => Err(format!("fq sqrt: expected {expected}, got none")),
        (expected, Some(root)) => {
            require(
                fq_to_hex(&root) == expected || fq_to_hex(&-root) == expected,
                &format!(
                    "fq sqrt: {} is neither {expected} nor its negation",
                    fq_to_hex(&root)
                ),
            )?;
            require(root.square() == a, "fq sqrt: the root does not square back")
        }
    }
}

fn check_fq2_sqrt(expected: &str, a: Fq2) -> Result<(), String> {
    match (expected, a.sqrt()) {
        ("none", None) => Ok(()),
        ("none", Some(v)) => Err(format!(
            "fq2 sqrt: expected a nonresidue, got {}",
            fq2_to_hex(&v)
        )),
        (expected, None) => Err(format!("fq2 sqrt: expected {expected}, got none")),
        (expected, Some(root)) => {
            require(
                fq2_to_hex(&root) == expected || fq2_to_hex(&-root) == expected,
                &format!(
                    "fq2 sqrt: {} is neither {expected} nor its negation",
                    fq2_to_hex(&root)
                ),
            )?;
            require(
                root.square() == a,
                "fq2 sqrt: the root does not square back",
            )
        }
    }
}

/// `r` as canonical little-endian bytes. Not an `Fr` value: `r` is `Fr`'s
/// modulus.
fn r_hex() -> String {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        bytes[8 * i..8 * i + 8].copy_from_slice(&FR_MODULUS[i].to_le_bytes());
    }
    to_hex(&bytes)
}

fn exponent(hex: &str) -> Result<[u64; 4], String> {
    let bytes = hex_to_32(hex)?;
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[8 * i..8 * i + 8]);
        limbs[i] = u64::from_le_bytes(w);
    }
    Ok(limbs)
}

fn reject_coordinate(hex: &str) -> Result<(), String> {
    require(
        Fq::from_bytes(&hex_to_32(hex)?).is_none(),
        &format!("{hex} was supposed to be non-canonical"),
    )
}

/// A G2 coordinate is two `Fq`s; at least one half must be the bad one.
fn reject_coordinate_pair(hex: &str) -> Result<(), String> {
    require(
        reject_coordinate(&hex[..64]).is_ok() || reject_coordinate(&hex[64..]).is_ok(),
        &format!("neither half of {hex} is non-canonical"),
    )
}

// ---------------------------------------------------------------------------
// The evaluator
// ---------------------------------------------------------------------------

fn evaluate(kat: &Kat) -> Result<(), String> {
    let f = &kat.fields;
    match kat.op.as_str() {
        // <a> <b> <a+b> <a-b> <a*b> <a^2> <1/a> <sqrt a>
        "fq_ops" => {
            arity(kat, 8)?;
            let (a, b) = (fq_from_hex(&f[0])?, fq_from_hex(&f[1])?);
            want(&f[2], &fq_to_hex(&(a + b)), "fq add")?;
            want(&f[3], &fq_to_hex(&(a - b)), "fq sub")?;
            want(&f[4], &fq_to_hex(&(a * b)), "fq mul")?;
            want(&f[5], &fq_to_hex(&a.square()), "fq square")?;
            match (f[6].as_str(), a.inverse()) {
                ("none", None) => require(a == Fq::ZERO, "only zero has no inverse")?,
                ("none", Some(_)) => return Err("fq inverse: expected none".to_string()),
                (expected, None) => return Err(format!("fq inverse: expected {expected}")),
                (expected, Some(inv)) => {
                    want(expected, &fq_to_hex(&inv), "fq inverse")?;
                    require(a * inv == Fq::ONE, "fq a * (1/a) != 1")?;
                }
            }
            check_fq_sqrt(&f[7], a)
        }

        // <a> <b> <a+b> <a-b> <a*b> <a^2> <1/a> <sqrt a> <conj a> <a*xi>
        "fq2_ops" => {
            arity(kat, 10)?;
            let (a, b) = (fq2_from_hex(&f[0])?, fq2_from_hex(&f[1])?);
            want(&f[2], &fq2_to_hex(&(a + b)), "fq2 add")?;
            want(&f[3], &fq2_to_hex(&(a - b)), "fq2 sub")?;
            want(&f[4], &fq2_to_hex(&(a * b)), "fq2 mul")?;
            want(&f[5], &fq2_to_hex(&a.square()), "fq2 square")?;
            match (f[6].as_str(), a.inverse()) {
                ("none", None) => require(a == Fq2::ZERO, "only zero has no inverse")?,
                ("none", Some(_)) => return Err("fq2 inverse: expected none".to_string()),
                (expected, None) => return Err(format!("fq2 inverse: expected {expected}")),
                (expected, Some(inv)) => {
                    want(expected, &fq2_to_hex(&inv), "fq2 inverse")?;
                    require(a * inv == Fq2::ONE, "fq2 a * (1/a) != 1")?;
                }
            }
            check_fq2_sqrt(&f[7], a)?;
            want(&f[8], &fq2_to_hex(&a.conjugate()), "fq2 conjugate")?;
            want(
                &f[9],
                &fq2_to_hex(&a.mul_by_nonresidue()),
                "fq2 mul_by_nonresidue",
            )
        }

        "fq_pow" => {
            arity(kat, 3)?;
            let a = fq_from_hex(&f[0])?;
            want(&f[2], &fq_to_hex(&a.pow(&exponent(&f[1])?)), "fq pow")
        }

        // <32 bytes> ok|reject
        "fq_bytes" => {
            arity(kat, 2)?;
            let bytes = hex_to_32(&f[0])?;
            match (Fq::from_bytes(&bytes), f[1].as_str()) {
                (Some(x), "ok") => want(&f[0], &fq_to_hex(&x), "fq wire round-trip"),
                (None, "reject") => Ok(()),
                (Some(_), "reject") => Err("from_bytes accepted a non-canonical value".to_string()),
                (None, "ok") => Err("from_bytes rejected a canonical value".to_string()),
                (_, other) => Err(format!("unknown fq_bytes verdict {other}")),
            }
        }

        "fq_u64" => {
            arity(kat, 2)?;
            let n: u64 = f[0].parse().map_err(|_| format!("bad u64 {}", f[0]))?;
            want(&f[1], &fq_to_hex(&Fq::from_u64(n)), "fq from_u64")
        }

        // ------------------------------------------------------------------
        // G1
        // ------------------------------------------------------------------
        "g1_generator" => {
            arity(kat, 1)?;
            want(
                &f[0],
                &g1_to_hex(&G1Affine::GENERATOR),
                "G1 generator bytes",
            )?;
            require(
                G1Affine::from_bytes(&g1_bytes_from_hex(&f[0])?) == Some(G1Affine::GENERATOR),
                "from_bytes did not recover the generator",
            )
        }

        // <P> <Q> <k> <P+Q> <2P> <kP> <-P>
        "g1_ops" => {
            arity(kat, 7)?;
            let (p, q) = (g1_raw(&f[0])?, g1_raw(&f[1])?);
            let k =
                fr_from_hex(&f[2])?.ok_or_else(|| "the scalar must be canonical".to_string())?;

            // Every random point is also a `from_bytes` acceptance case.
            for (hex, point) in [(&f[0], &p), (&f[1], &q)] {
                require(
                    G1Affine::from_bytes(&g1_bytes_from_hex(hex)?) == Some(*point),
                    &format!("from_bytes did not accept and recover {hex}"),
                )?;
            }

            let (pp, qp) = (G1Projective::from(p), G1Projective::from(q));
            want(&f[3], &g1_to_hex(&pp.add(&qp).to_affine()), "G1 add")?;
            want(
                &f[3],
                &g1_to_hex(&qp.add(&pp).to_affine()),
                "G1 add commuted",
            )?;
            want(&f[3], &g1_to_hex(&pp.add_affine(&q).to_affine()), "G1 madd")?;
            want(&f[4], &g1_to_hex(&pp.double().to_affine()), "G1 double")?;
            want(&f[5], &g1_to_hex(&pp.mul(&k).to_affine()), "G1 mul")?;
            want(&f[6], &g1_to_hex(&(-p)), "G1 neg affine")?;
            want(&f[6], &g1_to_hex(&(-pp).to_affine()), "G1 neg projective")?;

            // The fixtures only ever hand the formulas Z = 1. These two make
            // every random vector exercise the general case too: a generic add
            // with both operands at Z != 1, and a mixed add against a Z != 1
            // accumulator, cross-checked against the generic path.
            let sum = G1Projective::from(g1_raw(&f[3])?);
            require(
                pp.double().add(&qp.double()) == sum.double(),
                "G1 add with both Z != 1 disagrees with 2(P+Q)",
            )?;
            require(
                pp.double().add_affine(&q) == pp.double().add(&qp),
                "G1 madd at Z != 1 disagrees with the generic add",
            )
        }

        // <name> <A> <B> <A+B>
        "g1_add_edge" => {
            arity(kat, 4)?;
            let (a, b) = (g1_raw(&f[1])?, g1_raw(&f[2])?);
            check_add_edge_name(&f[0], a.infinity, b.infinity, a == b, b == -a)?;
            if f[0] == "gen_plus_neg_gen" {
                require(a == G1Affine::GENERATOR, "the name claims the generator")?;
            }
            let (ap, bp) = (G1Projective::from(a), G1Projective::from(b));
            want(&f[3], &g1_to_hex(&ap.add(&bp).to_affine()), "G1 edge add")?;
            want(
                &f[3],
                &g1_to_hex(&bp.add(&ap).to_affine()),
                "G1 edge add commuted",
            )?;
            want(
                &f[3],
                &g1_to_hex(&ap.add_affine(&b).to_affine()),
                "G1 edge madd",
            )
        }

        // <P> <2P> <4P> <-2P>
        "g1_madd_edge" => {
            arity(kat, 4)?;
            let p = g1_raw(&f[0])?;
            let (two_p, neg_two_p) = (g1_raw(&f[1])?, g1_raw(&f[3])?);
            require(neg_two_p == -two_p, "the fourth point must be -(2P)")?;

            // `acc` is 2P with Z = 2y, so nothing below is the Z = 1 path.
            let acc = G1Projective::from(p).double();
            let inf = g1_to_hex(&G1Affine::IDENTITY);
            want(&f[1], &g1_to_hex(&acc.to_affine()), "G1 2P at Z != 1")?;
            want(
                &f[2],
                &g1_to_hex(&acc.add_affine(&two_p).to_affine()),
                "G1 madd against an equal affine point",
            )?;
            want(
                &inf,
                &g1_to_hex(&acc.add_affine(&neg_two_p).to_affine()),
                "G1 madd against the negated affine point",
            )?;
            want(
                &f[2],
                &g1_to_hex(&acc.add(&G1Projective::from(two_p)).to_affine()),
                "G1 generic add, Z1 != 1, Z2 == 1, equal points",
            )?;
            want(
                &f[2],
                &g1_to_hex(&acc.add(&acc).to_affine()),
                "G1 generic add of a Z != 1 point with itself",
            )?;
            want(
                &inf,
                &g1_to_hex(&acc.add(&(-acc)).to_affine()),
                "G1 generic add of a Z != 1 point with its negation",
            )
        }

        // <name> <P> <k> <kP>
        "g1_scalar_edge" => {
            arity(kat, 4)?;
            let p = g1_raw(&f[1])?;
            // The `k = r` line's expected value is infinity whatever P is, so
            // without this the point would be unchecked on that one line.
            require(p.is_in_subgroup(), "a scalar edge's P must be a real point")?;
            let pp = G1Projective::from(p);
            let inf = g1_to_hex(&G1Affine::IDENTITY);
            match fr_from_hex(&f[2])? {
                Some(k) => {
                    check_scalar_edge_name(&f[0], k, &f[3], &g1_to_hex(&p), &g1_to_hex(&-p), &inf)?;
                    want(&f[3], &g1_to_hex(&pp.mul(&k).to_affine()), "G1 scalar edge")
                }
                None => {
                    check_unrepresentable_scalar(&f[0], &f[2], &f[3], &inf)?;
                    want(
                        &f[3],
                        &g1_to_hex(&pp.mul(&Fr::ZERO).to_affine()),
                        "0 * P, since r == 0 in Fr",
                    )
                }
            }
        }

        // <P> <reason>
        "g1_reject" => {
            arity(kat, 2)?;
            require(
                G1Affine::from_bytes(&g1_bytes_from_hex(&f[0])?).is_none(),
                &format!("from_bytes accepted {} ({})", f[0], f[1]),
            )?;
            match f[1].as_str() {
                "off_curve" => {
                    let p = g1_raw(&f[0])?;
                    require(
                        !p.is_on_curve() && !p.is_in_subgroup(),
                        "an off_curve fixture is on the curve",
                    )
                }
                // Must-be-exact 3's fourth class: not infinity, because a byte
                // is set; not a point, because the pair is off the curve.
                "nonzero_infinity_pattern" => {
                    let bytes = g1_bytes_from_hex(&f[0])?;
                    require(
                        bytes.iter().any(|b| *b != 0),
                        "the infinity pattern is all-zero, so this fixture must not be",
                    )?;
                    require(
                        !g1_raw(&f[0])?.is_on_curve(),
                        "a near-infinity encoding must not be on the curve",
                    )
                }
                "non_canonical_x" => reject_coordinate(&f[0][..64]),
                "non_canonical_y" => reject_coordinate(&f[0][64..]),
                other => Err(format!("unknown G1 rejection reason {other}")),
            }
        }

        // ------------------------------------------------------------------
        // G2. The same shapes, plus the rejection reason G1 cannot have.
        // ------------------------------------------------------------------
        "g2_generator" => {
            arity(kat, 1)?;
            want(
                &f[0],
                &g2_to_hex(&G2Affine::GENERATOR),
                "G2 generator bytes",
            )?;
            require(
                G2Affine::from_bytes(&g2_bytes_from_hex(&f[0])?) == Some(G2Affine::GENERATOR),
                "from_bytes did not recover the generator",
            )
        }

        "g2_ops" => {
            arity(kat, 7)?;
            let (p, q) = (g2_raw(&f[0])?, g2_raw(&f[1])?);
            let k =
                fr_from_hex(&f[2])?.ok_or_else(|| "the scalar must be canonical".to_string())?;

            for (hex, point) in [(&f[0], &p), (&f[1], &q)] {
                require(
                    G2Affine::from_bytes(&g2_bytes_from_hex(hex)?) == Some(*point),
                    &format!("from_bytes did not accept and recover {hex}"),
                )?;
            }

            let (pp, qp) = (G2Projective::from(p), G2Projective::from(q));
            want(&f[3], &g2_to_hex(&pp.add(&qp).to_affine()), "G2 add")?;
            want(
                &f[3],
                &g2_to_hex(&qp.add(&pp).to_affine()),
                "G2 add commuted",
            )?;
            want(&f[3], &g2_to_hex(&pp.add_affine(&q).to_affine()), "G2 madd")?;
            want(&f[3], &g2_to_hex(&p.add(&q)), "G2Affine add")?;
            want(&f[4], &g2_to_hex(&pp.double().to_affine()), "G2 double")?;
            want(&f[4], &g2_to_hex(&p.double()), "G2Affine double")?;
            want(&f[5], &g2_to_hex(&pp.mul(&k).to_affine()), "G2 mul")?;
            want(&f[5], &g2_to_hex(&p.mul(&k)), "G2Affine mul")?;
            want(&f[6], &g2_to_hex(&(-p)), "G2 neg affine")?;
            want(&f[6], &g2_to_hex(&(-pp).to_affine()), "G2 neg projective")?;

            let sum = G2Projective::from(g2_raw(&f[3])?);
            require(
                pp.double().add(&qp.double()) == sum.double(),
                "G2 add with both Z != 1 disagrees with 2(P+Q)",
            )?;
            require(
                pp.double().add_affine(&q) == pp.double().add(&qp),
                "G2 madd at Z != 1 disagrees with the generic add",
            )
        }

        "g2_add_edge" => {
            arity(kat, 4)?;
            let (a, b) = (g2_raw(&f[1])?, g2_raw(&f[2])?);
            check_add_edge_name(&f[0], a.infinity, b.infinity, a == b, b == -a)?;
            if f[0] == "gen_plus_neg_gen" {
                require(a == G2Affine::GENERATOR, "the name claims the generator")?;
            }
            let (ap, bp) = (G2Projective::from(a), G2Projective::from(b));
            want(&f[3], &g2_to_hex(&ap.add(&bp).to_affine()), "G2 edge add")?;
            want(
                &f[3],
                &g2_to_hex(&bp.add(&ap).to_affine()),
                "G2 edge add commuted",
            )?;
            want(
                &f[3],
                &g2_to_hex(&ap.add_affine(&b).to_affine()),
                "G2 edge madd",
            )?;
            want(&f[3], &g2_to_hex(&a.add(&b)), "G2Affine edge add")
        }

        "g2_madd_edge" => {
            arity(kat, 4)?;
            let p = g2_raw(&f[0])?;
            let (two_p, neg_two_p) = (g2_raw(&f[1])?, g2_raw(&f[3])?);
            require(neg_two_p == -two_p, "the fourth point must be -(2P)")?;

            let acc = G2Projective::from(p).double();
            let inf = g2_to_hex(&G2Affine::IDENTITY);
            want(&f[1], &g2_to_hex(&acc.to_affine()), "G2 2P at Z != 1")?;
            want(
                &f[2],
                &g2_to_hex(&acc.add_affine(&two_p).to_affine()),
                "G2 madd against an equal affine point",
            )?;
            want(
                &inf,
                &g2_to_hex(&acc.add_affine(&neg_two_p).to_affine()),
                "G2 madd against the negated affine point",
            )?;
            want(
                &f[2],
                &g2_to_hex(&acc.add(&G2Projective::from(two_p)).to_affine()),
                "G2 generic add, Z1 != 1, Z2 == 1, equal points",
            )?;
            want(
                &f[2],
                &g2_to_hex(&acc.add(&acc).to_affine()),
                "G2 generic add of a Z != 1 point with itself",
            )?;
            want(
                &inf,
                &g2_to_hex(&acc.add(&(-acc)).to_affine()),
                "G2 generic add of a Z != 1 point with its negation",
            )
        }

        "g2_scalar_edge" => {
            arity(kat, 4)?;
            let p = g2_raw(&f[1])?;
            // The `k = r` line's expected value is infinity whatever P is, so
            // without this the point would be unchecked on that one line.
            require(p.is_in_subgroup(), "a scalar edge's P must be a real point")?;
            let pp = G2Projective::from(p);
            let inf = g2_to_hex(&G2Affine::IDENTITY);
            match fr_from_hex(&f[2])? {
                Some(k) => {
                    check_scalar_edge_name(&f[0], k, &f[3], &g2_to_hex(&p), &g2_to_hex(&-p), &inf)?;
                    want(&f[3], &g2_to_hex(&pp.mul(&k).to_affine()), "G2 scalar edge")
                }
                None => {
                    check_unrepresentable_scalar(&f[0], &f[2], &f[3], &inf)?;
                    want(
                        &f[3],
                        &g2_to_hex(&pp.mul(&Fr::ZERO).to_affine()),
                        "0 * P, since r == 0 in Fr",
                    )
                }
            }
        }

        "g2_reject" => {
            arity(kat, 2)?;
            require(
                G2Affine::from_bytes(&g2_bytes_from_hex(&f[0])?).is_none(),
                &format!("from_bytes accepted {} ({})", f[0], f[1]),
            )?;
            match f[1].as_str() {
                "off_curve" => {
                    let p = g2_raw(&f[0])?;
                    require(
                        !p.is_on_curve() && !p.is_in_subgroup(),
                        "an off_curve fixture is on the curve",
                    )
                }
                // Must-be-exact 3's fourth class: not infinity, because a byte
                // is set; not a point, because the pair is off the curve.
                "nonzero_infinity_pattern" => {
                    let bytes = g2_bytes_from_hex(&f[0])?;
                    require(
                        bytes.iter().any(|b| *b != 0),
                        "the infinity pattern is all-zero, so this fixture must not be",
                    )?;
                    require(
                        !g2_raw(&f[0])?.is_on_curve(),
                        "a near-infinity encoding must not be on the curve",
                    )
                }
                "not_in_subgroup" => {
                    let p = g2_raw(&f[0])?;
                    require(
                        p.is_on_curve(),
                        "a not_in_subgroup fixture must be on the curve",
                    )?;
                    require(
                        !p.is_in_subgroup(),
                        "a not_in_subgroup fixture passed the subgroup check",
                    )
                }
                "non_canonical_x" => reject_coordinate_pair(&f[0][..128]),
                "non_canonical_y" => reject_coordinate_pair(&f[0][128..]),
                other => Err(format!("unknown G2 rejection reason {other}")),
            }
        }

        other => Err(format!("unknown operator {other}")),
    }
}

/// The addition edges name which case they are; this is where the name is held
/// to it, so that a corpus which quietly stopped covering `P + (-P)` fails.
fn check_add_edge_name(
    name: &str,
    a_inf: bool,
    b_inf: bool,
    equal: bool,
    b_is_neg_a: bool,
) -> Result<(), String> {
    match name {
        "p_plus_inf" => require(!a_inf && b_inf, "p_plus_inf: B must be the only infinity"),
        "inf_plus_p" => require(a_inf && !b_inf, "inf_plus_p: A must be the only infinity"),
        "inf_plus_inf" => require(a_inf && b_inf, "inf_plus_inf: both must be infinity"),
        "p_plus_p" => require(
            equal && !a_inf,
            "p_plus_p: A and B must be one finite point",
        ),
        "p_plus_neg_p" | "gen_plus_neg_gen" => {
            require(b_is_neg_a && !a_inf, "the name claims B == -A")
        }
        other => Err(format!("unknown addition edge {other}")),
    }
}

fn check_scalar_edge_name(
    name: &str,
    k: Fr,
    expected: &str,
    p_hex: &str,
    neg_p_hex: &str,
    inf_hex: &str,
) -> Result<(), String> {
    match name {
        "k_zero" => {
            require(k == Fr::ZERO, "k_zero: the scalar must be zero")?;
            want(expected, inf_hex, "k_zero: 0 * P is infinity")
        }
        "k_one" => {
            require(k == Fr::ONE, "k_one: the scalar must be one")?;
            want(expected, p_hex, "k_one: 1 * P is P")
        }
        "k_r_minus_one" => {
            require(k == Fr::MINUS_ONE, "k_r_minus_one: the scalar must be r-1")?;
            want(expected, neg_p_hex, "k_r_minus_one: (r-1) * P is -P")
        }
        other => Err(format!(
            "unknown scalar edge {other} for a canonical scalar"
        )),
    }
}

/// `k = r` is the one scalar a fixture names that `Fr` cannot hold: `r` is
/// `Fr`'s modulus, so `from_bytes` refuses it. The claim `r * P == O` is then
/// discharged by the type system plus `0 * P == O`, since `r == 0` in `Fr`.
fn check_unrepresentable_scalar(
    name: &str,
    k_hex: &str,
    expected: &str,
    inf_hex: &str,
) -> Result<(), String> {
    require(
        name == "k_r",
        &format!("{name} must have a canonical scalar"),
    )?;
    want(&r_hex(), k_hex, "k_r: the scalar must be exactly r")?;
    want(expected, inf_hex, "k_r: r * P is infinity")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn every_committed_vector_passes() {
    let kats = read_kats();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for kat in &kats {
        if let Err(why) = evaluate(kat) {
            panic!("{}:{} ({}): {why}", kat.file, kat.line_no, kat.op);
        }
        *counts.entry(kat.op.as_str()).or_default() += 1;
    }

    let expected: BTreeMap<&str, usize> = EXPECTED_KINDS.into_iter().collect();
    assert_eq!(counts, expected, "the corpus is not the shape it claims");
}

/// The negative control. Corrupting a field of any line kind — or truncating
/// a line, or renaming its operator — has to fail. A field that survives
/// corruption in every vector of its kind is a field the harness never read.
///
/// The claim is per *kind*, not per line, because a single line can be
/// mathematically insensitive to a corruption without the harness being at
/// fault: the first `fq_pow` vector is `0^0 = 1`, and `1^0` is also 1. So each
/// field must be caught in at least one vector of its kind.
///
/// Six (kind, case, field) triples are exempt, and none is a gap: all six are
/// the *input to a predicate*, where corrupting a byte yields a different,
/// equally valid case of the same predicate. A corrupted canonical `fq_bytes`
/// value is still canonical; a corrupted `off_curve` or `not_in_subgroup`
/// point is still off the curve or still outside the subgroup; a corrupted
/// `nonzero_infinity_pattern` encoding still has a nonzero byte and is still
/// not a point. Their verdict and reason fields are swept, as is the point of
/// every `non_canonical` rejection — where a corrupted byte *does* turn the
/// value canonical, so the sweep catches it.
#[test]
fn corrupted_vectors_are_rejected() {
    const INSENSITIVE: [(&str, &str, usize); 6] = [
        ("fq_bytes", "ok", 0),
        ("g1_reject", "off_curve", 0),
        ("g1_reject", "nonzero_infinity_pattern", 0),
        ("g2_reject", "off_curve", 0),
        ("g2_reject", "not_in_subgroup", 0),
        ("g2_reject", "nonzero_infinity_pattern", 0),
    ];
    /// Vectors tried per group before concluding a field is unread. Enough to
    /// step past a degenerate first line, small enough to stay quick.
    const CANDIDATES: usize = 4;

    let kats = read_kats();

    // Group by line kind and by named case or rejection reason, skipping lines
    // with a `none` field so that flipping a digit is always meaningful.
    let mut groups: BTreeMap<(String, String), Vec<&Kat>> = BTreeMap::new();
    for kat in &kats {
        if kat.fields.iter().any(|f| f == "none") {
            continue;
        }
        let discriminator = match kat.op.as_str() {
            "g1_add_edge" | "g2_add_edge" | "g1_scalar_edge" | "g2_scalar_edge" => {
                kat.fields[0].clone()
            }
            "fq_bytes" | "g1_reject" | "g2_reject" => kat.fields[1].clone(),
            _ => String::new(),
        };
        let group = groups.entry((kat.op.clone(), discriminator)).or_default();
        if group.len() < CANDIDATES {
            group.push(kat);
        }
    }
    for (kind, _) in EXPECTED_KINDS {
        assert!(
            groups.keys().any(|(op, _)| op == kind),
            "{kind} has no corruptible vector"
        );
    }

    for ((op, case), candidates) in &groups {
        let label = format!("{op} {case}");
        let first = candidates[0];

        // An unknown operator is never silently skipped.
        assert!(
            evaluate(&mutate(first, Some(&format!("{op}_nope")), None)).is_err(),
            "{label}: a renamed operator must not evaluate"
        );

        // A truncated line is never silently accepted.
        let mut short = first.fields.clone();
        short.pop();
        assert!(
            evaluate(&mutate(first, None, Some(short))).is_err(),
            "{label}: a truncated line must not evaluate"
        );

        // ...and every field is read.
        for i in 0..first.fields.len() {
            if INSENSITIVE.contains(&(op.as_str(), case.as_str(), i)) {
                continue;
            }
            let caught = candidates.iter().any(|kat| {
                positions(&kat.fields[i]).into_iter().any(|pos| {
                    let mut fields = kat.fields.clone();
                    fields[i] = corrupt_at(&fields[i], pos);
                    evaluate(&mutate(kat, None, Some(fields))).is_err()
                })
            });
            assert!(
                caught,
                "{label}: corrupting field {i} passed in all {} vectors tried",
                candidates.len()
            );
        }
    }
}

fn mutate(kat: &Kat, op: Option<&str>, fields: Option<Vec<String>>) -> Kat {
    Kat {
        file: kat.file,
        line_no: kat.line_no,
        op: op.unwrap_or(&kat.op).to_string(),
        fields: fields.unwrap_or_else(|| kat.fields.clone()),
    }
}

/// The character positions a sweep tries. A field can be legitimately read in
/// part: the `x` of a `non_canonical_y` rejection is a free parameter, while
/// its `y` is the whole point of the line, so a corruption at one end says
/// nothing about the other.
fn positions(field: &str) -> Vec<usize> {
    let mut out = vec![0, field.len() / 2, field.len() - 1];
    out.sort();
    out.dedup();
    out
}

/// Flip one character of a field, keeping its shape: a hex digit stays a hex
/// digit, a decimal stays a decimal, and a name becomes a different name.
fn corrupt_at(field: &str, pos: usize) -> String {
    let bytes = field.as_bytes();
    let replacement = match bytes[pos] {
        b'0' => '1',
        b'1' => '2',
        b'2'..=b'9' => '0',
        b'a' => 'b',
        _ => 'a',
    };
    let mut out = String::with_capacity(field.len());
    out.push_str(&field[..pos]);
    out.push(replacement);
    out.push_str(&field[pos + 1..]);
    out
}
