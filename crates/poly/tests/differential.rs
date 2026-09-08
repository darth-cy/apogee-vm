//! Acceptance 2: `evaluate` against three independent oracles — the committed
//! `ark-poly` answers, a naive `eq_eval` sum, and `ark-poly` again in-process.
//!
//! The in-process arkworks check is what pins the variable-order and
//! endianness convention against an external authority: it reads our table
//! through `get` in index order and evaluates at the same point, so agreement
//! is only possible if both sides put variable `j` in bit `j`.

mod common;

use common::{
    assert_sha256, corpus_backing, corrupt, data_lines, field_element, index, read_vectors,
    table_digest, to_ark, to_ark_mle, vertex,
};
use field::Fr;
use poly::{eq_eval, MultilinearPoly};
use test_support::Rng;

use ark_poly::{MultilinearExtension, Polynomial};

const DIFF_PATH: &str = "tests/vectors/evaluate_diff.txt";
const DIFF_SHA256: &str = "a711842a7df3239df8ed44aa6f690c3ed73ab15daa7ff80d35372cf1bae01271";
/// Case `i` of the corpus draws from this seed plus `i`; the file header says so.
const DIFF_SEED: u64 = 20260908;

struct Case {
    i: usize,
    backing: String,
    num_vars: usize,
    digest: String,
    point: Vec<Fr>,
    result: Option<Fr>,
}

fn parse(text: &str) -> Result<Vec<Case>, String> {
    let mut cases: Vec<Case> = Vec::new();
    for line in data_lines(text) {
        let n = line.no;
        let fields = line.fields.len();
        match line.fields[0].as_str() {
            "case" => {
                if fields != 5 {
                    return Err(format!("line {n}: a case has 5 fields, got {fields}"));
                }
                if index(&line, 1)? != cases.len() {
                    return Err(format!("line {n}: cases are out of order"));
                }
                cases.push(Case {
                    i: cases.len(),
                    backing: line.fields[2].clone(),
                    num_vars: index(&line, 3)?,
                    digest: line.fields[4].clone(),
                    point: Vec::new(),
                    result: None,
                });
            }
            "point" => {
                if fields != 4 {
                    return Err(format!("line {n}: a point has 4 fields, got {fields}"));
                }
                let (case, j) = (index(&line, 1)?, index(&line, 2)?);
                let value = field_element(&line.fields[3])?;
                let cur = cases
                    .last_mut()
                    .ok_or_else(|| format!("line {n}: a point before any case"))?;
                if case != cur.i || j != cur.point.len() || cur.result.is_some() {
                    return Err(format!("line {n}: point {case}/{j} is out of order"));
                }
                cur.point.push(value);
            }
            "result" => {
                if fields != 3 {
                    return Err(format!("line {n}: a result has 3 fields, got {fields}"));
                }
                let case = index(&line, 1)?;
                let value = field_element(&line.fields[2])?;
                let cur = cases
                    .last_mut()
                    .ok_or_else(|| format!("line {n}: a result before any case"))?;
                if case != cur.i || cur.result.is_some() {
                    return Err(format!("line {n}: result {case} is out of order"));
                }
                cur.result = Some(value);
            }
            other => return Err(format!("line {n}: unknown record `{other}`")),
        }
    }
    for c in &cases {
        if c.result.is_none() {
            return Err(format!("case {} has no result", c.i));
        }
        if c.point.len() != c.num_vars {
            return Err(format!(
                "case {} has {} coordinates for {} variables",
                c.i,
                c.point.len(),
                c.num_vars
            ));
        }
        if c.digest.len() != 64 {
            return Err(format!("case {} has a malformed digest", c.i));
        }
    }
    Ok(cases)
}

fn load() -> Vec<Case> {
    let text = read_vectors(DIFF_PATH);
    assert_sha256(DIFF_PATH, &text, DIFF_SHA256);
    parse(&text).expect("the committed corpus must parse")
}

/// The case's table, rebuilt by the draw rule the file header documents.
/// `every_committed_table_rebuilds` proves the rebuild is the generator's.
fn rebuild(c: &Case) -> MultilinearPoly {
    let mut rng = Rng::new(DIFF_SEED + c.i as u64);
    MultilinearPoly::new(corpus_backing(&mut rng, &c.backing, 1usize << c.num_vars))
}

fn expected(c: &Case) -> Fr {
    c.result.expect("load() rejects a case with no result")
}

/// `sum_x f(x) * eq(point, x)` over the cube, through `eq_eval` alone.
fn naive_evaluate(p: &MultilinearPoly, point: &[Fr]) -> Fr {
    let mut acc = Fr::ZERO;
    for x in 0..p.len() {
        acc += p.get(x) * eq_eval(point, &vertex(x, p.num_vars()));
    }
    acc
}

// ---------------------------------------------------------------------------

/// A corpus that had quietly shrunk, or collapsed onto one size or one
/// backing, would pass every comparison below while checking almost nothing.
#[test]
fn the_corpus_covers_what_it_claims() {
    let cases = load();
    assert_eq!(cases.len(), 100, "acceptance 2 asks for 100 polys");
    for name in ["u1", "u8", "u16", "u32", "fr"] {
        assert!(
            cases.iter().any(|c| c.backing == name),
            "no {name}-backed case in the corpus"
        );
    }
    for n in 0..=12 {
        assert!(
            cases.iter().any(|c| c.num_vars == n),
            "no {n}-variable case in the corpus"
        );
    }
    assert!(
        cases.iter().all(|c| c.num_vars <= 12),
        "acceptance 2 caps n"
    );
}

/// The corpus tables are not written out, so this is what pins them: the
/// rebuild must hash to the digest the generator wrote from arkworks values.
/// It checks the draw rule and the lift in one go.
#[test]
fn every_committed_table_rebuilds() {
    for c in &load() {
        assert_eq!(
            table_digest(&rebuild(c)),
            c.digest,
            "case {} rebuilt a different table",
            c.i
        );
    }
}

#[test]
fn evaluate_matches_the_committed_arkworks_values() {
    for c in &load() {
        assert_eq!(
            rebuild(c).evaluate(&c.point),
            expected(c),
            "case {} disagrees with the committed value",
            c.i
        );
    }
}

#[test]
fn evaluate_matches_the_naive_eq_sum() {
    for c in &load() {
        let p = rebuild(c);
        assert_eq!(
            p.evaluate(&c.point),
            naive_evaluate(&p, &c.point),
            "case {} disagrees with the naive sum",
            c.i
        );
    }
}

#[test]
fn evaluate_matches_arkworks_in_process() {
    for c in &load() {
        let p = rebuild(c);
        let mle = to_ark_mle(&p);
        let point: Vec<ark_bn254::Fr> = c.point.iter().map(to_ark).collect();
        assert_eq!(
            to_ark(&p.evaluate(&c.point)),
            mle.evaluate(&point),
            "case {} disagrees with ark-poly",
            c.i
        );
    }
}

/// The other half of the convention: `bind` fixes variable 0, which is exactly
/// what `ark-poly`'s `fix_variables` does with a one-element partial point.
#[test]
fn bind_matches_arkworks_fix_variables() {
    for c in load().iter().filter(|c| c.num_vars > 0) {
        let mut p = rebuild(c);
        let folded = to_ark_mle(&p).fix_variables(&[to_ark(&c.point[0])]);
        p.bind(c.point[0]);
        assert_eq!(p.num_vars(), c.num_vars - 1);
        assert_eq!(p.len(), folded.evaluations.len());
        for i in 0..p.len() {
            assert_eq!(
                to_ark(&p.get(i)),
                folded.evaluations[i],
                "case {} disagrees with fix_variables at {i}",
                c.i
            );
        }
    }
}

/// The corpus rebuild reads four `u64` draws as a 256-bit little-endian integer
/// mod p through `Fr::from_u64`, because `crates/field` has no reducing
/// constructor. The generator used arkworks' `from_le_bytes_mod_order` on the
/// same draws, so the two have to agree — otherwise every digest above would be
/// pinning the wrong table.
#[test]
fn the_corpus_rebuild_rule_matches_the_arkworks_reduction() {
    let mut ours = Rng::new(1);
    let mut theirs = Rng::new(1);
    for _ in 0..1000 {
        let mine = common::next_fr(&mut ours);
        let ark: ark_bn254::Fr = ark_ff::PrimeField::from_le_bytes_mod_order(&theirs.next_le32());
        assert_eq!(to_ark(&mine), ark);
    }
}

// ---------------------------------------------------------------------------
// Negative controls
// ---------------------------------------------------------------------------

#[test]
fn a_corrupted_corpus_is_rejected() {
    let text = read_vectors(DIFF_PATH);

    // A flipped digit in a committed answer.
    let cases = parse(&corrupt(&text, "result 5 ")).expect("still parses");
    assert_ne!(
        rebuild(&cases[5]).evaluate(&cases[5].point),
        expected(&cases[5])
    );

    // A flipped digit in an input: the committed answer stops matching.
    let cases = parse(&corrupt(&text, "point 6 0 ")).expect("still parses");
    assert_ne!(
        rebuild(&cases[6]).evaluate(&cases[6].point),
        expected(&cases[6])
    );

    // A flipped digit in a table digest: the rebuild stops matching.
    let cases = parse(&corrupt(&text, "case 7 ")).expect("still parses");
    assert_ne!(table_digest(&rebuild(&cases[7])), cases[7].digest);
}

#[test]
fn a_malformed_corpus_is_rejected() {
    let text = read_vectors(DIFF_PATH);
    let cases: [(&str, String); 6] = [
        (
            "unknown record",
            text.replacen("\ncase 0 ", "\ncases 0 ", 1),
        ),
        (
            "out-of-order case",
            text.replacen("\ncase 1 ", "\ncase 9 ", 1),
        ),
        (
            "a point after its result",
            format!("{text}point 99 0 {}\n", "00".repeat(32)),
        ),
        (
            "truncated case",
            text.replacen("\ncase 2 u16 2 ", "\ncase 2 u16 2\n#", 1),
        ),
        ("bad hex", text.replacen("\nresult 3 ", "\nresult 3 zz", 1)),
        (
            "a result with no case",
            format!("result 0 {}\n", "00".repeat(32)),
        ),
    ];
    for (what, bad) in cases {
        assert!(
            parse(&bad).is_err(),
            "the parser must reject a corpus with {what}"
        );
    }
    assert!(parse(&text).is_ok());
}
