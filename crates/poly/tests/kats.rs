//! Acceptance 1 and 9: the committed fixture for one fixed seeded 10-variable
//! polynomial, replayed byte-exact, and the negative control that proves the
//! replay can fail.
//!
//! Every expected value in `poly_kats.txt` was produced by `tools/kat-gen`
//! against `ark-poly`: bind chains from `fix_variables`, evaluations from
//! `evaluate`, `eq` from the direct product formula. Nothing here is this
//! crate's own answer read back.

mod common;

use common::{
    assert_sha256, corrupt, data_lines, field_element, index, read_vectors, vertex, Line,
};
use field::Fr;
use poly::{eq_eval, eq_table, MultilinearPoly, PolyBacking};

const KATS_PATH: &str = "tests/vectors/poly_kats.txt";
const KATS_SHA256: &str = "816ef7fe908bca15d8a71e0728de92aedc3be6358e2653979dc8ba45de54542a";

// ---------------------------------------------------------------------------
// The committed file
// ---------------------------------------------------------------------------

struct Kats {
    num_vars: usize,
    /// The source table in its committed native width.
    source: Vec<u32>,
    challenges: Vec<Fr>,
    /// `bind[k - 1]` is the table after binding `challenges[..k]`.
    bind: Vec<Vec<Fr>>,
    points: Vec<Vec<Fr>>,
    results: Vec<Fr>,
    /// `eq[k]` is `eq_table(challenges[..k])`.
    eq: Vec<Vec<Fr>>,
}

/// Start or continue the block `k` of `blocks`, where `first` is the block's
/// lowest key. Blocks and the entries inside them must both arrive in order,
/// so a dropped or reordered line is a parse error rather than silent thinning.
fn block<'a>(
    blocks: &'a mut Vec<Vec<Fr>>,
    first: usize,
    k: usize,
    i: usize,
    line: &Line,
) -> Result<&'a mut Vec<Fr>, String> {
    if k < first {
        return Err(format!("line {}: block {k} is below {first}", line.no));
    }
    if i == 0 && k - first == blocks.len() {
        blocks.push(Vec::new());
    }
    if k - first + 1 != blocks.len() {
        return Err(format!("line {}: block {k} is out of order", line.no));
    }
    let cur = blocks
        .last_mut()
        .expect("the length check above found a block");
    if i != cur.len() {
        return Err(format!(
            "line {}: entry {i} arrived where {} was expected",
            line.no,
            cur.len()
        ));
    }
    Ok(cur)
}

fn parse(text: &str) -> Result<Kats, String> {
    let mut backing = String::new();
    let mut num_vars = 0usize;
    let mut source: Vec<u32> = Vec::new();
    let mut challenges: Vec<Fr> = Vec::new();
    let mut bind: Vec<Vec<Fr>> = Vec::new();
    let mut points: Vec<Vec<Fr>> = Vec::new();
    let mut results: Vec<Fr> = Vec::new();
    let mut eq: Vec<Vec<Fr>> = Vec::new();

    for line in data_lines(text) {
        let n = line.no;
        let want = |k: usize| -> Result<(), String> {
            if line.fields.len() == k {
                Ok(())
            } else {
                Err(format!(
                    "line {n}: expected {k} fields, got {}",
                    line.fields.len()
                ))
            }
        };
        match line.fields[0].as_str() {
            "source" => {
                want(3)?;
                backing = line.fields[1].clone();
                num_vars = index(&line, 2)?;
            }
            "value" => {
                want(3)?;
                if index(&line, 1)? != source.len() {
                    return Err(format!("line {n}: source values are out of order"));
                }
                let v = &line.fields[2];
                if v.len() != 8 {
                    return Err(format!("line {n}: a u32 is 8 hex digits, got {}", v.len()));
                }
                source.push(
                    u32::from_str_radix(v, 16).map_err(|_| format!("line {n}: bad u32 {v}"))?,
                );
            }
            "challenge" => {
                want(3)?;
                if index(&line, 1)? != challenges.len() {
                    return Err(format!("line {n}: challenges are out of order"));
                }
                challenges.push(field_element(&line.fields[2])?);
            }
            "bind" => {
                want(4)?;
                let (k, i) = (index(&line, 1)?, index(&line, 2)?);
                let value = field_element(&line.fields[3])?;
                block(&mut bind, 1, k, i, &line)?.push(value);
            }
            "point" => {
                want(4)?;
                let (case, i) = (index(&line, 1)?, index(&line, 2)?);
                if case != results.len() {
                    return Err(format!("line {n}: point block {case} is out of order"));
                }
                let value = field_element(&line.fields[3])?;
                block(&mut points, 0, case, i, &line)?.push(value);
            }
            "result" => {
                want(3)?;
                if index(&line, 1)? != results.len() || points.len() != results.len() + 1 {
                    return Err(format!("line {n}: results are out of order"));
                }
                results.push(field_element(&line.fields[2])?);
            }
            "eq" => {
                want(4)?;
                let (k, i) = (index(&line, 1)?, index(&line, 2)?);
                let value = field_element(&line.fields[3])?;
                block(&mut eq, 0, k, i, &line)?.push(value);
            }
            other => return Err(format!("line {n}: unknown record `{other}`")),
        }
    }

    if backing != "u32" {
        return Err(format!("the source backing must be u32, got `{backing}`"));
    }
    if num_vars == 0 || source.len() != 1usize << num_vars {
        return Err(format!(
            "a {num_vars}-variable source needs {} values, got {}",
            1usize << num_vars,
            source.len()
        ));
    }
    if challenges.len() != num_vars || bind.len() != num_vars {
        return Err(format!(
            "expected {num_vars} challenges and bind blocks, got {} and {}",
            challenges.len(),
            bind.len()
        ));
    }
    for (step, table) in bind.iter().enumerate() {
        if table.len() != 1usize << (num_vars - step - 1) {
            return Err(format!(
                "bind block {} has {} entries",
                step + 1,
                table.len()
            ));
        }
    }
    if points.len() != results.len() {
        return Err(format!(
            "{} point blocks against {} results",
            points.len(),
            results.len()
        ));
    }
    if points.iter().any(|p| p.len() != num_vars) {
        return Err("every point needs one coordinate per variable".to_string());
    }
    for (k, table) in eq.iter().enumerate() {
        if table.len() != 1usize << k {
            return Err(format!("eq block {k} has {} entries", table.len()));
        }
    }

    Ok(Kats {
        num_vars,
        source,
        challenges,
        bind,
        points,
        results,
        eq,
    })
}

fn load() -> Kats {
    let text = read_vectors(KATS_PATH);
    assert_sha256(KATS_PATH, &text, KATS_SHA256);
    parse(&text).expect("the committed fixture must parse")
}

fn source_poly(k: &Kats) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::U32(k.source.clone()))
}

// ---------------------------------------------------------------------------
// The three replays, written to return errors so the negative control can use
// exactly the code the passing tests use.
// ---------------------------------------------------------------------------

fn replay_bind_chain(k: &Kats) -> Result<(), String> {
    let mut p = source_poly(k);
    for (step, r) in k.challenges.iter().enumerate() {
        p.bind(*r);
        let expected = &k.bind[step];
        if p.num_vars() != k.num_vars - step - 1 || p.len() != expected.len() {
            return Err(format!(
                "after {} binds the poly has {} variables",
                step + 1,
                p.num_vars()
            ));
        }
        match p.backing() {
            PolyBacking::Fr(values) => {
                if values != expected {
                    return Err(format!("bind step {} disagrees with the fixture", step + 1));
                }
            }
            _ => return Err("bind must leave an Fr backing".to_string()),
        }
    }
    Ok(())
}

fn replay_evaluations(k: &Kats) -> Result<(), String> {
    let p = source_poly(k);
    for (case, point) in k.points.iter().enumerate() {
        if p.evaluate(point) != k.results[case] {
            return Err(format!("evaluation {case} disagrees with the fixture"));
        }
    }
    // Must-be-exact 3: reading never lifts.
    if p.backing() != &PolyBacking::U32(k.source.clone()) {
        return Err("evaluate mutated the backing".to_string());
    }
    Ok(())
}

fn replay_eq_tables(k: &Kats) -> Result<(), String> {
    for (prefix, expected) in k.eq.iter().enumerate() {
        if &eq_table(&k.challenges[..prefix]) != expected {
            return Err(format!("eq_table on the {prefix}-prefix disagrees"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance 1
// ---------------------------------------------------------------------------

/// A fixture that quietly shrank would satisfy every replay below without
/// checking anything, so its shape is asserted before its contents.
#[test]
fn the_committed_fixture_covers_what_it_claims() {
    let k = load();
    assert_eq!(k.num_vars, 10);
    assert_eq!(k.source.len(), 1024);
    assert_eq!(k.challenges.len(), 10);
    assert_eq!(k.bind.len(), 10);
    assert_eq!(k.results.len(), 20, "acceptance 1 asks for 20 points");
    assert_eq!(k.eq.len(), 7, "eq_table on prefixes 0..=6");
    assert!(
        k.source.iter().any(|v| *v > u32::MAX / 2),
        "a source table that fitted in a byte would not exercise u32"
    );
}

#[test]
fn the_committed_bind_chain_replays() {
    replay_bind_chain(&load()).expect("the committed bind chain must replay");
}

#[test]
fn the_committed_evaluations_replay() {
    replay_evaluations(&load()).expect("the committed evaluations must replay");
}

#[test]
fn the_committed_eq_tables_replay() {
    replay_eq_tables(&load()).expect("the committed eq tables must replay");
}

/// The two paths meet: binding all ten challenges leaves arkworks' committed
/// value, and `evaluate` at the same point must produce it too.
#[test]
fn the_full_bind_chain_is_the_committed_evaluation() {
    let k = load();
    let last = &k.bind[k.num_vars - 1];
    assert_eq!(last.len(), 1);
    assert_eq!(source_poly(&k).evaluate(&k.challenges), last[0]);
}

/// The fixture commits `eq_table` only on prefixes up to 6. At the full ten
/// variables the closed form is a stronger check than more committed hex:
/// every one of the 1024 entries, against `eq_eval` at that vertex.
#[test]
fn eq_table_matches_eq_eval_over_the_whole_cube() {
    let k = load();
    let table = eq_table(&k.challenges);
    assert_eq!(table.len(), 1024);
    for (y, entry) in table.iter().enumerate() {
        assert_eq!(
            *entry,
            eq_eval(&k.challenges, &vertex(y, k.num_vars)),
            "eq_table and eq_eval disagree at vertex {y}"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance 9: the negative control
// ---------------------------------------------------------------------------

/// One flipped digit anywhere in the file — in an expected value or in an input
/// the replay reads — has to be caught. The digest pin catches it first; these
/// assertions prove the replays themselves would too.
#[test]
fn a_corrupted_fixture_is_rejected() {
    let text = read_vectors(KATS_PATH);

    let flipped = corrupt(&text, "bind 1 0 ");
    assert_ne!(flipped, text);
    assert!(
        replay_bind_chain(&parse(&flipped).expect("still parses")).is_err(),
        "a flipped bind value must fail the replay"
    );

    let flipped = corrupt(&text, "result 0 ");
    assert!(replay_evaluations(&parse(&flipped).expect("still parses")).is_err());

    let flipped = corrupt(&text, "eq 3 2 ");
    assert!(replay_eq_tables(&parse(&flipped).expect("still parses")).is_err());

    // Corrupting an input, not an answer: every replay that reads it must fail.
    let flipped = corrupt(&text, "value 0 ");
    let k = parse(&flipped).expect("still parses");
    assert!(replay_bind_chain(&k).is_err());
    assert!(replay_evaluations(&k).is_err());

    let flipped = corrupt(&text, "challenge 0 ");
    let k = parse(&flipped).expect("still parses");
    assert!(replay_bind_chain(&k).is_err());
    assert!(replay_eq_tables(&k).is_err());

    // And the pin itself: the same file with one digit moved is a different file.
    assert_ne!(
        test_support::to_hex(&test_support::sha256(text.as_bytes())),
        test_support::to_hex(&test_support::sha256(
            corrupt(&text, "bind 1 0 ").as_bytes()
        ))
    );
}

/// The parser is a checker too, so it has to be able to fail.
#[test]
fn a_malformed_fixture_is_rejected() {
    let text = read_vectors(KATS_PATH);
    let cases: [(&str, String); 7] = [
        ("unknown record", text.replace("\nvalue 0 ", "\nvalues 0 ")),
        (
            "out-of-order value",
            text.replace("\nvalue 1 ", "\nvalue 7 "),
        ),
        (
            "out-of-order bind block",
            text.replace("\nbind 1 ", "\nbind 4 "),
        ),
        (
            "dropped value line",
            text.replacen("\nvalue 3 ", "\n#value 3 ", 1),
        ),
        (
            "truncated line",
            text.replacen("\nchallenge 0 ", "\nchallenge 0\n#", 1),
        ),
        ("bad hex", text.replacen("\nresult 0 ", "\nresult 0 zz", 1)),
        ("short u32", text.replacen("\nvalue 0 ", "\nvalue 0 00", 1)),
    ];
    for (what, bad) in cases {
        assert!(
            parse(&bad).is_err(),
            "the parser must reject a fixture with a {what}"
        );
    }
    // The control on the control: unmodified text parses.
    assert!(parse(&text).is_ok());
}
