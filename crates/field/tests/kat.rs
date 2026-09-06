//! Known-answer tests against the committed arkworks-generated vector file.
//!
//! The file is data, never inline literals, and is pinned by SHA-256. Refresh
//! it with `cargo run -p kat-gen`, then update `KAT_SHA256` deliberately.

mod common;

use common::{hex_to_32, sha256, to_hex};
use field::Fr;

const KAT_PATH: &str = "tests/vectors/fr_kats.txt";
const KAT_SHA256: &str = "cfb9db2443dc6d803104f7d89924235bcb2fa56cf6cfc04fc2e24cd31d0ce1df";

/// One parsed line: an operator and its whitespace-separated fields, the last
/// of which is the expected result.
struct Kat {
    line_no: usize,
    op: String,
    fields: Vec<String>,
}

fn read_kats() -> (String, Vec<Kat>) {
    let text = std::fs::read_to_string(KAT_PATH).expect("committed KAT file must be readable");
    let kats = text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|(i, l)| {
            let mut it = l.split_whitespace();
            let op = it
                .next()
                .expect("non-empty line has an operator")
                .to_string();
            Kat {
                line_no: i + 1,
                op,
                fields: it.map(|s| s.to_string()).collect(),
            }
        })
        .collect();
    (text, kats)
}

/// Parse canonical bytes into an `Fr`, refusing anything the wire form rejects.
fn field_element(s: &str) -> Result<Fr, String> {
    let bytes = hex_to_32(s)?;
    Fr::from_bytes(&bytes).ok_or_else(|| format!("KAT value {s} is not canonical"))
}

fn exponent(s: &str) -> Result<[u64; 4], String> {
    let bytes = hex_to_32(s)?;
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[8 * i..8 * i + 8]);
        limbs[i] = u64::from_le_bytes(w);
    }
    Ok(limbs)
}

/// Evaluate one vector with our implementation and compare. This is the single
/// place a KAT can fail, which is what the negative control exercises.
fn check(kat: &Kat) -> Result<(), String> {
    let arity_error = |want: usize| format!("{} takes {} fields", kat.op, want);
    let got: Option<Fr> = match kat.op.as_str() {
        "add" | "sub" | "mul" => {
            if kat.fields.len() != 3 {
                return Err(arity_error(3));
            }
            let a = field_element(&kat.fields[0])?;
            let b = field_element(&kat.fields[1])?;
            Some(match kat.op.as_str() {
                "add" => a + b,
                "sub" => a - b,
                _ => a * b,
            })
        }
        "square" => {
            if kat.fields.len() != 2 {
                return Err(arity_error(2));
            }
            Some(field_element(&kat.fields[0])?.square())
        }
        "inv" => {
            if kat.fields.len() != 2 {
                return Err(arity_error(2));
            }
            field_element(&kat.fields[0])?.inverse()
        }
        "pow" => {
            if kat.fields.len() != 3 {
                return Err(arity_error(3));
            }
            let a = field_element(&kat.fields[0])?;
            let e = exponent(&kat.fields[1])?;
            Some(a.pow(&e))
        }
        other => return Err(format!("unknown operator `{other}`")),
    };

    let want = kat.fields.last().expect("checked arity above");
    let got_hex = match &got {
        Some(x) => to_hex(&x.to_bytes()),
        None => "none".to_string(),
    };
    if &got_hex == want {
        Ok(())
    } else {
        Err(format!(
            "line {}: {} {:?}\n  expected {want}\n  got      {got_hex}",
            kat.line_no,
            kat.op,
            &kat.fields[..kat.fields.len() - 1]
        ))
    }
}

#[test]
fn sha256_matches_nist_vectors() {
    assert_eq!(
        to_hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        to_hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn kat_file_is_pinned_by_content() {
    let (text, _) = read_kats();
    assert_eq!(
        to_hex(&sha256(text.as_bytes())),
        KAT_SHA256,
        "{KAT_PATH} changed; regenerate with `cargo run -p kat-gen` and update KAT_SHA256"
    );
}

#[test]
fn kat_file_covers_every_operator() {
    let (_, kats) = read_kats();
    assert!(
        kats.len() >= 50,
        "need at least 50 vectors, have {}",
        kats.len()
    );
    for op in ["add", "sub", "mul", "square", "inv", "pow"] {
        let n = kats.iter().filter(|k| k.op == op).count();
        assert!(n > 0, "no vectors for `{op}`");
    }
}

#[test]
fn all_kats_match() {
    let (_, kats) = read_kats();
    let failures: Vec<String> = kats.iter().filter_map(|k| check(k).err()).collect();
    assert!(
        failures.is_empty(),
        "{} of {} vectors failed:\n{}",
        failures.len(),
        kats.len(),
        failures.join("\n")
    );
}

/// Negative control: the harness must reject a corrupted vector. Mutation is
/// local to this test; the committed file is untouched.
#[test]
fn corrupted_kats_are_rejected() {
    let (_, kats) = read_kats();

    for op in ["add", "sub", "mul", "square", "inv", "pow"] {
        let good = kats
            .iter()
            .find(|k| k.op == op)
            .expect("every operator appears");
        assert!(check(good).is_ok(), "unmodified `{op}` vector must pass");

        // Flip the low bit of the expected result's first byte.
        let mut bad = Kat {
            line_no: good.line_no,
            op: good.op.clone(),
            fields: good.fields.clone(),
        };
        let last = bad.fields.len() - 1;
        let expected = hex_to_32(&bad.fields[last]).unwrap_or([0u8; 32]);
        let mut flipped = expected;
        flipped[0] ^= 1;
        bad.fields[last] = to_hex(&flipped);
        assert!(
            check(&bad).is_err(),
            "corrupted `{op}` vector must fail the harness"
        );

        // A truncated field must be rejected too, not silently skipped.
        let mut short = Kat {
            line_no: good.line_no,
            op: good.op.clone(),
            fields: good.fields.clone(),
        };
        short.fields.pop();
        assert!(
            check(&short).is_err(),
            "malformed `{op}` vector must fail the harness"
        );
    }

    // A vector naming an operator we do not implement must fail, not pass.
    let bogus = Kat {
        line_no: 0,
        op: "nonsense".to_string(),
        fields: vec![to_hex(&[0u8; 32]), to_hex(&[0u8; 32])],
    };
    assert!(check(&bogus).is_err());
}
