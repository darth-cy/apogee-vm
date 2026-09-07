//! The permutation, against the committed reference vectors.
//!
//! Nothing here is a self-oracle: every expected value in
//! `tests/vectors/poseidon2_*.txt` was produced by `tools/transcript-ref` from
//! the Plonky3 permutation and the HorizenLabs `RC3` constants.

mod common;

use common::{assert_sha256, data_lines, field_element, read_vectors};
use field::Fr;
use transcript::poseidon2_permute;

const PERM_PATH: &str = "tests/vectors/poseidon2_perm.txt";
const PERM_SHA256: &str = "905e08088b1b9e1bfe985e1447f2f373d66b3e97ce1750714d39940de65e1fee";

/// The stage's known-answer input.
const KAT_INPUT: [u64; 3] = [0, 1, 2];

/// The committed file opens with the `[0,1,2]` known-answer vector and seven
/// structured ones; every vector after those is random-input.
const STRUCTURED_PREFIX: usize = 8;

// ---------------------------------------------------------------------------
// Parsing. Every reader returns `Result` so the negative controls can assert
// that a corrupted file is actually rejected.
// ---------------------------------------------------------------------------

struct PermVector {
    input: [Fr; 3],
    output: [Fr; 3],
}

fn parse_perm(text: &str) -> Result<Vec<PermVector>, String> {
    let mut out = Vec::new();
    for line in data_lines(text) {
        let f = &line.fields;
        if f.len() != 7 || f[0] != "perm" {
            return Err(format!("line {}: not a perm line", line.no));
        }
        let mut v = [Fr::ZERO; 6];
        for (i, slot) in v.iter_mut().enumerate() {
            *slot = field_element(&f[1 + i]).map_err(|e| format!("line {}: {e}", line.no))?;
        }
        out.push(PermVector {
            input: [v[0], v[1], v[2]],
            output: [v[3], v[4], v[5]],
        });
    }
    Ok(out)
}

fn check_perm(text: &str) -> Result<usize, String> {
    let vectors = parse_perm(text)?;
    for (i, v) in vectors.iter().enumerate() {
        let mut state = v.input;
        poseidon2_permute(&mut state);
        if state != v.output {
            return Err(format!("permutation vector {i} does not match"));
        }
    }
    Ok(vectors.len())
}

/// Flip one bit of the `field`th whitespace-separated field of the first line
/// satisfying `pick`. The change stays inside the low byte of a little-endian
/// value, so the result is still a canonical field element and the failure is a
/// genuine mismatch rather than a parse error.
fn flip_a_bit(text: &str, pick: impl Fn(&str) -> bool, field: usize) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut done = false;
    for line in text.lines() {
        if !done && pick(line) {
            let mut fields: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
            let target = &fields[field];
            let head = target
                .chars()
                .next()
                .expect("the field to corrupt is non-empty");
            let flipped = head.to_digit(16).expect("hex nibble") ^ 1;
            fields[field] = format!("{flipped:x}{}", &target[1..]);
            out.push(fields.join(" "));
            done = true;
        } else {
            out.push(line.to_string());
        }
    }
    assert!(done, "nothing matched the corruption target");
    out.join("\n") + "\n"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Acceptance 1: the `[0, 1, 2]` known-answer vector, byte-exact from the file.
#[test]
fn permutation_kat() {
    let text = read_vectors(PERM_PATH);
    let vectors = parse_perm(&text).expect("the permutation vectors must parse");

    let kat = &vectors[0];
    assert_eq!(
        kat.input,
        KAT_INPUT.map(Fr::from_u64),
        "the first committed vector is the [0, 1, 2] known-answer test"
    );

    let mut state = kat.input;
    poseidon2_permute(&mut state);
    assert_eq!(state, kat.output);
}

/// Acceptance 2: every committed reference vector, with at least 100 of them.
#[test]
fn permutation_matches_every_reference_vector() {
    let text = read_vectors(PERM_PATH);
    assert_sha256(PERM_PATH, &text, PERM_SHA256);
    let checked = check_perm(&text).expect("every reference permutation vector must match");
    let random = checked - STRUCTURED_PREFIX;
    assert!(
        random >= 100,
        "the stage asks for at least 100 random-input vectors, found {random}"
    );
}

/// The committed set really covers 128 different inputs.
///
/// Without this, a generator whose input stream had collapsed — every vector the
/// same, or every input equal to its output — would still satisfy
/// `permutation_matches_every_reference_vector`, which only checks agreement.
/// The distinctness is asserted over *our* outputs, so it is a statement about
/// this crate and not only about the fixture.
#[test]
fn committed_vectors_cover_distinct_inputs() {
    let text = read_vectors(PERM_PATH);
    let vectors = parse_perm(&text).expect("the permutation vectors must parse");

    let mut ours: Vec<[u8; 32]> = Vec::with_capacity(vectors.len());
    for v in &vectors {
        let mut state = v.input;
        poseidon2_permute(&mut state);
        assert_ne!(state, v.input, "a vector is a fixed point");
        ours.push(state[0].to_bytes());
    }

    let before = ours.len();
    ours.sort_unstable();
    ours.dedup();
    assert_eq!(before, ours.len(), "two vectors share an output lane 0");
}

// --- negative controls -----------------------------------------------------

#[test]
fn corrupted_permutation_vectors_are_rejected() {
    let text = read_vectors(PERM_PATH);

    // A wrong expected output.
    let flipped_out = flip_a_bit(&text, |l| l.starts_with("perm "), 4);
    assert!(
        check_perm(&flipped_out).is_err(),
        "a flipped output slips by"
    );

    // A wrong input against a correct output fails just as loudly.
    let flipped_in = flip_a_bit(&text, |l| l.starts_with("perm "), 1);
    assert!(check_perm(&flipped_in).is_err(), "a flipped input slips by");

    let truncated: String = text
        .lines()
        .map(|l| {
            if l.starts_with("perm ") {
                let f: Vec<&str> = l.split_whitespace().take(6).collect();
                format!("{}\n", f.join(" "))
            } else {
                format!("{l}\n")
            }
        })
        .collect();
    assert!(check_perm(&truncated).is_err(), "a short line slips by");

    let renamed = text.replace("\nperm ", "\nperms ");
    assert!(
        check_perm(&renamed).is_err(),
        "an unknown operator slips by"
    );
}
