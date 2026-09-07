//! The permutation, against the committed reference vectors.
//!
//! Nothing here is a self-oracle: every expected value in
//! `tests/vectors/poseidon2_*.txt` was produced by `tools/transcript-ref` from
//! the Plonky3 permutation and the HorizenLabs `RC3` constants.

mod common;

use common::{assert_sha256, data_lines, field_element, hex_to_32, read_vectors, sha256, to_hex};
use constants::{POSEIDON2_RC3_INITIAL, POSEIDON2_RC3_INTERNAL, POSEIDON2_RC3_TERMINAL};
use field::Fr;
use transcript::poseidon2_permute;

const RC3_PATH: &str = "tests/vectors/poseidon2_rc3.txt";
const RC3_SHA256: &str = "40d9c19a629f6c7262a06730a78be8031975027c5f85b37c75681a05080e3d19";

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

fn limbs(bytes: [u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, limb) in out.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[8 * i..8 * i + 8]);
        *limb = u64::from_le_bytes(w);
    }
    out
}

/// The upstream 64x3 table, as canonical limbs.
fn parse_rc3(text: &str) -> Result<[[[u64; 4]; 3]; 64], String> {
    let mut table = [[[0u64; 4]; 3]; 64];
    let mut seen = [[false; 3]; 64];
    let lines = data_lines(text);
    if lines.len() != 64 * 3 {
        return Err(format!("expected 192 rc lines, got {}", lines.len()));
    }
    for line in lines {
        let f = &line.fields;
        if f.len() != 4 || f[0] != "rc" {
            return Err(format!("line {}: not an rc line", line.no));
        }
        let round: usize = f[1]
            .parse()
            .map_err(|_| format!("line {}: bad round", line.no))?;
        let lane: usize = f[2]
            .parse()
            .map_err(|_| format!("line {}: bad lane", line.no))?;
        if round >= 64 || lane >= 3 {
            return Err(format!("line {}: index out of range", line.no));
        }
        table[round][lane] = limbs(hex_to_32(&f[3])?);
        seen[round][lane] = true;
    }
    if seen.iter().flatten().any(|s| !s) {
        return Err("the rc3 table has a hole".to_string());
    }
    Ok(table)
}

/// Check the vendored constants against the upstream table.
fn check_rc3(text: &str) -> Result<(), String> {
    let upstream = parse_rc3(text)?;

    for round in 0..4 {
        for lane in 0..3 {
            if POSEIDON2_RC3_INITIAL[round][lane] != upstream[round][lane] {
                return Err(format!("initial round {round} lane {lane} differs"));
            }
            if POSEIDON2_RC3_TERMINAL[round][lane] != upstream[60 + round][lane] {
                return Err(format!("terminal round {round} lane {lane} differs"));
            }
        }
    }
    for round in 0..56 {
        if POSEIDON2_RC3_INTERNAL[round] != upstream[4 + round][0] {
            return Err(format!("internal round {round} differs"));
        }
        // Nothing was dropped: the lanes `constants` does not store are zero
        // upstream, so the partial rounds really do use lane 0 alone.
        for (lane, c) in upstream[4 + round].iter().enumerate().skip(1) {
            if *c != [0u64; 4] {
                return Err(format!(
                    "internal round {round} lane {lane} is not zero upstream"
                ));
            }
        }
    }
    Ok(())
}

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

/// The fixture pin is only as good as the hash behind it.
#[test]
fn sha256_matches_nist_vectors() {
    assert_eq!(
        to_hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        to_hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn vendored_rc3_matches_upstream() {
    let text = read_vectors(RC3_PATH);
    assert_sha256(RC3_PATH, &text, RC3_SHA256);
    check_rc3(&text).expect("the vendored round constants must match upstream RC3");
}

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
fn corrupted_rc3_is_rejected() {
    let text = read_vectors(RC3_PATH);

    let flipped = flip_a_bit(&text, |l| l.starts_with("rc 0 0 "), 3);
    assert!(check_rc3(&flipped).is_err(), "a flipped bit must be caught");

    // A partial round's unused lane must still be checked for zero.
    let mut nonzero = String::new();
    for line in text.lines() {
        if line.starts_with("rc 7 1 ") {
            nonzero.push_str(&format!("rc 7 1 {}\n", "01".repeat(32)));
        } else {
            nonzero.push_str(line);
            nonzero.push('\n');
        }
    }
    assert!(
        check_rc3(&nonzero).is_err(),
        "a nonzero unused lane must be caught"
    );

    let truncated: String = text
        .lines()
        .map(|l| {
            if l.starts_with("rc 3 2 ") {
                "rc 3 2\n".to_string()
            } else {
                format!("{l}\n")
            }
        })
        .collect();
    assert!(
        check_rc3(&truncated).is_err(),
        "a truncated line must be caught"
    );

    let dropped: String = text
        .lines()
        .filter(|l| !l.starts_with("rc 12 0 "))
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(
        check_rc3(&dropped).is_err(),
        "a missing constant must be caught"
    );
}

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
