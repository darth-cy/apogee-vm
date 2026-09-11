//! Test support specific to this crate: the vector-file reader and the
//! transcript-case script replayer. Hex and SHA-256 are shared with the other
//! test suites and live in `tools/test-support`. Test-only; never compiled into
//! the library.
#![allow(dead_code)]

use constants::transcript_tags;
use field::Fr;
use test_support::{hex_to_32, hex_to_bytes, sha256, to_hex};
use transcript::{Tag, Transcript};

/// Parse a committed field element, refusing anything the wire form rejects.
pub fn field_element(s: &str) -> Result<Fr, String> {
    let bytes = hex_to_32(s)?;
    Fr::from_bytes(&bytes).ok_or_else(|| format!("vector value {s} is not canonical"))
}

// ---------------------------------------------------------------------------
// Vector files
// ---------------------------------------------------------------------------

/// One non-comment, non-blank line, split on whitespace.
pub struct Line {
    pub no: usize,
    pub fields: Vec<String>,
}

/// The full text of a committed vector file.
pub fn read_vectors(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("committed vector file {path} must be readable: {e}"))
}

pub fn data_lines(text: &str) -> Vec<Line> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|(i, l)| Line {
            no: i + 1,
            fields: l.split_whitespace().map(|s| s.to_string()).collect(),
        })
        .collect()
}

pub fn assert_sha256(path: &str, text: &str, expected: &str) {
    let got = to_hex(&sha256(text.as_bytes()));
    assert_eq!(
        got, expected,
        "{path} changed. Regenerate it with \
         `cargo run --manifest-path tools/transcript-ref/Cargo.toml`, review the \
         diff, then update the pinned digest deliberately."
    );
}

// ---------------------------------------------------------------------------
// Transcript case scripts
//
// The grammar is the one `tools/transcript-ref` writes; see the header of
// `tests/vectors/transcript_cases.txt`.
// ---------------------------------------------------------------------------

pub enum Op {
    Observe(Fr),
    Sample(Fr),
    AppendScalar(Tag, Fr),
    AppendScalars(Tag, Vec<Fr>),
    AppendBytes(Tag, Vec<u8>),
    Challenge(Tag, Fr),
}

pub struct Case {
    pub name: String,
    pub ops: Vec<Op>,
}

/// Resolve a tag name through `constants`, so a renumbering there breaks the
/// replay instead of silently changing the absorbed stream.
pub fn tag_by_name(name: &str) -> Result<Tag, String> {
    match name {
        "PROTOCOL_SUITE" => Ok(transcript_tags::PROTOCOL_SUITE),
        "PUBLIC_INPUTS" => Ok(transcript_tags::PUBLIC_INPUTS),
        "COMMITMENT" => Ok(transcript_tags::COMMITMENT),
        "SUMCHECK_ROUND" => Ok(transcript_tags::SUMCHECK_ROUND),
        "SUMCHECK_CHALLENGE" => Ok(transcript_tags::SUMCHECK_CHALLENGE),
        "EVALUATION_CLAIM" => Ok(transcript_tags::EVALUATION_CLAIM),
        "PCS_OPENING" => Ok(transcript_tags::PCS_OPENING),
        "WITNESS_DIGEST" => Ok(transcript_tags::WITNESS_DIGEST),
        "SUMCHECK_FINAL_EVALS" => Ok(transcript_tags::SUMCHECK_FINAL_EVALS),
        "MERCURY_INSTANCE" => Ok(transcript_tags::MERCURY_INSTANCE),
        "MERCURY_ALPHA" => Ok(transcript_tags::MERCURY_ALPHA),
        "MERCURY_GAMMA" => Ok(transcript_tags::MERCURY_GAMMA),
        "MERCURY_Z" => Ok(transcript_tags::MERCURY_Z),
        "BDFG_BATCH" => Ok(transcript_tags::BDFG_BATCH),
        "BDFG_POINT" => Ok(transcript_tags::BDFG_POINT),
        "PAIRING_MERGE" => Ok(transcript_tags::PAIRING_MERGE),
        "MERCURY_BATCH" => Ok(transcript_tags::MERCURY_BATCH),
        "ACCUMULATOR_DIGEST" => Ok(transcript_tags::ACCUMULATOR_DIGEST),
        "ACCUMULATOR_MERGE" => Ok(transcript_tags::ACCUMULATOR_MERGE),
        "PUBLIC_INPUT_STREAM" => Ok(transcript_tags::PUBLIC_INPUT_STREAM),
        "PUBLIC_OUTPUT_STREAM" => Ok(transcript_tags::PUBLIC_OUTPUT_STREAM),
        "PROGRAM_IDENTITY" => Ok(transcript_tags::PROGRAM_IDENTITY),
        "VM_CONFIG" => Ok(transcript_tags::VM_CONFIG),
        "SHARD_COUNTS" => Ok(transcript_tags::SHARD_COUNTS),
        other => Err(format!("unknown tag name {other}")),
    }
}

fn need(f: &[String], i: usize, line: usize) -> Result<&str, String> {
    f.get(i)
        .map(|s| s.as_str())
        .ok_or_else(|| format!("line {line}: missing field {i}"))
}

pub fn parse_cases(text: &str) -> Result<Vec<Case>, String> {
    let mut cases: Vec<Case> = Vec::new();
    let mut open: Option<Case> = None;

    for line in data_lines(text) {
        let f = &line.fields;
        let head = need(f, 0, line.no)?;
        if head == "case" {
            if open.is_some() {
                return Err(format!("line {}: nested case", line.no));
            }
            open = Some(Case {
                name: need(f, 1, line.no)?.to_string(),
                ops: Vec::new(),
            });
            continue;
        }
        if head == "end" {
            cases.push(
                open.take()
                    .ok_or_else(|| format!("line {}: stray end", line.no))?,
            );
            continue;
        }

        let case = open
            .as_mut()
            .ok_or_else(|| format!("line {}: operation outside a case", line.no))?;
        let at = |i: usize| need(f, i, line.no);
        let op = match head {
            "observe" => Op::Observe(field_element(at(1)?)?),
            "sample" => Op::Sample(field_element(at(1)?)?),
            "append_scalar" => Op::AppendScalar(tag_by_name(at(1)?)?, field_element(at(2)?)?),
            "append_scalars" => {
                let tag = tag_by_name(at(1)?)?;
                let n: usize = at(2)?
                    .parse()
                    .map_err(|_| format!("line {}: bad scalar count", line.no))?;
                let mut xs = Vec::with_capacity(n);
                for i in 0..n {
                    xs.push(field_element(at(3 + i)?)?);
                }
                if f.len() != 3 + n {
                    return Err(format!("line {}: scalar count does not match", line.no));
                }
                Op::AppendScalars(tag, xs)
            }
            "append_bytes" => {
                let tag = tag_by_name(at(1)?)?;
                let n: usize = at(2)?
                    .parse()
                    .map_err(|_| format!("line {}: bad byte count", line.no))?;
                let body = at(3)?;
                let bytes = if body == "-" {
                    Vec::new()
                } else {
                    hex_to_bytes(body)?
                };
                if bytes.len() != n {
                    return Err(format!("line {}: byte count does not match", line.no));
                }
                Op::AppendBytes(tag, bytes)
            }
            "challenge" => Op::Challenge(tag_by_name(at(1)?)?, field_element(at(2)?)?),
            other => return Err(format!("line {}: unknown operation {other}", line.no)),
        };
        case.ops.push(op);
    }

    if open.is_some() {
        return Err("unterminated case".to_string());
    }
    Ok(cases)
}

/// Apply one operation, checking any value the file says it should produce.
/// Returns the produced value, if the operation produces one.
pub fn apply(t: &mut Transcript, op: &Op, where_: &str) -> Result<Option<Fr>, String> {
    let produced = match op {
        Op::Observe(x) => {
            t.observe(*x);
            None
        }
        Op::Sample(expected) => {
            let got = t.sample();
            if got != *expected {
                return Err(format!("{where_}: sample mismatch, got {got:?}"));
            }
            Some(got)
        }
        Op::AppendScalar(tag, x) => {
            t.append_scalar(*tag, *x);
            None
        }
        Op::AppendScalars(tag, xs) => {
            t.append_scalars(*tag, xs);
            None
        }
        Op::AppendBytes(tag, bytes) => {
            t.append_bytes(*tag, bytes);
            None
        }
        Op::Challenge(tag, expected) => {
            let got = t.challenge_scalar(*tag);
            if got != *expected {
                return Err(format!("{where_}: challenge mismatch, got {got:?}"));
            }
            Some(got)
        }
    };
    Ok(produced)
}

/// Replay a slice of a case, returning every value it produced.
pub fn run_ops(t: &mut Transcript, ops: &[Op], name: &str) -> Result<Vec<Fr>, String> {
    let mut out = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        if let Some(v) = apply(t, op, &format!("case {name} op {i}"))? {
            out.push(v);
        }
    }
    Ok(out)
}

/// Replay a whole case into a fresh transcript.
pub fn run_case(case: &Case) -> Result<Vec<Fr>, String> {
    let mut t = Transcript::new();
    run_ops(&mut t, &case.ops, &case.name)
}

pub fn case<'a>(cases: &'a [Case], name: &str) -> &'a Case {
    cases
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("case {name} must be in the committed vector file"))
}
