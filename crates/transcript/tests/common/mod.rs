//! Shared test support: hex, SHA-256 for pinning committed fixtures, the
//! vector-file reader, and the transcript-case script replayer.
//!
//! Test-only; never compiled into the library. SHA-256 is duplicated from
//! `crates/field/tests/common/mod.rs` rather than shared through a new crate —
//! master rule 11 wants fixtures pinned by hash, and duplication is cheaper than
//! an abstraction with two callers.
#![allow(dead_code)]

use constants::transcript_tags;
use field::Fr;
use transcript::{Tag, Transcript};

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

pub fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| format!("bad hex byte at {i}"))?;
    }
    Ok(out)
}

pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd hex length {}", s.len()));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| format!("bad hex byte at {i}"))
        })
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 * bytes.len());
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

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

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4). Pins committed fixture files by content.
// Checked against the two NIST vectors in `tests/poseidon2.rs`.
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}
