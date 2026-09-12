//! Serialization, written here: the code a guest author ports first, because a
//! guest reads its input and commits its output through one.
//!
//! A dynamic document is generated from the seed, then carried through a
//! binary codec (tags, LEB128, zigzag, float bits, length prefixes), an
//! untrusted-input decoder fed systematic corruptions, a JSON writer and a
//! recursive-descent JSON parser, float text in both directions, base64 in all
//! four variants, hex, CSV, a bit-packer and a fixed-layout record. Each round
//! trips, and each section is either a fingerprint or short text naming what
//! came out, so a mismatch says which feature it was.
//!
//! What this leans on is what a port leans on: `core::fmt` (integers, floats
//! with `{:?}` and `{:e}`, padding, `{:04X}`), `str::parse` for `f64`, `i64`
//! and `u64`, `str::from_utf8` and its `Utf8Error`, `char::encode_utf16` and
//! `char::decode_utf16`, `String::from_utf8_lossy`, `BTreeMap` order,
//! `to_le_bytes`/`from_be_bytes`/`try_into`/`split_first_chunk`, 128-bit
//! shifts, and 64-bit bit operations that RV32 lowers to pairs of registers.

use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::hint::black_box;
use core::str::Utf8Error;

use crate::{Ctx, Digest, Fault, Rng};

pub const TAGS: (u8, u8) = (0x50, 0x5f);

pub const FAULT_UNWRAP_DECODE: u8 = 0x50;
pub const FAULT_EXPECT_JSON: u8 = 0x51;
pub const FAULT_ASSERT_BITS: u8 = 0x52;
pub const FAULT_TRUSTED_LENGTH: u8 = 0x53;

pub const FAULTS: &[Fault] = &[
    Fault {
        code: FAULT_UNWRAP_DECODE,
        what: "`Result::unwrap` on the binary decoder's error for a truncated encoding",
    },
    Fault {
        code: FAULT_EXPECT_JSON,
        what: "`Result::expect` on the JSON parser's error for a truncated document",
    },
    Fault {
        code: FAULT_ASSERT_BITS,
        what: "`assert_eq!` between a bit-packed field and its read-back with one bit flipped",
    },
    Fault {
        code: FAULT_TRUSTED_LENGTH,
        what: "a slice range taken from a length prefix that was never checked",
    },
];

/// The generated document's shape, as text.
pub const TAG_DOCUMENT: u8 = 0x50;
/// The binary encoding's length and fingerprint, after a checked round trip.
pub const TAG_BINARY: u8 = 0x51;
/// Hand-made hostile encodings, one decoder error per line.
pub const TAG_CRAFTED: u8 = 0x52;
/// Truncations, bit flips and appended junk, tallied by error kind.
pub const TAG_CORRUPT: u8 = 0x53;
/// The payload, decoded as one value and as a stream of values.
pub const TAG_PAYLOAD_BINARY: u8 = 0x54;
/// The document as JSON, after a checked round trip.
pub const TAG_JSON: u8 = 0x55;
/// Hand-made JSON, each parsed and written back or refused.
pub const TAG_JSON_CASES: u8 = 0x56;
/// The payload parsed as JSON, and escaped into a JSON string and back.
pub const TAG_JSON_PAYLOAD: u8 = 0x57;
/// Floats to text and back, shortest and scientific.
pub const TAG_FLOAT_TEXT: u8 = 0x58;
/// base64, standard and URL-safe, padded and not.
pub const TAG_BASE64: u8 = 0x59;
pub const TAG_HEX: u8 = 0x5a;
pub const TAG_CSV: u8 = 0x5b;
/// Fields of 1..=64 bits packed through a 128-bit accumulator.
pub const TAG_BITS: u8 = 0x5c;
/// A fixed-layout record, little- and big-endian.
pub const TAG_RECORD: u8 = 0x5d;

/// How deep either decoder nests before refusing: a hostile input must not
/// choose the depth of the recursion.
const MAX_DEPTH: u32 = 16;

/// The payload the per-byte passes read — escaping, encoding, CSV — which
/// grows with the scale. The untrusted decoders take the payload whole, and
/// stop at its first error.
fn cap(payload: &[u8], scale: u32) -> &[u8] {
    &payload[..payload.len().min(16 + 64 * scale as usize)]
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// A self-describing document: what `serde_json::Value` or CBOR's data model
/// is, with the integers split by sign so `u64::MAX` survives.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Bytes(Vec<u8>),
    Text(String),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

/// Equality with floats compared by bits, which is what a round trip owes:
/// `==` would call `-0.0` and `0.0` the same.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Float(x), Value::Float(y)) => x.to_bits() == y.to_bits(),
        (Value::List(x), Value::List(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same(x, y))
        }
        (Value::Map(x), Value::Map(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y)
                    .all(|((kx, vx), (ky, vy))| kx == ky && same(vx, vy))
        }
        _ => a == b,
    }
}

/// Characters a codec has to get right: quotes and backslashes, control
/// characters, DEL, two- three- and four-byte UTF-8, a line separator.
const CHARS: [char; 22] = [
    'a', 'b', 'Z', '0', '9', ' ', '_', '"', '\\', '/', '\n', '\t', '\u{1}', '\u{1f}', '\u{7f}',
    'é', 'ß', '€', '日', '🦀', '\u{2028}', '\u{fffd}',
];

fn gen_text(rng: &mut Rng, max: usize) -> String {
    let len = rng.index(max + 1);
    (0..len).map(|_| CHARS[rng.index(CHARS.len())]).collect()
}

fn gen_int(rng: &mut Rng) -> i64 {
    match rng.below(5) {
        0 => rng.below(200) as i64 - 100,
        1 => i64::MIN,
        2 => i64::MAX,
        3 => rng.next_u64() as i64,
        _ => (rng.next_u64() as i64) >> rng.below(64),
    }
}

fn gen_uint(rng: &mut Rng) -> u64 {
    match rng.below(5) {
        0 => rng.below(1000),
        1 => u64::MAX,
        2 => rng.next_u64(),
        3 => 1 << rng.below(64),
        _ => rng.next_u64() >> rng.below(64),
    }
}

/// A finite float, never NaN: NaN has no JSON form and no single bit pattern.
fn gen_f64(rng: &mut Rng) -> f64 {
    match rng.below(6) {
        0 => f64::from(rng.next_u32() as i32) / 64.0,
        1 => {
            let f = f64::from_bits(rng.next_u64());
            if f.is_finite() {
                f
            } else {
                // A zero exponent field: subnormal or zero, finite either way.
                f64::from_bits(rng.next_u64() >> 12)
            }
        }
        2 => f64::from_bits(rng.below(1 << 52)),
        3 => {
            if rng.chance(1, 2) {
                0.0
            } else {
                -0.0
            }
        }
        4 => rng.below(1_000_000) as f64 / 1000.0,
        _ => rng.next_u64() as f64 * 1e-300,
    }
}

/// A value at most `depth` containers deep, spending one unit of `budget` per
/// node so the document's size follows the scale and not the luck of the draw.
fn gen_value(rng: &mut Rng, depth: u32, budget: &mut u32) -> Value {
    *budget = budget.saturating_sub(1);
    if depth > 0 && *budget > 0 && rng.chance(1, 3) {
        let n = rng.index(6);
        if rng.chance(1, 2) {
            let mut items = Vec::new();
            for _ in 0..n {
                if *budget == 0 {
                    break;
                }
                items.push(gen_value(rng, depth - 1, budget));
            }
            return Value::List(items);
        }
        let mut map = BTreeMap::new();
        for _ in 0..n {
            if *budget == 0 {
                break;
            }
            let key = gen_text(rng, 5);
            map.insert(key, gen_value(rng, depth - 1, budget));
        }
        return Value::Map(map);
    }
    match rng.below(8) {
        0 => Value::Null,
        1 => Value::Bool(rng.chance(1, 2)),
        2 => Value::Int(gen_int(rng)),
        3 => Value::UInt(gen_uint(rng)),
        4 => Value::Float(gen_f64(rng)),
        5 => {
            let len = rng.index(13);
            Value::Bytes(rng.bytes(len))
        }
        _ => Value::Text(gen_text(rng, 8)),
    }
}

/// A map at the top, so no strict prefix of its encoding is a whole value, with
/// the payload's first bytes in it both raw and as lossy text.
fn document(rng: &mut Rng, nodes: u32, depth: u32, payload: &[u8]) -> Value {
    let head = &payload[..payload.len().min(12)];
    let mut map = BTreeMap::new();
    map.insert("payload".to_owned(), Value::Bytes(head.to_vec()));
    map.insert(
        "payload text".to_owned(),
        Value::Text(String::from_utf8_lossy(head).into_owned()),
    );
    let mut budget = nodes;
    let mut i = 0u32;
    while budget > 0 {
        map.insert(format!("k{i:02}"), gen_value(rng, depth, &mut budget));
        i += 1;
    }
    Value::Map(map)
}

/// Node counts by kind, the deepest nesting, and the bytes of text and blobs.
#[derive(Default)]
struct Shape {
    kinds: [u64; 9],
    depth: u32,
    text: u64,
    blobs: u64,
}

impl Shape {
    fn walk(&mut self, v: &Value, depth: u32) {
        self.depth = self.depth.max(depth);
        let kind = match v {
            Value::Null => 0,
            Value::Bool(_) => 1,
            Value::Int(_) => 2,
            Value::UInt(_) => 3,
            Value::Float(_) => 4,
            Value::Bytes(b) => {
                self.blobs += b.len() as u64;
                5
            }
            Value::Text(s) => {
                self.text += s.len() as u64;
                6
            }
            Value::List(items) => {
                items.iter().for_each(|item| self.walk(item, depth + 1));
                7
            }
            Value::Map(map) => {
                for (key, item) in map {
                    self.text += key.len() as u64;
                    self.walk(item, depth + 1);
                }
                8
            }
        };
        self.kinds[kind] += 1;
    }
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [&str; 9] = [
            "null", "bool", "int", "uint", "float", "bytes", "text", "list", "map",
        ];
        for (name, n) in NAMES.iter().zip(self.kinds) {
            write!(f, "{name} {n}, ")?;
        }
        write!(
            f,
            "depth {}, text {} B, blobs {} B",
            self.depth, self.text, self.blobs
        )
    }
}

/// A one-line description of a decoded value, for a section a person reads.
fn describe(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => format!("bool {b}"),
        Value::Int(i) => format!("int {i}"),
        Value::UInt(u) => format!("uint {u}"),
        Value::Float(x) => format!("float {x:?}"),
        Value::Bytes(b) => format!("{} bytes", b.len()),
        Value::Text(s) => {
            let head: String = s.chars().take(16).collect();
            format!("text {head:?} ({} chars)", s.chars().count())
        }
        Value::List(items) => format!("list of {}", items.len()),
        Value::Map(map) => format!("map of {}", map.len()),
    }
}

// ---------------------------------------------------------------------------
// The binary codec
// ---------------------------------------------------------------------------

const T_NULL: u8 = 0x00;
const T_FALSE: u8 = 0x01;
const T_TRUE: u8 = 0x02;
const T_INT: u8 = 0x03;
const T_UINT: u8 = 0x04;
const T_FLOAT: u8 = 0x05;
const T_BYTES: u8 = 0x06;
const T_TEXT: u8 = 0x07;
const T_LIST: u8 = 0x08;
const T_MAP: u8 = 0x09;

/// LEB128: seven bits a byte, low first, the high bit meaning "more".
fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Small magnitudes of either sign to small unsigned numbers: 0, -1, 1, -2...
fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}

fn put_len(out: &mut Vec<u8>, bytes: &[u8]) {
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// The canonical encoding: minimal varints and keys in order, so a decoder can
/// insist on it and every accepted input re-encodes to itself.
fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.push(T_NULL),
        Value::Bool(false) => out.push(T_FALSE),
        Value::Bool(true) => out.push(T_TRUE),
        Value::Int(i) => {
            out.push(T_INT);
            put_varint(out, zigzag(*i));
        }
        Value::UInt(u) => {
            out.push(T_UINT);
            put_varint(out, *u);
        }
        Value::Float(x) => {
            out.push(T_FLOAT);
            out.extend_from_slice(&x.to_bits().to_le_bytes());
        }
        Value::Bytes(b) => {
            out.push(T_BYTES);
            put_len(out, b);
        }
        Value::Text(s) => {
            out.push(T_TEXT);
            put_len(out, s.as_bytes());
        }
        Value::List(items) => {
            out.push(T_LIST);
            put_varint(out, items.len() as u64);
            items.iter().for_each(|item| encode_into(item, out));
        }
        Value::Map(map) => {
            out.push(T_MAP);
            put_varint(out, map.len() as u64);
            for (key, item) in map {
                put_len(out, key.as_bytes());
                encode_into(item, out);
            }
        }
    }
}

fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

/// Why bytes are not a canonical encoding. Every offset is into the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ends `need` bytes short of the item starting at `at`.
    Truncated {
        at: usize,
        need: u64,
    },
    BadTag {
        tag: u8,
        at: usize,
    },
    /// A varint with a redundant trailing zero group.
    Overlong {
        at: usize,
    },
    /// A varint past 64 bits.
    Overflow {
        at: usize,
    },
    InvalidUtf8 {
        at: usize,
        error: Utf8Error,
    },
    /// NaN has more than one bit pattern, so it has no canonical encoding.
    NotANumber {
        at: usize,
    },
    /// A map key not strictly after the one before it.
    KeyOrder {
        at: usize,
    },
    TooDeep {
        at: usize,
    },
    TrailingBytes {
        at: usize,
        extra: usize,
    },
}

impl DecodeError {
    fn at(&self) -> usize {
        match *self {
            DecodeError::Truncated { at, .. }
            | DecodeError::BadTag { at, .. }
            | DecodeError::Overlong { at }
            | DecodeError::Overflow { at }
            | DecodeError::InvalidUtf8 { at, .. }
            | DecodeError::NotANumber { at }
            | DecodeError::KeyOrder { at }
            | DecodeError::TooDeep { at }
            | DecodeError::TrailingBytes { at, .. } => at,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            DecodeError::Truncated { .. } => "Truncated",
            DecodeError::BadTag { .. } => "BadTag",
            DecodeError::Overlong { .. } => "Overlong",
            DecodeError::Overflow { .. } => "Overflow",
            DecodeError::InvalidUtf8 { .. } => "InvalidUtf8",
            DecodeError::NotANumber { .. } => "NotANumber",
            DecodeError::KeyOrder { .. } => "KeyOrder",
            DecodeError::TooDeep { .. } => "TooDeep",
            DecodeError::TrailingBytes { .. } => "TrailingBytes",
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated { at, need } => {
                write!(f, "truncated: {need} more bytes for the item at byte {at}")
            }
            DecodeError::BadTag { tag, at } => write!(f, "bad tag {tag:#04x} at byte {at}"),
            DecodeError::Overlong { at } => write!(f, "overlong varint at byte {at}"),
            DecodeError::Overflow { at } => write!(f, "varint past 64 bits at byte {at}"),
            DecodeError::InvalidUtf8 { at, error } => {
                write!(f, "invalid UTF-8 in the string at byte {at}: {error}")
            }
            DecodeError::NotANumber { at } => write!(f, "NaN at byte {at}"),
            DecodeError::KeyOrder { at } => write!(f, "map key out of order at byte {at}"),
            DecodeError::TooDeep { at } => {
                write!(f, "nested deeper than {MAX_DEPTH} at byte {at}")
            }
            DecodeError::TrailingBytes { at, extra } => {
                write!(f, "{extra} trailing bytes at byte {at}")
            }
        }
    }
}

/// A cursor over untrusted bytes. Nothing it reads sizes an allocation before
/// the bytes to back it are known to exist.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = *self.bytes.get(self.at).ok_or(DecodeError::Truncated {
            at: self.at,
            need: 1,
        })?;
        self.at += 1;
        Ok(b)
    }

    fn varint(&mut self) -> Result<u64, DecodeError> {
        let start = self.at;
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.byte()?;
            let low = u64::from(b & 0x7f);
            // The tenth group holds bit 63 alone.
            if shift == 63 && low > 1 {
                return Err(DecodeError::Overflow { at: start });
            }
            value |= low << shift;
            if b & 0x80 == 0 {
                if b == 0 && shift > 0 {
                    return Err(DecodeError::Overlong { at: start });
                }
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err(DecodeError::Overflow { at: start });
            }
        }
    }

    /// `n` bytes, compared as `u64` so a length past `usize` on the guest is
    /// an ordinary truncation rather than a conversion to fail.
    fn take(&mut self, n: u64) -> Result<&'a [u8], DecodeError> {
        let left = self.remaining() as u64;
        if n > left {
            return Err(DecodeError::Truncated {
                at: self.at,
                need: n - left,
            });
        }
        let bytes = &self.bytes[self.at..self.at + n as usize];
        self.at += bytes.len();
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        match self.bytes[self.at..].first_chunk::<N>() {
            Some(chunk) => {
                self.at += N;
                Ok(*chunk)
            }
            None => Err(DecodeError::Truncated {
                at: self.at,
                need: (N - self.remaining()) as u64,
            }),
        }
    }

    fn text(&mut self) -> Result<String, DecodeError> {
        let n = self.varint()?;
        let start = self.at;
        let bytes = self.take(n)?;
        match core::str::from_utf8(bytes) {
            Ok(s) => Ok(s.to_owned()),
            Err(error) => Err(DecodeError::InvalidUtf8 {
                at: start + error.valid_up_to(),
                error,
            }),
        }
    }

    /// An element count, refused before anything is allocated for it if the
    /// input cannot hold that many one-byte elements.
    fn count(&mut self) -> Result<usize, DecodeError> {
        let at = self.at;
        let n = self.varint()?;
        let left = self.remaining() as u64;
        if n > left {
            return Err(DecodeError::Truncated { at, need: n - left });
        }
        Ok(n as usize)
    }

    fn value(&mut self, depth: u32) -> Result<Value, DecodeError> {
        let at = self.at;
        if depth > MAX_DEPTH {
            return Err(DecodeError::TooDeep { at });
        }
        let tag = self.byte()?;
        Ok(match tag {
            T_NULL => Value::Null,
            T_FALSE => Value::Bool(false),
            T_TRUE => Value::Bool(true),
            T_INT => Value::Int(unzigzag(self.varint()?)),
            T_UINT => Value::UInt(self.varint()?),
            T_FLOAT => {
                let x = f64::from_bits(u64::from_le_bytes(self.array::<8>()?));
                if x.is_nan() {
                    return Err(DecodeError::NotANumber { at });
                }
                Value::Float(x)
            }
            T_BYTES => {
                let n = self.varint()?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            T_TEXT => Value::Text(self.text()?),
            T_LIST => {
                let n = self.count()?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Value::List(items)
            }
            T_MAP => {
                let n = self.count()?;
                let mut map = BTreeMap::new();
                for _ in 0..n {
                    let key_at = self.at;
                    let key = self.text()?;
                    if map.last_key_value().is_some_and(|(last, _)| *last >= key) {
                        return Err(DecodeError::KeyOrder { at: key_at });
                    }
                    let item = self.value(depth + 1)?;
                    map.insert(key, item);
                }
                Value::Map(map)
            }
            tag => return Err(DecodeError::BadTag { tag, at }),
        })
    }
}

/// Exactly one value, and nothing after it.
fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut reader = Reader { bytes, at: 0 };
    let value = reader.value(0)?;
    if reader.at != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            at: reader.at,
            extra: reader.remaining(),
        });
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// A JSON string, ASCII only: control characters, DEL and everything past
/// ASCII as `\uXXXX`, a character past the BMP as its UTF-16 surrogate pair.
fn json_string(s: &str, out: &mut String) -> fmt::Result {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    write!(out, "\\u{unit:04X}")?;
                }
            }
        }
    }
    out.push('"');
    Ok(())
}

/// JSON has one number type and no bytes, so a `UInt` is written as the
/// number it is and a blob as a base64 string; [`json_view`] is what reading
/// it back owes. A non-finite float is `null`, as `JSON.stringify` has it.
fn json_write(v: &Value, out: &mut String) -> fmt::Result {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => write!(out, "{i}")?,
        Value::UInt(u) => write!(out, "{u}")?,
        // `{:?}` is the shortest text that reads back to the same bits, and
        // always has a `.` or an `e`, so it reads back as a float.
        Value::Float(x) if x.is_finite() => write!(out, "{x:?}")?,
        Value::Float(_) => out.push_str("null"),
        Value::Bytes(b) => json_string(&base64_encode(b, &STANDARD, true), out)?,
        Value::Text(s) => json_string(s, out)?,
        Value::List(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_write(item, out)?;
            }
            out.push(']');
        }
        Value::Map(map) => {
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_string(key, out)?;
                out.push(':');
                json_write(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn to_json(v: &Value) -> String {
    let mut out = String::new();
    json_write(v, &mut out).expect("a String takes every write");
    out
}

/// What JSON can carry of a value: what parsing [`to_json`]'s output returns.
fn json_view(v: &Value) -> Value {
    match v {
        Value::UInt(u) => match i64::try_from(*u) {
            Ok(i) => Value::Int(i),
            Err(_) => Value::UInt(*u),
        },
        Value::Float(x) if !x.is_finite() => Value::Null,
        Value::Bytes(b) => Value::Text(base64_encode(b, &STANDARD, true)),
        Value::List(items) => Value::List(items.iter().map(json_view).collect()),
        Value::Map(map) => Value::Map(
            map.iter()
                .map(|(key, item)| (key.clone(), json_view(item)))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonErrorKind {
    End,
    Unexpected(u8),
    Escape,
    LoneSurrogate,
    Number,
    ControlInString,
    InvalidUtf8,
    TooDeep,
    Trailing,
}

/// Why text is not JSON, and the byte where the parser gave up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonError {
    pub at: usize,
    pub kind: JsonErrorKind,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at byte {}: ", self.at)?;
        match self.kind {
            JsonErrorKind::End => f.write_str("unexpected end of input"),
            JsonErrorKind::Unexpected(b) if b.is_ascii_graphic() => {
                write!(f, "unexpected {:?}", char::from(b))
            }
            JsonErrorKind::Unexpected(b) => write!(f, "unexpected byte {b:#04x}"),
            JsonErrorKind::Escape => f.write_str("bad escape"),
            JsonErrorKind::LoneSurrogate => f.write_str("unpaired surrogate"),
            JsonErrorKind::Number => f.write_str("malformed number"),
            JsonErrorKind::ControlInString => f.write_str("raw control character in a string"),
            JsonErrorKind::InvalidUtf8 => f.write_str("invalid UTF-8"),
            JsonErrorKind::TooDeep => write!(f, "nested deeper than {MAX_DEPTH}"),
            JsonErrorKind::Trailing => f.write_str("text after the value"),
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl JsonParser<'_> {
    fn fail<T>(&self, kind: JsonErrorKind) -> Result<T, JsonError> {
        Err(JsonError { at: self.at, kind })
    }

    /// The error for the byte at the cursor: whatever is there is not what the
    /// grammar wanted.
    fn unexpected<T>(&self) -> Result<T, JsonError> {
        match self.bytes.get(self.at) {
            Some(&b) => self.fail(JsonErrorKind::Unexpected(b)),
            None => self.fail(JsonErrorKind::End),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), JsonError> {
        if self.peek() != Some(b) {
            return self.unexpected();
        }
        self.at += 1;
        Ok(())
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, JsonError> {
        for &b in word {
            self.expect(b)?;
        }
        Ok(value)
    }

    fn value(&mut self, depth: u32) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return self.fail(JsonErrorKind::TooDeep);
        }
        match self.peek() {
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'"') => Ok(Value::Text(self.string()?)),
            Some(b'[') => self.list(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => self.unexpected(),
        }
    }

    fn list(&mut self, depth: u32) -> Result<Value, JsonError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::List(items));
        }
        loop {
            self.whitespace();
            items.push(self.value(depth + 1)?);
            self.whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::List(items));
                }
                _ => return self.unexpected(),
            }
        }
    }

    /// A repeated key keeps its last value, as most parsers do; `BTreeMap`
    /// makes that, and the order written back, independent of the input's.
    fn object(&mut self, depth: u32) -> Result<Value, JsonError> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        self.whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Map(map));
        }
        loop {
            self.whitespace();
            if self.peek() != Some(b'"') {
                return self.unexpected();
            }
            let key = self.string()?;
            self.whitespace();
            self.expect(b':')?;
            self.whitespace();
            let item = self.value(depth + 1)?;
            map.insert(key, item);
            self.whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Map(map));
                }
                _ => return self.unexpected(),
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        let mut unit = 0u16;
        for _ in 0..4 {
            let digit = self.peek().and_then(|b| char::from(b).to_digit(16));
            let Some(digit) = digit else {
                return self.fail(JsonErrorKind::Escape);
            };
            unit = (unit << 4) | digit as u16;
            self.at += 1;
        }
        Ok(unit)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            // A run of plain bytes. It ends only at ASCII, which is never
            // inside a multi-byte character, so each run is valid UTF-8 or
            // the input is not.
            let start = self.at;
            while matches!(self.peek(), Some(b) if b >= 0x20 && b != b'"' && b != b'\\') {
                self.at += 1;
            }
            match core::str::from_utf8(&self.bytes[start..self.at]) {
                Ok(run) => out.push_str(run),
                Err(e) => {
                    return Err(JsonError {
                        at: start + e.valid_up_to(),
                        kind: JsonErrorKind::InvalidUtf8,
                    })
                }
            }
            match self.peek() {
                None => return self.fail(JsonErrorKind::End),
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    self.escape(&mut out)?;
                }
                Some(_) => return self.fail(JsonErrorKind::ControlInString),
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), JsonError> {
        let at = self.at;
        let simple = match self.peek() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.at += 1;
                let mut units = [self.hex4()?, 0];
                let mut len = 1;
                if (0xd800..0xdc00).contains(&units[0]) {
                    // A high surrogate owes a `\u` low one straight after.
                    if self.bytes[self.at..].starts_with(b"\\u") {
                        self.at += 2;
                        units[1] = self.hex4()?;
                        len = 2;
                    }
                }
                for c in char::decode_utf16(units[..len].iter().copied()) {
                    match c {
                        Ok(c) => out.push(c),
                        Err(_) => {
                            return Err(JsonError {
                                at,
                                kind: JsonErrorKind::LoneSurrogate,
                            })
                        }
                    }
                }
                return Ok(());
            }
            _ => return self.fail(JsonErrorKind::Escape),
        };
        self.at += 1;
        out.push(simple);
        Ok(())
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at - start
    }

    /// RFC 8259's grammar checked here, the value left to `str::parse`: an
    /// integer is `i64` or `u64` when it fits and a float when it does not.
    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.at;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return self.fail(JsonErrorKind::Number),
        }
        let mut float = false;
        if self.peek() == Some(b'.') {
            self.at += 1;
            float = true;
            if self.digits() == 0 {
                return self.fail(JsonErrorKind::Number);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            float = true;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if self.digits() == 0 {
                return self.fail(JsonErrorKind::Number);
            }
        }
        let Ok(text) = core::str::from_utf8(&self.bytes[start..self.at]) else {
            return self.fail(JsonErrorKind::Number);
        };
        let whole = if float {
            None
        } else if negative {
            text.parse::<i64>().ok().map(Value::Int)
        } else {
            text.parse::<u64>().ok().map(|u| match i64::try_from(u) {
                Ok(i) => Value::Int(i),
                Err(_) => Value::UInt(u),
            })
        };
        match whole {
            Some(v) => Ok(v),
            None => match text.parse::<f64>() {
                Ok(x) => Ok(Value::Float(x)),
                Err(_) => self.fail(JsonErrorKind::Number),
            },
        }
    }
}

fn parse_json(bytes: &[u8]) -> Result<Value, JsonError> {
    let mut parser = JsonParser { bytes, at: 0 };
    parser.whitespace();
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.at != bytes.len() {
        return parser.fail(JsonErrorKind::Trailing);
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// base64 and hex
// ---------------------------------------------------------------------------

const STANDARD: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// RFC 4648 section 4 (`STANDARD`) or section 5 (`URL_SAFE`), padded to a
/// multiple of four with `=` or not padded at all.
fn base64_encode(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut group = [0u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let n = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        let chars = chunk.len() + 1;
        for i in 0..4 {
            if i < chars {
                out.push(char::from(alphabet[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base64Error {
    InvalidByte {
        at: usize,
        byte: u8,
    },
    InvalidLength {
        len: usize,
    },
    InvalidPadding {
        at: usize,
    },
    /// The last character carries bits no byte uses, and they are not zero:
    /// accepting it would give one byte string two encodings.
    TrailingBits {
        at: usize,
    },
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Base64Error::InvalidByte { at, byte } => {
                write!(f, "invalid byte {byte:#04x} at {at}")
            }
            Base64Error::InvalidLength { len } => write!(f, "invalid length {len}"),
            Base64Error::InvalidPadding { at } => write!(f, "invalid padding at {at}"),
            Base64Error::TrailingBits { at } => write!(f, "nonzero trailing bits at {at}"),
        }
    }
}

/// A character's value in `alphabet`: the two alphabets share their first 62.
fn sextet(c: u8, alphabet: &[u8; 64]) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        _ if c == alphabet[62] => Some(62),
        _ if c == alphabet[63] => Some(63),
        _ => None,
    }
}

/// Strict: padding exactly when `pad`, and canonical trailing bits.
fn base64_decode(text: &[u8], alphabet: &[u8; 64], pad: bool) -> Result<Vec<u8>, Base64Error> {
    let mut body = text;
    if pad {
        if !text.len().is_multiple_of(4) {
            return Err(Base64Error::InvalidLength { len: text.len() });
        }
        for _ in 0..2 {
            if let Some(rest) = body.strip_suffix(b"=") {
                body = rest;
            }
        }
    }
    if body.len() % 4 == 1 {
        return Err(Base64Error::InvalidLength { len: text.len() });
    }
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    for (k, chunk) in body.chunks(4).enumerate() {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let at = 4 * k + i;
            let Some(v) = sextet(c, alphabet) else {
                return Err(if c == b'=' {
                    Base64Error::InvalidPadding { at }
                } else {
                    Base64Error::InvalidByte { at, byte: c }
                });
            };
            n |= u32::from(v) << (18 - 6 * i);
        }
        let bytes = n.to_be_bytes();
        let keep = chunk.len() - 1;
        if bytes[1 + keep..].iter().any(|&b| b != 0) {
            return Err(Base64Error::TrailingBits { at: 4 * k + keep });
        }
        out.extend_from_slice(&bytes[1..1 + keep]);
    }
    Ok(out)
}

fn hex_encode(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 * data.len());
    for &b in data {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexError {
    OddLength { len: usize },
    InvalidDigit { at: usize, byte: u8 },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            HexError::OddLength { len } => write!(f, "odd length {len}"),
            HexError::InvalidDigit { at, byte } => {
                write!(f, "invalid digit {byte:#04x} at {at}")
            }
        }
    }
}

/// Either case.
fn hex_decode(text: &[u8]) -> Result<Vec<u8>, HexError> {
    if !text.len().is_multiple_of(2) {
        return Err(HexError::OddLength { len: text.len() });
    }
    let digit = |at: usize| match text[at] {
        b @ b'0'..=b'9' => Ok(b - b'0'),
        b @ b'a'..=b'f' => Ok(b - b'a' + 10),
        b @ b'A'..=b'F' => Ok(b - b'A' + 10),
        byte => Err(HexError::InvalidDigit { at, byte }),
    };
    (0..text.len() / 2)
        .map(|i| -> Result<u8, HexError> { Ok((digit(2 * i)? << 4) | digit(2 * i + 1)?) })
        .collect()
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// RFC 4180: a field holding a comma, a quote or a line break is quoted, and a
/// quote inside one is doubled. Every row ends in `\n`.
fn csv_write(rows: &[Vec<String>]) -> String {
    let mut out = String::new();
    for row in rows {
        for (i, field) in row.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            if field.contains([',', '"', '\n', '\r']) {
                out.push('"');
                out.push_str(&field.replace('"', "\"\""));
                out.push('"');
            } else {
                out.push_str(field);
            }
        }
        out.push('\n');
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsvErrorKind {
    UnterminatedQuote,
    QuoteInBareField,
    TextAfterQuote,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsvError {
    pub line: u32,
    pub at: usize,
    pub kind: CsvErrorKind,
}

impl fmt::Display for CsvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            CsvErrorKind::UnterminatedQuote => "unterminated quote",
            CsvErrorKind::QuoteInBareField => "quote in an unquoted field",
            CsvErrorKind::TextAfterQuote => "text after a closing quote",
        };
        write!(f, "line {}, byte {}: {what}", self.line, self.at)
    }
}

/// Rows of fields. `\n` and `\r\n` both end a row, a final line break adds no
/// row, and a blank line is a row of one empty field, which is what
/// [`csv_write`] writes for one.
fn csv_parse(text: &str) -> Result<Vec<Vec<String>>, CsvError> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut line = 1u32;
    let mut chars = text.char_indices().peekable();
    // Whether anything of the current row has been read, so a final line
    // break does not add an empty one.
    let mut pending = false;
    let fail = |line, at, kind| Err(CsvError { line, at, kind });
    while let Some((at, c)) = chars.next() {
        match c {
            '"' if field.is_empty() => {
                pending = true;
                let open = at;
                loop {
                    match chars.next() {
                        None => return fail(line, open, CsvErrorKind::UnterminatedQuote),
                        Some((_, '"')) => {
                            if chars.next_if(|&(_, c)| c == '"').is_some() {
                                field.push('"');
                            } else {
                                break;
                            }
                        }
                        Some((_, c)) => {
                            if c == '\n' {
                                line += 1;
                            }
                            field.push(c);
                        }
                    }
                }
                match chars.peek() {
                    None | Some((_, ',' | '\n' | '\r')) => {}
                    Some(&(at, _)) => return fail(line, at, CsvErrorKind::TextAfterQuote),
                }
            }
            '"' => return fail(line, at, CsvErrorKind::QuoteInBareField),
            ',' => {
                row.push(core::mem::take(&mut field));
                pending = true;
            }
            '\r' if chars.peek().is_some_and(|&(_, c)| c == '\n') => {}
            '\n' => {
                row.push(core::mem::take(&mut field));
                rows.push(core::mem::take(&mut row));
                pending = false;
                line += 1;
            }
            c => {
                field.push(c);
                pending = true;
            }
        }
    }
    if pending {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Bits and records
// ---------------------------------------------------------------------------

/// The low `width` bits, `width` in `1..=64`.
fn mask(width: u32) -> u64 {
    u64::MAX >> (64 - width)
}

/// Fields packed low bit first through a 128-bit accumulator, which holds a
/// whole 64-bit field on top of up to seven bits not yet flushed.
#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    acc: u128,
    bits: u32,
}

impl BitWriter {
    fn write(&mut self, value: u64, width: u32) {
        debug_assert!(
            value & !mask(width) == 0,
            "{value:#x} is wider than {width}"
        );
        self.acc |= u128::from(value) << self.bits;
        self.bits += width;
        while self.bits >= 8 {
            self.bytes.push(self.acc as u8);
            self.acc >>= 8;
            self.bits -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits > 0 {
            self.bytes.push(self.acc as u8);
        }
        self.bytes
    }
}

struct BitReader<'a> {
    bytes: &'a [u8],
    next: usize,
    acc: u128,
    bits: u32,
}

impl BitReader<'_> {
    /// `None` once the bytes run out: the reader's one error.
    fn read(&mut self, width: u32) -> Option<u64> {
        while self.bits < width {
            let byte = *self.bytes.get(self.next)?;
            self.acc |= u128::from(byte) << self.bits;
            self.next += 1;
            self.bits += 8;
        }
        let value = self.acc as u64 & mask(width);
        self.acc >>= width;
        self.bits -= width;
        Some(value)
    }
}

/// A field read as two's complement of its width.
fn sign_extend(value: u64, width: u32) -> i64 {
    let shift = 64 - width;
    ((value << shift) as i64) >> shift
}

/// A wire record of one fixed layout, the way a protocol header is: every
/// field at a fixed offset, in both byte orders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    kind: u8,
    flags: u16,
    id: u32,
    stamp: u64,
    delta: i64,
    small: i16,
    tag: [u8; 6],
    live: bool,
}

const RECORD_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordError {
    Kind(u8),
    Bool(u8),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::Kind(k) => write!(f, "kind {k} is not below 8"),
            RecordError::Bool(b) => write!(f, "live byte {b:#04x} is not 0 or 1"),
        }
    }
}

/// The front `N` bytes of `rest`, advancing it.
fn front<const N: usize>(rest: &mut &[u8]) -> [u8; N] {
    let (head, tail) = rest
        .split_first_chunk::<N>()
        .expect("a record is RECORD_LEN bytes");
    *rest = tail;
    *head
}

impl Record {
    fn generate(rng: &mut Rng) -> Record {
        let mut tag = [0u8; 6];
        rng.fill(&mut tag);
        Record {
            kind: rng.below(8) as u8,
            flags: rng.next_u32() as u16,
            id: rng.next_u32(),
            stamp: rng.next_u64(),
            delta: gen_int(rng),
            small: rng.next_u32() as i16,
            tag,
            live: rng.chance(1, 2),
        }
    }

    fn to_le(self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[0] = self.kind;
        out[1..3].copy_from_slice(&self.flags.to_le_bytes());
        out[3..7].copy_from_slice(&self.id.to_le_bytes());
        out[7..15].copy_from_slice(&self.stamp.to_le_bytes());
        out[15..23].copy_from_slice(&self.delta.to_le_bytes());
        out[23..25].copy_from_slice(&self.small.to_le_bytes());
        out[25..31].copy_from_slice(&self.tag);
        out[31] = u8::from(self.live);
        out
    }

    fn to_be(self) -> [u8; RECORD_LEN] {
        let mut out = Vec::with_capacity(RECORD_LEN);
        out.push(self.kind);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.stamp.to_be_bytes());
        out.extend_from_slice(&self.delta.to_be_bytes());
        out.extend_from_slice(&self.small.to_be_bytes());
        out.extend_from_slice(&self.tag);
        out.push(u8::from(self.live));
        out.try_into().expect("the fields add up to RECORD_LEN")
    }

    fn check(kind: u8, live: u8) -> Result<(u8, bool), RecordError> {
        if kind >= 8 {
            return Err(RecordError::Kind(kind));
        }
        match live {
            0 => Ok((kind, false)),
            1 => Ok((kind, true)),
            b => Err(RecordError::Bool(b)),
        }
    }

    fn from_le(bytes: &[u8; RECORD_LEN]) -> Result<Record, RecordError> {
        let mut rest = &bytes[..];
        let [kind] = front::<1>(&mut rest);
        let flags = u16::from_le_bytes(front(&mut rest));
        let id = u32::from_le_bytes(front(&mut rest));
        let stamp = u64::from_le_bytes(front(&mut rest));
        let delta = i64::from_le_bytes(front(&mut rest));
        let small = i16::from_le_bytes(front(&mut rest));
        let tag = front::<6>(&mut rest);
        let [live] = front::<1>(&mut rest);
        let (kind, live) = Record::check(kind, live)?;
        Ok(Record {
            kind,
            flags,
            id,
            stamp,
            delta,
            small,
            tag,
            live,
        })
    }

    fn from_be(bytes: &[u8; RECORD_LEN]) -> Result<Record, RecordError> {
        let field = |at: usize, len: usize| &bytes[at..at + len];
        let (kind, live) = Record::check(bytes[0], bytes[31])?;
        Ok(Record {
            kind,
            flags: u16::from_be_bytes(field(1, 2).try_into().expect("2 bytes")),
            id: u32::from_be_bytes(field(3, 4).try_into().expect("4 bytes")),
            stamp: u64::from_be_bytes(field(7, 8).try_into().expect("8 bytes")),
            delta: i64::from_be_bytes(field(15, 8).try_into().expect("8 bytes")),
            small: i16::from_be_bytes(field(23, 2).try_into().expect("2 bytes")),
            tag: field(25, 6).try_into().expect("6 bytes"),
            live,
        })
    }
}

// ---------------------------------------------------------------------------
// The workload
// ---------------------------------------------------------------------------

pub fn run(cx: &mut Ctx) {
    let scale = cx.scale();
    let payload = cx.payload();
    let doc = document(cx.rng(), 2 + 5 * scale, 1 + scale / 4, payload);
    // The corruption sweeps decode once per trial, so they take a small
    // document of their own rather than the scaled one.
    let small = document(cx.rng(), 1, 2, b"");

    let mut shape = Shape::default();
    shape.walk(&doc, 0);
    cx.section(TAG_DOCUMENT, shape.to_string().as_bytes());

    binary(cx, &doc);
    crafted(cx);
    corrupt(cx, &small);
    payload_binary(cx, payload);
    json(cx, &doc);
    json_cases(cx, &small);
    json_payload(cx, payload);
    float_text(cx);
    base64(cx, payload);
    hex(cx, payload);
    csv(cx, payload);
    bits(cx);
    records(cx, payload);
}

/// `n` of `len` hand-made cases, consecutive from a drawn start. At opt-level
/// 0 each case costs thousands of cycles, so one run takes a few and the
/// corpus's many seeds take them all.
fn picks(rng: &mut Rng, len: usize, n: usize) -> Vec<usize> {
    let start = rng.index(len);
    (0..n.min(len)).map(|i| (start + i) % len).collect()
}

fn fnv(bytes: &[u8]) -> u64 {
    Digest::new().bytes(bytes).finish()
}

fn binary(cx: &mut Ctx, doc: &Value) {
    let enc = encode(doc);
    match decode(&enc) {
        Ok(back) => {
            assert!(
                same(&back, doc),
                "the binary round trip changed the document"
            );
            assert!(
                encode(&back) == enc,
                "the decoded document re-encodes differently"
            );
        }
        Err(e) => panic!("the document's own encoding does not decode: {e}"),
    }
    let line = format!("{} bytes, fnv {:016x}", enc.len(), fnv(&enc));
    cx.section(TAG_BINARY, line.as_bytes());

    if cx.fault(FAULT_UNWRAP_DECODE) {
        // A strict prefix of a map's encoding is never a whole value.
        let cut = black_box(cx.rng().index(enc.len()));
        let v = decode(&enc[..cut]).unwrap();
        cx.section(TAG_BINARY, describe(&v).as_bytes());
    }
}

fn outcome(result: Result<Value, DecodeError>) -> String {
    match result {
        Ok(v) => format!("ok {}", describe(&v)),
        Err(e) => e.to_string(),
    }
}

/// One hostile input per way a decoder can be lied to, and three it must
/// accept at the edges of the integer and float encodings.
fn crafted(cx: &mut Ctx) {
    let mut deep = Vec::new();
    for _ in 0..20 {
        deep.extend_from_slice(&[T_LIST, 1]);
    }
    deep.push(T_NULL);
    let mut min_int = alloc::vec![T_INT];
    put_varint(&mut min_int, zigzag(i64::MIN));
    let ones = [0xff; 9];
    let cases: [(&str, Vec<u8>); 18] = [
        ("empty", Vec::new()),
        ("bad tag", alloc::vec![0x0b]),
        ("overlong varint", alloc::vec![T_UINT, 0x80, 0x00]),
        ("u64::MAX", [&[T_UINT][..], &ones, &[0x01]].concat()),
        ("bit 64", [&[T_UINT][..], &ones, &[0x02]].concat()),
        (
            "eleven groups",
            [&[T_UINT][..], &ones, &[0x81, 0x00]].concat(),
        ),
        ("i64::MIN", min_int),
        ("NaN", alloc::vec![T_FLOAT, 1, 0, 0, 0, 0, 0, 0xf8, 0x7f]),
        ("-0.0", alloc::vec![T_FLOAT, 0, 0, 0, 0, 0, 0, 0, 0x80]),
        ("bad UTF-8", alloc::vec![T_TEXT, 3, b'o', 0xc3, 0x28]),
        ("cut UTF-8", alloc::vec![T_TEXT, 2, 0xe6, 0x97]),
        (
            "2^40 bytes",
            alloc::vec![T_BYTES, 0x80, 0x80, 0x80, 0x80, 0x80, 0x20, 0],
        ),
        ("count 100", alloc::vec![T_LIST, 100, T_NULL]),
        (
            "keys b, a",
            alloc::vec![T_MAP, 2, 1, b'b', T_NULL, 1, b'a', T_NULL],
        ),
        (
            "keys a, a",
            alloc::vec![T_MAP, 2, 1, b'a', T_NULL, 1, b'a', T_TRUE],
        ),
        ("20 deep", deep),
        ("null, null", alloc::vec![T_NULL, T_NULL]),
        ("empty key", alloc::vec![T_MAP, 1, 0, T_LIST, 0]),
    ];
    let mut text = String::new();
    let n = 1 + cx.scale() as usize;
    for i in picks(cx.rng(), cases.len(), n) {
        let (what, bytes) = &cases[i];
        let result = decode(bytes);
        if let Ok(v) = &result {
            assert!(encode(v) == *bytes, "{what}: accepted, and not canonical");
        }
        text.push_str(&format!("{what}: {}\n", outcome(result)));
    }
    cx.section(TAG_CRAFTED, text.as_bytes());
}

/// Truncations, bit flips, deletions, insertions and appended junk: every
/// result is an error of a known kind, or a value that re-encodes to exactly
/// the corrupted bytes, which is what a canonical decoder promises.
fn corrupt(cx: &mut Ctx, small: &Value) {
    let enc = encode(small);
    let trials = 1 + cx.scale() / 4;
    let reshape = cx.scale() > 0;
    let mut tally: BTreeMap<(&str, &str), u32> = BTreeMap::new();
    let mut digest = Digest::new();
    let mut record = |how: &'static str, bytes: &[u8]| {
        let kind = match decode(bytes) {
            Ok(v) => {
                assert!(encode(&v) == bytes, "{how}: accepted, and not canonical");
                digest.bytes(bytes);
                "ok"
            }
            Err(e) => {
                digest.str(e.kind()).count(e.at());
                e.kind()
            }
        };
        *tally.entry((how, kind)).or_insert(0) += 1;
    };
    for _ in 0..trials {
        let rng = cx.rng();
        let at = rng.index(enc.len());
        record("truncate", &enc[..at]);

        let mut flipped = enc.clone();
        flipped[at] ^= 1 << rng.below(8);
        record("flip", &flipped);

        // The two that move every later byte cost a decode each and say the
        // least, so scale 0 -- which the instruction-by-instruction
        // differential runs -- leaves them out.
        if reshape {
            let mut shorter = enc.clone();
            shorter.remove(at);
            record("delete", &shorter);

            let mut longer = enc.clone();
            longer.insert(at, rng.next_u32() as u8);
            record("insert", &longer);
        }

        let mut junk = enc.clone();
        let extra = 1 + rng.index(4);
        junk.extend_from_slice(&rng.bytes(extra));
        record("append", &junk);
    }
    let mut text = format!("{} bytes, {trials} trials each\n", enc.len());
    for ((how, kind), n) in &tally {
        text.push_str(&format!("{how} {kind} {n}\n"));
    }
    text.push_str(&format!("fnv {:016x}", digest.finish()));
    cx.section(TAG_CORRUPT, text.as_bytes());
}

/// The payload as one value, then as a stream of values up to the first
/// error: every byte below four is a whole value, so most payloads yield some.
fn payload_binary(cx: &mut Ctx, payload: &[u8]) {
    let one = outcome(decode(payload));
    let mut reader = Reader {
        bytes: payload,
        at: 0,
    };
    let mut n = 0u32;
    let mut digest = Digest::new();
    let end = loop {
        if reader.remaining() == 0 {
            break "the end".to_string();
        }
        match reader.value(0) {
            Ok(v) => {
                n += 1;
                digest.bytes(&encode(&v));
            }
            Err(e) => break e.to_string(),
        }
    };
    let text = format!(
        "one value: {one}\nstream: {n} values, fnv {:016x}, then {end}",
        digest.finish()
    );
    cx.section(TAG_PAYLOAD_BINARY, text.as_bytes());
}

fn json(cx: &mut Ctx, doc: &Value) {
    let text = to_json(doc);
    let view = json_view(doc);
    match parse_json(text.as_bytes()) {
        Ok(back) => assert!(
            same(&back, &view),
            "the JSON round trip changed the document"
        ),
        Err(e) => panic!("the document's own JSON does not parse: {e}"),
    }
    let head: String = text.chars().take(96).collect();
    let line = format!(
        "{} bytes, fnv {:016x}: {head}",
        text.len(),
        fnv(text.as_bytes())
    );
    cx.section(TAG_JSON, line.as_bytes());
}

impl JsonErrorKind {
    fn name(&self) -> &'static str {
        match self {
            JsonErrorKind::End => "End",
            JsonErrorKind::Unexpected(_) => "Unexpected",
            JsonErrorKind::Escape => "Escape",
            JsonErrorKind::LoneSurrogate => "LoneSurrogate",
            JsonErrorKind::Number => "Number",
            JsonErrorKind::ControlInString => "ControlInString",
            JsonErrorKind::InvalidUtf8 => "InvalidUtf8",
            JsonErrorKind::TooDeep => "TooDeep",
            JsonErrorKind::Trailing => "Trailing",
        }
    }
}

fn json_outcome(bytes: &[u8]) -> String {
    match parse_json(bytes) {
        Ok(v) => format!("ok {}", to_json(&v)),
        Err(e) => format!("err {e}"),
    }
}

/// The grammar's corners by hand, then the small document's JSON with bytes
/// cut and overwritten.
fn json_cases(cx: &mut Ctx, small: &Value) {
    let deep = format!("{}{}", "[".repeat(20), "]".repeat(20));
    let cases: [&str; 22] = [
        r#"{"b":1,"a":[true,false,null],"a":2}"#,
        r#"  [ "🦀 café", "\"\\\/\b\f\n\r\t" ]  "#,
        r#""\ud800""#,
        r#""\udc00x""#,
        r#""\ud800A""#,
        "[1.5e3,-0.0,1E-7,0.1,5e-324,2.2250738585072011e-308,1.7976931348623157e308,1e400]",
        "[-9223372036854775808,9223372036854775808,18446744073709551615,\
         18446744073709551616,-9223372036854775809,-0]",
        "[01]",
        "[1.]",
        "[-]",
        "[.5]",
        "1e",
        r#"{"a" 1}"#,
        "[1,]",
        "tru",
        r#""\x""#,
        "\"a\u{1}b\"",
        "{} x",
        "",
        " \t\r\n ",
        "\"caf\u{e9} \u{1f980}\"",
        &deep,
    ];
    let mut text = String::new();
    let n = 1 + cx.scale() as usize;
    for i in picks(cx.rng(), cases.len(), n) {
        text.push_str(&format!("{i:2}: {}\n", json_outcome(cases[i].as_bytes())));
    }

    let json = to_json(small);
    let mut tally: BTreeMap<&str, u32> = BTreeMap::new();
    let mut digest = Digest::new();
    const JUNK: &[u8; 14] = b"{}[],:\"\\0-.e \x01";
    for _ in 0..1 + cx.scale() / 4 {
        let rng = cx.rng();
        let at = rng.index(json.len());
        let mut bytes = json.as_bytes()[..at].to_vec();
        if rng.chance(1, 2) {
            bytes.push(JUNK[rng.index(JUNK.len())]);
            bytes.extend_from_slice(&json.as_bytes()[at + 1..]);
        }
        let kind = match parse_json(&bytes) {
            Ok(v) => {
                digest.str(&to_json(&v));
                "ok"
            }
            Err(e) => {
                digest.str(e.kind.name()).count(e.at);
                e.kind.name()
            }
        };
        *tally.entry(kind).or_insert(0) += 1;
    }
    text.push_str(&format!("corrupted {} bytes:", json.len()));
    for (kind, n) in &tally {
        text.push_str(&format!(" {kind} {n}"));
    }
    text.push_str(&format!(", fnv {:016x}", digest.finish()));
    cx.section(TAG_JSON_CASES, text.as_bytes());

    if cx.fault(FAULT_EXPECT_JSON) {
        let cut = black_box(cx.rng().index(json.len()));
        let v = parse_json(&json.as_bytes()[..cut]).expect("the document's JSON parses");
        cx.section(TAG_JSON_CASES, to_json(&v).as_bytes());
    }
}

/// The payload as JSON, and as text: its UTF-8 verdict, and its lossy form
/// escaped into a JSON string that must read back as itself.
fn json_payload(cx: &mut Ctx, payload: &[u8]) {
    let parsed = json_outcome(payload);
    let parsed: String = parsed.chars().take(160).collect();
    let utf8 = match core::str::from_utf8(payload) {
        Ok(s) => format!("valid UTF-8, {} chars", s.chars().count()),
        Err(e) => e.to_string(),
    };
    let capped = cap(payload, cx.scale());
    let lossy = String::from_utf8_lossy(capped);
    let mut quoted = String::new();
    json_string(&lossy, &mut quoted).expect("a String takes every write");
    let back = parse_json(quoted.as_bytes());
    assert!(
        matches!(&back, Ok(Value::Text(t)) if *t == *lossy),
        "a JSON string does not read back as itself: {back:?}"
    );
    let text = format!(
        "json: {parsed}\nutf8: {utf8}\nstring: {} chars as {} bytes, fnv {:016x}",
        lossy.chars().count(),
        quoted.len(),
        fnv(quoted.as_bytes())
    );
    cx.section(TAG_JSON_PAYLOAD, text.as_bytes());
}

/// Floats to text and back. `{:?}` and `{:e}` are the shortest text that
/// reads back to the same bits, so both round trips are exact; the rest is
/// core's formatting and parsing on the guest's soft float, digested.
fn float_text(cx: &mut Ctx) {
    const SPECIAL: [f64; 14] = [
        0.0,
        -0.0,
        1.0,
        0.1,
        1.0 / 3.0,
        f64::MIN_POSITIVE,
        5e-324,
        f64::MAX,
        f64::EPSILON,
        1e21,
        1e-7,
        123456789.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ];
    /// Parses with a known hard case each: the exact decimal of 0.1, a tie
    /// that rounds to even, the input that once hung PHP, far too many
    /// digits, and an underflow and overflow.
    const HARD: [&str; 8] = [
        "0.1000000000000000055511151231257827021181583404541015625",
        "9007199254740993",
        "2.2250738585072011e-308",
        "1.00000000000000011102230246251565404236316680908203125",
        "123456789012345678901234567890123456789e-20",
        "1e-400",
        "-1e400",
        "0.000000000000000000000000000000000000000000001e45",
    ];
    let mut text = String::new();
    let n = 2 + cx.scale() as usize / 2;
    for i in picks(cx.rng(), SPECIAL.len(), n) {
        let x = SPECIAL[i];
        text.push_str(&format!("{x:?} {x:e}, "));
    }
    text.push('\n');
    let third = black_box(1.0f64) / 3.0;
    text.push_str(&format!(
        "{third:.3} {:+.2e} [{:>10.1}] [{:<8}] {:08.2} {} {}\n",
        12345.678, 2.25, 0.5, -6.02214, 1e21, third as f32
    ));
    let n = 1 + cx.scale() as usize / 4;
    for i in picks(cx.rng(), HARD.len(), n) {
        let hard = HARD[i];
        let x: f64 = hard.parse().expect("a well-formed float");
        let y: f32 = hard.parse().expect("a well-formed float");
        text.push_str(&format!("{x:?}/{y:?} "));
    }
    text.push('\n');

    let trials = 1 + cx.scale() / 2;
    let rng = cx.rng();
    let mut digest = Digest::new();
    for _ in 0..trials {
        let x = gen_f64(rng);
        let shortest = format!("{x:?}");
        let sci = format!("{x:e}");
        for s in [&shortest, &sci] {
            let back: f64 = s.parse().expect("a float's own text parses");
            assert!(back.to_bits() == x.to_bits(), "{s} reads back as {back:?}");
        }
        let narrow = x as f32;
        let narrow_text = format!("{narrow:?}");
        let back: f32 = narrow_text.parse().expect("a float's own text parses");
        assert!(
            back.to_bits() == narrow.to_bits(),
            "{narrow_text} reads back"
        );
        digest
            .str(&shortest)
            .str(&sci)
            .str(&narrow_text)
            .f32(narrow);

        // A decimal from parts: mantissa digits, a fraction and an exponent
        // spanning subnormals to overflow.
        let sign = if rng.chance(1, 2) { "-" } else { "" };
        let decimal = format!(
            "{sign}{}.{:06}e{}",
            rng.below(1 << 40),
            rng.below(1_000_000),
            rng.below(700) as i32 - 350
        );
        let wide: f64 = decimal.parse().expect("a well-formed float");
        let narrow: f32 = decimal.parse().expect("a well-formed float");
        digest.f64(wide).f32(narrow).str(&format!("{wide}"));

        // Conversions to and from integers, which saturate.
        let i = gen_int(rng);
        digest
            .i64(x as i64)
            .u64(x as u64)
            .i32(x as i32)
            .f64(i as f64)
            .f32(i as f32)
            .f64(gen_uint(rng) as f64);
    }
    text.push_str(&format!("random: fnv {:016x}", digest.finish()));
    cx.section(TAG_FLOAT_TEXT, text.as_bytes());
}

fn base64_outcome(text: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    match base64_decode(text, alphabet, pad) {
        Ok(bytes) => format!("ok {}", hex_encode(&bytes)),
        Err(e) => e.to_string(),
    }
}

fn base64(cx: &mut Ctx, payload: &[u8]) {
    let variants = [
        (&STANDARD, true),
        (&STANDARD, false),
        (&URL_SAFE, true),
        (&URL_SAFE, false),
    ];
    let mut text = String::new();
    const RFC: [&str; 7] = ["", "f", "fo", "foo", "foob", "fooba", "foobar"];
    let n = 2 + cx.scale() as usize / 2;
    for i in picks(cx.rng(), RFC.len(), n) {
        text.push_str(&base64_encode(RFC[i].as_bytes(), &STANDARD, true));
        text.push('|');
    }
    text.push('\n');
    for (alphabet, pad) in variants {
        text.push_str(&base64_encode(&[0xfb, 0xff, 0xbf, 0xe0], alphabet, pad));
        text.push(' ');
    }
    text.push('\n');

    let lengths = 4 + 2 * cx.scale() as usize;
    let rng = cx.rng();
    let first = rng.index(variants.len());
    let mut digest = Digest::new();
    for len in 0..lengths {
        // One variant per length, rotating, so every run meets all four and
        // the lengths below four meet every remainder mod 3.
        let (alphabet, pad) = variants[(first + len) % variants.len()];
        let data = rng.bytes(len);
        let enc = base64_encode(&data, alphabet, pad);
        let back = base64_decode(enc.as_bytes(), alphabet, pad);
        assert!(
            back.as_ref() == Ok(&data),
            "base64 of {data:?} reads back wrong"
        );
        // The other padding rule refuses it exactly when padding is owed.
        let other = base64_decode(enc.as_bytes(), alphabet, !pad);
        assert!(
            other.is_ok() == len.is_multiple_of(3),
            "base64 of {len} bytes under the other padding rule: {other:?}"
        );
        digest.str(&enc);
    }
    text.push_str(&format!("round trips: fnv {:016x}\n", digest.finish()));

    let bad: [&[u8]; 9] = [
        b"Zm9v!A==",
        b"Zm9",
        b"Zg=a",
        b"Zh==",
        b"Zm9v=",
        b"====",
        b"Zm_v",
        b"Zm9v\n",
        b"Zm8=",
    ];
    let n = 1 + cx.scale() as usize / 4;
    for i in picks(cx.rng(), bad.len(), n) {
        let input = bad[i];
        let shown = String::from_utf8_lossy(input);
        text.push_str(&format!(
            "{shown:?}: {}\n",
            base64_outcome(input, &STANDARD, true)
        ));
    }
    let capped = cap(payload, cx.scale());
    let enc = base64_encode(capped, &URL_SAFE, false);
    text.push_str(&format!(
        "payload: {}; url-safe unpadded {} chars, fnv {:016x}",
        base64_outcome(capped, &STANDARD, true)
            .chars()
            .take(80)
            .collect::<String>(),
        enc.len(),
        fnv(enc.as_bytes())
    ));
    cx.section(TAG_BASE64, text.as_bytes());
}

fn hex(cx: &mut Ctx, payload: &[u8]) {
    let data = {
        let len = 2 + cx.scale() as usize;
        cx.rng().bytes(len)
    };
    let enc = hex_encode(&data);
    let formatted: String = data.iter().map(|b| format!("{b:02x}")).collect();
    assert!(enc == formatted, "hex_encode and {{:02x}} disagree");
    let upper = enc.to_uppercase();
    assert!(
        hex_decode(upper.as_bytes()).as_ref() == Ok(&data),
        "upper-case hex reads back wrong"
    );
    let mut text = format!("{enc}\n");
    const CASES: [&str; 7] = ["", "0", "0g", "DEADbeef", "c0ffee", "zz", "12 34"];
    let n = 1 + cx.scale() as usize / 4;
    for i in picks(cx.rng(), CASES.len(), n) {
        let input = CASES[i];
        let result = match hex_decode(input.as_bytes()) {
            Ok(bytes) => format!("ok {bytes:?}"),
            Err(e) => e.to_string(),
        };
        text.push_str(&format!("{input:?}: {result}\n"));
    }
    let capped = cap(payload, cx.scale());
    let result = match hex_decode(capped) {
        Ok(bytes) => format!("ok, {} bytes", bytes.len()),
        Err(e) => e.to_string(),
    };
    let head = hex_encode(&capped[..capped.len().min(16)]);
    text.push_str(&format!("payload: {result}; begins {head}"));
    cx.section(TAG_HEX, text.as_bytes());
}

fn csv(cx: &mut Ctx, payload: &[u8]) {
    const FIELDS: [&str; 10] = [
        "plain",
        "",
        "a,b",
        "say \"hi\"",
        "two\nlines",
        " spaced ",
        "é日🦀",
        "cr\rlf",
        "\"",
        ",",
    ];
    let count = 1 + cx.scale() / 2;
    let rng = cx.rng();
    let rows: Vec<Vec<String>> = (0..count)
        .map(|_| {
            (0..1 + rng.index(4))
                .map(|_| {
                    if rng.chance(1, 4) {
                        gen_int(rng).to_string()
                    } else {
                        FIELDS[rng.index(FIELDS.len())].to_owned()
                    }
                })
                .collect()
        })
        .collect();
    let written = csv_write(&rows);
    assert_eq!(csv_parse(&written), Ok(rows.clone()), "CSV round trip");
    let fields: usize = rows.iter().map(Vec::len).sum();
    let mut text = format!(
        "{} rows, {fields} fields, {} bytes, fnv {:016x}\n",
        rows.len(),
        written.len(),
        fnv(written.as_bytes())
    );
    let cases = [
        "a,\"b\"\"c\",d\r\ne,f",
        "\"open",
        "a\"b",
        "\"a\"x",
        "x,\n\n,y",
        "",
        "\n",
        "last,no,newline",
        "\"multi\nline\",2\n3",
    ];
    let n = 1 + cx.scale() as usize / 4;
    for i in picks(cx.rng(), cases.len(), n) {
        let case = cases[i];
        let result = match csv_parse(case) {
            Ok(rows) => format!("{rows:?}"),
            Err(e) => e.to_string(),
        };
        text.push_str(&format!("{case:?}: {result}\n"));
    }
    let capped = cap(payload, cx.scale());
    let result = match csv_parse(&String::from_utf8_lossy(capped)) {
        Ok(rows) => format!(
            "{} rows, widest {}, fnv {:016x}",
            rows.len(),
            rows.iter().map(Vec::len).max().unwrap_or(0),
            fnv(csv_write(&rows).as_bytes())
        ),
        Err(e) => e.to_string(),
    };
    text.push_str(&format!("payload: {result}"));
    cx.section(TAG_CSV, text.as_bytes());
}

fn bits(cx: &mut Ctx) {
    let n = 2 + 4 * cx.scale() as usize;
    let rng = cx.rng();
    let fields: Vec<(u32, u64)> = (0..n)
        .map(|_| {
            let width = 1 + rng.below(64) as u32;
            (width, rng.next_u64() & mask(width))
        })
        .collect();
    let mut writer = BitWriter::default();
    for &(width, value) in &fields {
        writer.write(value, width);
    }
    let bytes = writer.finish();
    let total: u64 = fields.iter().map(|&(width, _)| u64::from(width)).sum();
    assert!(
        bytes.len() as u64 == total.div_ceil(8),
        "{total} bits packed wrong"
    );

    let mut reader = BitReader {
        bytes: &bytes,
        next: 0,
        acc: 0,
        bits: 0,
    };
    let back: Vec<u64> = fields
        .iter()
        .map(|&(width, _)| reader.read(width).expect("the writer wrote it"))
        .collect();
    assert!(
        back.iter().zip(&fields).all(|(b, (_, v))| b == v),
        "bit-packed fields read back wrong"
    );
    // A width the leftover bits sometimes satisfy and sometimes do not, so the
    // reader's `None` is a decision about this run's data rather than a
    // constant: eight bits never fit, and one often does.
    let past = reader.read(1 + (fields.len() as u32 % 8));

    // What RV32 does to a 64-bit value in pairs of registers: counts,
    // rotations, byte and bit reversal, and division by a small divisor.
    let mut digest = Digest::new();
    let mut prev = 1u64;
    for &(width, value) in &fields {
        let signed = sign_extend(value, width);
        digest
            .u8(width as u8)
            .u64(value)
            .i64(signed)
            .u32(value.leading_zeros())
            .u32(value.trailing_zeros())
            .u32(value.count_ones())
            .u64(value.rotate_left(width))
            .u64(value.swap_bytes())
            .u64(value.reverse_bits())
            .u64(value / u64::from(width))
            .u64(value % u64::from(width))
            .i64(
                signed
                    .checked_div(i64::from(width) - 33)
                    .unwrap_or(i64::MIN),
            )
            .i64(
                signed
                    .checked_rem(i64::from(width) - 33)
                    .unwrap_or(i64::MIN),
            )
            .i64(signed.wrapping_mul(0x9e37_79b9))
            .u128(u128::from(value) * u128::from(prev))
            .u64(value.abs_diff(prev));
        prev = value | 1;
    }
    let head: Vec<String> = fields
        .iter()
        .take(4)
        .map(|(width, value)| format!("{width}:{value:#x}"))
        .collect();
    let text = format!(
        "{n} fields, {total} bits in {} bytes, fnv {:016x} {:016x}; {}; past the end {past:?}",
        bytes.len(),
        fnv(&bytes),
        digest.finish(),
        head.join(" ")
    );
    cx.section(TAG_BITS, text.as_bytes());

    if cx.fault(FAULT_ASSERT_BITS) {
        let rng = cx.rng();
        let i = black_box(rng.index(n));
        let (width, value) = fields[i];
        let flip = 1u64 << rng.below(u64::from(width));
        assert_eq!(
            value,
            back[i] ^ flip,
            "bit-packed field {i} of width {width}"
        );
    }
}

fn records(cx: &mut Ctx, payload: &[u8]) {
    let n = 1 + cx.scale() as usize / 2;
    let rng = cx.rng();
    let records: Vec<Record> = (0..n).map(|_| Record::generate(rng)).collect();
    let mut digest = Digest::new();
    for &record in &records {
        let (le, be) = (record.to_le(), record.to_be());
        assert_eq!(Record::from_le(&le), Ok(record), "little-endian round trip");
        assert_eq!(Record::from_be(&be), Ok(record), "big-endian round trip");
        // Each multi-byte field is the other order's bytes reversed.
        for (at, len) in [(1, 2), (3, 4), (7, 8), (15, 8), (23, 2)] {
            let mut field = be[at..at + len].to_vec();
            field.reverse();
            assert!(
                le[at..at + len] == field[..],
                "field at {at} is not reversed"
            );
        }
        digest.bytes(&le).bytes(&be);
    }
    let mut ok = 0u32;
    let mut first_refusal = None;
    let chunks = payload.chunks_exact(RECORD_LEN);
    let left = chunks.remainder().len();
    for chunk in chunks {
        let bytes: &[u8; RECORD_LEN] = chunk.try_into().expect("chunks_exact");
        match Record::from_le(bytes) {
            Ok(record) => {
                ok += 1;
                digest.bytes(&record.to_be());
            }
            Err(e) => {
                first_refusal.get_or_insert(e);
            }
        }
    }
    let refusal = first_refusal.map_or("none".to_string(), |e| e.to_string());
    let text = format!(
        "{n} records, fnv {:016x}; first {}\npayload: {ok} read, first refusal {refusal}, \
         {left} bytes left over",
        digest.finish(),
        hex_encode(&records[0].to_le())
    );
    cx.section(TAG_RECORD, text.as_bytes());

    if cx.fault(FAULT_TRUSTED_LENGTH) {
        // A frame whose length prefix claims more than it holds, read by code
        // that believes it.
        let rng = cx.rng();
        let len = 8 + rng.index(24);
        let data = rng.bytes(len);
        let mut frame = (data.len() as u16).to_le_bytes().to_vec();
        frame.extend_from_slice(&data);
        let claimed = usize::from(u16::from_le_bytes([frame[0], frame[1]]));
        let claimed = claimed + black_box(1 + rng.index(8));
        let body = &frame[2..2 + claimed];
        cx.section(TAG_RECORD, body);
    }
}
