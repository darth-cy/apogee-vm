//! Text: `str`, `String`, `char` and `core::fmt`, over the payload exactly as
//! fd 0 gave it and over generated multilingual text.
//!
//! Text is where a port meets the most library code it did not write: UTF-8
//! validation, core's Unicode tables behind every `is_*` and case mapping,
//! the pattern searchers, and the formatting machinery — integer, float and
//! padding code, `Debug` escaping — all of it compiled for a 32-bit target
//! with soft float. Each feature area is its own section, so a mismatch names
//! the area. A section is a short readable summary followed by a digest of
//! everything the area computed, so it is both complete and debuggable.
//!
//! Every length and index reaching the output is a count of this input's
//! bytes or chars, the same number on either target.
//!
//! # Cost
//!
//! The guest is an opt-level 0 build, with core's debug checks compiled into
//! every generic function it instantiates: one formatted argument costs about
//! a thousand cycles, one allocation as much, one char of a per-char pass a
//! few hundred. So a section is a list of probes, and a run takes every probe
//! only from [`FULL_SCALE`]; below it, `1 + scale` of them drawn by the rng.
//! The corpus runs many seeds, so it reaches every probe, and each section
//! shows the probes it ran as a hex mask. Per-char passes walk a prefix of
//! the text that grows with the scale, and long strings are fingerprinted by
//! [`fold`] rather than a byte at a time through [`Digest`].

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::char::ParseCharError;
use core::fmt::{self, Write};
use core::hint::black_box;
use core::num::{IntErrorKind, NonZeroU32, ParseFloatError, ParseIntError};
use core::ops::Bound;
use core::str::ParseBoolError;

use crate::{Ctx, Digest, Fault, Rng};

pub const TAGS: (u8, u8) = (0x30, 0x3f);

pub const TAG_UTF8: u8 = 0x30;
pub const TAG_CLASSES: u8 = 0x31;
pub const TAG_CASE: u8 = 0x32;
pub const TAG_CHAR: u8 = 0x33;
pub const TAG_SEARCH: u8 = 0x34;
pub const TAG_MUTATE: u8 = 0x35;
pub const TAG_PARSE_INT: u8 = 0x36;
pub const TAG_FLOAT: u8 = 0x37;
pub const TAG_FORMAT: u8 = 0x38;
pub const TAG_DEBUG: u8 = 0x39;
pub const TAG_DISPLAY: u8 = 0x3a;
pub const TAG_FREQUENCY: u8 = 0x3b;

pub const FAULT_CHAR_BOUNDARY: u8 = 0x30;
pub const FAULT_PARSE_UNWRAP: u8 = 0x31;
pub const FAULT_SURROGATE: u8 = 0x32;
pub const FAULT_REMOVE_PAST_END: u8 = 0x33;

pub const FAULTS: &[Fault] = &[
    Fault {
        code: FAULT_CHAR_BOUNDARY,
        what: "a `&str` sliced inside a multi-byte char",
    },
    Fault {
        code: FAULT_PARSE_UNWRAP,
        what: "`parse::<u8>()` of a word, unwrapped",
    },
    Fault {
        code: FAULT_SURROGATE,
        what: "`char::from_u32` of a surrogate, expected",
    },
    Fault {
        code: FAULT_REMOVE_PAST_END,
        what: "`String::remove` at the end of the string",
    },
];

/// The scale from which a section runs every one of its probes.
pub const FULL_SCALE: usize = 8;

/// The most payload any pass reads. The corpus's largest payload is 4 KiB;
/// the cap keeps the work bounded whatever fd 0 holds.
const PAYLOAD_CAP: usize = 4096;

/// Words the generator draws from, chosen for what they trip over: a char
/// whose uppercase is two chars (`ß`, `ŉ`), one whose lowercase is two
/// (`İ`), a ligature, final sigma, a titlecase digraph, a numeric char that
/// is not a digit, non-ASCII digits, a combining mark, an emoji with a skin
/// tone modifier, and tokens the parsers accept, refuse and overflow on.
const WORDS: [&str; 40] = [
    "the",
    "The",
    "THE",
    "fox",
    "naïve",
    "café",
    "Straße",
    "STRASSE",
    "straße",
    "İstanbul",
    "ıi",
    "ﬃx",
    "ΣΟΦΟΣ",
    "σοφός",
    "Ὀδυσσεύς",
    "ŉ",
    "Жук",
    "жук",
    "日本語",
    "中文",
    "🦀",
    "👍🏽",
    "e\u{301}",
    "ǅemal",
    "Ⅻ",
    "٣٤",
    "½",
    "42",
    "-17",
    "+300",
    "0042",
    "3.25",
    "1e-3",
    "0x1F",
    "true",
    "x",
    "a\"b",
    "back\\slash",
    "255",
    "65536",
];

/// What separates generated words: ASCII and Unicode whitespace (the
/// ideographic space and NBSP are whitespace to `split_whitespace` and not
/// to `split_ascii_whitespace`), CRLF for `lines`, and punctuation.
const SEPARATORS: [&str; 12] = [
    " ", " ", ", ", ". ", "\n", "\t", "  ", "\u{3000}", "\r\n", "; ", "\u{a0}", " — ",
];

/// Code point blocks the generator samples single chars from: ASCII, Latin-1,
/// combining marks, Greek, Cyrillic, CJK, emoji, and the whole supplementary
/// range, most of it unassigned — which the Unicode tables must answer too.
const BLOCKS: [(u32, u32); 8] = [
    (0x20, 0x7f),
    (0x80, 0x100),
    (0x300, 0x370),
    (0x370, 0x400),
    (0x400, 0x500),
    (0x4e00, 0xa000),
    (0x1f300, 0x1f650),
    (0x10000, 0x110000),
];

pub fn run(cx: &mut Ctx) {
    let payload = cx.payload();
    let payload = &payload[..payload.len().min(PAYLOAD_CAP)];
    let scale = cx.scale() as usize;
    // The UTF-8 section reads the payload's bytes. Every other section reads
    // one text, or a prefix of it: the payload's first chars, lossily
    // decoded, then generated words, both growing with the scale.
    let lossy = String::from_utf8_lossy(payload);
    let head = prefix(&lossy, 8 + 16 * scale);
    let generated = generate(cx.rng(), 3 + 5 * scale);
    let mut text = String::with_capacity(head.len() + 1 + generated.len());
    text.push_str(head);
    text.push('\n');
    text.push_str(&generated);

    utf8(cx, payload);
    classes(cx, &text, scale);
    case(cx, &text, scale);
    chars(cx, &text, scale);
    search(cx, &text, scale);
    mutate(cx, &generated, scale);
    parse_int(cx, &text, scale);
    float(cx, scale);
    format(cx, scale);
    debug(cx, &text, scale);
    display(cx, scale);
    frequency(cx, &text, scale);
}

/// Words and separators from [`WORDS`] and [`SEPARATORS`], with a char from
/// one of [`BLOCKS`] now and then. The first word is always non-ASCII, so the
/// text always has a char boundary that is not a byte boundary.
fn generate(rng: &mut Rng, words: usize) -> String {
    let mut out = String::new();
    out.push_str(WORDS[4 + rng.index(22)]);
    for _ in 0..words {
        out.push_str(SEPARATORS[rng.index(SEPARATORS.len())]);
        if rng.chance(1, 5) {
            let (lo, hi) = BLOCKS[rng.index(BLOCKS.len())];
            let c = char::from_u32(lo + rng.below(u64::from(hi - lo)) as u32);
            out.push(c.unwrap_or(char::REPLACEMENT_CHARACTER));
        }
        out.push_str(WORDS[rng.index(WORDS.len())]);
    }
    out
}

/// The first `n` chars of `s`, or all of it.
fn prefix(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

/// Which of a section's `len` probes this run takes, as a mask: every one
/// from [`FULL_SCALE`], else `1 + scale` drawn by the rng (a repeat draws
/// fewer).
fn choose(rng: &mut Rng, len: usize, scale: usize) -> u64 {
    assert!((1..=64).contains(&len), "a probe mask is a u64");
    if scale >= FULL_SCALE {
        return u64::MAX >> (64 - len);
    }
    let mut mask = 0u64;
    for _ in 0..1 + scale {
        mask |= 1 << rng.index(len);
    }
    mask
}

fn has(mask: u64, k: usize) -> bool {
    (mask >> k) & 1 == 1
}

/// One step of a 32-bit running fingerprint, for per-char loops.
fn mix(h: u32, x: u32) -> u32 {
    (h ^ x).wrapping_mul(0x0100_0193).rotate_left(5)
}

/// A string into `d` by its length, a rotate-xor of its 32-bit words and
/// their sum. Indexing and `as` casts rather than iterator adapters and
/// `from_le_bytes`, which at opt-level 0 are calls through core's debug
/// checks: this costs a tenth of `Digest::str`.
fn fold(d: &mut Digest, s: &str) {
    let bytes = s.as_bytes();
    let (mut h, mut sum) = (0x811c_9dc5u32, 0u64);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let w = (bytes[i] as u32)
            | ((bytes[i + 1] as u32) << 8)
            | ((bytes[i + 2] as u32) << 16)
            | ((bytes[i + 3] as u32) << 24);
        h = h.rotate_left(5) ^ w;
        sum += w as u64;
        i += 4;
    }
    while i < bytes.len() {
        h = h.rotate_left(5) ^ (bytes[i] as u32);
        sum += bytes[i] as u64;
        i += 1;
    }
    d.count(bytes.len()).u32(h).u64(sum);
}

/// `text`, then ` #` and the digest in hex, as one section.
fn emit(cx: &mut Ctx, tag: u8, mut text: String, digest: &Digest) {
    let _ = write!(text, " #{:016x}", digest.finish());
    cx.section(tag, text.as_bytes());
}

/// The payload as given: validation's `Ok` and `Err` paths, every error in
/// turn, `utf8_chunks` finding the same pieces, and the lossy decoding —
/// which borrows when it can.
fn utf8(cx: &mut Ctx, payload: &[u8]) {
    let mut d = Digest::new();
    let mut out = match core::str::from_utf8(payload) {
        Ok(s) => format!("ok bytes={} chars={}", s.len(), s.chars().count()),
        Err(e) => format!(
            "err valid_up_to={} error_len={:?} \"{e}\"",
            e.valid_up_to(),
            e.error_len()
        ),
    };

    // Walk the errors one at a time, as a decoder resynchronising would.
    let (mut rest, mut errors, mut valid, mut lens) = (payload, 0u32, 0u64, 0u32);
    let mut incomplete = false;
    loop {
        match core::str::from_utf8(rest) {
            Ok(s) => {
                valid += s.len() as u64;
                break;
            }
            Err(e) => {
                errors += 1;
                valid += e.valid_up_to() as u64;
                let Some(n) = e.error_len() else {
                    incomplete = true;
                    lens = mix(lens, (rest.len() - e.valid_up_to()) as u32);
                    break;
                };
                lens = mix(lens, n as u32);
                rest = &rest[e.valid_up_to() + n..];
            }
        }
    }

    // `utf8_chunks` must find the same pieces.
    let (mut chunks, mut invalid, mut valid_chunks, mut chunk_lens) = (0u32, 0u32, 0u64, 0u32);
    for chunk in payload.utf8_chunks() {
        chunks += 1;
        valid_chunks += chunk.valid().len() as u64;
        if !chunk.invalid().is_empty() {
            invalid += 1;
            chunk_lens = mix(chunk_lens, chunk.invalid().len() as u32);
        }
    }
    let agree = valid == valid_chunks && lens == chunk_lens && errors == invalid;

    let lossy = String::from_utf8_lossy(payload);
    let borrowed = matches!(lossy, Cow::Borrowed(_));
    let replaced = lossy.matches(char::REPLACEMENT_CHARACTER).count();
    fold(&mut d, &lossy);
    d.u32(errors).u64(valid).u32(lens).u32(chunks);

    // `String::from_utf8` agrees, and hands the bytes back on failure.
    let owned_ok = match (
        String::from_utf8(payload.to_vec()),
        core::str::from_utf8(payload),
    ) {
        (Ok(s), Ok(_)) => s.as_bytes() == payload,
        (Err(e), Err(first)) => e.utf8_error() == first && e.into_bytes() == payload,
        _ => false,
    };
    let _ = write!(
        out,
        "; errors={errors} incomplete={incomplete} chunks={chunks} agree={agree} \
         borrowed={borrowed} replaced={replaced} from_utf8={owned_ok}"
    );
    emit(cx, TAG_UTF8, out, &d);
}

/// Twelve classes of a char, one bit each.
fn class_bits(c: char) -> u32 {
    u32::from(c.is_alphabetic())
        | (u32::from(c.is_numeric()) << 1)
        | (u32::from(c.is_alphanumeric()) << 2)
        | (u32::from(c.is_whitespace()) << 3)
        | (u32::from(c.is_control()) << 4)
        | (u32::from(c.is_uppercase()) << 5)
        | (u32::from(c.is_lowercase()) << 6)
        | (u32::from(c.is_ascii()) << 7)
        | (u32::from(c.is_ascii_punctuation()) << 8)
        | (u32::from(c.is_ascii_graphic()) << 9)
        | (u32::from(c.is_ascii_hexdigit()) << 10)
        | (u32::from(c.is_digit(36)) << 11)
}

/// Char classes — each an `is_*` over core's Unicode tables — over a prefix
/// of the text and over code points drawn from the whole range, most of them
/// unassigned; the `char_indices`, reversed and byte walks fingerprinted.
fn classes(cx: &mut Ctx, text: &str, scale: usize) {
    let mut d = Digest::new();
    let text = prefix(text, 16 + 12 * scale);
    let (mut alpha, mut numeric, mut space, mut upper, mut lower, mut wide) =
        (0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
    let mut h = 0u32;
    for (i, c) in text.char_indices() {
        let bits = class_bits(c);
        alpha += bits & 1;
        numeric += (bits >> 1) & 1;
        space += (bits >> 3) & 1;
        upper += (bits >> 5) & 1;
        lower += (bits >> 6) & 1;
        wide += u32::from(c.len_utf8() > 1);
        h = mix(mix(h, i as u32), u32::from(c) | (bits << 21));
    }
    let mut reversed = 0u32;
    for c in text.chars().rev() {
        reversed = mix(reversed, u32::from(c));
    }
    fold(&mut d, text);
    d.u32(h).u32(reversed);

    let (mut sampled, mut hs) = (0u32, 0u32);
    for _ in 0..2 + 4 * scale {
        let c = char::from_u32(cx.rng().below(0x11_0000) as u32).unwrap_or('\u{d7ff}');
        let bits = class_bits(c);
        sampled += bits & 1;
        hs = mix(hs, u32::from(c) ^ (bits << 21));
    }
    d.u32(hs);

    let out = format!(
        "chars={} alpha={alpha} numeric={numeric} space={space} upper={upper} lower={lower} \
         multibyte={wide} sampled_alpha={sampled}",
        text.chars().count()
    );
    emit(cx, TAG_CLASSES, out, &d);
}

/// Case mapping: whole strings, where `ß` grows to `SS`, `İ` lowercases to
/// two chars and a word-final `Σ` lowercases to `ς`; single chars whose
/// mappings are several chars; and the ASCII-only family, which must leave
/// everything else alone.
fn case(cx: &mut Ctx, text: &str, scale: usize) {
    const FIXED: &str = "Straße İstanbul ﬃ ΣΟΦΟΣ ΌΣΟΣ. ǅemal ŉ ΐ";
    let mut d = Digest::new();
    let text = prefix(text, 16 + 12 * scale);
    let mask = choose(cx.rng(), 5, scale);
    let mut out = format!("probes={mask:x}");
    if has(mask, 0) {
        let upper = text.to_uppercase();
        let lower = text.to_lowercase();
        fold(&mut d, &upper);
        fold(&mut d, &lower);
        let _ = write!(
            out,
            " upper_bytes={} lower_bytes={}",
            upper.len(),
            lower.len()
        );
    }
    if has(mask, 1) {
        // Case mapping does not round-trip: `lower(upper(w))` is not
        // `lower(w)` for `ß` → `SS` → `ss`, nor for final sigma.
        let (mut unstable, mut the, mut strasse) = (0u32, 0u32, 0u32);
        for w in text.split_whitespace().take(1 + scale) {
            unstable += u32::from(w.to_uppercase().to_lowercase() != w.to_lowercase());
            the += u32::from(w.eq_ignore_ascii_case("the"));
            strasse += u32::from(w.eq_ignore_ascii_case("STRAßE"));
        }
        let _ = write!(out, " unstable={unstable} the={the} straße={strasse}");
    }
    if has(mask, 2) {
        let (mut longer_upper, mut longer_lower, mut h) = (0u32, 0u32, 0u32);
        for c in text.chars().take(8 + 6 * scale) {
            let (up, lo) = (c.to_uppercase(), c.to_lowercase());
            longer_upper += u32::from(up.len() > 1);
            longer_lower += u32::from(lo.len() > 1);
            for m in up.chain(lo) {
                h = mix(h, u32::from(m));
            }
            let ascii =
                (u32::from(c.to_ascii_uppercase()) << 16) ^ u32::from(c.to_ascii_lowercase());
            h = mix(h, ascii);
        }
        d.u32(h);
        let _ = write!(
            out,
            " multi_upper={longer_upper} multi_lower={longer_lower}"
        );
    }
    if has(mask, 3) {
        let mut ascii = text.to_ascii_uppercase();
        fold(&mut d, &ascii);
        ascii.make_ascii_lowercase();
        let lowered = ascii == text.to_ascii_lowercase();
        ascii.make_ascii_uppercase();
        let _ = write!(
            out,
            " ascii_ok={}",
            lowered && ascii.eq_ignore_ascii_case(text)
        );
    }
    if has(mask, 4) {
        let _ = write!(
            out,
            " | {} | {}",
            FIXED.to_uppercase(),
            FIXED.to_lowercase()
        );
    }
    emit(cx, TAG_CASE, out, &d);
}

/// `char` alone: digits in several radices, `from_u32` across the surrogate
/// gap and past `char::MAX`, the UTF-8 and UTF-16 encodings and their round
/// trips, a lone surrogate refused, the conversions' errors, and the three
/// escapes.
fn chars(cx: &mut Ctx, text: &str, scale: usize) {
    const RADICES: [u32; 5] = [2, 8, 10, 16, 36];
    const DIGITS: [char; 8] = ['0', '9', 'a', 'z', 'Z', '/', '٣', '９'];
    const EDGES: [u32; 17] = [
        0,
        0x7f,
        0x80,
        0x7ff,
        0x800,
        0xd7ff,
        0xd800,
        0xdbff,
        0xdc00,
        0xdfff,
        0xe000,
        0xfffd,
        0xffff,
        0x1_0000,
        0x10_ffff,
        0x11_0000,
        u32::MAX,
    ];
    const ESCAPED: &str = "a\"b\\c\nd\u{301}e\u{200b}🦀\u{7f}'\t\u{feff}ß";
    let mut d = Digest::new();
    let mask = choose(cx.rng(), 5, scale);
    let mut out = format!("probes={mask:x}");

    if has(mask, 0) {
        let (mut digits, mut h) = (0u32, 0u32);
        for c in text.chars().take(4 + 6 * scale).chain(DIGITS) {
            for r in RADICES {
                if let Some(v) = c.to_digit(r) {
                    digits += 1;
                    h = mix(h, v);
                }
            }
        }
        let mut from_digit = String::new();
        for r in RADICES {
            let n = [0, 9, 10, 35, 36, 39];
            from_digit.extend(n.into_iter().filter_map(|n| char::from_digit(n, r)));
            from_digit.push('|');
        }
        d.u32(h);
        fold(&mut d, &from_digit);
        let _ = write!(out, " digits={digits} from_digit={from_digit}");
    }

    if has(mask, 1) {
        let edges = choose(cx.rng(), EDGES.len(), scale);
        let mut values: Vec<u32> = (0..EDGES.len())
            .filter(|&k| has(edges, k))
            .map(|k| EDGES[k])
            .collect();
        for _ in 0..scale / 2 {
            let shift = cx.rng().below(22) as u32;
            values.push(cx.rng().next_u32() >> shift);
        }
        let (mut none, mut four, mut pairs, mut round) = (0u32, 0u32, 0u32, true);
        let mut escapes = String::new();
        let mut h = 0u32;
        for v in values {
            let Some(c) = char::from_u32(v) else {
                none += 1;
                round &= char::try_from(v).is_err();
                h = mix(h, v);
                continue;
            };
            let mut buf8 = [0u8; 4];
            let mut buf16 = [0u16; 2];
            let s = c.encode_utf8(&mut buf8);
            let u = c.encode_utf16(&mut buf16);
            four += u32::from(c.len_utf8() == 4);
            pairs += u32::from(c.len_utf16() == 2);
            round &= s.len() == c.len_utf8()
                && u.len() == c.len_utf16()
                && s.starts_with(c)
                && char::decode_utf16(u.iter().copied()).next() == Some(Ok(c))
                && char::try_from(v) == Ok(c);
            for w in u.iter() {
                h = mix(h, u32::from(*w));
            }
            let _ = write!(
                escapes,
                "{}{}{}",
                c.escape_debug(),
                c.escape_default(),
                c.escape_unicode()
            );
        }
        d.u32(h);
        fold(&mut d, &escapes);
        let _ = write!(
            out,
            " edges={edges:x} none={none} utf8_four={four} utf16_pairs={pairs} round={round}"
        );
    }

    // A surrogate the data chose: inserted into the text's UTF-16 below, and
    // the fault's operand.
    let lone = 0xd800 + cx.rng().below(0x800) as u16;
    if has(mask, 2) {
        // A valid sequence holds its surrogates in pairs, so one more always
        // leaves one unpaired.
        let units: Vec<u16> = prefix(text, 12 + 12 * scale).encode_utf16().collect();
        let back = String::from_utf16(&units);
        let utf16_ok = back.is_ok_and(|s| s.encode_utf16().eq(units.iter().copied()));
        let mut broken = units.clone();
        let at = cx.rng().index(broken.len() + 1);
        broken.insert(at, lone);
        let refused = String::from_utf16(&broken).map_err(|e| e.to_string());
        let lossy = String::from_utf16_lossy(&broken);
        let mut unpaired = 0u32;
        for r in char::decode_utf16(broken.iter().copied()) {
            if let Err(e) = r {
                unpaired += 1;
                d.u16(e.unpaired_surrogate());
            }
        }
        fold(&mut d, &lossy);
        let _ = write!(
            out,
            " utf16_text={utf16_ok} lone={refused:?} unpaired={unpaired}"
        );
    }
    if cx.fault(FAULT_SURROGATE) {
        let c = char::from_u32(black_box(u32::from(lone))).expect("a surrogate is not a char");
        d.u32(u32::from(c));
    }
    if has(mask, 3) {
        let pick = char::from_u32(0xc0 + cx.rng().below(0x100) as u32).unwrap_or('?');
        let _ = write!(
            out,
            " u8::try_from({pick:?})={:?} char::try_from(0xd800)={:?} char::from(0xff)={:?}",
            u8::try_from(pick).map_err(|e| e.to_string()),
            char::try_from(black_box(0xd800u32)).map_err(|e| e.to_string()),
            char::from(black_box(0xffu8)),
        );
    }
    if has(mask, 4) {
        let _ = write!(
            out,
            " | {} | {} | {}",
            ESCAPED.escape_debug(),
            ESCAPED.escape_default(),
            "ß🦀".escape_unicode(),
        );
    }
    emit(cx, TAG_CHAR, out, &d);
}

/// How many pieces an iterator of `&str` yields, and a fingerprint of their
/// lengths: the pieces are slices of one text, so their lengths in order say
/// where every cut fell.
fn pieces<'a>(it: impl Iterator<Item = &'a str>) -> (u32, u32) {
    let (mut n, mut h) = (0u32, 0u32);
    for p in it {
        n += 1;
        h = mix(h, p.len() as u32);
    }
    (n, h)
}

/// As [`pieces`], for `match_indices`: where each match is, and its length.
fn positions<'a>(it: impl Iterator<Item = (usize, &'a str)>) -> (u32, u32) {
    let (mut n, mut h) = (0u32, 0u32);
    for (i, m) in it {
        n += 1;
        h = mix(mix(h, i as u32), m.len() as u32);
    }
    (n, h)
}

/// The probes of [`search`].
const SEARCH_PROBES: usize = 25;

/// Searching and splitting with every kind of pattern — a char, a char array,
/// a closure, a `&str`, a `&String` — forwards and backwards; the trims,
/// strips and replacements; and slicing, at char boundaries `char_indices`
/// found and through `get` with ranges it must refuse.
fn search(cx: &mut Ctx, text: &str, scale: usize) {
    let mut d = Digest::new();
    let text = prefix(text, 24 + 12 * scale);
    let first = text.split_whitespace().next().unwrap_or("");
    let last = text.split_whitespace().next_back().unwrap_or("");
    let needle = String::from("ss");
    let mask = choose(cx.rng(), SEARCH_PROBES, scale);
    let mut counts: Vec<u32> = Vec::new();
    for k in 0..SEARCH_PROBES {
        if !has(mask, k) {
            continue;
        }
        let (n, h) = match k {
            0 => pieces(text.split(' ')),
            1 => pieces(text.rsplit(',')),
            2 => pieces(text.splitn(3, ' ')),
            3 => pieces(text.rsplitn(2, '.')),
            4 => pieces(text.split_terminator('\n')),
            5 => pieces(text.rsplit_terminator(';')),
            6 => pieces(text.split_whitespace()),
            7 => pieces(text.split_ascii_whitespace()),
            8 => pieces(text.lines()),
            9 => pieces(text.split_inclusive('\n')),
            10 => pieces(text.split([',', ';', '.'])),
            11 => pieces(text.split(|c: char| !c.is_alphanumeric())),
            12 => pieces(text.split("the")),
            13 => pieces(text.split(&needle)),
            14 => pieces(text.matches(char::is_numeric)),
            15 => pieces(text.rmatches("ß")),
            16 => positions(text.match_indices('e')),
            17 => positions(text.rmatch_indices(char::is_uppercase)),
            18 => {
                let finds = [
                    text.find('e'),
                    text.rfind('e'),
                    text.find("Straße"),
                    text.rfind(char::is_numeric),
                    text.find(['日', '🦀']),
                    text.find(needle.as_str()),
                    text.rfind(|c: char| c > '\u{ff}'),
                ];
                let mut h = 0u32;
                for at in finds {
                    h = mix(h, at.map_or(u32::MAX, |i| i as u32));
                }
                (finds.iter().filter(|f| f.is_some()).count() as u32, h)
            }
            19 => {
                let tests = [
                    text.contains('ß'),
                    text.contains("the"),
                    text.contains(char::is_control),
                    text.starts_with(first),
                    text.starts_with(['\n', ' ']),
                    text.ends_with(last),
                    text.ends_with(char::is_alphabetic),
                    text.strip_prefix(first).is_some(),
                    text.strip_suffix(last).is_some(),
                ];
                let bits = tests
                    .iter()
                    .rev()
                    .fold(0u32, |b, t| (b << 1) | u32::from(*t));
                (bits, 0)
            }
            20 => pieces(
                [
                    text.trim(),
                    text.trim_start(),
                    text.trim_end(),
                    text.trim_matches(' '),
                    text.trim_start_matches("the"),
                    text.trim_end_matches(|c: char| !c.is_alphabetic()),
                    text.trim_matches(['\n', ' ', '.']),
                ]
                .into_iter(),
            ),
            21 => {
                for replaced in [
                    text.replace("ß", "ss"),
                    text.replace(' ', "_"),
                    text.replacen(char::is_whitespace, "·", 5),
                    text.replacen("the", "THE", 2),
                    first.repeat(3),
                ] {
                    fold(&mut d, &replaced);
                }
                (5, 0)
            }
            22 => {
                let once = (text.split_once(' '), text.rsplit_once(", "));
                let h = once.0.map_or(u32::MAX, |(a, _)| a.len() as u32);
                (u32::from(once.1.is_some()), h)
            }
            23 => {
                // Boundaries: one per char, plus the end.
                let boundaries = (0..=text.len())
                    .filter(|&i| text.is_char_boundary(i))
                    .count() as u32;
                let starts: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
                let mut h = 0u32;
                for _ in 0..2 + scale / 2 {
                    let a = starts[cx.rng().index(starts.len())];
                    let b = starts[cx.rng().index(starts.len())];
                    let (lo, hi) = (a.min(b), a.max(b));
                    let (head, tail) = text.split_at(lo);
                    fold(&mut d, &text[lo..hi]);
                    h = mix(mix(h, head.len() as u32), tail.len() as u32);
                    let byte = cx.rng().index(text.len() + 1);
                    h = mix(h, text.floor_char_boundary(byte) as u32);
                    h = mix(h, text.ceil_char_boundary(byte) as u32);
                }
                (boundaries, h)
            }
            _ => {
                let mid = inside_a_char(cx.rng(), text);
                let refused = [
                    text.get(mid..),
                    text.get(..mid),
                    text.get(black_box(2)..black_box(1)),
                    text.get(..text.len() + 1),
                    text.get(text.len() + 1..),
                ];
                let none = refused.iter().filter(|r| r.is_none()).count() as u32;
                (none, u32::from(text.split_at_checked(mid).is_none()))
            }
        };
        counts.push(n);
        d.u32(h);
    }

    if cx.fault(FAULT_CHAR_BOUNDARY) {
        let mid = inside_a_char(cx.rng(), text);
        fold(&mut d, &text[..black_box(mid)]);
    }
    let out = format!("probes={mask:x} counts={counts:?}");
    emit(cx, TAG_SEARCH, out, &d);
}

/// A byte offset `text` refuses: inside one of its multi-byte chars where it
/// has one, and past its end where it has none.
///
/// Both callers want an offset that `get` answers `None` for and that slicing
/// panics on, and an all-ASCII text — which the payload can force, since the
/// generated words are only part of it — has no interior offset to give them.
/// Drawing from an empty set was a panic on every such input, and one the host
/// took as well, so the suite reported agreement while the sections after it
/// never ran.
fn inside_a_char(rng: &mut Rng, text: &str) -> usize {
    let inside: Vec<usize> = text
        .char_indices()
        .filter(|(_, c)| c.len_utf8() > 1)
        .map(|(i, _)| i + 1)
        .collect();
    match inside.len() {
        0 => text.len() + 1,
        n => inside[rng.index(n)],
    }
}

/// A `String` built up and cut down by every mutator, each at a boundary the
/// data chose; then the words collected every way `FromIterator` allows,
/// joined, sorted — stable sorts whose ties keep input order, which is the
/// point — deduplicated and binary-searched.
fn mutate(cx: &mut Ctx, generated: &str, scale: usize) {
    let mut d = Digest::new();
    let words: Vec<&str> = generated.split_whitespace().take(4 + 2 * scale).collect();
    let mask = choose(cx.rng(), 4, scale);
    let mut s = String::with_capacity(8);
    for (k, w) in words.iter().enumerate() {
        match k % 4 {
            0 => s.push_str(w),
            1 => {
                s.push(' ');
                s.extend(w.chars().rev());
            }
            2 => s += w,
            _ => s.extend([" ", w]),
        }
    }
    fold(&mut d, &s);
    let mut out = format!("probes={mask:x} words={}", words.len());

    if has(mask, 0) {
        let mut h = 0u32;
        for _ in 0..2 + scale {
            let at = s.floor_char_boundary(cx.rng().index(s.len() + 1));
            let op = cx.rng().below(8) as u32;
            match op {
                0 => s.insert(at, 'ß'),
                1 => s.insert_str(at, "日本 "),
                2 if at < s.len() => h = mix(h, u32::from(s.remove(at))),
                3 => {
                    let end = s.floor_char_boundary(at + cx.rng().index(s.len() - at + 1));
                    let drained: String = s.drain(at..end).collect();
                    fold(&mut d, &drained);
                }
                4 => s.retain(|c| !c.is_whitespace() || c == ' '),
                5 => {
                    let tail = s.split_off(at);
                    s.push_str(&tail.to_uppercase());
                }
                6 => {
                    s.truncate(at);
                    s.push_str(words[at % words.len()]);
                }
                _ => h = mix(h, s.pop().map_or(0, u32::from)),
            }
            h = mix(mix(h, op), s.len() as u32);
        }
        fold(&mut d, &s);
        d.u32(h);
        let _ = write!(out, " chars={}", s.chars().count());
    }
    if cx.fault(FAULT_REMOVE_PAST_END) {
        let end = black_box(s.len());
        d.u32(u32::from(s.remove(end)));
    }
    s.clear();
    d.count(s.len());

    if has(mask, 1) {
        let initials: String = words
            .iter()
            .map(|w| w.chars().next().unwrap_or('_'))
            .collect();
        let glued: String = words.iter().copied().collect();
        let shouted: String = words.iter().map(|w| w.to_uppercase()).collect();
        let boxed: Box<str> = glued.clone().into_boxed_str();
        for built in [
            initials,
            shouted,
            words.join("·"),
            words.concat(),
            String::from(boxed),
            'ß'.to_string() + &String::from('🦀'),
        ] {
            fold(&mut d, &built);
        }
    }
    if has(mask, 2) {
        // Stable sorts: equal keys keep input order, so the order is defined.
        let mut by_len = words.clone();
        by_len.sort_by_key(|w| w.chars().count());
        let mut folded = words.clone();
        folded.sort_by_cached_key(|w| w.to_lowercase());
        let mut h = 0u32;
        for w in by_len.iter().chain(&folded) {
            h = mix(h, w.len() as u32);
        }
        d.u32(h);
        let mut order = [0u32; 3];
        for pair in words.windows(2) {
            order[(pair[0].cmp(pair[1]) as i8 + 1) as usize] += 1;
        }
        let _ = write!(
            out,
            " less={} equal={} greater={}",
            order[0], order[1], order[2]
        );
    }
    if has(mask, 3) {
        let mut sorted = words.clone();
        sorted.sort();
        sorted.dedup();
        let found = words
            .iter()
            .filter(|w| sorted.binary_search(w).is_ok())
            .count();
        let missing = sorted.binary_search(&"\u{10ffff}").unwrap_or_else(|at| at);
        let head: Vec<&str> = sorted.iter().take(6).copied().collect();
        let _ = write!(
            out,
            " distinct={} found={found} insert_at={missing} max={:?} sorted={}",
            sorted.len(),
            words.iter().max(),
            head.join("|")
        );
    }
    emit(cx, TAG_MUTATE, out, &d);
}

/// Parse outcomes: each `Ok` value and each error's kind fingerprinted, and
/// each distinct error message kept once, in order of first sight —
/// formatting every error would cost more than the parsing.
struct Outcomes {
    d: Digest,
    ok: [u32; 9],
    seen: u32,
    messages: Vec<String>,
}

impl Outcomes {
    fn new() -> Outcomes {
        Outcomes {
            d: Digest::new(),
            ok: [0; 9],
            seen: 0,
            messages: Vec::new(),
        }
    }

    fn note<T, E: fmt::Display>(
        &mut self,
        slot: usize,
        result: Result<T, E>,
        code: fn(&E) -> u32,
        put: fn(&mut Digest, T),
    ) {
        match result {
            Ok(v) => {
                self.ok[slot] += 1;
                put(&mut self.d, v);
            }
            Err(e) => {
                let c = code(&e);
                self.d.u32(c);
                if self.seen & (1 << c) == 0 {
                    self.seen |= 1 << c;
                    self.messages.push(e.to_string());
                }
            }
        }
    }

    /// The messages, oldest first, for a section's readable half.
    fn errors(&self) -> String {
        self.messages.join(" | ")
    }

    fn total(&self) -> u32 {
        self.ok.iter().sum()
    }
}

fn int_code(e: &ParseIntError) -> u32 {
    match e.kind() {
        IntErrorKind::Empty => 1,
        IntErrorKind::InvalidDigit => 2,
        IntErrorKind::PosOverflow => 3,
        IntErrorKind::NegOverflow => 4,
        IntErrorKind::Zero => 5,
        _ => 0,
    }
}

/// `ParseFloatError` keeps its kind private; its two are told apart by
/// comparing with the empty string's.
fn float_code(e: &ParseFloatError) -> u32 {
    if *e == "".parse::<f64>().unwrap_err() {
        6
    } else {
        7
    }
}

fn bool_code(_: &ParseBoolError) -> u32 {
    8
}

/// As [`float_code`].
fn char_code(e: &ParseCharError) -> u32 {
    if *e == "".parse::<char>().unwrap_err() {
        9
    } else {
        10
    }
}

/// Integer, `bool` and `char` parsing, of the text's tokens and of tokens on
/// every edge: signs alone, leading zeros, empty, one past each type's range,
/// zero for a `NonZero`, non-ASCII digits. Then 128-bit values through
/// `Display`, hex and back — on the guest, 128-bit division and
/// multiplication are compiler-builtins calls.
fn parse_int(cx: &mut Ctx, text: &str, scale: usize) {
    const EDGE: [&str; 30] = [
        "",
        "+",
        "-",
        "0",
        "-0",
        "+7",
        "127",
        "128",
        "-128",
        "-129",
        "256",
        "65535",
        "65536",
        "9223372036854775807",
        "-9223372036854775809",
        "340282366920938463463374607431768211455",
        "340282366920938463463374607431768211456",
        "0042",
        " 7",
        "1_000",
        "٣",
        "９",
        "ff",
        "zz",
        "true",
        "False",
        "t",
        "é",
        "ab",
        "0x10",
    ];
    let mut o = Outcomes::new();
    let mask = choose(cx.rng(), EDGE.len(), scale);
    let tokens = (0..EDGE.len())
        .filter(|&k| has(mask, k))
        .map(|k| EDGE[k])
        .chain(text.split_whitespace().take(1 + scale / 2));
    let mut n = 0u32;
    for t in tokens {
        n += 1;
        o.note(0, t.parse::<i8>(), int_code, |d, v| {
            d.u8(v as u8);
        });
        o.note(1, t.parse::<u16>(), int_code, |d, v| {
            d.u16(v);
        });
        o.note(2, t.parse::<i64>(), int_code, |d, v| {
            d.i64(v);
        });
        o.note(3, t.parse::<u128>(), int_code, |d, v| {
            d.u128(v);
        });
        o.note(4, t.parse::<NonZeroU32>(), int_code, |d, v| {
            d.u32(v.get());
        });
        o.note(5, t.parse::<bool>(), bool_code, |d, v| {
            d.u8(u8::from(v));
        });
        o.note(6, t.parse::<char>(), char_code, |d, v| {
            d.u32(u32::from(v));
        });
        o.note(7, i32::from_str_radix(t, 16), int_code, |d, v| {
            d.i32(v);
        });
        o.note(8, u64::from_str_radix(t, 36), int_code, |d, v| {
            d.u64(v);
        });
    }

    let mut roundtrip = 0u32;
    let rounds = 1 + scale / 4;
    let mut buf = String::new();
    for _ in 0..rounds {
        let wide = (u128::from(cx.rng().next_u64()) << 64) | u128::from(cx.rng().next_u64());
        let v = wide >> cx.rng().below(128);
        let signed = -((v >> 1) as i128);
        buf.clear();
        let _ = write!(buf, "{v} {signed} {v:x} {signed:X}");
        fold(&mut o.d, &buf);
        let mut parts = buf.split(' ');
        let ok_all = parts.next().map(str::parse::<u128>) == Some(Ok(v))
            && parts.next().map(str::parse::<i128>) == Some(Ok(signed))
            && parts.next().map(|h| u128::from_str_radix(h, 16)) == Some(Ok(v));
        roundtrip += u32::from(ok_all);
    }

    if cx.fault(FAULT_PARSE_UNWRAP) {
        let words: Vec<&str> = WORDS
            .iter()
            .copied()
            .filter(|w| w.chars().all(char::is_alphabetic))
            .collect();
        let word = black_box(words[cx.rng().index(words.len())]);
        o.d.u8(word.parse::<u8>().unwrap());
    }

    let out = format!(
        "probes={mask:x} tokens={n} ok={} roundtrip128={roundtrip}/{rounds} {:?} errors={}",
        o.total(),
        black_box("256").parse::<u8>(),
        o.errors()
    );
    emit(cx, TAG_PARSE_INT, out, &o.d);
}

/// Float parsing and formatting on a target with no float unit: literals on
/// the edges of `f64` and `f32` — the subnormal boundary, halfway ties, one
/// past the largest finite, the spellings of infinity and NaN, malformed
/// ones — and generated ones, through `parse`; then the float formats back
/// out, and the shortest forms parsed back to the same bits.
fn float(cx: &mut Ctx, scale: usize) {
    const EDGE: [&str; 26] = [
        "0.1",
        "-0",
        "1e23",
        "9007199254740993",
        "2.2250738585072011e-308",
        "4.9e-324",
        "2.4703282292062327e-324",
        "2.4703282292062328e-324",
        "1.7976931348623157e308",
        "1.7976931348623159e308",
        "1e309",
        "16777217",
        "3.4028236e38",
        "1.00000017881393432617187499",
        "inf",
        "-infinity",
        "NaN",
        "1.",
        ".5",
        "+.5e-3",
        "e5",
        "1e",
        "",
        "+-1",
        "0x1p3",
        "1_0",
    ];
    let mut o = Outcomes::new();
    let mask = choose(cx.rng(), EDGE.len(), scale);
    let mut values: Vec<f64> = Vec::new();
    let mut literal = String::new();
    for k in 0..EDGE.len() + 1 + scale / 2 {
        let t = match EDGE.get(k) {
            Some(t) if has(mask, k) => *t,
            Some(_) => continue,
            None => {
                let rng = cx.rng();
                literal.clear();
                if rng.chance(1, 4) {
                    literal.push('-');
                }
                for i in 0..1 + rng.index(20) {
                    literal.push(char::from(b'0' + rng.below(10) as u8));
                    if i == 0 && rng.chance(1, 2) {
                        literal.push('.');
                    }
                }
                if rng.chance(2, 3) {
                    let _ = write!(literal, "e{}", rng.below(700) as i32 - 350);
                }
                &literal
            }
        };
        let wide = t.parse::<f64>();
        if let Ok(x) = wide {
            values.push(x);
        }
        o.note(0, wide, float_code, |d, v| {
            d.f64(v);
        });
        o.note(1, t.parse::<f32>(), float_code, |d, v| {
            d.f32(v);
        });
    }
    for _ in 0..scale / 4 {
        values.push(f64::from_bits(cx.rng().next_u64()));
    }

    // Soft-float arithmetic on neighbours; `Digest::f64` folds any NaN.
    for pair in values.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        o.d.f64(a + b).f64(a * b).f64(a / b).f64(a - b);
        o.d.u8(a.partial_cmp(&b).map_or(3, |c| c as i8 as u8));
    }

    // One formatting of each value, and the shortest forms parsed back.
    let mut buf = String::new();
    let mut failures = 0u32;
    for (i, &x) in values.iter().enumerate() {
        // Fixed-point forms of huge or tiny values run to hundreds of digits.
        let modest = x == 0.0 || (1e-30..1e30).contains(&x) || (-1e30..-1e-30).contains(&x);
        buf.clear();
        let _ = match (i % 4, modest, x.is_nan()) {
            (0, _, false) => {
                let _ = write!(buf, "{x:?}");
                failures += u32::from(buf.parse::<f64>().map(f64::to_bits) != Ok(x.to_bits()));
                Ok(())
            }
            (1, _, false) => {
                let single = x as f32;
                let _ = write!(buf, "{single:e}");
                failures += u32::from(buf.parse::<f32>().map(f32::to_bits) != Ok(single.to_bits()));
                Ok(())
            }
            (2, true, _) => write!(buf, "{x} {x:+09.2}"),
            (3, true, _) => write!(buf, "{x:.3} {x:<9.1}"),
            _ => write!(buf, "{x:.4e} {x:+12.2e}"),
        };
        fold(&mut o.d, &buf);
    }

    // Values whose formatting is worth reading: rounding half to even, the
    // shortest form of an inexact sum, and the non-finite spellings.
    let shows = choose(cx.rng(), 7, scale);
    let mut out = format!(
        "probes={mask:x} values={} ok={} roundtrip_failures={failures} shows={shows:x} errors={}",
        values.len(),
        o.total(),
        o.errors()
    );
    let (a, b) = (black_box(0.1f64), black_box(0.2f64));
    for k in 0..7 {
        if !has(shows, k) {
            continue;
        }
        let _ = match k {
            0 => write!(out, " | {} {:?}", a + b, a + b),
            1 => write!(out, " | {:.20}", black_box(1.0f64) / black_box(3.0)),
            2 => write!(
                out,
                " | {:.0} {:.0} {:.0}",
                black_box(0.5f64),
                black_box(1.5f64),
                black_box(2.5f64)
            ),
            3 => write!(
                out,
                " | {:.1} {:e}",
                black_box(0.25f64),
                black_box(1234.5e10f64)
            ),
            4 => write!(
                out,
                " | {:?} {:?} {:?}",
                black_box(1e16f64),
                black_box(1e-7f64),
                black_box(-0.0f64)
            ),
            5 => write!(out, " | {} {:?} {}", f64::NAN, f64::NEG_INFINITY, f64::MAX),
            _ => write!(
                out,
                " | f32 {} {:?}",
                black_box(16_777_217.0f32),
                black_box(0.1f32) + black_box(0.2f32)
            ),
        };
    }
    emit(cx, TAG_FLOAT, out, &o.d);
}

/// A `fmt::Write` sink that fingerprints what it is handed and refuses
/// anything past `limit` bytes, so `write!`'s error path runs too.
struct Sink {
    h: u32,
    taken: usize,
    limit: usize,
    chars: u32,
}

impl fmt::Write for Sink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.taken + s.len() > self.limit {
            return Err(fmt::Error);
        }
        self.taken += s.len();
        self.h = mix(self.h, s.len() as u32);
        Ok(())
    }

    fn write_char(&mut self, c: char) -> fmt::Result {
        self.chars += 1;
        self.write_str(c.encode_utf8(&mut [0; 4]))
    }
}

/// `format_args!` handed on, as a library taking `fmt::Arguments` would.
fn render(args: fmt::Arguments<'_>) -> String {
    match args.as_str() {
        Some(literal) => String::from(literal),
        None => alloc::fmt::format(args),
    }
}

/// Integers, strs and chars through width, fill, alignment, precision, sign,
/// `#`, zero padding and every way of naming an argument — inline, positional,
/// named, and width and precision taken from arguments — into a `String` and
/// into a sink that fails part-way through.
fn format(cx: &mut Ctx, scale: usize) {
    let mut d = Digest::new();
    let mut shown = String::new();
    let mut buf = String::new();
    let mut refused = 0u32;
    let mut probes = 0u64;
    let mut sink = Sink {
        h: 0,
        taken: 0,
        limit: 0,
        chars: 0,
    };
    for k in 0..1 + scale / 6 {
        let mask = choose(cx.rng(), 6, scale);
        probes |= mask;
        let rng = cx.rng();
        let a = rng.next_u32() as i32 >> rng.below(31);
        let b = rng.next_u64() >> rng.below(64);
        let c = rng.next_u32() as i8;
        let wide = (rng.next_u64() as i128) << rng.below(64);
        let (w, p) = (rng.index(14), rng.index(6));
        let s = WORDS[rng.index(WORDS.len())];
        let ch = s.chars().next_back().unwrap_or('?');
        let x = f64::from(a) / 7.0;
        buf.clear();
        if has(mask, 0) {
            let _ = write!(
                buf,
                "[{a:>8}|{a:<8}|{a:^9}|{a:*^9}|{a:+}|{a:08}|{a:#x}|{a:#010b}|{a:o}|{a:X}|{a:e}]"
            );
        }
        if has(mask, 1) {
            let _ = write!(
                buf,
                "[{b:>w$}|{b:#0w$x}|{c:+04}|{c:?}|{wide}|{wide:#x}|{wide:+e}|{b:.p$e}]"
            );
        }
        if has(mask, 2) {
            let _ = write!(buf, "[{0}-{0}-{1}|{1:>2$}|{0:^2$}|{0:_<1$}]", s, w, p);
        }
        if has(mask, 3) {
            let _ = write!(buf, "[{:.*}|{:.*}|{3:>4$.3}]", p, x, 2, s, w);
        }
        if has(mask, 4) {
            let _ = write!(
                buf,
                "[{name:>width$.prec$}|{s:^w$}|{ch:>4}|{ch:?}|{ch:_<3}]",
                name = s,
                width = w,
                prec = p
            );
        }
        if has(mask, 5) {
            let _ = write!(buf, "{}", render(format_args!("[{s}:{a:+}]")));
            buf.push_str(&render(format_args!("[plain]")));
        }
        fold(&mut d, &buf);
        if k == 0 {
            shown.push_str(&buf);
        }

        // The sink takes part of the same text, and refuses the rest.
        sink.taken = 0;
        sink.limit = cx.rng().index(buf.len() + 8);
        let r = write!(sink, "{buf}{ch}{:>4}", ch);
        refused += u32::from(r.is_err());
        sink.h = mix(sink.h, sink.taken as u32);
    }
    d.u32(sink.h).u32(sink.chars);

    let out = format!(
        "probes={probes:x} {shown} refused={refused} error=\"{}\"",
        fmt::Error
    );
    emit(cx, TAG_FORMAT, out, &d);
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Word,
    Number(i64),
    Mixed { upper: u32, lower: u32 },
    Empty,
}

#[derive(Debug)]
#[expect(
    dead_code,
    reason = "read only by the derived `Debug`, which is its purpose"
)]
struct Token<'a> {
    text: &'a str,
    owned: String,
    kind: Kind,
    span: (u32, u32),
    chars: Vec<char>,
    next: Option<Box<Token<'a>>>,
}

#[derive(Debug)]
struct Unit;

#[derive(Debug)]
#[expect(
    dead_code,
    reason = "read only by the derived `Debug`, which is its purpose"
)]
struct Pair(i8, &'static str);

/// `Debug` by hand, through each of `Formatter`'s builders.
struct Manual<'a>(&'a [&'a str]);

impl fmt::Debug for Manual<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manual")
            .field("words", &self.0.len())
            .field("first", &self.0.first())
            .finish_non_exhaustive()?;
        f.write_str(" ")?;
        f.debug_tuple("Lens")
            .field(&self.0.iter().map(|w| w.len() as u32).sum::<u32>())
            .finish()?;
        f.write_str(" ")?;
        f.debug_list().entries(self.0).finish()?;
        f.write_str(" ")?;
        f.debug_map()
            .entries(self.0.iter().map(|w| (w, w.chars().count())))
            .finish()?;
        f.write_str(" ")?;
        f.debug_set()
            .entries(self.0.iter().flat_map(|w| w.chars().next()))
            .finish()
    }
}

fn kind(word: &str) -> Kind {
    if word.is_empty() {
        return Kind::Empty;
    }
    if let Ok(n) = word.parse::<i64>() {
        return Kind::Number(n);
    }
    let upper = word.chars().filter(|c| c.is_uppercase()).count() as u32;
    let lower = word.chars().filter(|c| c.is_lowercase()).count() as u32;
    if upper > 0 && lower > 0 {
        Kind::Mixed { upper, lower }
    } else {
        Kind::Word
    }
}

/// The probes of [`debug`].
const DEBUG_PROBES: usize = 11;

/// Derived and hand-written `Debug`, `{:?}` and `{:#?}`, over nested structs,
/// enums, `Option`s, tuples, `Vec`s and maps, with strings that need escaping:
/// quotes, backslashes, newlines, a combining mark, a zero-width space, DEL,
/// and whatever the payload holds.
fn debug(cx: &mut Ctx, text: &str, scale: usize) {
    const TRICKY: &str = "a\"b\\c\nd\té\u{301}\u{200b}🦀\u{7f}'";
    let mut d = Digest::new();
    let mask = choose(cx.rng(), DEBUG_PROBES, scale);
    // A few of the text's words, cut to eight chars, chained as tokens.
    let words: Vec<String> = text
        .split_whitespace()
        .take(1 + scale / 4)
        .map(|w| w.chars().take(8).collect())
        .collect();
    let mut chain: Option<Box<Token>> = None;
    let mut at = 0u32;
    for w in words.iter().rev() {
        let len = w.chars().count() as u32;
        chain = Some(Box::new(Token {
            text: w,
            owned: w.to_uppercase(),
            kind: kind(w),
            span: (at, at + len),
            chars: w.chars().collect(),
            next: chain,
        }));
        at += len + 1;
    }
    let manual = Manual(&[TRICKY, "x", "日本"]);

    let mut out = format!("probes={mask:x}");
    let mut pretty = String::new();
    for k in 0..DEBUG_PROBES {
        if !has(mask, k) {
            continue;
        }
        let _ = match k {
            0 => write!(out, " | {chain:?}"),
            1 => write!(pretty, "{chain:#?}"),
            2 => write!(
                out,
                " | {:?}",
                Token {
                    text: TRICKY,
                    owned: String::from("ß"),
                    kind: Kind::Mixed { upper: 1, lower: 2 },
                    span: (0, 1),
                    chars: TRICKY.chars().take(4).collect(),
                    next: None,
                }
            ),
            3 => write!(
                out,
                " | {:?}",
                (
                    1u8,
                    'x',
                    '\'',
                    '"',
                    "y",
                    2.5f32,
                    true,
                    (),
                    [1u8, 2, 3],
                    &[-1i16, 2][..]
                )
            ),
            4 => write!(
                out,
                " | {:?}",
                (
                    Some("s"),
                    None::<u8>,
                    Ok::<u8, String>(3),
                    Err::<u8, String>("e\n".into()),
                    Unit,
                    Pair(-1, "p"),
                    Some(Box::new(Kind::Word)),
                )
            ),
            5 => {
                let mut map: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
                map.insert("b\"", Vec::from(*b"\x00\xff"));
                map.insert("é", Vec::new());
                let set: BTreeSet<char> = TRICKY.chars().take(6).collect();
                write!(out, " | {map:?} {set:?}")
            }
            6 => {
                let mut kinds = [
                    Kind::Empty,
                    Kind::Number(cx.rng().next_u64() as i64),
                    Kind::Word,
                    Kind::Mixed { upper: 2, lower: 1 },
                ];
                kinds.sort();
                write!(out, " | {kinds:?}")
            }
            7 => write!(out, " | {manual:?}"),
            8 => write!(pretty, "{manual:#?} {:#?}", Pair(0, "")),
            9 => {
                let nested: Vec<Vec<&str>> =
                    alloc::vec![alloc::vec!["a"], Vec::new(), alloc::vec!["'", "\""]];
                write!(out, " | {nested:?}")
            }
            _ => write!(out, " | {words:?}"),
        };
    }
    fold(&mut d, &out);
    fold(&mut d, &pretty);
    let _ = write!(out, " | pretty_lines={}", pretty.lines().count());
    emit(cx, TAG_DEBUG, out, &d);
}

/// A name whose `Display` hands padding and truncation to `f.pad`, so width,
/// fill, alignment and precision act on it as on a `str`; `{:#}` shouts it.
struct Name<'a>(&'a str);

impl fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.pad(&self.0.to_uppercase())
        } else {
            f.pad(self.0)
        }
    }
}

/// Thousandths, whose `Display` takes `f.precision()` as the decimal places
/// (rounding half to even), groups thousands under `{:#}`, and hands sign,
/// `+`, zero padding and width to `f.pad_integral` — whose prefix, `¤`, is
/// written under `{:#}` alone.
struct Milli(i64);

impl fmt::Display for Milli {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let places = f.precision().unwrap_or(3).min(3) as u32;
        let divisor = 10u64.pow(3 - places);
        let magnitude = self.0.unsigned_abs();
        let (mut q, r) = (magnitude / divisor, magnitude % divisor);
        let half = divisor / 2;
        if divisor > 1 && (r > half || (r == half && q % 2 == 1)) {
            q += 1;
        }
        let unit = 10u64.pow(places);
        let mut whole = String::new();
        let _ = write!(whole, "{}", q / unit);
        let mut digits = String::new();
        for (i, c) in whole.chars().enumerate() {
            if f.alternate() && i > 0 && (whole.len() - i).is_multiple_of(3) {
                digits.push(',');
            }
            digits.push(c);
        }
        if places > 0 {
            let _ = write!(digits, ".{:01$}", q % unit, places as usize);
        }
        f.pad_integral(self.0 >= 0, "¤", &digits)
    }
}

/// Every option the formatter was given, reported back.
struct Spec;

impl fmt::Display for Spec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let options = (
            f.width(),
            f.precision(),
            f.fill(),
            f.align(),
            f.sign_plus(),
            f.sign_minus(),
            f.alternate(),
            f.sign_aware_zero_pad(),
        );
        write!(f, "{options:?}")
    }
}

/// The probes of [`display`]: five values under eight specs, three names
/// under six, and five formatter-option spellings.
const DISPLAY_PROBES: usize = 63;

/// Custom `Display` impls that honour the formatter: `f.pad`,
/// `f.pad_integral`, `f.alternate()`, `f.precision()` and the rest, each
/// value under the format specs this run chose.
fn display(cx: &mut Ctx, scale: usize) {
    let mut d = Digest::new();
    let rng = cx.rng();
    let millis = [
        Milli(black_box(1_234_567)),
        Milli(-500),
        Milli(2_500),
        Milli(i64::MIN),
        Milli((rng.next_u64() as i64) >> rng.below(64)),
    ];
    let word = WORDS[rng.index(WORDS.len())];
    let (w, p) = (rng.index(12), rng.index(5));
    let names = [Name("Straße"), Name("日本語"), Name(word)];
    let mask = choose(rng, DISPLAY_PROBES, scale);
    let mut out = format!("probes={mask:x}");
    for k in 0..DISPLAY_PROBES {
        if !has(mask, k) {
            continue;
        }
        let _ = if k < 40 {
            let m = &millis[k / 8];
            match k % 8 {
                0 => write!(out, " {m}"),
                1 => write!(out, " {m:.0}"),
                2 => write!(out, " {m:.1}"),
                3 => write!(out, " {m:+.2}"),
                4 => write!(out, " {m:#}"),
                5 => write!(out, " {m:#015.2}"),
                6 => write!(out, " {m:>12}"),
                _ => write!(out, " {m:*<10.1}"),
            }
        } else if k < 58 {
            let n = &names[(k - 40) / 6];
            match (k - 40) % 6 {
                0 => write!(out, " {n}"),
                1 => write!(out, " {n:>8}"),
                2 => write!(out, " {n:-^9}"),
                3 => write!(out, " {n:.3}"),
                4 => write!(out, " {n:#}"),
                _ => write!(out, " {n:>w$.p$}"),
            }
        } else {
            match k - 58 {
                0 => write!(out, " {Spec}"),
                1 => write!(out, " {Spec:>5}"),
                2 => write!(out, " {Spec:*^+#08.3}"),
                3 => write!(out, " {Spec:<}"),
                _ => write!(out, " {Spec:-}"),
            }
        };
    }
    fold(&mut d, &out);
    emit(cx, TAG_DISPLAY, out, &d);
}

/// A tokenizer and a word-frequency table: a token is a maximal run of
/// alphanumeric chars, folded to lowercase and counted in a `BTreeMap`. The
/// top entries rank by count, then by the word, so the order is total.
fn frequency(cx: &mut Ctx, text: &str, scale: usize) {
    let text = prefix(text, 16 + 32 * scale);
    let mut table: BTreeMap<String, u32> = BTreeMap::new();
    let mut tokens = 0u32;
    for w in text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
    {
        tokens += 1;
        *table.entry(w.to_lowercase()).or_insert(0) += 1;
    }
    let mut d = Digest::new();
    let mut h = 0u32;
    for (w, n) in &table {
        fold(&mut d, w);
        h = mix(h, *n);
    }
    d.u32(h);
    let mut ranked: Vec<(&String, &u32)> = table.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let before_n = table
        .range::<str, _>((Bound::Unbounded, Bound::Excluded("n")))
        .count();
    let mut out = format!(
        "tokens={tokens} distinct={} before_n={before_n}",
        table.len()
    );
    for (w, n) in ranked.iter().take(4) {
        let _ = write!(out, " {:?}:{n}", prefix(w, 12));
    }
    emit(cx, TAG_FREQUENCY, out, &d);
}
