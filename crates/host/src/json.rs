//! A JSON reader, about as small as one gets.
//!
//! The recorder reads five JSON-RPC responses and no more: `eth_blockNumber`,
//! `eth_getBlockByNumber`, `eth_getProof`, `eth_getCode` and
//! `eth_getStorageAt`. Every value in them is a string, a number, an array or
//! an object of those, and nothing needs a schema. So this is a reader, not a
//! deserializer: `parse` returns a tree and the caller walks it by name.
//!
//! Master anti-goal 6 — "write the eight lines yourself" — is why it is here
//! rather than a dependency, and must-be-exact 6's "a minimal JSON-RPC client
//! rather than an Ethereum SDK" is the stage's version of the same rule. The
//! whole of it runs in the manual refresh command; CI never reaches it.
//!
//! What it does **not** do: `\u` escapes beyond the plain ones below, and
//! numeric conversion. Ethereum's JSON-RPC answers every quantity as a `0x`
//! string, so a bare number appears only in a field this crate does not read,
//! and a `\u` escape appears in no field at all. Both are refused loudly
//! rather than guessed at.

/// A JSON value.
///
/// An object is a `Vec` of pairs rather than a map: lookups are by name over
/// a handful of keys, duplicate keys are a malformed response rather than a
/// last-wins rule, and the field order a server sent is preserved.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// A number, kept as the text the server sent. Nothing here converts one.
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// The value of `key`, or `None` if this is not an object or has no such
    /// key.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// This value as a string, or `None` if it is not one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// This value as an array, or `None` if it is not one.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(items) => Some(items),
            _ => None,
        }
    }

    /// Whether this is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }
}

/// Parse `text` as one JSON value, which must be the whole of it.
///
/// Trailing content is an error rather than ignored: a response with a second
/// value after the first is a response this crate does not understand, and
/// deciding it means the first is how a reader ends up reading half a message.
pub fn parse(text: &str) -> Result<Json, String> {
    let bytes = text.as_bytes();
    let mut at = 0;
    let value = value(bytes, &mut at)?;
    skip_space(bytes, &mut at);
    if at != bytes.len() {
        return Err(format!("json: {} bytes after the value", bytes.len() - at));
    }
    Ok(value)
}

fn value(b: &[u8], at: &mut usize) -> Result<Json, String> {
    skip_space(b, at);
    match b.get(*at) {
        None => Err("json: the text ended where a value was expected".into()),
        Some(b'{') => object(b, at),
        Some(b'[') => array(b, at),
        Some(b'"') => Ok(Json::Str(string(b, at)?)),
        Some(b't') => literal(b, at, "true").map(|()| Json::Bool(true)),
        Some(b'f') => literal(b, at, "false").map(|()| Json::Bool(false)),
        Some(b'n') => literal(b, at, "null").map(|()| Json::Null),
        Some(_) => number(b, at),
    }
}

fn object(b: &[u8], at: &mut usize) -> Result<Json, String> {
    *at += 1; // '{'
    let mut fields: Vec<(String, Json)> = Vec::new();
    skip_space(b, at);
    if b.get(*at) == Some(&b'}') {
        *at += 1;
        return Ok(Json::Obj(fields));
    }
    loop {
        skip_space(b, at);
        if b.get(*at) != Some(&b'"') {
            return Err("json: an object key must be a string".into());
        }
        let key = string(b, at)?;
        if fields.iter().any(|(k, _)| *k == key) {
            return Err(format!("json: the key {key} appears twice"));
        }
        skip_space(b, at);
        if b.get(*at) != Some(&b':') {
            return Err(format!("json: no ':' after the key {key}"));
        }
        *at += 1;
        fields.push((key, value(b, at)?));
        skip_space(b, at);
        match b.get(*at) {
            Some(b',') => *at += 1,
            Some(b'}') => {
                *at += 1;
                return Ok(Json::Obj(fields));
            }
            _ => return Err("json: no ',' or '}' after an object member".into()),
        }
    }
}

fn array(b: &[u8], at: &mut usize) -> Result<Json, String> {
    *at += 1; // '['
    let mut items = Vec::new();
    skip_space(b, at);
    if b.get(*at) == Some(&b']') {
        *at += 1;
        return Ok(Json::Arr(items));
    }
    loop {
        items.push(value(b, at)?);
        skip_space(b, at);
        match b.get(*at) {
            Some(b',') => *at += 1,
            Some(b']') => {
                *at += 1;
                return Ok(Json::Arr(items));
            }
            _ => return Err("json: no ',' or ']' after an array element".into()),
        }
    }
}

fn string(b: &[u8], at: &mut usize) -> Result<String, String> {
    *at += 1; // '"'
    let mut out = String::new();
    loop {
        let c = *b
            .get(*at)
            .ok_or_else(|| String::from("json: the text ended inside a string"))?;
        *at += 1;
        match c {
            b'"' => return Ok(out),
            b'\\' => {
                let e = *b
                    .get(*at)
                    .ok_or_else(|| String::from("json: the text ended inside an escape"))?;
                *at += 1;
                out.push(match e {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{8}',
                    b'f' => '\u{c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    // Refused rather than decoded. No field this crate reads
                    // can contain one, and a half-right `\u` reader is worse
                    // than none.
                    _ => return Err("json: a \\u escape, which this reader refuses".into()),
                });
            }
            // A raw control character is not valid JSON, and letting one
            // through would make two texts read as one value.
            0x00..=0x1f => return Err("json: a raw control character in a string".into()),
            _ => {
                // `c` is one byte of a UTF-8 sequence the input already holds,
                // so copying bytes through keeps the text well-formed.
                let start = *at - 1;
                let mut end = *at;
                while end < b.len() && b[end] & 0xc0 == 0x80 {
                    end += 1;
                }
                match core::str::from_utf8(&b[start..end]) {
                    Ok(s) => out.push_str(s),
                    Err(_) => return Err("json: a string is not UTF-8".into()),
                }
                *at = end;
            }
        }
    }
}

fn number(b: &[u8], at: &mut usize) -> Result<Json, String> {
    let start = *at;
    if b.get(*at) == Some(&b'-') {
        *at += 1;
    }
    while matches!(b.get(*at), Some(c) if c.is_ascii_digit() || *c == b'.' || *c == b'e' || *c == b'E' || *c == b'+' || *c == b'-')
    {
        *at += 1;
    }
    if *at == start {
        return Err("json: a value that is not a number, string, object, array, literal".into());
    }
    Ok(Json::Num(
        core::str::from_utf8(&b[start..*at])
            .map_err(|_| String::from("json: a number that is not UTF-8"))?
            .into(),
    ))
}

fn literal(b: &[u8], at: &mut usize, word: &str) -> Result<(), String> {
    if b[*at..].starts_with(word.as_bytes()) {
        *at += word.len();
        Ok(())
    } else {
        Err(format!("json: expected {word}"))
    }
}

fn skip_space(b: &[u8], at: &mut usize) {
    while matches!(b.get(*at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        *at += 1;
    }
}

/// The bytes of a `0x`-prefixed hex string, which is how Ethereum's JSON-RPC
/// writes every byte string it answers.
pub fn hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    let body = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("hex: {text} has no 0x prefix"))?;
    if body.len() % 2 != 0 {
        return Err(format!("hex: {text} has an odd digit count"));
    }
    let mut out = Vec::with_capacity(body.len() / 2);
    let digits = body.as_bytes();
    for pair in digits.chunks(2) {
        out.push(nibble(pair[0])? << 4 | nibble(pair[1])?);
    }
    Ok(out)
}

/// A `0x`-prefixed hex quantity as a big-endian 32-byte word.
///
/// Ethereum writes a quantity **without** leading zeros, so this
/// left-pads rather than requiring 64 digits.
pub fn hex_word(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex_quantity_bytes(text)?;
    if bytes.len() > 32 {
        return Err(format!("hex: {text} is wider than 32 bytes"));
    }
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(word)
}

/// A `0x`-prefixed hex quantity as a `u64`.
pub fn hex_u64(text: &str) -> Result<u64, String> {
    let bytes = hex_quantity_bytes(text)?;
    if bytes.len() > 8 {
        return Err(format!("hex: {text} is wider than 8 bytes"));
    }
    let mut value = 0u64;
    for byte in bytes {
        value = value << 8 | byte as u64;
    }
    Ok(value)
}

/// A `0x`-prefixed hex quantity as a `u128`, for the EIP-1559 fee fields.
pub fn hex_u128(text: &str) -> Result<u128, String> {
    let bytes = hex_quantity_bytes(text)?;
    if bytes.len() > 16 {
        return Err(format!("hex: {text} is wider than 16 bytes"));
    }
    let mut value = 0u128;
    for byte in bytes {
        value = value << 8 | byte as u128;
    }
    Ok(value)
}

/// A `0x`-prefixed hex **address**, exactly 20 bytes.
pub fn hex_address(text: &str) -> Result<[u8; 20], String> {
    let bytes = hex_bytes(text)?;
    if bytes.len() != 20 {
        return Err(format!("hex: {text} is not 20 bytes"));
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes);
    Ok(address)
}

/// A quantity's digits, left-padded to a whole byte. `0x0` is one zero byte
/// and `0x` alone is refused.
fn hex_quantity_bytes(text: &str) -> Result<Vec<u8>, String> {
    let body = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("hex: {text} has no 0x prefix"))?;
    if body.is_empty() {
        return Err("hex: 0x with no digits".into());
    }
    if body.len() % 2 == 0 {
        hex_bytes(text)
    } else {
        hex_bytes(&format!("0x0{body}"))
    }
}

fn nibble(digit: u8) -> Result<u8, String> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err(format!("hex: {} is not a hex digit", digit as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_parses() {
        let text = r#"{"jsonrpc":"2.0","id":1,"result":{"a":["0x1",null,true],"b":{}}}"#;
        let value = parse(text).expect("parses");
        assert_eq!(value.get("jsonrpc").and_then(Json::as_str), Some("2.0"));
        let result = value.get("result").expect("a result");
        let a = result.get("a").and_then(Json::as_array).expect("an array");
        assert_eq!(a[0].as_str(), Some("0x1"));
        assert!(a[1].is_null());
        assert_eq!(a[2], Json::Bool(true));
        assert_eq!(result.get("b"), Some(&Json::Obj(Vec::new())));
    }

    #[test]
    fn trailing_content_is_refused() {
        assert!(parse("{} {}").is_err());
        assert!(parse("1 2").is_err());
    }

    #[test]
    fn a_duplicate_key_is_refused() {
        assert!(parse(r#"{"a":1,"a":2}"#).is_err());
    }

    #[test]
    fn escapes_and_utf8_survive() {
        assert_eq!(
            parse(r#""a\"b\\c\nd""#).expect("parses"),
            Json::Str("a\"b\\c\nd".into())
        );
        assert_eq!(parse("\"é☃\"").expect("parses"), Json::Str("é☃".into()));
        // Written as bytes, not as a literal: a source literal of this
        // escape is one an editor or a tool is liable to decode on the way
        // in, and the test would then be about the letter A.
        let u_escape = String::from_utf8(vec![b'"', b'\\', b'u', b'0', b'0', b'4', b'1', b'"'])
            .expect("ascii");
        assert!(
            parse(&u_escape).is_err(),
            "an escape this reader refuses must be refused"
        );
    }

    #[test]
    fn quantities_and_byte_strings_decode() {
        assert_eq!(hex_u64("0x0").expect("zero"), 0);
        assert_eq!(hex_u64("0x18d6bf9").expect("odd digits"), 26_045_433);
        assert_eq!(hex_u128("0x1bf08eb000").expect("a fee"), 120_000_000_000);
        assert_eq!(hex_bytes("0x").expect("empty"), Vec::<u8>::new());
        assert_eq!(hex_bytes("0xdeadBEEF").expect("mixed case"), [
            0xde, 0xad, 0xbe, 0xef
        ]);
        assert_eq!(hex_word("0x1").expect("a word")[31], 1);
        assert!(hex_u64("18d6bf9").is_err(), "no prefix");
        assert!(hex_bytes("0xabc").is_err(), "odd digits are not bytes");
        assert!(hex_address("0x01").is_err(), "not 20 bytes");
    }
}
