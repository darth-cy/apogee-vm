//! Rust symbol demangling, both mangling schemes, written here because master
//! anti-goal 6 makes `rustc-demangle` an eight-lines-yourself dependency.
//!
//! `guests/revm-block` carries **both** forms — 1,154 legacy and 139 v0, the v0
//! ones being the precompiled sysroot crates, `core` and `compiler_builtins` —
//! so a demangler that handled one would leave a tenth of the symbols
//! unreadable.
//!
//! # What this does and does not decode
//!
//! **Legacy** (`_ZN` … `E`) is decoded completely: it is a run of
//! length-prefixed components, and the trailing `17h<16 hex>` disambiguator is
//! dropped because two monomorphizations of one function are one function to a
//! reader. `$LT$`-style escapes are expanded.
//!
//! **v0** (`_R` …) is decoded **partially, on purpose**: its grammar is nested
//! paths, base-62 back-references and generic arguments, and a complete decoder
//! is several hundred lines for names that are all `core::*` here. What this
//! extracts is the run of identifiers in order, joined with `::`, which is the
//! path a reader wants and the substring a category rule matches. A name it
//! could not read at all comes back as it was.
//!
//! Classification never depends on this: a crate and module name appears as a
//! literal ASCII substring in **both** manglings, so
//! `crate::categories::classify` would reach the same answer on the raw symbol
//! (`docs/spec/profiling.md` §3).

/// `name` as a reader wants it, or `name` itself if it is not mangled.
pub fn demangle(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("_ZN") {
        if let Some(out) = legacy(rest) {
            return out;
        }
    }
    if let Some(rest) = name.strip_prefix("_R") {
        return v0(rest);
    }
    name.to_string()
}

/// The legacy scheme: `_ZN` then `<len><ident>` components, then `E`.
fn legacy(mut rest: &str) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    loop {
        if rest.starts_with('E') {
            break;
        }
        let digits = rest.find(|c: char| !c.is_ascii_digit())?;
        if digits == 0 {
            return None;
        }
        let len: usize = rest[..digits].parse().ok()?;
        let body = rest.get(digits..digits + len)?;
        rest = &rest[digits + len..];
        parts.push(unescape(body));
    }
    // The trailing `17h<16 hex>` is the monomorphization disambiguator: two
    // instantiations of one function are one function to a reader.
    if parts
        .last()
        .is_some_and(|p| p.len() == 17 && p.starts_with('h'))
    {
        parts.pop();
    }
    (!parts.is_empty()).then(|| parts.join("::"))
}

/// The legacy scheme's `$..$` escapes, and `..` for a path separator.
fn unescape(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let (token, len) = match rest {
            r if r.starts_with("$LT$") => ("<", 4),
            r if r.starts_with("$GT$") => (">", 4),
            r if r.starts_with("$LP$") => ("(", 4),
            r if r.starts_with("$RP$") => (")", 4),
            r if r.starts_with("$C$") => (",", 3),
            r if r.starts_with("$RF$") => ("&", 4),
            r if r.starts_with("$BP$") => ("*", 4),
            r if r.starts_with("$u20$") => (" ", 5),
            r if r.starts_with("$u27$") => ("'", 5),
            r if r.starts_with("$u5b$") => ("[", 5),
            r if r.starts_with("$u5d$") => ("]", 5),
            r if r.starts_with("$u7b$") => ("{", 5),
            r if r.starts_with("$u7d$") => ("}", 5),
            r if r.starts_with("$u3b$") => (";", 5),
            _ => ("$", 1),
        };
        out.push_str(token);
        rest = &rest[len..];
    }
    out.push_str(rest);
    out.replace("..", "::")
}

/// The v0 scheme, read for its identifiers alone.
///
/// An identifier there is `<decimal len><bytes>`, optionally preceded by a `_`
/// when the name would otherwise start with a digit. What makes a naive scan
/// wrong is the **disambiguator**, `s<base-62>_`, whose base-62 digits include
/// decimal ones: a scan that read `CsxJ7lp9_17compiler_builtins` from the left
/// finds the `7` inside the crate id and takes the seven bytes after it. So a
/// disambiguator is skipped by name — an `s` right after a tag letter, up to and
/// past its `_` — and only then are the identifier runs collected.
///
/// Everything else the grammar has — the nesting tags, the back-references, the
/// generic arguments — is skipped by scanning, which is enough for a path and
/// for a category rule and is not a complete decoder.
fn v0(rest: &str) -> String {
    let bytes = rest.as_bytes();
    let mut parts: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // A disambiguator: `s` directly after a path tag, then base-62 digits,
        // then `_`. `Cs…_` is the common one, a crate's id.
        if bytes[i] == b's' && i > 0 && bytes[i - 1].is_ascii_uppercase() {
            match bytes[i..].iter().position(|b| *b == b'_') {
                Some(at) => {
                    i += at + 1;
                    continue;
                }
                None => break,
            }
        }
        if !bytes[i].is_ascii_digit() || bytes[i] == b'0' {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let Ok(len) = rest[start..i].parse::<usize>() else {
            continue;
        };
        // A leading `_` before an identifier that would start with a digit.
        if i < bytes.len() && bytes[i] == b'_' {
            i += 1;
        }
        let Some(body) = rest.get(i..i + len) else {
            continue;
        };
        if !body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            continue;
        }
        i += len;
        parts.push(body);
    }
    match parts.is_empty() {
        true => format!("_R{rest}"),
        false => parts.join("::"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_names_decode() {
        assert_eq!(
            demangle("_ZN4core3ptr13drop_in_place17h0123456789abcdefE"),
            "core::ptr::drop_in_place"
        );
        assert_eq!(demangle("_ZN5ruint3mul17habcdef0123456789E"), "ruint::mul");
        // The escapes, and a trait impl's `<T as Trait>` shape.
        assert_eq!(
            demangle("_ZN42_$LT$u32$u20$as$u20$core..fmt..Display$GT$3fmt17h00112233445566aaE"),
            "_<u32 as core::fmt::Display>::fmt"
        );
    }

    #[test]
    fn an_unmangled_name_is_itself() {
        assert_eq!(demangle("memcpy"), "memcpy");
        assert_eq!(demangle("native_keccak256"), "native_keccak256");
        assert_eq!(demangle("__udivdi3"), "__udivdi3");
    }

    #[test]
    fn v0_names_give_their_path() {
        // `_RNvNtCs1234_4core3ptr13drop_in_place` — the identifiers in order.
        let out = demangle("_RNvNtCs1234_4core3ptr13drop_in_place");
        assert_eq!(out, "core::ptr::drop_in_place");
    }

    /// The crate disambiguator's base-62 digits include decimal ones, and a
    /// scan that did not skip it read the `7` inside `xJ7lp9` as a length. This
    /// is the name that exposed it, from `guests/revm-block`.
    #[test]
    fn a_v0_disambiguator_is_not_a_length() {
        assert_eq!(
            demangle("_RNvNtCsxJ7lp9_17compiler_builtins3mem6memcpy"),
            "compiler_builtins::mem::memcpy"
        );
    }

    #[test]
    fn a_name_that_decodes_to_nothing_survives() {
        assert_eq!(demangle("_ZNE"), "_ZNE");
        assert_eq!(demangle("_ZN"), "_ZN");
    }
}
