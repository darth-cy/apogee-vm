//! `docs/spec/ecall-abi.md` is the ABI, and this holds it to `constants::ecall`.
//!
//! Acceptance 9 wants the single source of truth in code with the document
//! checked against it. So the document's three tables — the numbers, the file
//! descriptors and the ranges — are parsed here and compared to the constants,
//! in both directions: a number in the document that is not a constant fails,
//! and a constant the document does not mention fails too.
//!
//! It also checks that `crates/guest-sdk` reaches those constants rather than
//! spelling a number itself, because a shim with `93` written into it would
//! satisfy every other test in this repository while quietly owning a second
//! copy of the ABI.
//!
//! An integration test rather than a unit test: `crates/constants` is
//! `#![no_std]` and holds no code, and a test target is a separate crate that
//! changes neither.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use constants::{ecall, guest_memory};

/// Every `constants::ecall` item, by the name the document uses.
fn constants_table() -> BTreeMap<&'static str, u32> {
    BTreeMap::from([
        ("READ", ecall::READ),
        ("WRITE", ecall::WRITE),
        ("EXIT", ecall::EXIT),
        ("PRECOMPILE_POSEIDON2", ecall::PRECOMPILE_POSEIDON2),
        ("FD_PUBLIC_INPUT", ecall::FD_PUBLIC_INPUT),
        ("FD_PUBLIC_OUTPUT", ecall::FD_PUBLIC_OUTPUT),
        ("FD_STDERR", ecall::FD_STDERR),
        ("FD_HINT", ecall::FD_HINT),
        ("ZKVM_IO_FIRST", ecall::ZKVM_IO_FIRST),
        ("ZKVM_IO_LAST", ecall::ZKVM_IO_LAST),
        ("PRECOMPILE_FIRST", ecall::PRECOMPILE_FIRST),
        ("PRECOMPILE_LAST", ecall::PRECOMPILE_LAST),
        ("ENOSYS", ecall::ENOSYS),
    ])
}

#[test]
fn the_document_and_the_constants_agree() {
    let doc = document_table();

    for (name, value) in constants_table() {
        let found = doc
            .get(name)
            .unwrap_or_else(|| panic!("docs/spec/ecall-abi.md does not mention `{name}`"));
        assert_eq!(
            *found, value,
            "docs/spec/ecall-abi.md says `{name}` is {found}, constants says {value}"
        );
    }
    for name in doc.keys() {
        assert!(
            constants_table().contains_key(name.as_str()),
            "docs/spec/ecall-abi.md names `{name}`, which is not in constants::ecall"
        );
    }
    assert_eq!(
        doc.len(),
        constants_table().len(),
        "the document and constants::ecall list different numbers"
    );
}

/// Every implemented number carries a nondeterminism class, per must-be-exact 7.
#[test]
fn every_implemented_number_is_classified() {
    let text = document();
    let rows = table_rows(section_of(&text, "## 3. Syscall numbers"));
    assert!(
        rows.len() >= 4,
        "the syscall table parsed to {} rows, so this check is nearly vacuous",
        rows.len()
    );
    for row in rows {
        // `| Number | Constant | Class | What |`
        assert!(
            ["deterministic", "per fd", "advice"].contains(&row[2].as_str()),
            "{}: `{}` is not a nondeterminism class",
            row[1],
            row[2]
        );
    }
    // The classes the document defines are the classes it uses, and it says
    // what an unimplemented number does.
    assert!(
        text.contains("-ENOSYS"),
        "the document must say what an unimplemented number returns"
    );
    for advice in ["getrandom", "clock_gettime", "RandomState"] {
        assert!(
            text.contains(advice),
            "the document must classify {advice}: it is host data, which is prover advice"
        );
    }
}

/// The two non-Linux ranges sit above every Linux number, and are disjoint.
#[test]
fn the_ranges_are_above_linux_and_disjoint() {
    // `const` blocks: these are relations between constants, so a violation
    // should stop the build rather than wait for a test run.
    const {
        assert!(
            ecall::ZKVM_IO_FIRST > 1023,
            "the zkVM range must sit above the whole Linux number space, not \
             just the numbers implemented today"
        );
        assert!(ecall::ZKVM_IO_FIRST <= ecall::ZKVM_IO_LAST);
        assert!(ecall::PRECOMPILE_FIRST <= ecall::PRECOMPILE_LAST);
        assert!(
            ecall::ZKVM_IO_LAST < ecall::PRECOMPILE_FIRST,
            "the two ranges must be disjoint: a reviewer has to tell host \
             advice from a proven function at a glance"
        );
        assert!(
            ecall::PRECOMPILE_FIRST <= ecall::PRECOMPILE_POSEIDON2
                && ecall::PRECOMPILE_POSEIDON2 <= ecall::PRECOMPILE_LAST,
            "every shim must land inside the precompile range"
        );
    }
    assert_eq!(
        (ecall::ZKVM_IO_FIRST, ecall::ZKVM_IO_LAST),
        (0x0400, 0x04FF)
    );
    assert_eq!(
        (ecall::PRECOMPILE_FIRST, ecall::PRECOMPILE_LAST),
        (0x0500, 0x05FF)
    );

    // Every shim lands inside the precompile range.
    assert!(
        (ecall::PRECOMPILE_FIRST..=ecall::PRECOMPILE_LAST).contains(&ecall::PRECOMPILE_POSEIDON2),
        "PRECOMPILE_POSEIDON2 is outside the precompile range"
    );
}

/// The file descriptors are the four the document names, and distinct.
#[test]
fn the_file_descriptors_are_distinct() {
    let fds = [
        ecall::FD_PUBLIC_INPUT,
        ecall::FD_PUBLIC_OUTPUT,
        ecall::FD_STDERR,
        ecall::FD_HINT,
    ];
    assert_eq!(fds, [0, 1, 2, 3]);
    let mut sorted = fds.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), fds.len(), "two descriptors share a number");
}

/// The guest memory map is written down three times. They must agree.
///
/// `link.ld` is what the linker reads, `constants::guest_memory` is what
/// `crates/loader` enforces, and `docs/spec/ecall-abi.md` section 7 is what a
/// reader believes. A map that can disagree with itself is a map that will.
#[test]
fn the_memory_map_agrees_across_its_three_copies() {
    let script = fs::read_to_string(repo_root().join("crates/guest-sdk/link.ld"))
        .expect("crates/guest-sdk/link.ld is readable");
    let memory_line = script
        .lines()
        .find(|l| l.trim_start().starts_with("MEMORY"))
        .expect("link.ld declares a MEMORY region")
        .trim();

    let value = |key: &str| -> u32 {
        let at = memory_line
            .find(key)
            .unwrap_or_else(|| panic!("link.ld's MEMORY line has no {key}"));
        let rest = memory_line[at + key.len()..]
            .trim_start()
            .strip_prefix('=')
            .expect("an ld assignment")
            .trim_start();
        let digits: String = rest
            .strip_prefix("0x")
            .expect("link.ld writes the map in hex")
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        u32::from_str_radix(&digits, 16).expect("a hex literal")
    };

    assert_eq!(value("ORIGIN"), guest_memory::RAM_ORIGIN, "ORIGIN");
    assert_eq!(value("LENGTH"), guest_memory::RAM_LENGTH, "LENGTH");
    assert!(
        document().contains(memory_line),
        "docs/spec/ecall-abi.md must quote link.ld's MEMORY line verbatim, and \
         it does not: `{memory_line}`"
    );

    // The map has to leave room for a program and a stack, and its top has to
    // stay inside the 32-bit address space -- `__stack_top` is ORIGIN + LENGTH.
    const {
        assert!(
            guest_memory::RAM_ORIGIN > 0,
            "address 0 stays unmapped so a null pointer traps"
        );
        assert!(
            (guest_memory::RAM_ORIGIN as u64) + (guest_memory::RAM_LENGTH as u64)
                <= u32::MAX as u64 + 1,
            "the RAM window must fit in the 32-bit address space"
        );
    }
}

/// `guest-sdk`'s shims reach the constants rather than owning a second copy.
#[test]
fn the_shims_use_the_constants() {
    let source = fs::read_to_string(repo_root().join("crates/guest-sdk/src/lib.rs"))
        .expect("crates/guest-sdk/src/lib.rs is readable");

    for name in [
        "ecall::READ",
        "ecall::WRITE",
        "ecall::EXIT",
        "ecall::FD_PUBLIC_INPUT",
        "ecall::FD_PUBLIC_OUTPUT",
        "ecall::FD_STDERR",
        "ecall::FD_HINT",
        "ecall::PRECOMPILE_POSEIDON2",
    ] {
        assert!(
            source.contains(name),
            "guest-sdk does not reference {name}, so either a shim is missing or \
             it spells a number itself"
        );
    }

    // And it spells none of them. The numbers below are the ones a second copy
    // would most plausibly be written as.
    for literal in [" 63", " 64", " 93", "0x0500"] {
        assert!(
            !source.contains(&format!("= {}", literal.trim())),
            "guest-sdk assigns the literal {literal}, which is an ABI number \
             with a home in constants::ecall"
        );
    }
}

/// Master rule 8: the checker above must be able to fail.
///
/// The parsers here are not trivial — `table_rows` drops a header by looking one
/// line ahead, `document_table_of` picks the name cell by an all-caps heuristic
/// and the number cell by first-parse-wins — so a parse that silently yielded
/// nothing would make every comparison vacuous with no test noticing.
#[test]
fn the_document_checker_can_fail() {
    let text = document();
    let good = document_table_of(&text);
    assert_eq!(
        good.len(),
        constants_table().len(),
        "the parser did not find every documented constant"
    );

    // A wrong number.
    let wrong = text.replace("| 93 | `EXIT`", "| 94 | `EXIT`");
    assert_ne!(
        wrong, text,
        "the syscall table no longer spells EXIT that way"
    );
    assert_eq!(
        document_table_of(&wrong).get("EXIT"),
        Some(&94),
        "the parser did not see the changed number"
    );
    assert_ne!(
        document_table_of(&wrong)["EXIT"],
        ecall::EXIT,
        "a wrong number in the document must not match the constant"
    );

    // A deleted row.
    let missing = text.replace("| 63 | `READ` | per fd |", "");
    assert_ne!(
        missing, text,
        "the syscall table no longer spells READ that way"
    );
    assert!(
        !document_table_of(&missing).contains_key("READ"),
        "deleting a row must remove it from the parse"
    );

    // A wrong classification.
    let unclassified = text.replace("| 93 | `EXIT` | deterministic |", "| 93 | `EXIT` | free |");
    assert_ne!(unclassified, text);
    assert!(
        table_rows(section_of(&unclassified, "## 3. Syscall numbers"))
            .iter()
            .any(|row| row[2] == "free"),
        "the classification check reads a cell that a wrong document can change"
    );

    // A document with no tables at all parses to nothing, rather than to
    // something that happens to agree.
    assert!(document_table_of("# a document with no tables\n").is_empty());
}

// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn document() -> String {
    let path = repo_root().join("docs/spec/ecall-abi.md");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Every `` `NAME` `` in a table row, paired with the number in that row.
///
/// The document writes numbers as decimal or as `0x0400`; both are accepted,
/// because the ranges read better in hex and the Linux numbers read better in
/// decimal.
fn document_table() -> BTreeMap<String, u32> {
    document_table_of(&document())
}

fn document_table_of(text: &str) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    for row in table_rows(text) {
        let mut number: Option<u32> = None;
        let mut name: Option<String> = None;
        for cell in &row {
            if let Some(v) = parse_number(cell) {
                number = number.or(Some(v));
            }
            if let Some(ident) = cell.strip_prefix('`').and_then(|c| c.strip_suffix('`')) {
                let shouty = ident.starts_with(|c: char| c.is_ascii_uppercase())
                    && ident
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
                if shouty && ident.len() > 2 {
                    name = Some(ident.to_string());
                }
            }
        }
        if let (Some(number), Some(name)) = (number, name) {
            assert!(
                out.insert(name.clone(), number).is_none(),
                "docs/spec/ecall-abi.md names `{name}` in two rows"
            );
        }
    }
    out
}

fn parse_number(cell: &str) -> Option<u32> {
    let cell = cell.trim();
    match cell.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => cell.parse().ok(),
    }
}

/// The cells of every markdown table **body** row.
///
/// A markdown table's header is the row immediately above its `| --- |`
/// separator, so both are dropped by looking one line ahead.
fn table_rows(text: &str) -> Vec<Vec<String>> {
    let cells = |line: &str| -> Vec<String> {
        line.trim()
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_string())
            .collect()
    };
    let is_separator = |line: &str| {
        cells(line)
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-'))
    };

    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.trim_start().starts_with('|') || is_separator(line) {
            continue;
        }
        // The header row, identified by the separator beneath it.
        if lines
            .get(i + 1)
            .is_some_and(|next| next.trim_start().starts_with('|') && is_separator(next))
        {
            continue;
        }
        out.push(cells(line));
    }
    out
}

fn section_of<'a>(text: &'a str, heading: &str) -> &'a str {
    let start = text
        .find(heading)
        .unwrap_or_else(|| panic!("docs/spec/ecall-abi.md has no section `{heading}`"));
    let rest = &text[start + heading.len()..];
    match rest.find("\n## ") {
        Some(end) => &rest[..end],
        None => rest,
    }
}
