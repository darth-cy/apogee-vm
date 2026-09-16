//! Acceptance 10, the dump: the page names the header, every committed column
//! and virtual table, every layer, every relation, every address the toy uses
//! and the gate catalogue, and prints exactly one line per gate shape, the
//! cached entry, a scratch-bijection line and an output-map line. And the
//! `checker` CLI, run as a binary.

mod common;

use std::process::{Command, Output};

use checker::dump;
use common::*;
use constraints::{Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};
use field::Fr;

#[test]
fn the_dump_names_everything_in_the_toy() {
    for (label, a) in toys() {
        let text = dump(&a);
        let lines: Vec<&str> = text.lines().collect();
        let has_line = |line: &str| lines.contains(&line);
        let header = [
            "circuit artifact",
            "  format version        1",
            "  coefficient encoding  0 (every Fr canonical 32-byte little-endian)",
            "  trace length          2^4 rows",
            "  depth                 3 gate lists",
        ];
        let columns = [
            "  M[0]  m",
            "  W[0]  a",
            "  W[1]  b",
            "  W[2]  c",
            "  W[3]  e",
            "  S[0]  s",
            "  V[row]  row",
        ];
        let layers = [
            "layer 0  base  2^4 rows, width 6",
            "gate list 0  row-wise, layer 0 -> layer 1",
            "layer 1  row-wise  2^4 rows, width 3",
            "gate list 1  row-wise, layer 1 -> layer 2",
            "layer 2  row-wise  2^4 rows, width 2",
            "gate list 2  halving, layer 2 -> layer 3",
            "layer 3  halving, top  2^3 rows, width 2",
        ];
        let catalogue = [
            "  0 Linear",
            "  1 Product",
            "  2 MaskIntoIdentity",
            "  3 AffineProduct",
            "  4 TreeProduct",
            "  5 Quadratic",
        ];
        for line in header
            .iter()
            .chain(&columns)
            .chain(&layers)
            .chain(&catalogue)
        {
            assert!(has_line(line), "{label}: no line {line:?} in\n{text}");
        }
        let relations = [
            "define_ab",
            "define_fingerprint",
            "define_masked_m",
            "gated_equality",
            "define_abm",
            "define_fingerprint3",
            "define_abm_product",
            "define_fingerprint3_product",
        ];
        for (r, name) in relations.iter().enumerate() {
            assert!(text.contains(&format!("  {r} {name}: ")), "{label}: {name}");
            assert!(
                text.contains(&format!("[relation {r} {name}]")),
                "{label}: {name}"
            );
        }
        let mut addresses = vec!["M[0]", "W[0]", "W[1]", "W[2]", "W[3]", "S[0]", "V[row]"];
        addresses.extend([
            "L{1}[0]", "L{1}[1]", "L{1}[2]", "L{2}[0]", "L{2}[1]", "L{3}[0]",
        ]);
        addresses.extend(["L{3}[1]", "scratch[0]", "scratch[3]", "scratch[6]"]);
        if label == "cached" {
            addresses.push("C{0}[0]");
        }
        for address in addresses {
            assert!(text.contains(address), "{label}: no {address}");
        }
        // One line per gate shape, then a bijection line and an output line.
        // The `Quadratic` lines, the gated equality's gate and its relation,
        // kill a formula that drops a product's coefficient or a factor, or
        // the constant: its terms print in field order, never simplified.
        let mut exact = vec![
            "  L{2}[1](x) = Σ_y eq(x, y) · (1·L{1}[1] + 3)   [relation 5 define_fingerprint3]",
            "  L{1}[0](x) = Σ_y eq(x, y) · 1·W[0]·W[1]   [relation 0 define_ab]",
            "  L{1}[2](x) = Σ_y eq(x, y) · (M[0]·S[0] + 1 − S[0])   [relation 2 define_masked_m]",
            "  0 = (0 + 1·W[3]·S[0] + -1·W[0]·S[0])   for every y   [relation 3 gated_equality]",
            "  3 gated_equality: 0 = (0 + 1·W[3]·S[0] + -1·W[0]·S[0])   for every y",
            "  L{3}[0](x) = Σ_y eq(x, y) · L{2}[0](y, 0)·L{2}[0](y, 1)   [relation 6 define_abm_product]",
            "  scratch[0] = L{1}[0]  ab",
            "  0  L{3}[1]  fingerprint3_product",
        ];
        if label == "cached" {
            exact.push("  C{0}[0](y) = (toy·W[0] + 1·V[row] + 0)   [cached shifted_a]");
        }
        for line in exact {
            assert!(has_line(line), "{label}: no line {line:?} in\n{text}");
        }
    }
}

/// A literal at or above `2^64` prints as hex, even when its low eight bytes
/// alone are a small number.
#[test]
fn a_large_literal_is_not_read_from_its_low_bytes() {
    let mut a = load(CACHE_FREE);
    let value = (1u128 << 64) + 5;
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&value.to_le_bytes());
    *linear(&mut a.layers[1].producing[1].gate).1 = Coeff::Literal(Fr::from_bytes(&bytes).unwrap());
    let line = format!(
        "  L{{2}}[1](x) = Σ_y eq(x, y) · (1·L{{1}}[1] + 0x{value:064x})   [relation 5 define_fingerprint3]"
    );
    let text = dump(&a);
    assert!(
        text.lines().any(|l| l == line),
        "no line {line:?} in\n{text}"
    );
}

/// A negated literal as `-k`, a large one as 64 hex digits, a challenge by name.
#[test]
fn coefficients_render_one_way() {
    let mut a = load(CACHE_FREE);
    let (terms, constant) = linear(&mut a.layers[1].producing[1].gate);
    terms[0].0 = Coeff::Literal(-Fr::from_u64(7));
    *constant = Coeff::Literal(Fr::from_u64(1 << 40));
    let line = format!(
        "  L{{2}}[1](x) = Σ_y eq(x, y) · (-7·L{{1}}[1] + 0x{:064x})   [relation 5 define_fingerprint3]",
        1u64 << 40
    );
    let text = dump(&a);
    assert!(
        text.lines().any(|l| l == line),
        "no line {line:?} in\n{text}"
    );
    assert!(text.contains("(toy·W[0] + 1·V[row] + 0)·(1·W[2] + 0)"));
}

/// A lookup prints its name, its channel's number and name, its selector and
/// its tuple, each expression in the one formula notation; an unknown channel
/// prints as `?` rather than panicking.
#[test]
fn a_lookup_prints_its_channel_selector_and_tuple() {
    let mut a = load(CACHED);
    a.lookups.push(LookupExpr {
        name: "range".into(),
        channel: 0,
        selector: M0,
        tuple: vec![GateDef::Linear {
            terms: vec![
                (lit(4), W0),
                (
                    Coeff::Literal(-Fr::ONE),
                    PolyAddress::Virtual(VirtualKind::RamLive),
                ),
            ],
            constant: lit(0),
        }],
    });
    let text = dump(&a);
    for line in [
        "lookups (1)",
        "  range channel 0 timestamp, selector M[0]: ((4·W[0] + -1·V[ram_live] + 0))",
    ] {
        assert!(
            text.lines().any(|l| l == line),
            "no line {line:?} in\n{text}"
        );
    }
    a.lookups[0].channel = 9;
    assert!(dump(&a).contains("  range channel 9 ?, selector M[0]: "));
}

#[test]
fn a_lawless_artifact_still_dumps() {
    let mut a = load(CACHED);
    a.layers[0].producing[0].relation = 99;
    a.outputs.push(inner(9, 9));
    a.padding.row.push(Fr::ONE);
    let text = dump(&a);
    assert!(text.contains("[relation 99 ?]"));
    assert!(text.contains("  2  L{9}[9]  ?"));
    assert!(text.contains("?[6] = 1"));
}

fn checker(args: &[&str]) -> Output {
    let binary = env!("CARGO_BIN_EXE_checker");
    Command::new(binary)
        .args(args)
        .output()
        .expect("running checker")
}

#[test]
fn the_cli_passes_both_fixtures_and_prints_the_dump() {
    for path in [CACHED, CACHE_FREE] {
        for command in ["laws", "padding"] {
            let out = checker(&[command, path]);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "{command} {path}: {stderr}");
        }
        let out = checker(&["dump", path]);
        assert!(out.status.success());
        assert_eq!(String::from_utf8(out.stdout).unwrap(), dump(&load(path)));
    }
}

#[test]
fn the_cli_fails_on_a_corrupted_or_lawless_file() {
    let dir = env!("CARGO_TARGET_TMPDIR");
    let mut bytes = std::fs::read(CACHED).unwrap();
    // The last byte is `zero_row_valid`, written as 1; 0xfe is no boolean.
    *bytes.last_mut().unwrap() ^= 0xff;
    let corrupted = format!("{dir}/checker-corrupted.bin");
    std::fs::write(&corrupted, &bytes).unwrap();
    for command in ["laws", "padding", "dump"] {
        assert_eq!(
            checker(&[command, &corrupted]).status.code(),
            Some(1),
            "{command}"
        );
    }

    let mut a = load(CACHED);
    a.layers[0].width = 4;
    let lawless = format!("{dir}/checker-lawless.bin");
    std::fs::write(&lawless, a.to_bytes()).unwrap();
    let out = checker(&["laws", &lawless]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Law 2 (derived width)"));

    assert_eq!(checker(&["laws"]).status.code(), Some(2));
    assert_eq!(checker(&["prove", CACHED]).status.code(), Some(2));
}
