//! Fixture plumbing for `crates/program`'s suites.
//!
//! The guest ELFs are `crates/loader`'s committed fixtures, pinned there, and
//! the ISA corpus is `crates/isa`'s; this crate reads both in place rather than
//! keeping second copies. Its own fixtures live in `tests/vectors/` and are
//! pinned by SHA-256 in [`PINS`].

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use constants::family;
use loader::{load_elf, ProgramImage, Segment, Slot};
use program::{decode_program, ProgramParams};
use test_support::{sha256, to_hex};

/// Every guest with a committed ELF, in `guests/Cargo.toml`'s order.
pub const GUESTS: [&str; 14] = [
    "fib",
    "echo",
    "rvc-dense",
    "amm",
    "orderbook",
    "vault",
    "atomics",
    "opcodes",
    "heap",
    "addsub",
    "control",
    "alu",
    "mem",
    "shards",
];

/// This crate's committed fixtures and their digests. Refresh with
/// `cargo run -p kat-gen -- program`, which prints them.
pub const PINS: [(&str, &str); 2] = [
    (
        "mul_free.elf",
        "17a27f6ea5370cd865bb08afa7b2796274b41f0ede49f63d11a6314d7b4477fb",
    ),
    (
        "identity.txt",
        "0748de53892a494fe855fceb02eddf928a5431a3331e39b824b96c69dd81dd76",
    ),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: PathBuf) -> Vec<u8> {
    fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

pub fn loader_vector(name: &str) -> Vec<u8> {
    read(root().join("crates/loader/tests/vectors").join(name))
}

pub fn isa_vector(name: &str) -> Vec<u8> {
    read(root().join("crates/isa/tests/vectors").join(name))
}

pub fn own_vector(name: &str) -> Vec<u8> {
    read(root().join("crates/program/tests/vectors").join(name))
}

pub fn digest(bytes: &[u8]) -> String {
    to_hex(&sha256(bytes))
}

/// A committed guest, loaded.
pub fn guest(name: &str) -> ProgramImage {
    load_elf(&loader_vector(&format!("{name}.elf"))).unwrap_or_else(|e| panic!("{name}: {e:?}"))
}

/// Every instruction slot of an image, as `(pc, word, compressed)`.
pub fn instructions(image: &ProgramImage) -> Vec<(u32, u32, bool)> {
    image
        .slots
        .iter()
        .enumerate()
        .filter_map(|(i, slot)| match *slot {
            Slot::Instruction { word, compressed } => {
                Some((image.slot_base + 2 * i as u32, word, compressed))
            }
            _ => None,
        })
        .collect()
}

/// Every family at the smallest menu height a *decoded* table can take.
///
/// The menu opens with `2^12`, the two public-value families' pinned height,
/// and no guest's code fits in a table that short. The floor for an
/// instruction table is therefore the menu's *second* entry, and the tests
/// below spell that height out in their own arithmetic — pc `0x1fffe` is row
/// 65535 — so it is asserted here rather than left to an index. A 2^16 table
/// is cheap enough to export in full, and every committed guest fits in one.
pub fn smallest() -> ProgramParams {
    let height = family::HEIGHT_MENU[1];
    assert_eq!(height, 1 << 16, "the menu's second entry is not 2^16");
    ProgramParams {
        heights: [height; family::COUNT as usize],
        ..ProgramParams::defaults()
    }
}

/// Every family at the smallest menu height this image's code fits in.
///
/// A table's rows are absolute pcs, one per halfword, so a family's height has
/// to reach past its last instruction — and the heights are per family, which
/// makes the *smallest* family's the binding one. A test that is not *about*
/// the heights takes the ones that fit.
pub fn fitting(image: &ProgramImage) -> ProgramParams {
    for &height in &family::HEIGHT_MENU {
        let params = ProgramParams {
            heights: [height; family::COUNT as usize],
            ..ProgramParams::defaults()
        };
        if decode_program(image, &params).is_ok() {
            return params;
        }
    }
    panic!("no menu height holds this image's code")
}

/// A one-segment image of 32-bit `words` at `at`, built by hand.
pub fn image_of(at: u32, words: &[u32]) -> ProgramImage {
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut slots = Vec::new();
    for word in words {
        slots.push(Slot::Instruction {
            word: *word,
            compressed: false,
        });
        slots.push(Slot::MidInstruction);
    }
    ProgramImage {
        entry: at,
        segments: vec![Segment {
            vaddr: at,
            mem_len: bytes.len() as u32,
            bytes,
        }],
        slot_base: at,
        slots,
    }
}

/// `identity.txt` as `[(label, identity hex)]`.
pub fn pinned_identities() -> Vec<(String, String)> {
    let text = String::from_utf8(own_vector("identity.txt")).expect("UTF-8");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            assert_eq!(f.len(), 3, "an identity row is guest, parameters, identity");
            (format!("{} {}", f[0], f[1]), f[2].to_string())
        })
        .collect()
}

/// Build one guest from source into a fresh target directory, the way
/// `crates/loader/tests/common` does and for the same reasons: nothing from the
/// ambient environment reaches rustc, because the bytes are compared.
pub fn build(name: &str, slot: &str) -> Vec<u8> {
    build_profile(name, slot, "debug")
}

/// The same, at `profile` — `debug` or `release`.
///
/// `guests/Cargo.toml` pins both profiles to the same semantics; they differ in
/// `opt-level`.
pub fn build_profile(name: &str, slot: &str, profile: &str) -> Vec<u8> {
    let guest_dir = root().join("guests").join(name);
    let target_dir = std::env::temp_dir().join(format!("apogee-program-{slot}-{name}"));
    let _ = fs::remove_dir_all(&target_dir);
    let mut command = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(&guest_dir)
        .args(["build", "--target", "riscv32imac-unknown-none-elf"])
        .env("CARGO_TARGET_DIR", &target_dir);
    if profile == "release" {
        command.arg("--release");
    }
    for key in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        command.env_remove(key);
    }
    let out = command.output().expect("running cargo for a guest");
    assert!(
        out.status.success(),
        "{name}: guest build failed\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = read(
        target_dir
            .join(format!("riscv32imac-unknown-none-elf/{profile}"))
            .join(name),
    );
    let _ = fs::remove_dir_all(&target_dir);
    bytes
}
