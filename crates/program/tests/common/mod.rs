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
use program::ProgramParams;
use test_support::{sha256, to_hex};

/// Every guest with a committed ELF, in `guests/Cargo.toml`'s order.
pub const GUESTS: [&str; 7] = [
    "fib",
    "echo",
    "rvc-dense",
    "amm",
    "orderbook",
    "vault",
    "atomics",
];

/// This crate's committed fixtures and their digests. Refresh with
/// `cargo run -p kat-gen -- program`, which prints them; the identity file
/// needs the ceremony file.
pub const PINS: [(&str, &str); 2] = [
    (
        "mul_free.elf",
        "17a27f6ea5370cd865bb08afa7b2796274b41f0ede49f63d11a6314d7b4477fb",
    ),
    (
        "identity.txt",
        "5bae46b1f978bdd29c686a6a18781af4619f3f8e40fa13c40693f8d09936fba5",
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

/// Every family at the smallest menu height. Every committed guest fits, and
/// a 2^16 table is cheap enough to export in full.
pub fn smallest() -> ProgramParams {
    ProgramParams {
        heights: [family::HEIGHT_MENU[0]; family::COUNT as usize],
        ..ProgramParams::defaults()
    }
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

/// The ceremony file every identity is taken over.
///
/// Panics when it is absent: the tests that call this are `#[ignore]`d, so
/// reaching here means someone asked for them, and a silent pass would report
/// coverage that did not happen.
pub fn ptau() -> PathBuf {
    let path = root().join("assets/ptau/ppot_0080_24.ptau");
    assert!(
        path.exists(),
        "{} is absent. The identity tests need PSE's ceremony file, contribution \
         80, power 24; docs/handoff/S07-msm-srs-kzg.md has the download command.",
        path.display()
    );
    path
}

/// `identity.txt` as `(ceremony, [(label, identity hex)])`.
pub fn pinned_identities() -> (String, Vec<(String, String)>) {
    let text = String::from_utf8(own_vector("identity.txt")).expect("UTF-8");
    let ceremony = text
        .lines()
        .find_map(|l| l.strip_prefix("# ceremony "))
        .expect("identity.txt names its ceremony")
        .to_string();
    let rows = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            assert_eq!(f.len(), 3, "an identity row is guest, parameters, identity");
            (format!("{} {}", f[0], f[1]), f[2].to_string())
        })
        .collect();
    (ceremony, rows)
}

/// Build one guest from source into a fresh target directory, the way
/// `crates/loader/tests/common` does and for the same reasons: nothing from the
/// ambient environment reaches rustc, because the bytes are compared.
pub fn build(name: &str, slot: &str) -> Vec<u8> {
    let guest_dir = root().join("guests").join(name);
    let target_dir = std::env::temp_dir().join(format!("apogee-program-{slot}-{name}"));
    let _ = fs::remove_dir_all(&target_dir);
    let mut command = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(&guest_dir)
        .args(["build", "--target", "riscv32imac-unknown-none-elf"])
        .env("CARGO_TARGET_DIR", &target_dir);
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
            .join("riscv32imac-unknown-none-elf/debug")
            .join(name),
    );
    let _ = fs::remove_dir_all(&target_dir);
    bytes
}
