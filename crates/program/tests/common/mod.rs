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
pub const GUESTS: [&str; 19] = [
    "fib",
    "echo",
    "rvc-dense",
    "amm",
    "orderbook",
    "vault",
    "atomics",
    "opcodes",
    "heap",
    "consistency",
    "addsub",
    "control",
    "alu",
    "mem",
    "shards",
    "keccak-test",
    "keccak-unused",
    "ecrecover-test",
    "ecrecover-fail",
];

/// The guests whose image declares a delegation family, and which
/// (`docs/spec/delegation.md` §7). Every other guest declares none, which is
/// what `tests/delegation.rs` holds them to.
/// **Ascending by family id within a guest**, which is the order
/// `declared_delegations` returns.
///
/// The two S22 guests declare **both** families: `guest_sdk::ecrecover`
/// derives its address through `guest_sdk::keccak256`
/// (`docs/spec/ecrecover.md` §1.1), so linking the one shim makes the other
/// reachable. That is detachment working, not leaking — the keccak path is
/// genuinely called — and it is why the two records need **separate**
/// `link_section` names: `--gc-sections` collects at section granularity, so
/// records sharing one output section are kept or dropped together, and
/// `keccak-test` declared `ECRECOVER` until they were split.
pub const DECLARING_GUESTS: [(&str, u32); 6] = [
    ("keccak-test", family::KECCAK_F),
    ("keccak-unused", family::KECCAK_F),
    ("ecrecover-test", family::KECCAK_F),
    ("ecrecover-test", family::ECRECOVER),
    ("ecrecover-fail", family::KECCAK_F),
    ("ecrecover-fail", family::ECRECOVER),
];

/// This crate's committed fixtures and their digests. Refresh with
/// `cargo run -p kat-gen -- program`, which prints them; the identity and
/// generic-table files need the ceremony file.
pub const PINS: [(&str, &str); 3] = [
    (
        "mul_free.elf",
        "17a27f6ea5370cd865bb08afa7b2796274b41f0ede49f63d11a6314d7b4477fb",
    ),
    (
        "identity.txt",
        "5a0e27eaae71ef17e70594d0bb47b143f569bbdb705e63a0e539fcfe4b381745",
    ),
    (
        "generic_table.txt",
        "3c813459777d65a46855ddb763683714ea3fab182e0ffcba69fb6f74673c7b29",
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
/// Since S21 the menu opens with `2^8`, `KECCAK_F`'s height: a delegation
/// family's rows are invocations, not halfwords, so 256 rows is a sensible
/// table there and no guest's code fits in 256 halfwords anywhere else
/// (`docs/spec/delegation.md` §9). The floor for an instruction table is
/// therefore the menu's *second* entry, and the tests below spell that height
/// out in their own arithmetic — pc `0x1fffe` is row 65535 — so it is
/// asserted here rather than left to an index. A 2^16 table is cheap enough
/// to export in full, and every committed guest but `consistency` fits in
/// one.
pub fn smallest() -> ProgramParams {
    let height = family::HEIGHT_MENU[1];
    assert_eq!(height, 1 << 16, "the menu's second entry is no longer 2^16");
    ProgramParams {
        heights: [height; family::COUNT as usize],
        ..ProgramParams::defaults()
    }
}

/// Every family at the smallest menu height this image's code fits in.
///
/// A table's rows are absolute pcs, one per halfword, so a family's height has
/// to reach past its last instruction — and the heights are per family, which
/// makes the *smallest* family's the binding one. `guests/consistency` is
/// 1.7 MB of code with an `Arc` in it, so its atomics run up to pc `0x18e62a`,
/// and neither `smallest()` (2^16 rows, pc below `0x20000`) nor the frozen
/// defaults (2^16 for atomics) can hold them; a uniform 2^20 can. The S12 handoff records that as
/// an open question about the defaults; a test that is not *about* the heights
/// takes the ones that fit.
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

/// `generic_table.txt` as `(ceremony, [commitment hex; 3])`.
pub fn pinned_generic_table() -> (String, Vec<String>) {
    let text = String::from_utf8(own_vector("generic_table.txt")).expect("UTF-8");
    let ceremony = text
        .lines()
        .find_map(|l| l.strip_prefix("# ceremony "))
        .expect("generic_table.txt names its ceremony")
        .to_string();
    let rows: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .collect();
    assert_eq!(rows.len(), 1, "one row: the three commitments");
    let points = rows[0].split_whitespace().map(|x| x.to_string()).collect();
    (ceremony, points)
}

/// Build one guest from source into a fresh target directory, the way
/// `crates/loader/tests/common` does and for the same reasons: nothing from the
/// ambient environment reaches rustc, because the bytes are compared.
pub fn build(name: &str, slot: &str) -> Vec<u8> {
    build_profile(name, slot, "debug")
}

/// The same, at `profile` — `debug` or `release`.
///
/// `guests/Cargo.toml` pins both profiles to the same semantics and they differ
/// only in `opt-level`, which is exactly what makes the second one worth
/// building here: S21's declaration record is kept by **reachability**, and at
/// `opt-level = 3` LLVM will fold a constant read into an immediate and drop
/// the record unless something stops it (`docs/spec/delegation.md` §7).
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
