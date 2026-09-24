//! Fixture plumbing for `crates/loader`'s suites.
//!
//! Every committed fixture is pinned by SHA-256 in [`PINS`], in source, so a
//! hand-edited fixture fails the build and a deliberate refresh is a code edit
//! a reviewer can see. Refresh is:
//!
//! ```text
//! cargo run -p kat-gen -- guests    # the guest ELFs; one machine, deliberately
//! cargo run -p kat-gen -- loader    # everything derived from them
//! ```
//!
//! and then the digests those commands print go here.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use loader::{ProgramImage, Slot};
use test_support::{sha256, to_hex};

/// Every committed fixture, and the digest it must have.
///
/// The synthetic ELFs are not listed one by one: `synthetic_elfs.txt` carries
/// their digests and is itself pinned here, so the chain is one constant long
/// either way and the index stays readable.
pub const PINS: [(&str, &str); 23] = [
    (
        "fib.elf",
        "2cbe471d2da09e38d0c999612c0c60c84cffaaa027438d7b970a56dc258b40d3",
    ),
    (
        "echo.elf",
        "936d7c9ab23c0f30639ce5d3b98f99765aed7af00d8068e80fad5d5ed3414c6c",
    ),
    (
        "rvc-dense.elf",
        "fb4d520dfbcb79f43d26ea8670275e17e968964aece9309e3dc1f7c27baa2c32",
    ),
    (
        "amm.elf",
        "9f375b816f867b681ced96a6c2c6c136615cb74ee412c0cbf0bf1fae0e32df2a",
    ),
    (
        "orderbook.elf",
        "d292d9c8339cba67fed4caf8d3542472b7ef7054b549ddf2ab9445dbbf504196",
    ),
    (
        "vault.elf",
        "55470ac1379796ac8a824ae9bb051b100dedc2d45e5f2ed120d52ae2ef458b42",
    ),
    (
        "atomics.elf",
        "7675258a42b02b91adc68dc806c4c2724ec640c867b192d1166c559380ece920",
    ),
    (
        "opcodes.elf",
        "3794448bf3b6c4087325301e7bc6c8c4c69f08928a349470c52b63a12fd13ba5",
    ),
    (
        "heap.elf",
        "f6c7d7609bb4063cf2793ce937df9865b4b61f24f11b84d804aed5350af9b293",
    ),
    (
        "consistency.elf",
        "a191dcdeb94e2898357ac1fcf79a7720e493c5f02a9e94e80ebe5530ba495e7e",
    ),
    (
        "addsub.elf",
        "587f6bd45be8f242015a8870be2b765ede1e87d94219758dc9bc996a38827145",
    ),
    (
        "control.elf",
        "88f5b0ccf00b889c50ec81892a44550b5d19bde75f5fa388cea4027898aecdaa",
    ),
    (
        "alu.elf",
        "32f85c1799425f5de1a0ac04368e1e6b952289627710b804202f53895dccc168",
    ),
    (
        "mem.elf",
        "c8b5d5e79fa11571661cf11258ebee8cb450e7de8b9043d55b46d45a8f2d9dc1",
    ),
    (
        "fib.objdump.txt",
        "ef8432ea4eec4ddcbb73a6a133d28cb9b7526668a52f1ce101a0c0cb8074cd45",
    ),
    (
        "rvc-dense.objdump.txt",
        "375c39ebb1e7ea5d27e4fb155cdf42e779fdc984899a81e51d03eeab3a838538",
    ),
    (
        "amm.objdump.txt",
        "8fc60e80a1de1914f6e08ad2f75ac9ffd9e7b804fcb107f945392eb5678ce0ad",
    ),
    (
        "rvc-dense.nm.txt",
        "bfb63e4e814055732cb361916c34202250f52ad8d67ce4f351fd69d444acf336",
    ),
    (
        "shards.elf",
        "6b05f589f3726b8f7b42cd67547227a23640041eefa2e66d5277618735d34241",
    ),
    (
        "keccak-test.elf",
        "368a0aa51208a4e52ab42c5fc8fd35c4172c3646cb165311f56144e5e1989c62",
    ),
    (
        "keccak-unused.elf",
        "6c3ea1de6f1fc2e871cc94bad83cd532139075d281a00176459367296d32d455",
    ),
    (
        "recursion-ops.elf",
        "05b8555a4d5d2e231c948d935fd99e9120bec5700c050188ddf17b2ed5ace943",
    ),
    (
        "recursion-unused.elf",
        "58a4f00dc80e822ce46fd9ca74d84d74a7e92d33dff5ceb7d4aa58d84d09ded4",
    ),
];

pub fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

pub fn bytes(name: &str) -> Vec<u8> {
    let path = vectors_dir().join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

pub fn text(name: &str) -> String {
    String::from_utf8(bytes(name)).expect("a committed listing is UTF-8")
}

pub fn digest(name: &str) -> String {
    to_hex(&sha256(&bytes(name)))
}

/// One synthetic ELF, checked against the digest `synthetic_elfs.txt` records.
///
/// The index is itself pinned in [`PINS`]'s sibling test, so editing a
/// synthetic fixture means editing both files and a source constant.
pub fn synthetic(name: &str) -> Vec<u8> {
    let want = synthetic_index()
        .remove(name)
        .unwrap_or_else(|| panic!("{name} is not in synthetic_elfs.txt"));
    let file = bytes(name);
    assert_eq!(
        to_hex(&sha256(&file)),
        want,
        "{name} does not match the digest synthetic_elfs.txt records"
    );
    file
}

pub fn synthetic_index() -> BTreeMap<String, String> {
    rows("synthetic_elfs.txt")
        .into_iter()
        .map(|f| (f[0].clone(), f[1].clone()))
        .collect()
}

/// Every non-comment, non-blank line of a listing, split on whitespace.
pub fn rows(name: &str) -> Vec<Vec<String>> {
    text(name)
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split_whitespace().map(str::to_string).collect())
        .collect()
}

/// One line of an objdump listing: address, raw encoding, width in bytes.
pub type Disassembled = (u32, u32, usize);

/// One instruction of the image: address, expanded word, whether it was 16-bit.
pub type Expanded = (u32, u32, bool);

/// `<name>.objdump.txt` as `(address, encoding)` pairs.
///
/// The disassembly text is deliberately dropped here: the differential is
/// about addresses and encodings, and comparing mnemonics would be comparing
/// two spellings of the same table rather than two computations.
pub fn objdump(name: &str) -> Vec<Disassembled> {
    rows(&format!("{name}.objdump.txt"))
        .iter()
        .map(|f| {
            let addr = u32::from_str_radix(&f[0], 16).expect("an objdump address is hex");
            let encoding = u32::from_str_radix(&f[1], 16).expect("an objdump encoding is hex");
            (addr, encoding, f[1].len() / 2)
        })
        .collect()
}

/// `<name>.nm.txt` as `symbol -> address`.
pub fn nm(name: &str) -> BTreeMap<String, u32> {
    rows(&format!("{name}.nm.txt"))
        .iter()
        .map(|f| {
            (
                f[1].clone(),
                u32::from_str_radix(&f[0], 16).expect("an nm address is hex"),
            )
        })
        .collect()
}

/// The bytes an instruction actually occupies in the image, as an integer.
///
/// Read back out of the loaded segments rather than remembered by the slot:
/// the slot holds the *expansion*, and the differential is about the original.
pub fn original_encoding(image: &ProgramImage, pc: u32, width: usize) -> u32 {
    for segment in &image.segments {
        let lo = segment.vaddr;
        let hi = segment.vaddr + segment.bytes.len() as u32;
        if pc >= lo && pc + width as u32 <= hi {
            let at = (pc - lo) as usize;
            let mut value = 0u32;
            for (i, b) in segment.bytes[at..at + width].iter().enumerate() {
                value |= (*b as u32) << (8 * i);
            }
            return value;
        }
    }
    panic!("no loaded segment holds {width} bytes at {pc:#010x}");
}

/// The instructions in `[begin, end)`, in address order, as
/// `(address, expanded word, compressed)`.
pub fn instructions_in(image: &ProgramImage, begin: u32, end: u32) -> Vec<Expanded> {
    let mut out = Vec::new();
    let mut pc = begin;
    while pc < end {
        match image.slot_at(pc) {
            Some(Slot::Instruction { word, compressed }) => {
                out.push((pc, word, compressed));
                pc += if compressed { 2 } else { 4 };
            }
            other => panic!("{pc:#010x} is {other:?}, not the start of an instruction"),
        }
    }
    assert_eq!(pc, end, "the last instruction runs past {end:#010x}");
    out
}

/// The frozen wire form: `postcard` over the image.
///
/// `postcard` is taken with no features, so there is no `to_allocvec`; the
/// buffer is a heap `Vec` sized from the image and `to_slice` writes into it.
/// Keeping the feature graph as S01 froze it is worth four lines here.
pub fn to_postcard(image: &ProgramImage) -> Vec<u8> {
    let bound = 64
        + image.slots.len() * 8
        + image
            .segments
            .iter()
            .map(|s| s.bytes.len() + 32)
            .sum::<usize>();
    let mut buf = vec![0u8; bound];
    let used = postcard::to_slice(image, &mut buf).expect("the buffer bound holds");
    used.to_vec()
}

/// Build one guest into a fresh target directory and return its ELF bytes.
///
/// The command is acceptance 1's, typed out: nothing but `cargo build --target
/// riscv32imac-unknown-none-elf`, from the guest's own directory, with the
/// target, the runner and the linker flags coming from
/// `guests/.cargo/config.toml`.
///
/// Everything that could reach rustc from the ambient environment is cleared,
/// because a guest ELF is an artifact whose bytes get compared and a stray
/// `RUSTFLAGS` would make the comparison meaningless.
pub fn build(name: &str, slot: &str) -> Vec<u8> {
    build_profile(name, slot, "debug")
}

/// The profile the behaviour suite builds at: `debug`, unless
/// `APOGEE_GUEST_PROFILE` names another.
///
/// `guests/Cargo.toml` pins dev and release to the same *semantics* -- release
/// keeps `overflow-checks` and `debug-assertions` on -- so every test that
/// witnesses behaviour must give the same answer under either. CI runs
/// `tests/qemu.rs` twice, once per profile, which is what holds that pin
/// honest: unpinned, a release guest commits a wrapped `u32` on fd 1 where a
/// dev guest panics.
///
/// Only the QEMU suite reads this. `layout.rs` and `reproducible.rs` stay on
/// debug deliberately -- they are about the committed artifacts, which are dev
/// builds.
pub fn profile() -> String {
    std::env::var("APOGEE_GUEST_PROFILE").unwrap_or_else(|_| "debug".into())
}

/// [`build`], at a named cargo profile: `debug` or `release`.
pub fn build_profile(name: &str, slot: &str, profile: &str) -> Vec<u8> {
    assert!(
        matches!(profile, "debug" | "release"),
        "unknown guest profile {profile:?}: expected \"debug\" or \"release\""
    );
    let guest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../guests")
        .join(name);
    let target_dir = std::env::temp_dir().join(format!("apogee-{slot}-{profile}-{name}"));
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

    let elf = target_dir
        .join("riscv32imac-unknown-none-elf")
        .join(profile)
        .join(name);
    let bytes = fs::read(&elf).unwrap_or_else(|e| panic!("reading {}: {e}", elf.display()));
    let _ = fs::remove_dir_all(&target_dir);
    bytes
}
