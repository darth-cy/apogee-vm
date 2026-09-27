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
        "cdc30b5bb6adb6025213871b5fa939cf3b0a01e2392ddd1b68b2d971084287a7",
    ),
    (
        "echo.elf",
        "14353bb83c00dbc56347196b952e99a41067d64d0356bc2d140f263fb398b28a",
    ),
    (
        "rvc-dense.elf",
        "3818bdad9a78b1d44fa6fd9104532d6d3fc1fc3d6c4210f8eeda67ef2f29c420",
    ),
    (
        "amm.elf",
        "ba7de08297bb8b5108a2527440d7a22b1684355c846eb4f5749cd6190bfb6c3a",
    ),
    (
        "orderbook.elf",
        "19fb3b7e4540b0aae90cc6cec53bdcac87db7ca2632ec91755fa486abe6648f1",
    ),
    (
        "vault.elf",
        "3448255854c9612a0e59680585487f2e782d96d0fcbad73d9c431a24437ceb72",
    ),
    (
        "atomics.elf",
        "78a8c83c660becd0fe86405b6f9d42e7bce73151e9cf7eb0c59b1c1cb934a069",
    ),
    (
        "opcodes.elf",
        "b56f1379a7260ad3460ace802d09b3278e1269db144048ddaf5e71e582dc7502",
    ),
    (
        "heap.elf",
        "70b1729a42b95e9a64f28291eab80868e132131de804581bbedfd16f4ca2b431",
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
        "30be346529d47abb3739bb8140cbaee539f98091eec257e88297dedb90eaae7f",
    ),
    (
        "rvc-dense.objdump.txt",
        "fcb4f055fd0ce17e544d9b6d7ada4965fb4a0146efa3d1ac90daeb0a4c7020f3",
    ),
    (
        "amm.objdump.txt",
        "ef8d923229aa9a9578d7d153ef640d254eae06985dbe8da632f9fab39dc0602b",
    ),
    (
        "rvc-dense.nm.txt",
        "6ac86268873ee7b8040377edc34673a54608faf08c62c59c9351896ccf6da3e0",
    ),
    (
        "shards.elf",
        "6b05f589f3726b8f7b42cd67547227a23640041eefa2e66d5277618735d34241",
    ),
    (
        "keccak-test.elf",
        "72128c0e2dd863368d19f2ea07b2f215323b6a96583ef30fdee86aaca80080f0",
    ),
    (
        "keccak-unused.elf",
        "3afedf41f7f512dcf81cb2639abcad1c0ad1981167385f99bcac599ba54ca65d",
    ),
    (
        "recursion-ops.elf",
        "010d7acc02885a963eb12528544bcd8c5bf2f48e6a436a2e56664496b24170d8",
    ),
    (
        "recursion-unused.elf",
        "1d60f616c7c54e7c1b3902870fd46553038f4881b06343ff1625634cf1607ce1",
    ),
    (
        "public-io.elf",
        "d4594d1bb54aab5e24b638dd47a8f6b813abecbceed52581712ccb0785c65ee8",
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
/// witnesses behaviour must give the same answer under either. That is what
/// holds the pin
/// honest: unpinned, a release guest commits a wrapped `u32` to its journal
/// where a dev guest panics, which would make the optimisation level part of
/// the statement being proven. `crates/prover/tests/one_feature.rs` is what
/// asserts the pin itself.
///
/// `layout.rs` and `reproducible.rs` stay on debug deliberately -- they are
/// about the committed artifacts, which are dev builds.
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
