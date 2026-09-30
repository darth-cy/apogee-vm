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
pub const PINS: [(&str, &str); 26] = [
    (
        "fib.elf",
        "0bef35995d9c3cc2c70147c0902ae0aad892c77c2f35efe0c1d11271c06a9f9c",
    ),
    (
        "echo.elf",
        "866ea122cc7b41d5ba6c0a6f0229bfa82736e90e230c90da81a476f5e8177142",
    ),
    (
        "rvc-dense.elf",
        "13e94505c1dfcff523a1bbfdb0283518024f83fc58008ca986989a6ae32672f1",
    ),
    (
        "amm.elf",
        "c415fec91abf144e3adee92cd20a0ccb44cb283554c3e8fc91c7af4da90916c3",
    ),
    (
        "orderbook.elf",
        "4d2e59f5125e100f5e4ec0f46eae8d40e6bbff3c2c480f189b9658b3443276c6",
    ),
    (
        "vault.elf",
        "d54b9f423284e49bb1bc1211feae91fb5f4f1bbdbf8f768fdbc7f908e5547398",
    ),
    (
        "atomics.elf",
        "77abdff4cd470fcf9710f7ed5c9427f373b0ac0976832e8ec72f8851f539f06f",
    ),
    (
        "opcodes.elf",
        "36ce5e9899fc58bf5d2ad22b446123fefa3c6a8f7557297c7372067ab79b3c32",
    ),
    (
        "heap.elf",
        "f04fe50b8ed35884c31660666e6aa8c9dd3c4803d001a8ddb1d591b61e5e39ad",
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
        "09797eda61d19bba3b0786cfaa8f0d3433439226174fd643f1966f8b7107ef8e",
    ),
    (
        "keccak-unused.elf",
        "af73b4f8140bf8c01f33de18553d048ea7c31d6cf6d0c715f7609da82d226810",
    ),
    (
        "recursion-ops.elf",
        "515a36c8b900594b53773eb7d6953bbea135aa99df3300fac22413e4c12d405f",
    ),
    (
        "recursion-unused.elf",
        "836899ffbaff8a0f7beacb576e495dc353d03ab8198bbf9169ea7d1be11a0f20",
    ),
    (
        "public-io.elf",
        "7898beaa4bfdef2d9ac4b103f48eabd85aa9c4ea513d603fa9ba33170f340ece",
    ),
    (
        "mod-mul-ops.elf",
        "bb56510854af31e711f437e7480377a1a5397aa83a3504878f757e617600d34e",
    ),
    (
        "sha256-ops.elf",
        "498f061ccda3a3eae9273425ae56e3eaf7833e5518779fe0f81ecd6f810c26c5",
    ),
    (
        "ec-ops.elf",
        "40ed1d28933b37c55bf5bf7a71a9993f3902f1c8d82f67a07de49ab4909430bc",
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
