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
        "6b517e814c13c977248b8eae51277d411cccce75009d8a5396f6b5aa6af5c749",
    ),
    (
        "echo.elf",
        "e1bb10eeb6537c9bc639cb56b0c1f497382c858c8f53c8e6657472c5da2c7590",
    ),
    (
        "rvc-dense.elf",
        "af87f2cd34281d9afe92acfb8d896c13830a0ce7b04978c4de0d67dc03205b09",
    ),
    (
        "amm.elf",
        "36732ff38b60feb9a24587f8c55baadcad8673b9894a1204b41c1346acf6c649",
    ),
    (
        "orderbook.elf",
        "97c6f190824c023172b36c8d8a6d705b0b2d4c14b6a9e1336869c02907f84a46",
    ),
    (
        "vault.elf",
        "6d0e70ed41918e897feef12b1abf3daaece7a0398aa56164ba025666fb851e4a",
    ),
    (
        "atomics.elf",
        "4ea691b7ee988e96453a7203c9d3ebcd1de243db33e3e31ffc2b20d635fc7f69",
    ),
    (
        "opcodes.elf",
        "d8a35e299af2ab4ebacd87da8f4d778069269b198e736caef5e80c038f431265",
    ),
    (
        "heap.elf",
        "4557484c508e922270e0b923993e69da2ff82897db28da5324a8139e3b402b52",
    ),
    (
        "consistency.elf",
        "0cf55d06bb3e84e33ec65e071f2960b5d7fcd6c06de00c2b6df0cabf0bda3131",
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
        "edb521661d782689e9e0ebc4ccf972838de6d93cc1ef42915ec830997a630489",
    ),
    (
        "rvc-dense.objdump.txt",
        "f0ba5063259581040592218f52059d935c5b1eb4c14a6b32c25f28c028f6567e",
    ),
    (
        "amm.objdump.txt",
        "bb54985d4ded03480c628ae80372b072314b50400e0f3fa317e76e77db0a78e4",
    ),
    (
        "rvc-dense.nm.txt",
        "06362b158abae3b1d13cfd74781817c574e746ec1c7b9121daed0cfea53706e7",
    ),
    (
        "shards.elf",
        "6b05f589f3726b8f7b42cd67547227a23640041eefa2e66d5277618735d34241",
    ),
    (
        "keccak-test.elf",
        "c906c7f55ab7c047499e39d74cca7b58fd00deff1814f4090394f0513b1145eb",
    ),
    (
        "keccak-unused.elf",
        "ac1c8fdb1c166edd888d4789f7cd83b635c7636c2e6b5bd4fb8dc0699fbdbbf3",
    ),
    (
        "recursion-ops.elf",
        "edce5f735e12b69f591bf1b55fcb01917a03649d94e8601afcfd1b54f703230e",
    ),
    (
        "recursion-unused.elf",
        "3d0c175a049434ab6dab593f1a28dce2badf60ce10e7f2b7e834e7f6afec334f",
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
