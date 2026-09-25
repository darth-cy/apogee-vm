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
pub const PINS: [(&str, &str); 24] = [
    (
        "fib.elf",
        "110a004f6f9d615506a63f6d85d9b2600d33b5c2c80af5f6c32fe90a6e2228fe",
    ),
    (
        "echo.elf",
        "42930358224d45142d7c6e035ab33124c9c2b34134731997dc3bf178a9f23d8f",
    ),
    (
        "rvc-dense.elf",
        "a8f608f6a25d1b4411b5b170f181761ae52aa28a979e2e2c74018321465352cc",
    ),
    (
        "amm.elf",
        "fcc40a7cb1716774b12bdaf75c4269d68000c8de9d56fc9610ae1bdb9ee1d8e8",
    ),
    (
        "orderbook.elf",
        "5fa9a0fc6e3a3c383211c59b771576d5d99eb262ce797aa6dab1a0978381440b",
    ),
    (
        "vault.elf",
        "ee39551bcfcde0a4d16d012ab30f7b3db8c082927aa79e8244647b64bbbb634e",
    ),
    (
        "atomics.elf",
        "5513d253e4db8fbb217073ccbaff450d0f4a50e2673cdd414727e6327fd5288b",
    ),
    (
        "opcodes.elf",
        "520bb1988095b581e1e17898ca46c07fc6fc74e7ce177d576ec4c4ae9ea5acc3",
    ),
    (
        "heap.elf",
        "a780b55f22ed648fc3e0a4faf05e3f7af687543de187a8c4c0acae50a4e397b5",
    ),
    (
        "consistency.elf",
        "e06a8f3431924e1470c86e9be14d098248339af75e026f24a8e2bc21b5b4df74",
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
        "94b517b8585b5b8a44115bb918b33a5f75c871659798a89c8f27e4bc9700e060",
    ),
    (
        "rvc-dense.objdump.txt",
        "5c5a319f34472c7c52fd16ec94de24a9a3f58083fba6b72f65bedfa92dd7b812",
    ),
    (
        "amm.objdump.txt",
        "9ca5e5ab996910382a4fd9838d8105a3fae0e172e66da3ede6b1d2e265ead124",
    ),
    (
        "rvc-dense.nm.txt",
        "80d307baa758172d3126ab6ff38b78e3cf1ded52f1fba1940f98e495aa1a4ee5",
    ),
    (
        "shards.elf",
        "6b05f589f3726b8f7b42cd67547227a23640041eefa2e66d5277618735d34241",
    ),
    (
        "keccak-test.elf",
        "2bae76b84db83cd467be56e7615d9c971e6e3b5679002fb7194dc305a88a971e",
    ),
    (
        "keccak-unused.elf",
        "c47db58280ab8ab1132a39786f3ad11fca1b4cd3293a00f1218ff96aa20c803d",
    ),
    (
        "recursion-ops.elf",
        "f6958d7a9f9d10710dcfbeb6748d05b6be55dc14f29a25b49087b8b4f9751c20",
    ),
    (
        "recursion-unused.elf",
        "cb26d3481ba3d5bb8bf2301b6fdda242d4f66b3170db95a71c22fa775116d2a3",
    ),
    (
        "public-io.elf",
        "ae501a6dc95058189d8a57ddffb325492d1368c68daf868268830e70c652e6eb",
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
