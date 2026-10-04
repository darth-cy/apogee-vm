//! The leaf's image (`verifier_core::node::leaf_image`), built from
//! `base.key` — the base program's key — into `OUT_DIR`, where `main.rs` holds
//! it in `.rodata`: so this program's identity binds every tape it replays.
//! `profiler base-key` writes `base.key` from a proof archive's key.

use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets it"));
    let path = dir.join("base.key");
    println!("cargo:rerun-if-changed={}", path.display());
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let key = verifier_core::node::BaseKey::from_bytes(&bytes).expect("base.key is a BaseKey");
    let words = verifier_core::node::leaf_image(&key);
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets it"));
    let image: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    std::fs::write(out.join("leaf.img"), image).expect("OUT_DIR is writable");
    std::fs::write(out.join("base.key"), &bytes).expect("OUT_DIR is writable");
}
