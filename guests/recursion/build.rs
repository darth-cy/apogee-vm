//! The two nodes' images (`verifier_core::node::node_image`), built into
//! `OUT_DIR`, where each binary holds its own in `.rodata`: so a node's
//! identity binds every tape it replays.
//!
//! - `leaf.img`, from `base.key`: the base program's key, which `profiler
//!   base-key` writes from a proof archive's.
//! - `node.img`, from `base.key`'s SRS digest and table and from
//!   `programs.key`: the leaf program's and the node program's keys, each
//!   the config its ELF derives under its parameters, which `profiler
//!   program-keys` writes from the two binaries. Without it the node's image
//!   is empty and the node binary exits 10 — which is how the first build of
//!   the two programs goes, a config not depending on `.rodata`.

use std::path::PathBuf;

use verifier_core::node::{node_image, BaseKey, Kind, ProgramKey};

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets it"));
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets it"));
    let read = |name: &str| {
        let path = dir.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        std::fs::read(&path).ok()
    };
    let write = |name: &str, words: &[u32]| {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        std::fs::write(out.join(name), bytes).expect("OUT_DIR is writable");
    };
    let base = read("base.key").expect("base.key: run `profiler base-key` first");
    let base = BaseKey::from_bytes(&base).expect("base.key is a BaseKey");
    write("leaf.img", &node_image(Kind::Leaf, &base, &[]));
    let node = match read("programs.key") {
        Some(bytes) => {
            let keys = ProgramKey::list_from_bytes(&bytes).expect("programs.key is two keys");
            assert_eq!(
                keys.len(),
                2,
                "programs.key holds the leaf's and the node's keys"
            );
            node_image(Kind::Internal, &base, &keys)
        }
        None => Vec::new(),
    };
    write("node.img", &node);
}
