//! The two nodes' images (`verifier_core::node::node_image`), built into
//! `OUT_DIR`, where each binary holds its own in `.rodata`: so a node's
//! identity binds every tape it replays.
//!
//! The keys are read from the directory `APOGEE_RECURSION_KEYS` names, where
//! `bench recurse` writes them:
//!
//! - `base.key`, the base program's key, for `leaf.img`;
//! - `programs.key`, the leaf program's and the node program's keys, each the
//!   config its ELF derives under its parameters, for `node.img`.
//!
//! An image whose key is not there is empty and its binary exits 10 — which
//! is how a build with no proof at hand goes, and the node's first: a config
//! does not depend on `.rodata`, so the two programs' keys are read off that
//! build and the node is built again over them.

use std::path::PathBuf;

use verifier_core::node::{node_image, BaseKey, Kind, ProgramKey};

fn main() {
    println!("cargo:rerun-if-env-changed=APOGEE_RECURSION_KEYS");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets it"));
    let read = |name: &str| {
        let path = PathBuf::from(std::env::var_os("APOGEE_RECURSION_KEYS")?).join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        std::fs::read(&path).ok()
    };
    let write = |name: &str, words: &[u32]| {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        std::fs::write(out.join(name), bytes).expect("OUT_DIR is writable");
    };
    let base = read("base.key").map(|b| BaseKey::from_bytes(&b).expect("base.key is a BaseKey"));
    let keys = read("programs.key")
        .map(|b| ProgramKey::list_from_bytes(&b).expect("programs.key is the two programs' keys"));
    let image = |kind, keys: &[ProgramKey]| match &base {
        Some(base) => node_image(kind, base, keys),
        None => Vec::new(),
    };
    write("leaf.img", &image(Kind::Leaf, &[]));
    write(
        "node.img",
        &keys.map_or(Vec::new(), |k| image(Kind::Internal, &k)),
    );
}
