//! The `keccak` group: the `KECCAK_F` delegation family's circuit at its one
//! height, pinned by **digest** rather than by bytes.
//!
//! Every other circuit fixture in the repository is the artifact itself
//! (`family`, `memory`, `lookup`, `gkr`). This one cannot be: a keccak row is
//! a whole keccak-f[1600] permutation, so the artifact is 354,762 inner
//! columns and about 100 MB of wire form — three orders of magnitude past the
//! largest committed circuit, `atomics.bin`'s 102,965 bytes. What a fixture
//! buys is a regeneration CI can diff, and a digest buys exactly that at 1/10⁶
//! of the size. The owner chose it at S21: commit its SHA-256, diff that.
//!
//! So the file below is one line of shape plus one digest, and
//! `crates/constraints/tests/keccak.rs` holds the constructor to it. The shape
//! numbers are on the line for a reader: a digest that moves says only *that*
//! something moved, and the counts beside it say what.
//!
//! The height is the family's default and only sensible one, `2^8`
//! (`docs/spec/delegation.md` §9): a delegation family's rows are invocations,
//! not halfwords, and 2^16 rows of this circuit is 734 GB of forward pass.

use constants::family;
use constraints::keccak;
use test_support::{sha256, to_hex};

use crate::write_vectors;

/// The family's one height, read off the frozen defaults rather than spelled.
fn trace_vars() -> u32 {
    let height = family::DEFAULT_HEIGHTS[family::KECCAK_F as usize];
    assert!(height.is_power_of_two(), "a height is a power of two");
    let vars = height.trailing_zeros();
    assert_eq!(
        vars, 8,
        "the keccak family's default height is no longer 2^8"
    );
    vars
}

/// The fixture's one relative path and its contents.
fn fixture() -> (&'static str, String) {
    let vars = trace_vars();
    let artifact = keccak::artifact(vars);
    let bytes = artifact.to_bytes();
    // `inner` is §1.2's: the width of every layer above the committed base
    // layer, summed — so every gate list's output layer, `L1` included.
    let inner: usize = artifact.layers.iter().map(|l| l.width as usize).sum();
    let text = format!(
        "# the KECCAK_F delegation family's circuit, by SHA-256 of `artifact(n).to_bytes()`\n\
         # docs/spec/delegation.md is normative; docs/spec/constraint-manifest.md \u{00a7}12 is the accounting\n\
         # the artifact itself is about 100 MB, so what is committed is its digest\n\
         # n memory witness layers inner relations outputs bytes sha256\n\
         {n} {memory} {witness} {layers} {inner} {relations} {outputs} {len} {digest}\n",
        n = vars,
        memory = artifact.memory.len(),
        witness = artifact.witness.len(),
        layers = artifact.layers.len(),
        inner = inner,
        relations = artifact.relations.len(),
        outputs = artifact.outputs.len(),
        len = bytes.len(),
        digest = to_hex(&sha256(&bytes)),
    );
    ("crates/constraints/tests/vectors/keccak.txt", text)
}

pub fn generate() {
    let (path, text) = fixture();
    write_vectors(path, &text);
}

#[cfg(test)]
mod tests {
    /// The committed line is the constructor's today, so a change to the
    /// circuit that a developer regenerates over is one a test sees and not
    /// only CI's diff — `family`'s rule, over a digest instead of bytes.
    #[test]
    fn the_fixture_is_the_constructors_digest() {
        let (path, text) = super::fixture();
        let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        let have = std::fs::read_to_string(&committed)
            .unwrap_or_else(|e| panic!("reading {}: {e}", committed.display()));
        assert_eq!(
            have, text,
            "the circuit and `{path}` have diverged; `cargo run -p kat-gen -- keccak` writes \
             the constructor's digest"
        );
    }
}
