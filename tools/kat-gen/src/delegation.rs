//! The `delegation` group: every delegation family's circuit at its one
//! height, pinned by **digest** rather than by bytes.
//!
//! Every execution-family circuit fixture in the repository is the artifact
//! itself (`family`, `memory`, `lookup`, `gkr`). These cannot be: a delegation
//! row is a whole permutation or a whole field operation over a frame the
//! circuit decomposes to the bit, so the artifacts are 1 MB, 2 MB and — for
//! keccak — about 100 MB of wire form, three orders of magnitude past the
//! largest committed circuit, `atomics.bin`'s 102,965 bytes. What a fixture
//! buys is a regeneration CI can diff, and a digest buys exactly that at a
//! fraction of the size. The owner chose it at S21: commit the SHA-256, diff
//! that.
//!
//! So each file below is one line of shape plus one digest, and the matching
//! suite in `crates/checker/tests` holds the constructor to its document.
//! The shape numbers are on the line for a reader: a digest that moves says
//! only *that* something moved, and the counts beside it say what.
//!
//! Each height is the family's default and only sensible one
//! (`docs/spec/delegation.md` §9): a delegation family's rows are invocations,
//! not halfwords, and `2^16` rows of any of these is hundreds of gigabytes of
//! forward pass.

use constants::family;
use constraints::{fr_arith, keccak, poseidon2, CircuitArtifact};
use test_support::{sha256, to_hex};

use crate::write_vectors;

/// A family's height, read off the frozen defaults rather than spelled.
fn trace_vars(family: u32) -> u32 {
    let height = family::DEFAULT_HEIGHTS[family as usize];
    assert!(height.is_power_of_two(), "a height is a power of two");
    let vars = height.trailing_zeros();
    assert_eq!(
        vars,
        8,
        "{}'s default height is no longer 2^8",
        program::family_name(family)
    );
    vars
}

/// One fixture's line: the shape a reader wants and the digest CI diffs.
fn line(name: &str, spec: &str, artifact: &CircuitArtifact) -> String {
    let bytes = artifact.to_bytes();
    // `inner` is §1.2's: the width of every layer above the committed base
    // layer, summed — so every gate list's output layer, `L1` included.
    let inner: usize = artifact.layers.iter().map(|l| l.width as usize).sum();
    format!(
        "# the {name} delegation family's circuit, by SHA-256 of `artifact(n).to_bytes()`\n\
         # docs/spec/delegation.md is normative; docs/spec/constraint-manifest.md \u{00a7}{spec} is the accounting\n\
         # the artifact itself is megabytes, so what is committed is its digest\n\
         # n memory witness layers inner relations outputs bytes sha256\n\
         {n} {memory} {witness} {layers} {inner} {relations} {outputs} {len} {digest}\n",
        n = artifact.trace_vars,
        memory = artifact.memory.len(),
        witness = artifact.witness.len(),
        layers = artifact.layers.len(),
        inner = inner,
        relations = artifact.relations.len(),
        outputs = artifact.outputs.len(),
        len = bytes.len(),
        digest = to_hex(&sha256(&bytes)),
    )
}

/// Each fixture's relative path and its contents.
fn fixtures() -> [(&'static str, String); 3] {
    [
        (
            "crates/constraints/tests/vectors/keccak.txt",
            line(
                "KECCAK_F",
                "12",
                &keccak::artifact(trace_vars(family::KECCAK_F)),
            ),
        ),
        (
            "crates/constraints/tests/vectors/poseidon2.txt",
            line(
                "POSEIDON2",
                "13",
                &poseidon2::artifact(trace_vars(family::POSEIDON2)),
            ),
        ),
        (
            "crates/constraints/tests/vectors/fr_arith.txt",
            line(
                "FR_ARITH",
                "14",
                &fr_arith::artifact(trace_vars(family::FR_ARITH)),
            ),
        ),
    ]
}

pub fn generate() {
    for (path, text) in fixtures() {
        write_vectors(path, &text);
    }
}

#[cfg(test)]
mod tests {
    /// Each committed line is its constructor's today, so a change to a
    /// circuit that a developer regenerates over is one a test sees and not
    /// only CI's diff — `family`'s rule, over a digest instead of bytes.
    #[test]
    fn the_fixtures_are_the_constructors_digests() {
        for (path, text) in super::fixtures() {
            let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(path);
            let have = std::fs::read_to_string(&committed)
                .unwrap_or_else(|e| panic!("reading {}: {e}", committed.display()));
            assert_eq!(
                have, text,
                "the circuit and `{path}` have diverged; `cargo run -p kat-gen -- delegation` \
                 writes the constructors' digests"
            );
        }
    }
}
