//! The `family` group: S16's `ADD_SUB_LUI_AUIPC` circuit at `trace_vars` 22,
//! the height the family defaults to.
//!
//! `constraints::add_sub::artifact` is the only definition of the circuit;
//! this group writes its bytes, and CI regenerates and diffs them. It is not an
//! oracle: what the file holds is `docs/spec/shard-proof.md` §8, and
//! `crates/checker/tests/add_sub.rs` holds the gates to that section's
//! table one by one.

use constraints::add_sub;

use crate::write_bytes;

const FIXTURE: &str = "crates/constraints/tests/vectors/add_sub.bin";
const TRACE_VARS: u32 = 22;

pub fn generate() {
    write_bytes(FIXTURE, &add_sub::artifact(TRACE_VARS).to_bytes());
}

#[cfg(test)]
mod tests {
    use test_support::{sha256, to_hex};

    /// The committed fixture is the bytes the constructor writes today, so a
    /// change to the circuit that a developer regenerates over is one a test
    /// sees, not only CI's diff.
    #[test]
    fn the_fixture_is_the_constructors_bytes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(super::FIXTURE);
        let committed =
            std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let built = constraints::add_sub::artifact(super::TRACE_VARS).to_bytes();
        assert_eq!(
            to_hex(&sha256(&built)),
            to_hex(&sha256(&committed)),
            "the add/sub circuit and `{}` have diverged; `cargo run -p kat-gen -- family` \
             writes the constructor's bytes",
            super::FIXTURE
        );
    }
}
