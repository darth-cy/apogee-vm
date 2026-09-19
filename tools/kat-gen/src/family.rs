//! The `family` group: every registered execution family's circuit at
//! `trace_vars` 22, the height each defaults to — S16's
//! `ADD_SUB_LUI_AUIPC` and S17's `JUMP_BRANCH_SLT`.
//!
//! `constraints::add_sub::artifact` and `constraints::jump_branch_slt::artifact`
//! are the only definitions of the circuits; this group writes their bytes,
//! and CI regenerates and diffs them. It is not an oracle: what each file holds
//! is `docs/spec/shard-proof.md` §8 and `docs/spec/jump-branch-slt.md`, and
//! `crates/checker/tests/add_sub.rs` and `jump_branch_slt.rs` hold the gates to
//! those documents one by one.

use constraints::{add_sub, jump_branch_slt};

use crate::write_bytes;

const ADD_SUB: &str = "crates/constraints/tests/vectors/add_sub.bin";
const JUMP_BRANCH_SLT: &str = "crates/constraints/tests/vectors/jump_branch_slt.bin";
const TRACE_VARS: u32 = 22;

pub fn generate() {
    write_bytes(ADD_SUB, &add_sub::artifact(TRACE_VARS).to_bytes());
    write_bytes(
        JUMP_BRANCH_SLT,
        &jump_branch_slt::artifact(TRACE_VARS).to_bytes(),
    );
}

#[cfg(test)]
mod tests {
    use test_support::{sha256, to_hex};

    fn committed(fixture: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(fixture);
        std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
    }

    /// Each committed fixture is the bytes its constructor writes today, so a
    /// change to a circuit that a developer regenerates over is one a test
    /// sees, not only CI's diff.
    #[test]
    fn each_fixture_is_its_constructors_bytes() {
        for (fixture, built) in [
            (
                super::ADD_SUB,
                constraints::add_sub::artifact(super::TRACE_VARS).to_bytes(),
            ),
            (
                super::JUMP_BRANCH_SLT,
                constraints::jump_branch_slt::artifact(super::TRACE_VARS).to_bytes(),
            ),
        ] {
            assert_eq!(
                to_hex(&sha256(&built)),
                to_hex(&sha256(&committed(fixture))),
                "the circuit and `{fixture}` have diverged; `cargo run -p kat-gen -- family` \
                 writes the constructor's bytes"
            );
        }
    }
}
