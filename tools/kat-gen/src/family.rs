//! The `family` group: every registered execution family's circuit at
//! `trace_vars` 22, the height each defaults to — S16's
//! `ADD_SUB_LUI_AUIPC`, S17's `JUMP_BRANCH_SLT` and S18's `SHIFT_BITWISE` and
//! `MUL_DIV`.
//!
//! Each family's `artifact` constructor is the only definition of its circuit;
//! this group writes their bytes, and CI regenerates and diffs them. It is not
//! an oracle: what each file holds is `docs/spec/shard-proof.md` §8,
//! `docs/spec/jump-branch-slt.md`, `docs/spec/shift-bitwise.md` and
//! `docs/spec/mul-div.md`, and the matching suite in `crates/checker/tests`
//! holds the gates to those documents one by one.

use constraints::{add_sub, jump_branch_slt, mul_div, shift_bitwise};

use crate::write_bytes;

const TRACE_VARS: u32 = 22;

/// Each fixture's path and the bytes its constructor writes at [`TRACE_VARS`].
fn fixtures() -> [(&'static str, Vec<u8>); 4] {
    [
        (
            "crates/constraints/tests/vectors/add_sub.bin",
            add_sub::artifact(TRACE_VARS).to_bytes(),
        ),
        (
            "crates/constraints/tests/vectors/jump_branch_slt.bin",
            jump_branch_slt::artifact(TRACE_VARS).to_bytes(),
        ),
        (
            "crates/constraints/tests/vectors/shift_bitwise.bin",
            shift_bitwise::artifact(TRACE_VARS).to_bytes(),
        ),
        (
            "crates/constraints/tests/vectors/mul_div.bin",
            mul_div::artifact(TRACE_VARS).to_bytes(),
        ),
    ]
}

pub fn generate() {
    for (path, bytes) in fixtures() {
        write_bytes(path, &bytes);
    }
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
        for (fixture, built) in super::fixtures() {
            assert_eq!(
                to_hex(&sha256(&built)),
                to_hex(&sha256(&committed(fixture))),
                "the circuit and `{fixture}` have diverged; `cargo run -p kat-gen -- family` \
                 writes the constructor's bytes"
            );
        }
    }
}
