//! The `memory` group: S14's three memory artifacts at `trace_vars` 22, the
//! height every family defaults to.
//!
//! `constraints::memory`'s constructors are the only definition of these
//! circuits; this group writes their bytes, and CI regenerates and diffs them.
//! Neither file is an oracle. What each holds is `docs/spec/memory.md` §2 (the
//! execution family's memory subtree) and §3.3 (the two window artifacts), and
//! `crates/gkr/tests/memory.rs` holds the leaves to hand-written arithmetic.

use constraints::memory::{frame_artifact, image_window_artifact, zero_window_artifact};

use crate::write_bytes;

const TRACE_VARS: u32 = 22;

pub fn generate() {
    write_bytes(
        "crates/constraints/tests/vectors/memory_frame.bin",
        &frame_artifact(TRACE_VARS).to_bytes(),
    );
    write_bytes(
        "crates/constraints/tests/vectors/image_window.bin",
        &image_window_artifact(TRACE_VARS).to_bytes(),
    );
    write_bytes(
        "crates/constraints/tests/vectors/zero_window.bin",
        &zero_window_artifact(TRACE_VARS).to_bytes(),
    );
}
