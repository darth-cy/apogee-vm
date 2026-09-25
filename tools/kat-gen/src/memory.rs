//! The `memory` group: S14's memory artifacts at `trace_vars` 22, the height
//! every family defaults to, and S25b's advice window beside them.
//!
//! `constraints::memory`'s constructors are the only definition of these
//! circuits; this group writes their bytes, and CI regenerates and diffs them.
//! Neither file is an oracle. What each holds is `docs/spec/memory.md` §2 (the
//! execution family's memory subtree), §3.3 (the two RAM window artifacts) and
//! `docs/spec/advice.md` §5 (the advice one), and
//! `crates/gkr/tests/memory.rs` holds the leaves to hand-written arithmetic.

use constants::family;
use constraints::memory::{
    advice_window_artifact, family_frame_artifact, image_window_artifact, zero_window_artifact,
};

use crate::write_bytes;

const TRACE_VARS: u32 = 22;

/// One fixture per *distinct* frame. Families sharing a query list share their
/// artifact byte for byte, so `JUMP_BRANCH_SLT` stands for `SHIFT_BITWISE` and
/// `MUL_DIV`, and `MEM_WORD` for `MEM_SUBWORD`;
/// `crates/constraints/tests/memory.rs` holds every one of the seven execution
/// families to one of these four files.
const FRAMES: [(&str, u32); 4] = [
    ("memory_frame_alu.bin", family::ADD_SUB_LUI_AUIPC),
    ("memory_frame_reg.bin", family::JUMP_BRANCH_SLT),
    ("memory_frame_mem.bin", family::MEM_WORD),
    ("memory_frame_atomics.bin", family::ATOMICS),
];

pub fn generate() {
    for (name, id) in FRAMES {
        write_bytes(
            &format!("crates/constraints/tests/vectors/{name}"),
            &family_frame_artifact(id, TRACE_VARS).to_bytes(),
        );
    }
    write_bytes(
        "crates/constraints/tests/vectors/image_window.bin",
        &image_window_artifact(TRACE_VARS).to_bytes(),
    );
    write_bytes(
        "crates/constraints/tests/vectors/zero_window.bin",
        &zero_window_artifact(TRACE_VARS).to_bytes(),
    );
    write_bytes(
        "crates/constraints/tests/vectors/advice_window.bin",
        &advice_window_artifact(TRACE_VARS).to_bytes(),
    );
}
