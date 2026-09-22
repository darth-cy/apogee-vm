//! `constraints::memory`, `docs/spec/memory.md` §2, §3.3 and §8: every memory
//! artifact — one frame per execution family, and the two RAM windows —
//! validates and keeps the construction-time rules at two heights, their
//! layouts, obligations and read sets are the document's, the committed
//! fixtures are the constructors' bytes, and `check_memory` refuses each thing
//! §8 names. S14 acceptance 9 is here; acceptance 12's negative control is the
//! unit test in `src/memory.rs`, which reaches the private construction.
//!
//! A family's frame holds only the queries its instructions can make (§2.1), so
//! nothing below is written against the eight of the query table: every
//! expectation is derived from that family's list. **A query's address space
//! and its in-cycle slot Δ come from its id in the query table; its columns,
//! its gap chunk and its leaves come from its position — its *slot* — in the
//! family's list.** Where the two differ is where this suite is aimed.

use constants::{address_space, challenge_slot, family, lookup_channel, memory};
use constraints::memory::{
    check_memory, deleg_space, family_frame_artifact, frame, frame_artifact, frame_matches,
    frame_queries, gap_hi, image_window_artifact, is_delegation_anchor, rd_inv, rd_is_zero,
    rd_selected, read_tuple, zero_window_artifact, ARG1, ARG2, CYCLE, DELEG, DELEGATION_ANY,
    FIELD_ADDR, FIELD_MASK, FIELD_READ_TS, FIELD_READ_VALUE, FIELD_WRITE_VALUE, FRAME_DELTA,
    FRAME_NAMES, FRAME_QUERIES, FRAME_READ_ONLY, FRAME_SPACE, LOAD, PC, RAM, RD, RS1, RS2,
};
use constraints::{
    CachedEntry, CircuitArtifact, Coeff, ConstraintError, EnforcingEntry, GateDef, LayerSpec,
    LookupExpr, Padding, PolyAddress, ProducingEntry, Relation, ScratchSlot, VirtualKind,
    COEFFICIENT_ENCODING_CANONICAL_LE, FORMAT_VERSION,
};
use field::Fr;
use std::collections::HashSet;
use test_support::{sha256, to_hex};

const FRAME_ALU_SHA256: &str = "f199ca64e301ed301ffb69831342acdc45fc9abaeb06d76d5ec58a025bf6124d";
const FRAME_REG_SHA256: &str = "f94da36c6f7052acd10c36a3a0bd04ce09fe2419cdbfa046db4a58b1a716cbc0";
const FRAME_MEM_SHA256: &str = "7a31fd867d4b5490821bcef24e356daf34d834a397efed8fa41b8e821b6fee6f";
const FRAME_ATOMICS_SHA256: &str =
    "518c3853426a2ca30216536edc41a2659189c6c1e5abbeca9b516cf2032488c8";
const IMAGE_WINDOW_SHA256: &str =
    "39a8655d430ed5c031e4f27075662fe92a9a1274cd23dc300ae5e2e82df67ecc";
const ZERO_WINDOW_SHA256: &str = "f08dde677a70c8a15cc7b67b35806e6ee5d9afff9cb703586f21426baa51ec1c";

/// The seven execution families, ascending: every family that runs cycles and
/// so carries a frame. `INIT_TEARDOWN` and `ZERO_WINDOWS` have none — their
/// artifacts are §3.3's two windows — which `frame_queries` refuses in the unit
/// tests of `src/memory.rs`.
const EXECUTION_FAMILIES: [u32; 7] = [
    family::ADD_SUB_LUI_AUIPC,
    family::JUMP_BRANCH_SLT,
    family::SHIFT_BITWISE,
    family::MUL_DIV,
    family::MEM_WORD,
    family::MEM_SUBWORD,
    family::ATOMICS,
];

/// `docs/spec/memory.md` §2.1's table, written here again rather than read from
/// `frame_queries`: per family, its query list and, derived from it by hand,
/// `w`, the `M` and `W` column counts, the leaves a side, the obligations and
/// the enforcing gates — `w` booleanity gates, one write-back per read-only
/// query the family holds, and the four x0 gates.
///
/// The memory count is `1 + 5w`, and `1 + 5w + 1` on the one family that holds
/// the delegation mirror: `ADD_SUB_LUI_AUIPC` carries `deleg_space`, the tag
/// column S22 appended after the last query's five
/// (`docs/spec/ecrecover.md` §2.4).
#[allow(clippy::type_complexity)]
const FRAME_SHAPES: [(u32, &[usize], usize, usize, usize, usize, usize); 7] = [
    //  family                      queries                                w    M   W  side  lk  enf
    (
        family::ADD_SUB_LUI_AUIPC,
        &[PC, RS1, RS2, ARG1, ARG2, RAM, RD, DELEG],
        42,
        11,
        8,
        16,
        17,
    ),
    (
        family::JUMP_BRANCH_SLT,
        &[PC, RS1, RS2, RD],
        21,
        7,
        4,
        8,
        10,
    ),
    (family::SHIFT_BITWISE, &[PC, RS1, RS2, RD], 21, 7, 4, 8, 10),
    (family::MUL_DIV, &[PC, RS1, RS2, RD], 21, 7, 4, 8, 10),
    (
        family::MEM_WORD,
        &[PC, RS1, RS2, LOAD, RAM, RD],
        31,
        9,
        8,
        12,
        13,
    ),
    (
        family::MEM_SUBWORD,
        &[PC, RS1, RS2, LOAD, RAM, RD],
        31,
        9,
        8,
        12,
        13,
    ),
    (family::ATOMICS, &[PC, RS1, RS2, RAM, RD], 26, 8, 8, 10, 11),
];

/// The four *distinct* frames: families sharing a query list share their
/// artifact byte for byte, so these four stand for all seven.
/// `the_seven_families_frames_are_the_four_fixtures` is what holds that.
const DISTINCT_FRAMES: [u32; 4] = [
    family::ADD_SUB_LUI_AUIPC,
    family::JUMP_BRANCH_SLT,
    family::MEM_WORD,
    family::ATOMICS,
];

/// Every memory artifact there is, at `trace_vars`: one frame per execution
/// family, then the two windows. The label names the artifact in a failure.
fn every_artifact(trace_vars: u32) -> Vec<(String, CircuitArtifact)> {
    let mut all: Vec<(String, CircuitArtifact)> = EXECUTION_FAMILIES
        .iter()
        .map(|&id| {
            (
                format!("family {id}'s frame"),
                family_frame_artifact(id, trace_vars),
            )
        })
        .collect();
    all.push((
        String::from("image window"),
        image_window_artifact(trace_vars),
    ));
    all.push((
        String::from("zero window"),
        zero_window_artifact(trace_vars),
    ));
    all
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

/// Each committed fixture is pinned, then held to its constructor's bytes at
/// `trace_vars` 22 — the four distinct frames and the two windows. The
/// constructors are the only definition; the pin is what makes a changed
/// circuit a deliberate refresh.
#[test]
fn the_fixtures_are_the_constructors_bytes() {
    let fixtures = [
        (
            "memory_frame_alu.bin",
            FRAME_ALU_SHA256,
            family_frame_artifact(family::ADD_SUB_LUI_AUIPC, 22),
        ),
        (
            "memory_frame_reg.bin",
            FRAME_REG_SHA256,
            family_frame_artifact(family::JUMP_BRANCH_SLT, 22),
        ),
        (
            "memory_frame_mem.bin",
            FRAME_MEM_SHA256,
            family_frame_artifact(family::MEM_WORD, 22),
        ),
        (
            "memory_frame_atomics.bin",
            FRAME_ATOMICS_SHA256,
            family_frame_artifact(family::ATOMICS, 22),
        ),
        (
            "image_window.bin",
            IMAGE_WINDOW_SHA256,
            image_window_artifact(22),
        ),
        (
            "zero_window.bin",
            ZERO_WINDOW_SHA256,
            zero_window_artifact(22),
        ),
    ];
    for (name, digest, artifact) in fixtures {
        let bytes = fixture(name);
        assert_eq!(
            to_hex(&sha256(&bytes)),
            digest,
            "{name} changed. Regenerate it with `cargo run -p kat-gen -- memory`, review the \
             diff, then update the pinned digest deliberately."
        );
        assert_eq!(bytes, artifact.to_bytes(), "{name}");
        assert_eq!(CircuitArtifact::from_bytes(&bytes), Ok(artifact), "{name}");
    }
}

/// Four files pin seven families: a family's frame is decided by its query
/// list alone, so families sharing one share their artifact byte for byte —
/// `JUMP_BRANCH_SLT`, `SHIFT_BITWISE` and `MUL_DIV` are one frame, `MEM_WORD`
/// and `MEM_SUBWORD` another. Every execution family is held to the fixture
/// `kat-gen` writes for it, and the four fixtures are pairwise distinct, so a
/// family quietly re-pointed at another's frame fails here.
#[test]
fn the_seven_families_frames_are_the_four_fixtures() {
    let files = [
        (family::ADD_SUB_LUI_AUIPC, "memory_frame_alu.bin"),
        (family::JUMP_BRANCH_SLT, "memory_frame_reg.bin"),
        (family::SHIFT_BITWISE, "memory_frame_reg.bin"),
        (family::MUL_DIV, "memory_frame_reg.bin"),
        (family::MEM_WORD, "memory_frame_mem.bin"),
        (family::MEM_SUBWORD, "memory_frame_mem.bin"),
        (family::ATOMICS, "memory_frame_atomics.bin"),
    ];
    assert_eq!(files.map(|(id, _)| id), EXECUTION_FAMILIES);
    for (id, name) in files {
        assert_eq!(
            family_frame_artifact(id, 22).to_bytes(),
            fixture(name),
            "family {id} is {name}"
        );
    }
    let distinct: HashSet<Vec<u8>> = DISTINCT_FRAMES
        .iter()
        .map(|&id| family_frame_artifact(id, 22).to_bytes())
        .collect();
    assert_eq!(distinct.len(), 4, "the four fixtures are four circuits");
}

/// Every constructor there is — the seven families' frames and the two
/// windows — at both a small height and the default one.
#[test]
fn every_constructor_validates_and_keeps_the_memory_rules_at_12_and_22() {
    for trace_vars in [12, 22] {
        let all = every_artifact(trace_vars);
        assert_eq!(all.len(), EXECUTION_FAMILIES.len() + 2);
        for (label, a) in all {
            assert_eq!(a.validate(), Ok(()), "{label} at {trace_vars}");
            assert_eq!(check_memory(&a), Ok(()), "{label} at {trace_vars}");
            assert_eq!(a.trace_vars, trace_vars, "{label}");
        }
    }
}

fn inner(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Inner { layer, offset }
}

/// The shape every memory artifact shares — the seven frames and the two
/// windows: two output roots at the top, named, a padding row of zeros whose
/// zero row is valid, `trace_vars` halving lists whatever the width below
/// them, and no cached entries anywhere.
#[test]
fn every_artifact_has_two_named_roots_and_an_all_zero_padding_row() {
    for (label, a) in every_artifact(12) {
        let n = a.depth() as u32;
        assert_eq!(a.outputs, vec![inner(n, 0), inner(n, 1)], "{label}");
        let names: Vec<&str> = a.scratch[a.scratch.len() - 2..]
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, ["read_root", "write_root"], "{label}");
        assert_eq!(
            a.padding.row,
            vec![Fr::ZERO; a.committed().len()],
            "{label}"
        );
        assert!(a.padding.zero_row_valid, "{label}");
        // Halving from the first layer of width 2 down to one row.
        let halving = a.layers.iter().filter(|l| l.halving).count() as u32;
        assert_eq!(halving, 12, "{label}");
        assert!(a.layers.iter().all(|l| l.cached.is_empty()), "{label}");
    }
}

/// §1's part order, S14 must-be-exact 1: every query of the table has a read
/// tuple with one term per part, and its term `PART_*` is that part —
/// `(AS, mask)`, `(α_addr, addr)`, `(α_ts, read_ts)`, `(α_val, read_value)` —
/// with constant `γ_M`. `gkr_verify::boundary_factors` places its operand
/// values by the same constants. `read_tuple` takes the query's id in the
/// table and addresses the columns as a frame holding every query would; no
/// family holds every query, and the boundary reads only the coefficients and
/// their `PART_*` positions, which no slot changes — a family's leaf at slot
/// `at` is the same tuple over slot `at`'s columns, which
/// `a_query_at_a_slot_that_is_not_its_id_keeps_its_own_space_and_delta` holds.
/// Fails if a constant named a position its part is not at.
///
/// Eight queries of the nine, since S22: the delegation mirror's address space
/// is a column of the frame rather than a literal of the table, so it has no
/// frame-free tuple at all and `read_tuple` refuses it —
/// `the_delegation_mirror_has_no_frame_free_read_tuple` pins the refusal, and
/// `the_delegation_mirrors_leaves_take_their_address_space_from_the_tag_column`
/// pins the leaf it does have.
#[test]
fn the_read_tuples_parts_are_at_their_named_positions() {
    let slot = Coeff::Challenge;
    for (q, space) in FRAME_SPACE.iter().enumerate() {
        if q == DELEG {
            continue;
        }
        let GateDef::Linear { terms, constant } = read_tuple(q) else {
            panic!("a tuple is Linear");
        };
        assert_eq!(terms.len(), 4, "{q}");
        assert_eq!(constant, slot(challenge_slot::MEM_GAMMA), "{q}");
        let space = Coeff::Literal(Fr::from_u64(*space as u64));
        let parts = [
            (memory::PART_AS, space, FIELD_MASK),
            (
                memory::PART_ADDR,
                slot(challenge_slot::MEM_ALPHA_ADDR),
                FIELD_ADDR,
            ),
            (
                memory::PART_TS,
                slot(challenge_slot::MEM_ALPHA_TS),
                FIELD_READ_TS,
            ),
            (
                memory::PART_VAL,
                slot(challenge_slot::MEM_ALPHA_VAL),
                FIELD_READ_VALUE,
            ),
        ];
        for (part, coeff, field) in parts {
            assert_eq!(
                terms[part],
                (coeff, frame(q, field)),
                "query {q}, part {part}"
            );
        }
    }
}

/// The query table itself, §2.1: nine entries, their names, address spaces and
/// Δ, the five read-only queries, `rd` and then S21's `deleg` last, and `M[0]`
/// the cycle. These are indexed by a query's *id*, never by its slot in a
/// family.
///
/// `deleg` is a delegation request's mirror query
/// (`docs/spec/delegation.md` §5.1): the eighth role, at slot 3 like `ram` and
/// `rd`, in a delegation family's own address space, and read-write — the
/// value it writes back is not the value it read.
///
/// Its entry in `FRAME_SPACE` is `DELEGATION_ANY` and **not a tag**, because a
/// requesting family serves every delegation type and there is no one literal
/// to put there: the type the row requested is carried by its `deleg_space`
/// column, and routing a logged event to the slot is `frame_matches`
/// (`docs/spec/ecrecover.md` §2.4). 0 is free for that exactly because every
/// real address space is nonzero, which is asserted here over all six.
#[test]
fn the_query_table_is_the_documents() {
    assert_eq!(FRAME_QUERIES, 9);
    assert_eq!(
        FRAME_NAMES,
        ["pc", "rs1", "rs2", "arg1", "arg2", "load", "ram", "rd", "deleg"]
    );
    assert_eq!(
        [PC, RS1, RS2, ARG1, ARG2, LOAD, RAM, RD, DELEG],
        [0, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(FRAME_DELTA, [0, 1, 2, 2, 2, 2, 3, 3, 3]);
    let (pc, reg, ram) = (address_space::PC, address_space::REG, address_space::RAM);
    assert_eq!(
        FRAME_SPACE,
        [pc, reg, reg, reg, reg, ram, ram, reg, DELEGATION_ANY]
    );
    assert_eq!(DELEGATION_ANY, 0);
    for space in [
        pc,
        reg,
        ram,
        address_space::DELEGATION_KECCAK_F,
        address_space::DELEGATION_ECRECOVER,
        address_space::DELEGATION_ECRECOVER_SCRATCH,
    ] {
        assert_ne!(
            space, DELEGATION_ANY,
            "an address space took the free value"
        );
    }
    assert_eq!(FRAME_READ_ONLY, [RS1, RS2, ARG1, ARG2, LOAD]);
    assert_eq!(CYCLE, PolyAddress::Memory(0));
}

/// §2.1 and §2.4 per family, against [`FRAME_SHAPES`]'s hand-written query
/// lists: `frame_queries` is that list; `1 + 5w` memory columns — one more,
/// `deleg_space`, on a frame that holds the delegation mirror — and `w + 3`
/// witness columns named after the query at each slot; `2w` leaves in the
/// order `read_<q>` by slot, the read side's constant-1 pads, then the same
/// for the write side; row-wise widths halving from `2·side` to 2; and the
/// enforcing gates by name — one booleanity per slot, one write-back per
/// read-only query the family holds, the four x0 gates, and on a frame that
/// holds the delegation mirror the tag column's default pin. The column
/// addresses are the slot's, `M[1 + 5s + f]` and `W[s]`, with the x0 gadget's
/// three witness columns after the family's `w` gap chunks.
///
/// Fails if a family's frame kept the table's eight queries, if a query's
/// columns were placed by its id rather than its slot, if a write-back gate
/// were emitted for a query the family does not hold, if the tag column were
/// dropped, given to a frame with no mirror, or placed anywhere but after the
/// last query's five, or if the pads were dropped or misordered.
#[test]
fn the_frame_layout_is_the_documents() {
    for (id, queries, memory_columns, witness_columns, side, obligations, gates) in FRAME_SHAPES {
        let w = queries.len();
        assert_eq!(frame_queries(id), queries, "family {id}");
        assert_eq!(side, w.next_power_of_two(), "family {id}");
        let a = family_frame_artifact(id, 12);
        assert_eq!(a, frame_artifact(queries, 12), "family {id}");

        let mut columns = vec![String::from("cycle")];
        for &q in queries {
            for f in ["mask", "addr", "read_ts", "read_value", "write_value"] {
                columns.push(format!("{}_{f}", FRAME_NAMES[q]));
            }
        }
        // S22's tag column, on a frame that holds the delegation mirror and on
        // no other: the requested type's anchor space, appended after every
        // query's five so no existing `M` index moves
        // (`docs/spec/ecrecover.md` §2.4).
        if queries.contains(&DELEG) {
            columns.push(String::from("deleg_space"));
        }
        assert_eq!(a.memory, columns, "family {id}");
        assert_eq!(a.memory.len(), memory_columns, "family {id}");
        let mut witness: Vec<String> = queries
            .iter()
            .map(|&q| format!("{}_gap_hi", FRAME_NAMES[q]))
            .collect();
        witness.extend(["rd_inv", "rd_is_zero", "rd_selected"].map(String::from));
        assert_eq!(a.witness, witness, "family {id}");
        assert_eq!(a.witness.len(), witness_columns, "family {id}");
        assert!(a.setup.is_empty() && a.virtuals.is_empty(), "family {id}");

        // Columns are addressed by slot; the x0 columns follow the w chunks.
        for at in 0..w {
            for field in 0..5 {
                let expected = PolyAddress::Memory(1 + 5 * at as u32 + field);
                assert_eq!(frame(at, field), expected, "family {id}, slot {at}");
            }
            assert_eq!(gap_hi(at), PolyAddress::Witness(at as u32), "family {id}");
        }
        if queries.contains(&DELEG) {
            let tag = PolyAddress::Memory(1 + 5 * w as u32);
            assert_eq!(deleg_space(w), tag, "family {id}");
            assert_eq!(a.memory[1 + 5 * w], "deleg_space", "family {id}");
        }
        assert_eq!(rd_inv(w), PolyAddress::Witness(w as u32), "family {id}");
        assert_eq!(rd_is_zero(w), PolyAddress::Witness(w as u32 + 1), "{id}");
        assert_eq!(rd_selected(w), PolyAddress::Witness(w as u32 + 2), "{id}");

        let leaves: Vec<&str> = a.scratch[..2 * side]
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        let mut expected: Vec<String> = Vec::new();
        for tree in ["read", "write"] {
            expected.extend(
                queries
                    .iter()
                    .map(|&q| format!("{tree}_{}", FRAME_NAMES[q])),
            );
            expected.extend((0..side - w).map(|i| format!("{tree}_pad_{i}")));
        }
        assert_eq!(leaves, expected, "family {id}");

        let rows = side.trailing_zeros() as usize;
        let widths: Vec<u32> = a.layers[..=rows].iter().map(|l| l.width).collect();
        let expected: Vec<u32> = (0..=rows).map(|k| ((2 * side) >> k) as u32).collect();
        assert_eq!(widths, expected, "family {id}");
        assert_eq!(a.depth(), 1 + rows + 12, "family {id}");
        assert_eq!(a.lookups.len(), obligations, "family {id}");

        let enforcing: Vec<&str> = a.layers[0]
            .enforcing
            .iter()
            .map(|e| a.relations[e.relation as usize].name.as_str())
            .collect();
        let mut expected: Vec<String> = queries
            .iter()
            .map(|&q| format!("{}_mask_boolean", FRAME_NAMES[q]))
            .collect();
        expected.extend(
            queries
                .iter()
                .filter(|q| FRAME_READ_ONLY.contains(q))
                .map(|&q| format!("{}_writes_back", FRAME_NAMES[q])),
        );
        expected.extend(
            [
                "rd_is_zero_inverse",
                "rd_is_zero_at_nonzero",
                "rd_is_zero_boolean",
                "rd_write_masked",
            ]
            .map(String::from),
        );
        // The mirror slot's tag column is held to 0 by the frame itself,
        // because a bare frame declares no delegation type and a column that
        // supplies a leaf's address space may not be free. A requesting
        // family's own pin -- `add_sub`'s `deleg_space_rule`, a sum over its
        // type selectors -- replaces this one rather than joining it
        // (`docs/spec/ecrecover.md` §2.4).
        if queries.contains(&DELEG) {
            expected.push(String::from("deleg_space_unused"));
        }
        assert_eq!(enforcing, expected, "family {id}");
        assert_eq!(enforcing.len(), gates, "family {id}");
    }
}

/// The widest frame's layout written out once, undeduced, as the document's
/// §2.1 reads it: `ADD_SUB_LUI_AUIPC` holds every query but `load`, so `rd`
/// sits at slot 6 and its mask is `M[31]`, not the `M[36]` a frame of all nine
/// queries would give it, and S21's `deleg` follows at slot 7. S22's tag
/// column closes the list: `deleg_space` is `M[41]`, past the mirror's own
/// five, so the frame is 42 memory columns and every index below it is the
/// one S21 froze. Kills a layout that silently kept the table's width, and a
/// tag column inserted anywhere but the end.
#[test]
fn the_widest_frame_is_eight_queries_with_rd_at_slot_six() {
    let a = family_frame_artifact(family::ADD_SUB_LUI_AUIPC, 12);
    assert_eq!(
        a.memory,
        [
            "cycle",
            "pc_mask",
            "pc_addr",
            "pc_read_ts",
            "pc_read_value",
            "pc_write_value",
            "rs1_mask",
            "rs1_addr",
            "rs1_read_ts",
            "rs1_read_value",
            "rs1_write_value",
            "rs2_mask",
            "rs2_addr",
            "rs2_read_ts",
            "rs2_read_value",
            "rs2_write_value",
            "arg1_mask",
            "arg1_addr",
            "arg1_read_ts",
            "arg1_read_value",
            "arg1_write_value",
            "arg2_mask",
            "arg2_addr",
            "arg2_read_ts",
            "arg2_read_value",
            "arg2_write_value",
            "ram_mask",
            "ram_addr",
            "ram_read_ts",
            "ram_read_value",
            "ram_write_value",
            "rd_mask",
            "rd_addr",
            "rd_read_ts",
            "rd_read_value",
            "rd_write_value",
            "deleg_mask",
            "deleg_addr",
            "deleg_read_ts",
            "deleg_read_value",
            "deleg_write_value",
            "deleg_space",
        ]
    );
    assert_eq!(a.memory.len(), 42);
    assert_eq!(frame(0, FIELD_MASK), PolyAddress::Memory(1));
    assert_eq!(frame(6, FIELD_MASK), PolyAddress::Memory(31));
    assert_eq!(frame(6, FIELD_WRITE_VALUE), PolyAddress::Memory(35));
    assert_eq!(frame(7, FIELD_MASK), PolyAddress::Memory(36));
    assert_eq!(frame(7, FIELD_WRITE_VALUE), PolyAddress::Memory(40));
    assert_eq!(deleg_space(8), PolyAddress::Memory(41));
    assert_eq!(
        a.witness,
        [
            "pc_gap_hi",
            "rs1_gap_hi",
            "rs2_gap_hi",
            "arg1_gap_hi",
            "arg2_gap_hi",
            "ram_gap_hi",
            "rd_gap_hi",
            "deleg_gap_hi",
            "rd_inv",
            "rd_is_zero",
            "rd_selected",
        ]
    );
    assert_eq!(rd_inv(8), PolyAddress::Witness(8));
}

/// The two families whose query count is not a power of two pad each side of
/// gate list 0 up to one, with leaves that are literally the constant 1 — the
/// product's identity — reading no column at all, named `<tree>_pad_<i>` after
/// that side's real leaves, in the gate and in its relation alike. A family
/// whose width is already a power of two has none. `ATOMICS` is the widest gap:
/// 5 queries, 3 pads a side.
///
/// Kills a pad that carries a column (which would commit and open it, and let
/// a value of the trace reach the product unconstrained), a pad whose constant
/// is not 1 (which would scale one side of the multiset), and a pad list that
/// runs before the real leaves, which would renumber every slot's leaf.
#[test]
fn the_pad_leaves_are_the_constant_one_and_read_nothing() {
    let one = GateDef::Linear {
        terms: vec![],
        constant: Coeff::Literal(Fr::ONE),
    };
    for (id, pads) in [
        // The add/sub frame is eight queries since S21, a power of two, so it
        // pays no pad at all; the other two still do.
        (family::ADD_SUB_LUI_AUIPC, 0),
        (family::MEM_WORD, 2),
        (family::ATOMICS, 3),
    ] {
        let w = frame_queries(id).len();
        let side = w.next_power_of_two();
        assert_eq!(side - w, pads, "family {id}");
        let a = family_frame_artifact(id, 12);
        assert_eq!(a.layers[0].producing.len(), 2 * side, "family {id}");
        for (t, tree) in ["read", "write"].into_iter().enumerate() {
            for i in 0..pads {
                let e = &a.layers[0].producing[t * side + w + i];
                assert_eq!(e.gate, one, "family {id}, {tree} pad {i}");
                assert!(e.gate.operands().is_empty(), "family {id}");
                let r = &a.relations[e.relation as usize];
                assert_eq!(r.name, format!("define_{tree}_pad_{i}"), "family {id}");
                assert_eq!(r.gate, one, "family {id}");
            }
        }
    }
    // A width that is already a power of two pads with nothing.
    let a = family_frame_artifact(family::JUMP_BRANCH_SLT, 12);
    assert_eq!(a.layers[0].producing.len(), 8);
    assert!(a.scratch[..8].iter().all(|s| !s.name.contains("pad")));
    assert!(a.relations.iter().all(|r| !r.name.contains("pad")));
}

/// The distinction the whole layout turns on, §2.1: **a query's address space
/// and Δ come from its id in the query table; its columns come from its slot
/// in the family's list.** Every frame's leaves are checked against §2.2's
/// flat `Quadratic`, written here from the id and the slot separately:
///
/// ```text
/// read  leaf  1 + (γ_M, m) + (−1, m) + (AS_q, m)
///               + (α_addr, addr_s, m) + (α_ts, read_ts_s, m) + (α_val, read_value_s, m)
/// write leaf  1 + (γ_M, m) + (−1, m) + (AS_q, m) + (α_ts, m) × Δ_q
///               + (α_addr, addr_s, m) + (α_ts, cycle, m) × 4 + (α_val, write_value_s, m)
/// ```
///
/// where `m` and every column are slot `s`'s. At least one slot per family
/// holds a query whose id it is not — `ATOMICS` puts `ram` (AS RAM, Δ 3) at
/// slot 3, where the table's `arg1` (AS REG, Δ 2) sits — and the test asserts
/// it found one, so a frame that quietly became the identity would fail here
/// rather than pass vacuously.
///
/// The delegation mirror is the one query with no `AS_q` to write: its space
/// is the row's `deleg_space` column, so `(AS_q, m)` is gone from the linear
/// part and the product `(1, deleg_space, m)` heads the products instead
/// (`docs/spec/ecrecover.md` §2.4). The shape is written out here too, at
/// whichever slot each family gives it, and
/// `the_delegation_mirrors_leaves_take_their_address_space_from_the_tag_column`
/// is where the term itself is argued.
///
/// Kills a construction that reads `FRAME_SPACE[slot]` or `FRAME_DELTA[slot]`,
/// or that addresses a column by the query's id.
#[test]
fn a_query_at_a_slot_that_is_not_its_id_keeps_its_own_space_and_delta() {
    let alpha_ts = Coeff::Challenge(challenge_slot::MEM_ALPHA_TS);
    let lit = |v: u64| Coeff::Literal(Fr::from_u64(v));
    let mut displaced = 0;
    for &id in &EXECUTION_FAMILIES {
        let queries = frame_queries(id);
        let a = family_frame_artifact(id, 12);
        for (at, &q) in queries.iter().enumerate() {
            displaced += (at != q) as usize;
            let m = frame(at, FIELD_MASK);
            let mut head = vec![
                (Coeff::Challenge(challenge_slot::MEM_GAMMA), m),
                (Coeff::Literal(Fr::MINUS_ONE), m),
            ];
            // The address space, which the mirror alone takes from a column:
            // its term's operand is not the mask, so it is a product and it
            // leads both leaves' product lists.
            let space: Vec<(Coeff, PolyAddress, PolyAddress)> = match q {
                DELEG => vec![(lit(1), deleg_space(queries.len()), m)],
                _ => {
                    head.push((lit(FRAME_SPACE[q] as u64), m));
                    vec![]
                }
            };
            let mut read_products = space.clone();
            read_products.extend([
                (
                    Coeff::Challenge(challenge_slot::MEM_ALPHA_ADDR),
                    frame(at, FIELD_ADDR),
                    m,
                ),
                (alpha_ts, frame(at, FIELD_READ_TS), m),
                (
                    Coeff::Challenge(challenge_slot::MEM_ALPHA_VAL),
                    frame(at, FIELD_READ_VALUE),
                    m,
                ),
            ]);
            let read = GateDef::Quadratic {
                constant: lit(1),
                linear: head.clone(),
                products: read_products,
            };
            let mut linear = head;
            linear.extend(vec![(alpha_ts, m); FRAME_DELTA[q] as usize]);
            let mut products = space;
            products.push((
                Coeff::Challenge(challenge_slot::MEM_ALPHA_ADDR),
                frame(at, FIELD_ADDR),
                m,
            ));
            products.extend(vec![(alpha_ts, CYCLE, m); memory::TS_STEP as usize]);
            products.push((
                Coeff::Challenge(challenge_slot::MEM_ALPHA_VAL),
                frame(at, FIELD_WRITE_VALUE),
                m,
            ));
            let write = GateDef::Quadratic {
                constant: lit(1),
                linear,
                products,
            };
            let side = queries.len().next_power_of_two();
            let name = FRAME_NAMES[q];
            assert_eq!(
                a.layers[0].producing[at].gate, read,
                "family {id}, {name} at slot {at}"
            );
            assert_eq!(
                a.layers[0].producing[side + at].gate,
                write,
                "family {id}, {name} at slot {at}"
            );
        }
    }
    assert!(
        displaced > 0,
        "no family displaces a query from its id, so the distinction is untested"
    );
}

/// S22's tag column, on the one frame that holds the delegation mirror. A
/// requesting family serves **every** delegation type from its one `deleg`
/// slot, so the mirror's address space cannot be a literal of the query table:
/// the row carries the requested type's anchor tag in `deleg_space`, the
/// frame's last memory column, and the leaf's `AS` term is the product
/// `(1, deleg_space, m)` rather than `(tag, m)`
/// (`docs/spec/ecrecover.md` §2.4). Both leaves are written out whole, so the
/// coefficient, the column and the term's position at the head of the products
/// are each pinned, and `rd` at the slot before is written out beside them as
/// the literal-space shape the mirror is not.
///
/// The negative is asserted directly and not left to the two equalities: no
/// literal of any byte weights the mirror's mask, so no tag of any delegation
/// family can be hiding in either leaf, whatever the tags grow to.
///
/// Kills a regression to a hardcoded tag — which would answer an ecrecover
/// request with keccak's anchor space, so that a request could pair with an
/// invocation of the wrong type — and a tag column that reached the leaf as
/// anything but a product on the mask, which `check_memory` would then have to
/// refuse as a leaf cone reading a `W` column.
#[test]
fn the_delegation_mirrors_leaves_take_their_address_space_from_the_tag_column() {
    let queries = frame_queries(family::ADD_SUB_LUI_AUIPC);
    let (w, at) = (queries.len(), 7);
    assert_eq!((queries[at], queries[6]), (DELEG, RD));
    let a = family_frame_artifact(family::ADD_SUB_LUI_AUIPC, 12);
    let tag = deleg_space(w);
    assert_eq!(tag, PolyAddress::Memory(1 + 5 * w as u32));
    assert_eq!(a.memory[1 + 5 * w], "deleg_space");
    assert_eq!(a.memory.len(), 2 + 5 * w);

    let lit = |v: u64| Coeff::Literal(Fr::from_u64(v));
    let alpha_ts = Coeff::Challenge(challenge_slot::MEM_ALPHA_TS);
    let alpha_addr = Coeff::Challenge(challenge_slot::MEM_ALPHA_ADDR);
    let alpha_val = Coeff::Challenge(challenge_slot::MEM_ALPHA_VAL);
    let m = frame(at, FIELD_MASK);
    let head = vec![
        (Coeff::Challenge(challenge_slot::MEM_GAMMA), m),
        (Coeff::Literal(Fr::MINUS_ONE), m),
    ];
    let read = GateDef::Quadratic {
        constant: lit(1),
        linear: head.clone(),
        products: vec![
            (lit(1), tag, m),
            (alpha_addr, frame(at, FIELD_ADDR), m),
            (alpha_ts, frame(at, FIELD_READ_TS), m),
            (alpha_val, frame(at, FIELD_READ_VALUE), m),
        ],
    };
    let mut linear = head;
    linear.extend(vec![(alpha_ts, m); FRAME_DELTA[DELEG] as usize]);
    let mut products = vec![(lit(1), tag, m), (alpha_addr, frame(at, FIELD_ADDR), m)];
    products.extend(vec![(alpha_ts, CYCLE, m); memory::TS_STEP as usize]);
    products.push((alpha_val, frame(at, FIELD_WRITE_VALUE), m));
    let write = GateDef::Quadratic {
        constant: lit(1),
        linear,
        products,
    };
    let side = w.next_power_of_two();
    assert_eq!(a.layers[0].producing[at].gate, read, "read_deleg");
    assert_eq!(a.layers[0].producing[side + at].gate, write, "write_deleg");

    // No literal weights the mirror's mask, at any value a tag could take.
    for (name, gate) in [("read_deleg", &read), ("write_deleg", &write)] {
        let GateDef::Quadratic { linear, .. } = gate else {
            panic!("a leaf is a Quadratic");
        };
        for byte in 0..=u8::MAX {
            assert!(
                !linear.contains(&(lit(byte as u64), m)),
                "{name} weights its mask by the literal {byte}"
            );
        }
    }
    // `rd`, at the slot before, is the shape the mirror departs from: its
    // space is REG and REG is a literal on its mask.
    let GateDef::Quadratic { linear, .. } = &a.layers[0].producing[6].gate else {
        panic!("a leaf is a Quadratic");
    };
    assert!(linear.contains(&(lit(FRAME_SPACE[RD] as u64), frame(6, FIELD_MASK))));
}

/// The routing rule, §2.4: `frame_matches` is the one authority for whether a
/// logged event belongs to a frame slot, and the mirror is the one slot that
/// is not an exact `(FRAME_SPACE, FRAME_DELTA)` pair. It takes **any**
/// delegation anchor space at its Δ 3 — the type being the row's
/// `deleg_space`, not the slot's — and nothing else: not
/// `DELEGATION_ECRECOVER_SCRATCH`, which is a bus rather than an anchor and
/// which no frame slot answers, not `RAM`, which shares Δ 3 and is the near
/// miss, and no anchor at any other Δ. Every other query is held to its exact
/// pair over the whole tag space, and `is_delegation_anchor` over all 256.
///
/// Kills a router that kept S21's keccak literal — which would `continue` past
/// every ecrecover anchor event and fill the slot with zeros, so the honest
/// prover's frame would not balance — one that widened far enough to swallow
/// the scratch bus, and one that stopped reading Δ.
#[test]
fn the_mirror_slot_routes_every_delegation_anchor_and_never_the_scratch_bus() {
    let anchors = [
        address_space::DELEGATION_KECCAK_F,
        address_space::DELEGATION_ECRECOVER,
    ];
    for tag in 0..=u8::MAX {
        assert_eq!(
            is_delegation_anchor(tag),
            anchors.contains(&tag),
            "tag {tag}"
        );
    }
    assert!(!is_delegation_anchor(
        address_space::DELEGATION_ECRECOVER_SCRATCH
    ));
    assert!(!is_delegation_anchor(DELEGATION_ANY));

    for delta in 0..memory::TS_STEP {
        for tag in 0..=u8::MAX {
            let mirrored = is_delegation_anchor(tag) && delta == FRAME_DELTA[DELEG];
            assert_eq!(
                frame_matches(DELEG, tag, delta),
                mirrored,
                "the mirror on tag {tag} at Δ {delta}"
            );
        }
    }
    // The cases §2.4 names, written out beside the sweep: both anchors are the
    // mirror's at its own Δ; the scratch bus is no slot's; `RAM` shares the Δ
    // and is the near miss; and an anchor one slot early is nobody's either.
    let mirror = FRAME_DELTA[DELEG];
    for (tag, delta, matches) in [
        (address_space::DELEGATION_KECCAK_F, mirror, true),
        (address_space::DELEGATION_ECRECOVER, mirror, true),
        (address_space::DELEGATION_ECRECOVER_SCRATCH, mirror, false),
        (address_space::RAM, mirror, false),
        (address_space::DELEGATION_KECCAK_F, mirror - 1, false),
        (address_space::DELEGATION_ECRECOVER, 0, false),
    ] {
        assert_eq!(
            frame_matches(DELEG, tag, delta),
            matches,
            "the mirror on tag {tag} at Δ {delta}"
        );
    }

    // Every other query is its pair and nothing else, so an anchor event
    // reaches none of them — `ram` and `rd`, which sit at the mirror's Δ,
    // included.
    for query in 0..FRAME_QUERIES {
        if query == DELEG {
            continue;
        }
        for delta in 0..memory::TS_STEP {
            for tag in 0..=u8::MAX {
                assert_eq!(
                    frame_matches(query, tag, delta),
                    tag == FRAME_SPACE[query] && delta == FRAME_DELTA[query],
                    "{} on tag {tag} at Δ {delta}",
                    FRAME_NAMES[query]
                );
            }
        }
    }
}

/// The mirror has no frame-free read tuple. `read_tuple` spells a query's
/// tuple as a frame holding every query would address it, which the verifier's
/// boundary evaluates for the pc and `rs1` and for nothing else
/// (`gkr_verify::boundary_factors`); the mirror's address space is a column of
/// the frame it sits in, so there is no such spelling and asking for one is
/// refused rather than answered with a hardcoded tag.
#[test]
#[should_panic(expected = "the delegation mirror's address space is a column, not a literal")]
fn the_delegation_mirror_has_no_frame_free_read_tuple() {
    read_tuple(DELEG);
}

/// §2.4 per family: two obligations per *slot* in slot order, `gap_hi_<q>`
/// then `gap_lo_<q>`, on the timestamp channel under that slot's mask; the
/// high chunk is the slot's `W[s]` and the low chunk reads the slot's
/// `read_ts` — while the constant is `Δ − 1` for the query's **id**, `−1` for
/// the pc, which every frame holds at slot 0. `ATOMICS` is the witness that
/// the two differ: its `ram` sits at slot 3, whose table entry `arg1` has
/// Δ 2, and its obligation's constant is Δ(`ram`) − 1 = 2.
///
/// Fails if an obligation were keyed to the wrong slot's columns, if a query
/// took the Δ of the slot it happens to sit at, or if a family carried the
/// table's sixteen obligations rather than its own `2w`.
#[test]
fn the_frame_carries_two_gap_obligations_per_query() {
    let minus = |v: u64| Coeff::Literal(-Fr::from_u64(v));
    let lit = |v: u64| Coeff::Literal(Fr::from_u64(v));
    for &id in &EXECUTION_FAMILIES {
        let queries = frame_queries(id);
        let a = family_frame_artifact(id, 12);
        assert_eq!(a.lookups.len(), 2 * queries.len(), "family {id}");
        for (at, &q) in queries.iter().enumerate() {
            let name = FRAME_NAMES[q];
            let hi = PolyAddress::Witness(at as u32);
            let selector = frame(at, FIELD_MASK);
            let expected = [
                LookupExpr {
                    name: format!("gap_hi_{name}"),
                    channel: lookup_channel::TIMESTAMP,
                    selector,
                    tuple: vec![GateDef::Linear {
                        terms: vec![(lit(1), hi)],
                        constant: lit(0),
                    }],
                },
                LookupExpr {
                    name: format!("gap_lo_{name}"),
                    channel: lookup_channel::TIMESTAMP,
                    selector,
                    tuple: vec![GateDef::Linear {
                        terms: vec![
                            (lit(4), CYCLE),
                            (minus(1), frame(at, FIELD_READ_TS)),
                            (minus(1 << 19), hi),
                        ],
                        constant: Coeff::Literal(Fr::from_u64(FRAME_DELTA[q]) - Fr::ONE),
                    }],
                },
            ];
            assert_eq!(
                a.lookups[2 * at..2 * at + 2],
                expected,
                "family {id}, {name}"
            );
        }
        let GateDef::Linear { constant, .. } = &a.lookups[1].tuple[0] else {
            panic!("gap_lo_pc is Linear");
        };
        assert_eq!(
            *constant,
            minus(1),
            "family {id}: gap_lo_pc's constant is −1"
        );
    }
    // `ram` at slot 3 of ATOMICS keeps Δ = 3, not slot 3's `arg1` Δ = 2.
    let atomics = family_frame_artifact(family::ATOMICS, 12);
    assert_eq!(frame_queries(family::ATOMICS)[3], RAM);
    let GateDef::Linear { constant, .. } = &atomics.lookups[7].tuple[0] else {
        panic!("gap_lo_ram is Linear");
    };
    assert_eq!(atomics.lookups[7].name, "gap_lo_ram");
    assert_eq!(
        *constant,
        Coeff::Literal(Fr::from_u64(FRAME_DELTA[RAM]) - Fr::ONE)
    );
    assert_ne!(
        *constant,
        Coeff::Literal(Fr::from_u64(FRAME_DELTA[3]) - Fr::ONE)
    );
}

/// S14 acceptance 11, exhaustively at reduced width: §2.4's gap encoding with
/// `w = 5`-bit chunks over a 10-bit clock. The two obligations say
/// `hi ∈ [0, 2^w)` and `lo = gap − 2^w·hi ∈ [0, 2^w)`, `lo` a field element, so
/// a pair is admitted exactly when `gap`, computed in `Fr`, is one of the
/// `2^{2w}` field elements `lo + 2^w·hi` — which are distinct. The gap is the
/// library's: each slot's `gap_lo_<q>` from that family's frame, evaluated with
/// its high chunk `W[s]` at 0, at `cycle` and `read_ts`. Over the four distinct
/// frames — which between them place all eight queries of the table, asserted
/// below — every cycle in `[0, 2^8)`, so `ts = 4·cycle + Δ` meets every value
/// of the 10-bit clock across the four `Δ`, and every `read_ts` in `[0, 2^10)`,
/// where `read_ts ≥ ts` wraps the gap to `p − (read_ts − ts + 1)`, a pair is
/// admitted exactly when `read_ts < ts`.
///
/// This test holds the recombination at width 5 and the expression's cycle,
/// read-timestamp and constant terms; the chunk width `2^19` and the
/// evaluator are held at full width by `crates/checker/tests/multiset.rs`'
/// `the_gap_obligations_accept_exactly_0_through_2_38_minus_1`.
///
/// Fails if a wrapped negative gap were admitted, or a strictly ordered pair
/// refused — so if `gap_lo`'s constant were `Δ` rather than `Δ − 1`, admitting
/// `read_ts = ts`, or if a displaced query took its slot's Δ.
#[test]
fn the_gap_encoding_is_strict_at_reduced_width() {
    const W: u32 = 5;
    let clock = 1u64 << (2 * W);
    let mut admitted_gaps = HashSet::new();
    for hi in 0..1u64 << W {
        for lo in 0..1u64 << W {
            let gap = Fr::from_u64(lo) + Fr::from_u64(1 << W) * Fr::from_u64(hi);
            admitted_gaps.insert(gap.to_bytes());
        }
    }
    assert_eq!(
        admitted_gaps.len(),
        1 << (2 * W),
        "lo + 2^w·hi is injective"
    );
    let literal = |c: &Coeff| match c {
        Coeff::Literal(v) => *v,
        Coeff::Challenge(_) => panic!("gap_lo's coefficients are literals"),
    };
    let mut covered: HashSet<usize> = HashSet::new();
    for &id in &DISTINCT_FRAMES {
        let queries = frame_queries(id);
        let a = family_frame_artifact(id, 12);
        for (at, &q) in queries.iter().enumerate() {
            covered.insert(q);
            let GateDef::Linear { terms, constant } = &a.lookups[2 * at + 1].tuple[0] else {
                panic!("gap_lo_{} is Linear", FRAME_NAMES[q]);
            };
            let (mut step, mut sign) = (Fr::ZERO, Fr::ZERO);
            for (c, address) in terms {
                match *address {
                    CYCLE => step += literal(c),
                    x if x == frame(at, FIELD_READ_TS) => sign += literal(c),
                    x => assert_eq!(
                        x,
                        gap_hi(at),
                        "gap_lo_{} reads only its chunk",
                        FRAME_NAMES[q]
                    ),
                }
            }
            let constant = literal(constant);
            for cycle in 0..clock / 4 {
                let ts = 4 * cycle + FRAME_DELTA[q];
                for read_ts in 0..clock {
                    let gap = step * Fr::from_u64(cycle) + sign * Fr::from_u64(read_ts) + constant;
                    let ok = admitted_gaps.contains(&gap.to_bytes());
                    let name = FRAME_NAMES[q];
                    assert_eq!(
                        ok,
                        read_ts < ts,
                        "family {id}, {name} at slot {at}: ts {ts}, read_ts {read_ts}"
                    );
                }
            }
        }
    }
    assert_eq!(
        covered.len(),
        FRAME_QUERIES,
        "the four frames place every query of the table between them"
    );
}

/// Every base address a gate or an obligation of the artifact reads, once each,
/// ascending.
fn read_set(a: &CircuitArtifact) -> Vec<PolyAddress> {
    let list = &a.layers[0];
    let mut read: Vec<PolyAddress> = Vec::new();
    for gate in list.producing.iter().map(|e| &e.gate) {
        read.extend(gate.operands());
    }
    for gate in list.enforcing.iter().map(|e| &e.gate) {
        read.extend(gate.operands());
    }
    for l in &a.lookups {
        read.push(l.selector);
        read.extend(l.tuple.iter().flat_map(|g| g.operands()));
    }
    read.sort();
    read.dedup();
    read
}

/// §8's pinned read sets: `ZERO_WINDOWS` reads exactly `M[0]`, `M[1]`,
/// `V[row]`; `INIT_TEARDOWN` those and `S[0]`, `V[ram_live]`; a family's frame
/// reads exactly its own `1 + 5w` memory columns — and `M[1 + 5w]` besides,
/// where it holds the delegation mirror, whose two leaves take their address
/// space from that tag column — and `w + 3` witness columns, every column it
/// commits and nothing else, no `S` and no `V`. A frame that kept a column it
/// never reads would fail here, as would one reading past its own width into
/// the addresses a wider family's frame uses.
#[test]
fn the_read_sets_are_pinned() {
    let (m0, m1, s0) = (
        PolyAddress::Memory(0),
        PolyAddress::Memory(1),
        PolyAddress::Setup(0),
    );
    let row = PolyAddress::Virtual(VirtualKind::RowIndex);
    let live = PolyAddress::Virtual(VirtualKind::RamLive);
    for trace_vars in [12, 22] {
        assert_eq!(
            read_set(&zero_window_artifact(trace_vars)),
            [m0, m1, row],
            "{trace_vars}"
        );
        assert_eq!(
            read_set(&image_window_artifact(trace_vars)),
            [m0, m1, s0, row, live],
            "{trace_vars}"
        );
        for &id in &EXECUTION_FAMILIES {
            let queries = frame_queries(id);
            let w = queries.len() as u32;
            let tag = u32::from(queries.contains(&DELEG));
            let mut expected: Vec<PolyAddress> =
                (0..1 + 5 * w + tag).map(PolyAddress::Memory).collect();
            expected.extend((0..w + 3).map(PolyAddress::Witness));
            assert_eq!(
                read_set(&family_frame_artifact(id, trace_vars)),
                expected,
                "family {id} at {trace_vars}"
            );
        }
    }
    let zero = zero_window_artifact(12);
    assert_eq!(zero.memory, ["teardown_ts", "teardown_value"]);
    assert!(zero.witness.is_empty() && zero.setup.is_empty() && zero.lookups.is_empty());
    let image = image_window_artifact(12);
    assert_eq!(image.memory, ["teardown_ts", "teardown_value"]);
    assert_eq!(image.setup, ["init_value"]);
    assert!(image.witness.is_empty() && image.lookups.is_empty());
    for a in [&zero, &image] {
        assert!(a.layers[0].enforcing.is_empty());
        let leaves: Vec<&str> = a.scratch[..2].iter().map(|s| s.name.as_str()).collect();
        assert_eq!(leaves, ["teardown", "init"]);
    }
}

/// `gate` with every `from` operand replaced by `to`.
fn swap(gate: &GateDef, from: PolyAddress, to: PolyAddress) -> GateDef {
    let at = |x: PolyAddress| if x == from { to } else { x };
    let GateDef::Quadratic {
        constant,
        linear,
        products,
    } = gate
    else {
        panic!("a leaf is a Quadratic");
    };
    GateDef::Quadratic {
        constant: *constant,
        linear: linear.iter().map(|(c, x)| (*c, at(*x))).collect(),
        products: products
            .iter()
            .map(|(c, y, z)| (*c, at(*y), at(*z)))
            .collect(),
    }
}

/// S14 acceptance 9, on the widest frame — `ADD_SUB_LUI_AUIPC`, whose gate
/// list 0 also carries a constant-1 pad leaf a side: the `rs1` read leaf's
/// address, slot 1's `M[7]`, fed from `W[0]` instead, in its gate and its
/// relation alike. The artifact is still a lawful circuit — `validate` accepts
/// it — and `check_memory` refuses it by provenance, naming the leaf.
///
/// Kills a provenance check that ignores `W` operands or list 0.
#[test]
fn a_tuple_fed_from_a_witness_column_is_refused() {
    let mut a = family_frame_artifact(family::ADD_SUB_LUI_AUIPC, 12);
    assert_eq!(frame_queries(family::ADD_SUB_LUI_AUIPC)[1], RS1);
    let (from, to) = (frame(1, FIELD_ADDR), PolyAddress::Witness(0));
    assert_eq!(from, PolyAddress::Memory(7));
    let entry = &mut a.layers[0].producing[1];
    entry.gate = swap(&entry.gate, from, to);
    let r = entry.relation as usize;
    a.relations[r].gate = swap(&a.relations[r].gate, from, to);
    assert_eq!(a.relations[r].name, "define_read_rs1");
    assert_eq!(a.validate(), Ok(()));
    let e = check_memory(&a).unwrap_err();
    assert!(
        e.starts_with("memory provenance: `define_read_rs1` in gate list 0"),
        "{e}"
    );
}

/// §8's forward-provenance counterexample, built whole:
///
/// ```text
/// base    M[0] a   W[0] w                      2 rows
/// list 0  L{1}[0] tuple = α_addr·a + γ_M        names a slot, reads no W
///         L{1}[1] copy  = w                     reads W, names no slot
/// list 1  L{2}[0] mixed = tuple·copy            both, through its operands only
/// ```
///
/// No gate of list 0 is refused; the product in layer 2 is. Then the same
/// product as an enforcing gate of list 1, `mixed = 0`, beside a lawful
/// producing `squared = tuple·tuple`: refused too, and there rule 1 is the only
/// rule that can see it — its coefficient is a literal. The controls copy `a`
/// instead of `w` and pass. Kills a provenance check that reads a gate's own
/// coefficients and base operands without carrying flags up, or that skips
/// enforcing gates.
#[test]
fn a_product_of_a_tuple_and_a_witness_copy_two_layers_up_is_refused() {
    let circuit = |copied: PolyAddress, enforced: bool| {
        let (a, lit1) = (PolyAddress::Memory(0), Coeff::Literal(Fr::ONE));
        let tuple = GateDef::Linear {
            terms: vec![(Coeff::Challenge(challenge_slot::MEM_ALPHA_ADDR), a)],
            constant: Coeff::Challenge(challenge_slot::MEM_GAMMA),
        };
        let copy = GateDef::Linear {
            terms: vec![(lit1, copied)],
            constant: Coeff::Literal(Fr::ZERO),
        };
        let product = |left, right| GateDef::Product {
            coeff: lit1,
            left,
            right,
        };
        let relation = |name: &str, output, gate| Relation {
            name: name.into(),
            output,
            gate,
        };
        let entry = |relation, output, gate| ProducingEntry {
            relation,
            output,
            gate,
        };
        let slot = |name: &str, address| ScratchSlot {
            name: name.into(),
            address,
        };
        let (s0, s1) = (PolyAddress::Scratch(0), PolyAddress::Scratch(1));
        let mut relations = vec![
            relation("define_tuple", Some(0), tuple.clone()),
            relation("define_copy", Some(1), copy.clone()),
        ];
        let mut scratch = vec![slot("tuple", inner(1, 0)), slot("copy", inner(1, 1))];
        let mut list1 = LayerSpec {
            halving: false,
            num_vars: 1,
            width: 1,
            cached: vec![],
            producing: vec![],
            enforcing: vec![],
        };
        if enforced {
            list1.producing = vec![entry(2, inner(2, 0), product(inner(1, 0), inner(1, 0)))];
            list1.enforcing = vec![EnforcingEntry {
                relation: 3,
                gate: product(inner(1, 0), inner(1, 1)),
            }];
            relations.push(relation("define_squared", Some(2), product(s0, s0)));
            relations.push(relation("mixed", None, product(s0, s1)));
            scratch.push(slot("squared", inner(2, 0)));
        } else {
            list1.producing = vec![entry(2, inner(2, 0), product(inner(1, 0), inner(1, 1)))];
            relations.push(relation("define_mixed", Some(2), product(s0, s1)));
            scratch.push(slot("mixed", inner(2, 0)));
        }
        let artifact = CircuitArtifact {
            format_version: FORMAT_VERSION,
            coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
            trace_vars: 1,
            memory: vec!["a".into()],
            witness: vec!["w".into()],
            setup: vec![],
            virtuals: vec![],
            layers: vec![
                LayerSpec {
                    halving: false,
                    num_vars: 1,
                    width: 2,
                    cached: vec![],
                    producing: vec![
                        entry(0, inner(1, 0), tuple.clone()),
                        entry(1, inner(1, 1), copy.clone()),
                    ],
                    enforcing: vec![],
                },
                list1,
            ],
            relations,
            lookups: vec![],
            scratch,
            outputs: vec![inner(2, 0)],
            padding: Padding {
                row: vec![Fr::ZERO; 2],
                zero_row_valid: true,
            },
        };
        assert_eq!(artifact.validate(), Ok(()));
        artifact
    };
    for (enforced, name) in [(false, "define_mixed"), (true, "mixed")] {
        assert_eq!(
            check_memory(&circuit(PolyAddress::Witness(0), enforced)),
            Err(format!(
                "memory provenance: `{name}` in gate list 1 names a global memory slot and reads a \
                 W column"
            ))
        );
        assert_eq!(
            check_memory(&circuit(PolyAddress::Memory(0), enforced)),
            Ok(())
        );
    }
}

/// §8's root rule: `ZERO_WINDOWS` with its init leaf replaced, gate and
/// relation, by `Linear { [(1, W[0])], 0 }` over a new witness column `w`. The
/// write root's cone then reads `W` and names no slot, so the provenance rule,
/// which needs both, passes it, and so do the slot rule and the mask rule — yet
/// `W` is committed after the memory challenges, so the prover would choose
/// that root after them and balance any trace. `validate` accepts the circuit;
/// `check_memory` refuses the root. Fails if a root may read a `W` column.
#[test]
fn a_root_read_from_a_witness_column_alone_is_refused() {
    let mut a = zero_window_artifact(4);
    a.witness.push("w".into());
    a.padding.row.push(Fr::ZERO);
    let w = GateDef::Linear {
        terms: vec![(Coeff::Literal(Fr::ONE), PolyAddress::Witness(0))],
        constant: Coeff::Literal(Fr::ZERO),
    };
    let entry = &mut a.layers[0].producing[1];
    entry.gate = w.clone();
    let r = entry.relation as usize;
    assert_eq!(a.relations[r].name, "define_init");
    a.relations[r].gate = w;
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(
        check_memory(&a),
        Err(
            "memory provenance: output 1, `write_root`, reads a W column, which is committed \
             after the memory challenges"
                .to_string()
        )
    );
}

/// One gate list over `M[0] a` and `W[0] w`, 2 rows: `cached`, then one
/// producing gate `gate` writing the top column `out`, whose relation is
/// `flat`, the same polynomial with the cached entries substituted.
fn cached_circuit(cached: Vec<(&str, GateDef)>, gate: GateDef, flat: GateDef) -> CircuitArtifact {
    let artifact = CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars: 1,
        memory: vec!["a".into()],
        witness: vec!["w".into()],
        setup: vec![],
        virtuals: vec![],
        layers: vec![LayerSpec {
            halving: false,
            num_vars: 1,
            width: 1,
            cached: cached
                .into_iter()
                .enumerate()
                .map(|(j, (name, gate))| CachedEntry {
                    name: name.into(),
                    address: PolyAddress::Cached {
                        layer: 0,
                        offset: j as u32,
                    },
                    gate,
                })
                .collect(),
            producing: vec![ProducingEntry {
                relation: 0,
                output: inner(1, 0),
                gate,
            }],
            enforcing: vec![],
        }],
        relations: vec![Relation {
            name: "define_out".into(),
            output: Some(0),
            gate: flat,
        }],
        lookups: vec![],
        scratch: vec![ScratchSlot {
            name: "out".into(),
            address: inner(1, 0),
        }],
        outputs: vec![inner(1, 0)],
        padding: Padding {
            row: vec![Fr::ZERO; 2],
            zero_row_valid: true,
        },
    };
    assert_eq!(artifact.validate(), Ok(()));
    artifact
}

/// Cached entries under §8, substituted as `validate` substitutes them, each
/// circuit lawful:
///
/// ```text
/// C[0] tuple = γ_M + α_addr·a,  C[1] copy = w,  out = tuple·copy
///     refused at `out`: the slot and the W column meet only through the cache
/// C[0] slot_over_w = α_addr·w,  out = slot_over_w
///     refused at the cached entry itself, which is checked before `out`
/// C[0] copy_a = a,  out = γ_M·copy_a
///     refused by the slot rule: a slot over a cached entry
/// ```
///
/// Kills a check that gives a cached operand no flags or drops its W flag, that
/// does not check cached entries themselves, or that admits a slot over one.
#[test]
fn cached_entries_are_held_to_the_memory_rules() {
    let (a, w) = (PolyAddress::Memory(0), PolyAddress::Witness(0));
    let c = |offset| PolyAddress::Cached { layer: 0, offset };
    let (gamma, alpha) = (
        Coeff::Challenge(challenge_slot::MEM_GAMMA),
        Coeff::Challenge(challenge_slot::MEM_ALPHA_ADDR),
    );
    let (one, zero) = (Coeff::Literal(Fr::ONE), Coeff::Literal(Fr::ZERO));
    let linear = |terms, constant| GateDef::Linear { terms, constant };

    let through_the_cache = cached_circuit(
        vec![
            ("tuple", linear(vec![(alpha, a)], gamma)),
            ("copy", linear(vec![(one, w)], zero)),
        ],
        GateDef::Product {
            coeff: one,
            left: c(0),
            right: c(1),
        },
        GateDef::Quadratic {
            constant: zero,
            linear: vec![(gamma, w)],
            products: vec![(alpha, a, w)],
        },
    );
    assert_eq!(
        check_memory(&through_the_cache),
        Err(
            "memory provenance: `define_out` in gate list 0 names a global memory slot and reads \
             a W column"
                .to_string()
        )
    );

    let bad_entry = cached_circuit(
        vec![("slot_over_w", linear(vec![(alpha, w)], zero))],
        linear(vec![(one, c(0))], zero),
        linear(vec![(alpha, w)], zero),
    );
    assert_eq!(
        check_memory(&bad_entry),
        Err(
            "memory provenance: `slot_over_w` in gate list 0 names a global memory slot and reads \
             a W column"
                .to_string()
        )
    );

    let slot_over_cache = cached_circuit(
        vec![("copy_a", linear(vec![(one, a)], zero))],
        linear(vec![(gamma, c(0))], zero),
        linear(vec![(gamma, a)], zero),
    );
    assert_eq!(
        check_memory(&slot_over_cache),
        Err(
            "memory slot operands: `define_out` in gate list 0 carries a global memory slot and \
             reads C{0}[0]; only M, S and V columns may be weighted by one"
                .to_string()
        )
    );
}

/// The widest frame, `ADD_SUB_LUI_AUIPC`, with one query's booleanity gate
/// removed — its enforcing entry and its relation, every later relation index
/// shifted down — is still a lawful circuit, and `check_memory` refuses that
/// query's leaves' mask as unconstrained. Tried on `pc_mask_boolean`, at slot
/// 0, whose mask `M[1]` no other gate reads, and on `rd_mask_boolean`, at slot
/// 6 — so `M[31]`, the address the family's *width* gives it, not the `M[36]`
/// of the query table — whose mask `rd_is_zero_inverse` still reads. Kills a
/// mask rule that is not checked, or that accepts any enforcing gate on the
/// mask.
#[test]
fn a_frame_missing_a_booleanity_gate_is_refused() {
    let queries = frame_queries(family::ADD_SUB_LUI_AUIPC);
    assert_eq!((queries[0], queries[6]), (PC, RD));
    for (query, slot, mask) in [("pc", 0, "M[1]"), ("rd", 6, "M[31]")] {
        assert_eq!(format!("{}", frame(slot, FIELD_MASK)), mask);
        let mut a = family_frame_artifact(family::ADD_SUB_LUI_AUIPC, 12);
        let r = a
            .relations
            .iter()
            .position(|rel| rel.name == format!("{query}_mask_boolean"))
            .expect("the frame names it") as u32;
        a.layers[0].enforcing.retain(|e| e.relation != r);
        a.relations.remove(r as usize);
        for list in a.layers.iter_mut() {
            for e in list.producing.iter_mut() {
                e.relation -= (e.relation > r) as u32;
            }
            for e in list.enforcing.iter_mut() {
                e.relation -= (e.relation > r) as u32;
            }
        }
        // Two independent rules bite, and each names its own subject. Since
        // S15 a mask is also the selector of that query's gap obligations, and
        // `validate` refuses a selector gate list 0 does not hold to
        // booleanity (`docs/spec/lookup.md` §2).
        assert_eq!(
            a.validate(),
            Err(ConstraintError::Malformed {
                detail: format!(
                    "lookup `gap_hi_{query}` has selector {mask}, which gate list 0 does not \
                     hold to booleanity"
                )
            }),
            "{query}"
        );
        assert_eq!(
            check_memory(&a),
            Err(format!(
                "unconstrained mask: leaf `define_read_{query}` masks with {mask}, and gate list \
                 0 has no enforcing gate {mask} − {mask}·{mask}"
            ))
        );
    }
}

/// `INIT_TEARDOWN` with its teardown leaf's mask `V[ram_live]` swapped, in the
/// gate and its relation, for `S[0]` — a committed column no booleanity gate
/// holds — and for `V[row]`, which is not 0 or 1 on the cube. Both still lawful
/// circuits, both refused naming the leaf and the mask. Kills a mask rule that
/// covers `M` alone, or that exempts every virtual column.
#[test]
fn a_window_leaf_masked_by_a_setup_column_or_the_row_index_is_refused() {
    let live = PolyAddress::Virtual(VirtualKind::RamLive);
    let cases = [
        (
            PolyAddress::Setup(0),
            "unconstrained mask: leaf `define_teardown` masks with S[0], and gate list 0 has no \
             enforcing gate S[0] − S[0]·S[0]",
        ),
        (
            PolyAddress::Virtual(VirtualKind::RowIndex),
            "unconstrained mask: leaf `define_teardown` masks with V[row], which is not 0 or 1 on \
             every row",
        ),
    ];
    for (mask, expected) in cases {
        let mut a = image_window_artifact(12);
        let entry = &mut a.layers[0].producing[0];
        entry.gate = swap(&entry.gate, live, mask);
        let r = entry.relation as usize;
        a.relations[r].gate = swap(&a.relations[r].gate, live, mask);
        assert_eq!(a.validate(), Ok(()), "{mask}");
        assert_eq!(check_memory(&a), Err(expected.to_string()), "{mask}");
    }
}

/// §8's third rule, on the widest frame: `ADD_SUB_LUI_AUIPC`'s first row-wise
/// product weighted by `γ_M` reads two inner columns that come from `M` alone,
/// so provenance passes; the slot over an inner column is refused. Kills a slot
/// rule that only looks at list 0 or only at `W`.
#[test]
fn a_global_slot_over_an_inner_column_is_refused() {
    let mut a = family_frame_artifact(family::ADD_SUB_LUI_AUIPC, 4);
    let gamma = Coeff::Challenge(challenge_slot::MEM_GAMMA);
    let entry = &mut a.layers[1].producing[0];
    let GateDef::Product { coeff, .. } = &mut entry.gate else {
        panic!("list 1 multiplies");
    };
    *coeff = gamma;
    let r = entry.relation as usize;
    let GateDef::Product { coeff, .. } = &mut a.relations[r].gate else {
        panic!("its relation multiplies");
    };
    *coeff = gamma;
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(
        check_memory(&a),
        Err(
            "memory slot operands: `define_read_2_0` in gate list 1 carries a global memory slot \
             and reads L{1}[0]; only M, S and V columns may be weighted by one"
                .to_string()
        )
    );
}
