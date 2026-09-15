//! The memory argument's circuits, as data: the frame layout every execution
//! family's memory subtree follows, the tuple and leaf gates, the gadgets, the
//! two RAM window artifacts, and the construction-time rules a memory artifact
//! is held to beside `validate`.
//!
//! `docs/spec/memory.md` is normative: §1 the tuple, §2 the frame and its
//! gadgets, §3.3 the window artifacts, §7 the obligations, §8 the rules. Every
//! formula, layout, order and name here is that document's.
//!
//! ```text
//! frame      M[0] cycle; M[1 + 5q + f] query q, field f; W[q] <q>_gap_hi;
//!            W[8] rd_inv, W[9] rd_is_zero, W[10] rd_selected
//! list 0     L{1}[0..8] read_<q>, L{1}[8..16] write_<q>;
//!            enforcing: 8 booleanity, 5 write-back, 4 x0
//! lists 1-3  L{k+1}[j] = L{k}[2j]·L{k}[2j+1], width 16 -> 8 -> 4 -> 2
//!
//! windows    M[0] teardown_ts, M[1] teardown_value, V[row];
//!            INIT_TEARDOWN adds S[0] init_value and V[ram_live]
//! list 0     L{1}[0] teardown (read side), L{1}[1] init (write side)
//!
//! both       then trace_vars halving lists; outputs [read_root, write_root]
//! ```

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use constants::{address_space, challenge_slot, lookup_channel, memory};
use field::Fr;

use crate::{
    CircuitArtifact, Coeff, EnforcingEntry, GateDef, LayerSpec, LookupExpr, Padding, PolyAddress,
    ProducingEntry, Relation, ScratchSlot, VirtualKind, COEFFICIENT_ENCODING_CANONICAL_LE,
    FORMAT_VERSION,
};

// ---------------------------------------------------------------------------
// The frame layout
// ---------------------------------------------------------------------------

/// `M[0]`: the row's cycle. `docs/spec/memory.md` §2.1.
pub const CYCLE: PolyAddress = PolyAddress::Memory(0);

/// A frame query's field: 1 exactly when the row is live and has the query.
pub const FIELD_MASK: u32 = 0;
/// A frame query's field: the address it reads and writes.
pub const FIELD_ADDR: u32 = 1;
/// A frame query's field: the timestamp of the write it reads.
pub const FIELD_READ_TS: u32 = 2;
/// A frame query's field: the value it reads.
pub const FIELD_READ_VALUE: u32 = 3;
/// A frame query's field: the value it writes, at `4·cycle + Δ`.
pub const FIELD_WRITE_VALUE: u32 = 4;

/// Queries per frame row: the pc query, then the seven roles of
/// `docs/spec/execution-trace.md` §7 in their frozen order.
pub const FRAME_QUERIES: usize = 8;

/// Each query's name, which its columns, leaves and obligations are named after.
pub const FRAME_NAMES: [&str; FRAME_QUERIES] =
    ["pc", "rs1", "rs2", "arg1", "arg2", "load", "ram", "rd"];

/// Each query's address space, `constants::address_space`.
pub const FRAME_SPACE: [u8; FRAME_QUERIES] = [
    address_space::PC,
    address_space::REG,
    address_space::REG,
    address_space::REG,
    address_space::REG,
    address_space::RAM,
    address_space::RAM,
    address_space::REG,
];

/// Each query's in-cycle slot `Δ`: its write is at `4·cycle + Δ`.
pub const FRAME_DELTA: [u64; FRAME_QUERIES] = [0, 1, 2, 2, 2, 2, 3, 3];

/// `M[1 + 5·query + field]`: one field of one frame query.
pub fn frame(query: usize, field: u32) -> PolyAddress {
    PolyAddress::Memory(1 + 5 * query as u32 + field)
}

/// `W[query]`: the high chunk of a query's timestamp gap, `gap >> 19`.
pub fn gap_hi(query: usize) -> PolyAddress {
    PolyAddress::Witness(query as u32)
}

/// `W[8]`: the inverse of `rd`'s address, 0 where it has none. The x0
/// gadget's witness columns follow the eight gap columns.
pub const RD_INV: PolyAddress = PolyAddress::Witness(8);
/// `W[9]`: 1 exactly on a live `rd` query at address 0.
pub const RD_IS_ZERO: PolyAddress = PolyAddress::Witness(9);
/// `W[10]`: the value `rd` writes where its address is not 0.
pub const RD_SELECTED: PolyAddress = PolyAddress::Witness(10);

/// The query `rd`, whose writes the x0 gadget masks.
pub const RD: usize = 7;

// ---------------------------------------------------------------------------
// The tuple and the leaf
// ---------------------------------------------------------------------------

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn slot(s: u32) -> Coeff {
    Coeff::Challenge(s)
}

/// Query `query`'s read tuple, unmasked: `γ_M + AS·m + α_addr·addr +
/// α_ts·read_ts + α_val·read_value`, a `Linear` over the frame's columns. With
/// `m = 1` it is exactly `T(AS, addr, read_ts, read_value)` of
/// `docs/spec/memory.md` §1. The verifier's boundary evaluates it too, at
/// operand values `[1, addr, ts, value]`: `query` 0 is a PC tuple, 1 a REG one.
pub fn read_tuple(query: usize) -> GateDef {
    let space = FRAME_SPACE[query] as u64;
    GateDef::Linear {
        terms: vec![
            (lit(space), frame(query, FIELD_MASK)),
            (
                slot(challenge_slot::MEM_ALPHA_ADDR),
                frame(query, FIELD_ADDR),
            ),
            (
                slot(challenge_slot::MEM_ALPHA_TS),
                frame(query, FIELD_READ_TS),
            ),
            (
                slot(challenge_slot::MEM_ALPHA_VAL),
                frame(query, FIELD_READ_VALUE),
            ),
        ],
        constant: slot(challenge_slot::MEM_GAMMA),
    }
}

/// Query `query`'s write tuple, unmasked: `γ_M + AS·m + α_addr·addr +
/// α_ts·(4·cycle + Δ·m) + α_val·write_value`. A coefficient is one literal or
/// one slot, so `α_ts·4·cycle` is the term `(α_ts, cycle)` four times and
/// `α_ts·Δ·m` the term `(α_ts, m)` `Δ` times. With `m = 1` it is exactly
/// `T(AS, addr, 4·cycle + Δ, write_value)`.
pub fn write_tuple(query: usize) -> GateDef {
    let space = FRAME_SPACE[query] as u64;
    let mask = frame(query, FIELD_MASK);
    let mut terms = vec![
        (lit(space), mask),
        (
            slot(challenge_slot::MEM_ALPHA_ADDR),
            frame(query, FIELD_ADDR),
        ),
    ];
    for _ in 0..memory::TS_STEP {
        terms.push((slot(challenge_slot::MEM_ALPHA_TS), CYCLE));
    }
    for _ in 0..FRAME_DELTA[query] {
        terms.push((slot(challenge_slot::MEM_ALPHA_TS), mask));
    }
    terms.push((
        slot(challenge_slot::MEM_ALPHA_VAL),
        frame(query, FIELD_WRITE_VALUE),
    ));
    GateDef::Linear {
        terms,
        constant: slot(challenge_slot::MEM_GAMMA),
    }
}

/// A product-tree leaf, one flat `Quadratic`: at `mask = 1` the tuple, at
/// `mask = 0` exactly 1. `docs/spec/memory.md` §2.2 and §3.3.
///
/// Constant 1. Linear: the tuple's constant `c_0` as `(c_0, mask)`, then
/// `(−1, mask)`, then every tuple term whose operand is the mask, as it is.
/// Products: every other term `(c, x)` as `(c, x, mask)`, in the tuple's order.
/// A term already on the mask enters once, not squared, so the leaf is
/// `mask·tuple + 1 − mask` on a boolean mask only — which is why every mask a
/// leaf reads from a committed column carries a booleanity gate (§2.4, §8).
///
/// Panics on a tuple that is not `Linear`.
pub fn leaf(tuple: &GateDef, mask: PolyAddress) -> GateDef {
    let GateDef::Linear { terms, constant } = tuple else {
        panic!("leaf: a memory tuple is a Linear gate");
    };
    let mut linear = vec![(*constant, mask), (Coeff::Literal(Fr::MINUS_ONE), mask)];
    let mut products = Vec::new();
    for (c, x) in terms {
        if *x == mask {
            linear.push((*c, mask));
        } else {
            products.push((*c, *x, mask));
        }
    }
    GateDef::Quadratic {
        constant: lit(1),
        linear,
        products,
    }
}

// ---------------------------------------------------------------------------
// The gadgets
// ---------------------------------------------------------------------------

/// `mask − mask·mask = 0`: the column is 0 or 1 on every row.
/// `docs/spec/memory.md` §2.4.
pub fn booleanity(mask: PolyAddress) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(lit(1), mask)],
        products: vec![(Coeff::Literal(Fr::MINUS_ONE), mask, mask)],
    }
}

/// `write_value − read_value = 0`: a read-only query, `rs1` through `load`,
/// writes back what it read.
fn write_back(query: usize) -> GateDef {
    GateDef::Linear {
        terms: vec![
            (lit(1), frame(query, FIELD_WRITE_VALUE)),
            (
                Coeff::Literal(Fr::MINUS_ONE),
                frame(query, FIELD_READ_VALUE),
            ),
        ],
        constant: lit(0),
    }
}

/// The x0 rule on `rd`, `docs/spec/memory.md` §2.4, with its names:
///
/// ```text
/// addr·rd_inv + z − m = 0          rd_is_zero_inverse
/// addr·z = 0                       rd_is_zero_at_nonzero
/// z − z·z = 0                      rd_is_zero_boolean
/// write_value − sel + z·sel = 0    rd_write_masked
/// ```
fn x0_gates() -> [(&'static str, GateDef); 4] {
    let (addr, m) = (frame(RD, FIELD_ADDR), frame(RD, FIELD_MASK));
    let minus = Coeff::Literal(Fr::MINUS_ONE);
    [
        (
            "rd_is_zero_inverse",
            GateDef::Quadratic {
                constant: lit(0),
                linear: vec![(lit(1), RD_IS_ZERO), (minus, m)],
                products: vec![(lit(1), addr, RD_INV)],
            },
        ),
        (
            "rd_is_zero_at_nonzero",
            GateDef::Quadratic {
                constant: lit(0),
                linear: vec![],
                products: vec![(lit(1), addr, RD_IS_ZERO)],
            },
        ),
        ("rd_is_zero_boolean", booleanity(RD_IS_ZERO)),
        (
            "rd_write_masked",
            GateDef::Quadratic {
                constant: lit(0),
                linear: vec![(lit(1), frame(RD, FIELD_WRITE_VALUE)), (minus, RD_SELECTED)],
                products: vec![(lit(1), RD_IS_ZERO, RD_SELECTED)],
            },
        ),
    ]
}

/// Query `query`'s two timestamp-gap obligations, returned by value, on
/// `lookup_channel::TIMESTAMP` under the selector `M[mask]`:
///
/// ```text
/// gap_hi_<q> : Linear { [(1, hi)], 0 }
/// gap_lo_<q> : Linear { [(4, cycle), (−1, read_ts), (−2^19, hi)], Δ − 1 }
/// ```
///
/// Both below `2^19` make `gap = 4·cycle + Δ − read_ts − 1 = lo + 2^19·hi` an
/// integer in `[0, 2^38)`: strictly `read_ts < 4·cycle + Δ`.
/// `docs/spec/memory.md` §2.4; `Δ − 1` is the field element, `−1` for the pc.
pub fn gap_lookups(query: usize, hi: PolyAddress) -> [LookupExpr; 2] {
    let name = FRAME_NAMES[query];
    let selector = frame(query, FIELD_MASK);
    let channel = lookup_channel::TIMESTAMP;
    let chunk = Fr::from_u64(1 << lookup_channel::BITS[channel as usize]);
    [
        LookupExpr {
            name: format!("gap_hi_{name}"),
            channel,
            selector,
            tuple: vec![GateDef::Linear {
                terms: vec![(lit(1), hi)],
                constant: lit(0),
            }],
        },
        LookupExpr {
            name: format!("gap_lo_{name}"),
            channel,
            selector,
            tuple: vec![GateDef::Linear {
                terms: vec![
                    (lit(memory::TS_STEP), CYCLE),
                    (Coeff::Literal(Fr::MINUS_ONE), frame(query, FIELD_READ_TS)),
                    (Coeff::Literal(-chunk), hi),
                ],
                constant: Coeff::Literal(Fr::from_u64(FRAME_DELTA[query]) - Fr::ONE),
            }],
        },
    ]
}

// ---------------------------------------------------------------------------
// The artifacts
// ---------------------------------------------------------------------------

/// The memory subtree every execution family carries, `docs/spec/memory.md`
/// §2, over `2^trace_vars` rows: 41 `M` columns, 11 `W` columns, 16 leaves,
/// 17 enforcing gates and 16 gap obligations. Validated and held to
/// [`check_memory`]; panics if either refuses it.
pub fn frame_artifact(trace_vars: u32) -> CircuitArtifact {
    let mut lookups = Vec::new();
    for query in 0..FRAME_QUERIES {
        lookups.extend(gap_lookups(query, gap_hi(query)));
    }
    frame_with_lookups(trace_vars, lookups)
}

/// The frame, with the obligations its caller collected: the artifact's
/// construction asserts there are two per read.
fn frame_with_lookups(trace_vars: u32, lookups: Vec<LookupExpr>) -> CircuitArtifact {
    let mut columns = vec![String::from("cycle")];
    for name in FRAME_NAMES {
        for field in ["mask", "addr", "read_ts", "read_value", "write_value"] {
            columns.push(format!("{name}_{field}"));
        }
    }
    let mut witness: Vec<String> = FRAME_NAMES
        .iter()
        .map(|name| format!("{name}_gap_hi"))
        .collect();
    for name in ["rd_inv", "rd_is_zero", "rd_selected"] {
        witness.push(String::from(name));
    }

    let mut reads = Vec::new();
    let mut writes = Vec::new();
    let mut enforcing = Vec::new();
    for (query, name) in FRAME_NAMES.iter().enumerate() {
        let mask = frame(query, FIELD_MASK);
        reads.push((format!("read_{name}"), leaf(&read_tuple(query), mask)));
        writes.push((format!("write_{name}"), leaf(&write_tuple(query), mask)));
        enforcing.push((format!("{name}_mask_boolean"), booleanity(mask)));
    }
    for (query, name) in FRAME_NAMES.iter().enumerate().take(6).skip(1) {
        enforcing.push((format!("{name}_writes_back"), write_back(query)));
    }
    for (name, gate) in x0_gates() {
        enforcing.push((String::from(name), gate));
    }

    assemble(
        trace_vars,
        [columns, witness, vec![]],
        vec![],
        [reads, writes],
        enforcing,
        lookups,
        FRAME_QUERIES,
    )
}

/// Bytes per RAM word: row `y` of a window is the word at byte address
/// `4h·w + 4y`, a RAM address being the byte address of a 4-aligned word
/// (`docs/spec/memory.md` §3.1). Not `TS_STEP`, which is timestamps per cycle.
const WORD_BYTES: u64 = 4;

/// `γ_M + RAM + α_addr·4h·w`, slot 5, with `(α_addr, V[row])` `WORD_BYTES`
/// times for `4y`: a window row's tuple at `ts` and `value`, where given.
fn window_tuple(ts: Option<PolyAddress>, value: PolyAddress) -> GateDef {
    let row = PolyAddress::Virtual(VirtualKind::RowIndex);
    let mut terms = Vec::new();
    for _ in 0..WORD_BYTES {
        terms.push((slot(challenge_slot::MEM_ALPHA_ADDR), row));
    }
    if let Some(ts) = ts {
        terms.push((slot(challenge_slot::MEM_ALPHA_TS), ts));
    }
    terms.push((slot(challenge_slot::MEM_ALPHA_VAL), value));
    GateDef::Linear {
        terms,
        constant: slot(challenge_slot::MEM_WINDOW_CONSTANT),
    }
}

/// The two window columns every window artifact commits.
fn window_memory() -> Vec<String> {
    vec![String::from("teardown_ts"), String::from("teardown_value")]
}

/// `INIT_TEARDOWN`, RAM window 0, `docs/spec/memory.md` §3.3: `M[0]
/// teardown_ts`, `M[1] teardown_value`, `S[0] init_value`, `V[row]`,
/// `V[ram_live]`; the teardown leaf on the read side and the init leaf on the
/// write side, each masked by `V[ram_live]`; no enforcing gates, no
/// obligations. Validated and held to [`check_memory`]; panics if either
/// refuses it.
pub fn image_window_artifact(trace_vars: u32) -> CircuitArtifact {
    let live = PolyAddress::Virtual(VirtualKind::RamLive);
    let teardown = window_tuple(Some(PolyAddress::Memory(0)), PolyAddress::Memory(1));
    let init = window_tuple(None, PolyAddress::Setup(0));
    assemble(
        trace_vars,
        [window_memory(), vec![], vec![String::from("init_value")]],
        vec![
            (VirtualKind::RowIndex, String::from("row")),
            (VirtualKind::RamLive, String::from("ram_live")),
        ],
        [
            vec![(String::from("teardown"), leaf(&teardown, live))],
            vec![(String::from("init"), leaf(&init, live))],
        ],
        vec![],
        vec![],
        0,
    )
}

/// `ZERO_WINDOWS`, one zero-initialized window, `docs/spec/memory.md` §3.3:
/// `M[0] teardown_ts`, `M[1] teardown_value`, `V[row]`; the teardown tuple on
/// the read side and the init tuple, value literal 0, on the write side; no
/// enforcing gates, no obligations. Validated and held to [`check_memory`];
/// panics if either refuses it.
pub fn zero_window_artifact(trace_vars: u32) -> CircuitArtifact {
    let row = PolyAddress::Virtual(VirtualKind::RowIndex);
    let teardown = window_tuple(Some(PolyAddress::Memory(0)), PolyAddress::Memory(1));
    let init = GateDef::Linear {
        terms: vec![(slot(challenge_slot::MEM_ALPHA_ADDR), row); WORD_BYTES as usize],
        constant: slot(challenge_slot::MEM_WINDOW_CONSTANT),
    };
    assemble(
        trace_vars,
        [window_memory(), vec![], vec![]],
        vec![(VirtualKind::RowIndex, String::from("row"))],
        [
            vec![(String::from("teardown"), teardown)],
            vec![(String::from("init"), init)],
        ],
        vec![],
        vec![],
        0,
    )
}

fn inner(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Inner { layer, offset }
}

/// Whether `gate` is 0 on the all-zero committed row, for every challenge
/// value and row index: a `Linear` or `Quadratic` over committed columns is its
/// constant there. Panics on any other gate, which no memory artifact enforces.
fn zero_on_zero_row(name: &str, gate: &GateDef) -> bool {
    let committed = gate.operands().iter().all(|op| {
        matches!(
            op,
            PolyAddress::Memory(_) | PolyAddress::Witness(_) | PolyAddress::Setup(_)
        )
    });
    match gate {
        GateDef::Linear { constant, .. } | GateDef::Quadratic { constant, .. } if committed => {
            *constant == lit(0)
        }
        _ => panic!(
            "memory artifact: enforcing gate `{name}` is not a Linear or Quadratic gate over \
             committed columns, so zero_row_valid is not decided for it"
        ),
    }
}

/// A whole memory artifact, as a struct literal of complete vectors:
///
/// - `layout`: the `M`, `W`, `S` names; `virtuals` the tables it reads;
/// - `leaves`: the read leaves, then the write leaves, `(name, gate)`, equal
///   power-of-two counts; gate list 0 writes them to layer 1 in that order,
///   beside `enforcing`, its enforcing gates;
/// - row-wise lists of `Product`, `L{k+1}[j] = L{k}[2j]·L{k}[2j+1]`, until the
///   layer is `[read, write]`, then `trace_vars` halving lists of
///   `TreeProduct`; `outputs` is `[L{N}[READ_ROOT], L{N}[WRITE_ROOT]]`;
/// - the flat relations and the scratch bijection mirror every gate, list by
///   list, producing before enforcing; the padding row is all zeros.
///
/// Asserts first that `lookups` holds exactly two obligations per read of
/// `reads` (`docs/spec/memory.md` §2.4; S14 must-be-exact 5), then validates
/// and runs [`check_memory`], panicking on any refusal.
fn assemble(
    trace_vars: u32,
    layout: [Vec<String>; 3],
    virtuals: Vec<(VirtualKind, String)>,
    leaves: [Vec<(String, GateDef)>; 2],
    enforcing: Vec<(String, GateDef)>,
    lookups: Vec<LookupExpr>,
    reads: usize,
) -> CircuitArtifact {
    assert_eq!(
        lookups.len(),
        2 * reads,
        "memory artifact: every read carries two gap obligations, so {reads} reads need {} \
         obligations; {} reached the artifact",
        2 * reads,
        lookups.len()
    );
    let [read, write] = leaves;
    let side = read.len();
    assert!(
        side.is_power_of_two() && write.len() == side,
        "memory artifact: {side} read leaves and {} write leaves; the counts are equal powers \
         of two",
        write.len()
    );
    let zero_row_valid = enforcing
        .iter()
        .all(|(name, gate)| zero_on_zero_row(name, gate));
    let depth = 1 + side.trailing_zeros() + trace_vars;
    let name = |layer: u32, j: usize, width: usize| -> String {
        let half = width / 2;
        let (tree, i) = if j < half {
            ("read", j)
        } else {
            ("write", j - half)
        };
        if layer == depth {
            format!("{tree}_root")
        } else if layer == 1 {
            read.iter().chain(&write).nth(j).expect("a leaf").0.clone()
        } else {
            format!("{tree}_{layer}_{i}")
        }
    };

    let mut relations: Vec<Relation> = Vec::new();
    let mut scratch: Vec<ScratchSlot> = Vec::new();
    let mut layers: Vec<LayerSpec> = Vec::new();

    let width = 2 * side;
    let mut producing = Vec::new();
    for (j, (_, gate)) in read.iter().chain(&write).enumerate() {
        let (output, n) = (inner(1, j as u32), name(1, j, width));
        producing.push(ProducingEntry {
            relation: relations.len() as u32,
            output,
            gate: gate.clone(),
        });
        relations.push(Relation {
            name: format!("define_{n}"),
            output: Some(scratch.len() as u32),
            gate: gate.clone(),
        });
        scratch.push(ScratchSlot {
            name: n,
            address: output,
        });
    }
    let mut enforcing_entries = Vec::new();
    for (n, gate) in enforcing {
        enforcing_entries.push(EnforcingEntry {
            relation: relations.len() as u32,
            gate: gate.clone(),
        });
        relations.push(Relation {
            name: n,
            output: None,
            gate,
        });
    }
    layers.push(LayerSpec {
        halving: false,
        num_vars: trace_vars,
        width: width as u32,
        cached: vec![],
        producing,
        enforcing: enforcing_entries,
    });

    let (mut width, mut vars) = (width, trace_vars);
    for k in 1..depth {
        // Layer k's columns are the last `width` scratch slots.
        let below = (scratch.len() - width) as u32;
        let halving = width == 2;
        let (up_width, up_vars) = if halving {
            (2, vars - 1)
        } else {
            (width / 2, vars)
        };
        let mut producing = Vec::new();
        for j in 0..up_width {
            let (output, n) = (inner(k + 1, j as u32), name(k + 1, j, up_width));
            let x = j as u32;
            let (gate, flat) = if halving {
                (
                    GateDef::TreeProduct { input: inner(k, x) },
                    GateDef::TreeProduct {
                        input: PolyAddress::Scratch(below + x),
                    },
                )
            } else {
                (
                    GateDef::Product {
                        coeff: lit(1),
                        left: inner(k, 2 * x),
                        right: inner(k, 2 * x + 1),
                    },
                    GateDef::Product {
                        coeff: lit(1),
                        left: PolyAddress::Scratch(below + 2 * x),
                        right: PolyAddress::Scratch(below + 2 * x + 1),
                    },
                )
            };
            producing.push(ProducingEntry {
                relation: relations.len() as u32,
                output,
                gate,
            });
            relations.push(Relation {
                name: format!("define_{n}"),
                output: Some(scratch.len() as u32),
                gate: flat,
            });
            scratch.push(ScratchSlot {
                name: n,
                address: output,
            });
        }
        layers.push(LayerSpec {
            halving,
            num_vars: up_vars,
            width: up_width as u32,
            cached: vec![],
            producing,
            enforcing: vec![],
        });
        (width, vars) = (up_width, up_vars);
    }

    let [columns, witness, setup] = layout;
    let committed = columns.len() + witness.len() + setup.len();
    let artifact = CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars,
        memory: columns,
        witness,
        setup,
        virtuals,
        layers,
        relations,
        lookups,
        scratch,
        outputs: vec![
            inner(depth, memory::READ_ROOT as u32),
            inner(depth, memory::WRITE_ROOT as u32),
        ],
        padding: Padding {
            row: vec![Fr::ZERO; committed],
            zero_row_valid,
        },
    };
    if let Err(e) = artifact.validate() {
        panic!("memory artifact: not a circuit: {e}");
    }
    if let Err(e) = check_memory(&artifact) {
        panic!("memory artifact: {e}");
    }
    artifact
}

// ---------------------------------------------------------------------------
// The construction-time rules
// ---------------------------------------------------------------------------

/// Whether `c` is one of the memory argument's slots, 1 through 5.
fn global(c: &Coeff) -> bool {
    let memory_slots = challenge_slot::MEM_GAMMA..=challenge_slot::MEM_WINDOW_CONSTANT;
    matches!(c, Coeff::Challenge(s) if memory_slots.contains(s))
}

/// `(names a global slot, reads a W column)` for `gate`, from its own
/// coefficients and the flags of what it reads: `below` for layer `k`'s inner
/// columns, `cached` for its list's cached entries.
fn provenance(gate: &GateDef, below: &[(bool, bool)], cached: &[(bool, bool)]) -> (bool, bool) {
    let mut flags = (gate.coefficients().iter().any(global), false);
    for op in gate.operands() {
        let (g, w) = match op {
            PolyAddress::Witness(_) => (false, true),
            PolyAddress::Inner { offset, .. } => below[offset as usize],
            PolyAddress::Cached { offset, .. } => cached[offset as usize],
            _ => (false, false),
        };
        flags = (flags.0 || g, flags.1 || w);
    }
    flags
}

/// The construction-time rules of `docs/spec/memory.md` §8, run where a memory
/// artifact is built, beside [`CircuitArtifact::validate`], which it assumes
/// the artifact has passed. Refuses, naming the gate:
///
/// 1. **provenance**: any gate — cached, producing or enforcing, in any list —
///    whose cone both names a global memory slot (1–5) and reads a `W` column.
///    Computed forward: a committed or virtual column names no slot and reads
///    `W` exactly when it is a `W` column; a gate or cached entry names a slot
///    when a coefficient is one or an operand does, and reads `W` when an
///    operand does. So a product of a tuple and a copy of a `W` column two
///    layers up is refused too. An output is a gate's column, so this covers
///    outputs;
/// 2. **a global slot over anything but `M`, `S` and `V`**: a gate with a
///    global-slot coefficient that reads a `W` column, an inner column or a
///    cached entry;
/// 3. **unconstrained masks**: a leaf — a producing `Quadratic` of gate list 0
///    with constant literal 1 and a linear term weighted by a global slot —
///    whose mask, that term's operand, is an `M`, `W` or `S` column, when gate
///    list 0 has no enforcing gate equal to [`booleanity`] of it; or is any
///    virtual column but `V[ram_live]`, the one virtual that is 0 or 1 on every
///    row. (A `W` mask is refused by rule 1 first.)
pub fn check_memory(a: &CircuitArtifact) -> Result<(), String> {
    let gate_name = |relation: u32| {
        a.relations
            .get(relation as usize)
            .map_or("?", |r| r.name.as_str())
    };
    let mut below: Vec<(bool, bool)> = Vec::new();
    for (k, list) in a.layers.iter().enumerate() {
        let mut gates: Vec<(&str, &GateDef)> = Vec::new();
        let mut cached: Vec<(bool, bool)> = Vec::new();
        let mut above: Vec<(bool, bool)> = Vec::new();
        for e in &list.cached {
            cached.push(provenance(&e.gate, &below, &cached));
            gates.push((e.name.as_str(), &e.gate));
        }
        for e in &list.producing {
            above.push(provenance(&e.gate, &below, &cached));
            gates.push((gate_name(e.relation), &e.gate));
        }
        for e in &list.enforcing {
            gates.push((gate_name(e.relation), &e.gate));
        }
        for (name, gate) in gates {
            if provenance(gate, &below, &cached) == (true, true) {
                return Err(format!(
                    "memory provenance: `{name}` in gate list {k} names a global memory slot and \
                     reads a W column"
                ));
            }
            if gate.coefficients().iter().any(global) {
                let off_column = gate.operands().into_iter().find(|op| {
                    !matches!(
                        op,
                        PolyAddress::Memory(_) | PolyAddress::Setup(_) | PolyAddress::Virtual(_)
                    )
                });
                if let Some(op) = off_column {
                    return Err(format!(
                        "memory slot operands: `{name}` in gate list {k} carries a global memory \
                         slot and reads {op}; only M, S and V columns may be weighted by one"
                    ));
                }
            }
        }
        below = above;
    }

    let Some(list) = a.layers.first() else {
        return Ok(());
    };
    for e in &list.producing {
        let GateDef::Quadratic {
            constant, linear, ..
        } = &e.gate
        else {
            continue;
        };
        if *constant != lit(1) {
            continue;
        }
        for (c, mask) in linear {
            if !global(c) {
                continue;
            }
            let leaf = gate_name(e.relation);
            match mask {
                PolyAddress::Memory(_) | PolyAddress::Witness(_) | PolyAddress::Setup(_) => {
                    if !list.enforcing.iter().any(|b| b.gate == booleanity(*mask)) {
                        return Err(format!(
                            "unconstrained mask: leaf `{leaf}` masks with {mask}, and gate list \
                             0 has no enforcing gate {mask} − {mask}·{mask}"
                        ));
                    }
                }
                PolyAddress::Virtual(VirtualKind::RamLive) => {}
                _ => {
                    return Err(format!(
                        "unconstrained mask: leaf `{leaf}` masks with {mask}, which is not 0 or \
                         1 on every row"
                    ))
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S14 acceptance 12's negative control. The frame's 16 obligations, less
    /// the last gadget's `gap_lo_rd` — an obligation built and then dropped
    /// before the artifact is written — fail the build at the count assertion,
    /// before `validate` or `check_memory` run. The control beside it is the
    /// same call with every obligation, which is `frame_artifact`.
    #[test]
    #[should_panic(
        expected = "every read carries two gap obligations, so 8 reads need 16 \
                               obligations; 15 reached the artifact"
    )]
    fn a_dropped_gap_obligation_fails_the_build() {
        let mut lookups = Vec::new();
        for query in 0..FRAME_QUERIES {
            lookups.extend(gap_lookups(query, gap_hi(query)));
        }
        assert_eq!(frame_with_lookups(4, lookups.clone()), frame_artifact(4));
        lookups.pop();
        frame_with_lookups(4, lookups);
    }
}
