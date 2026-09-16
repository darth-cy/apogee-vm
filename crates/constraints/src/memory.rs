//! The memory argument's circuits, as data: the frame layout every execution
//! family's memory subtree follows, the tuple and leaf gates, the gadgets, the
//! two RAM window artifacts, and the construction-time rules a memory artifact
//! is held to beside `validate`.
//!
//! `docs/spec/memory.md` is normative: §1 the tuple, §2 the frame and its
//! gadgets, §3.3 the window artifacts, §7 the obligations, §8 the rules. Every
//! formula, layout, order and name here is that document's.
//!
//! A family's frame holds only the queries its instructions can make, so `w`
//! below is `frame_queries(family).len()`, never 8.
//!
//! ```text
//! frame      M[0] cycle; M[1 + 5s + f] the query at slot s, field f;
//!            W[s] <q>_gap_hi; W[w] rd_inv, W[w+1] rd_is_zero, W[w+2] rd_selected
//! list 0     L{1}[0..w] read_<q>, then 1s to a power of two; likewise write_<q>;
//!            enforcing: w booleanity, one write-back per read-only query, 4 x0
//! lists 1-k  L{k+1}[j] = L{k}[2j]·L{k}[2j+1], halving the width to 2
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

use constants::{address_space, challenge_slot, family, lookup_channel, memory};
use field::Fr;

use crate::build;
use crate::lookup;
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

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

/// The query table's size: the pc query, then the seven roles of
/// `docs/spec/execution-trace.md` §7 in their frozen order. A family's frame
/// holds a *subset* of these — [`frame_queries`] — so this is the table's
/// length, never a frame's width.
pub const FRAME_QUERIES: usize = 8;

/// The pc query, which every execution family's frame holds first.
pub const PC: usize = 0;
/// `rs1`; an ecall row's `a7`.
pub const RS1: usize = 1;
/// `rs2`; an ecall row's `a0`.
pub const RS2: usize = 2;
/// An ecall row's `a1`.
pub const ARG1: usize = 3;
/// An ecall row's `a2`.
pub const ARG2: usize = 4;
/// A load's word, at slot 2.
pub const LOAD: usize = 5;
/// A store's, an atomic's or an ecall transfer's word, at slot 3.
pub const RAM: usize = 6;

/// Each query's name, which its columns, leaves and obligations are named after.
pub const FRAME_NAMES: [&str; FRAME_QUERIES] =
    ["pc", "rs1", "rs2", "arg1", "arg2", "load", "ram", "rd"];

/// The read-only queries, which write back what they read: `rs1` through
/// `load`. `docs/spec/memory.md` §2.4.
pub const FRAME_READ_ONLY: [usize; 5] = [RS1, RS2, ARG1, ARG2, LOAD];

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

/// `M[1 + 5·slot + field]`: one field of the query at `slot` — its position in
/// the family's query list, not its id in [`FRAME_NAMES`]. The two agree only
/// for a family holding every query, and none does.
pub fn frame(slot: usize, field: u32) -> PolyAddress {
    PolyAddress::Memory(1 + 5 * slot as u32 + field)
}

/// `W[slot]`: the high chunk of a query's timestamp gap, `gap >> 19`.
pub fn gap_hi(slot: usize) -> PolyAddress {
    PolyAddress::Witness(slot as u32)
}

/// `W[width]`: the inverse of `rd`'s address, 0 where it has none. The x0
/// gadget's three witness columns follow a frame's `width` gap columns.
pub fn rd_inv(width: usize) -> PolyAddress {
    PolyAddress::Witness(width as u32)
}
/// `W[width + 1]`: 1 exactly on a live `rd` query at address 0.
pub fn rd_is_zero(width: usize) -> PolyAddress {
    PolyAddress::Witness(width as u32 + 1)
}
/// `W[width + 2]`: the value `rd` writes where its address is not 0.
pub fn rd_selected(width: usize) -> PolyAddress {
    PolyAddress::Witness(width as u32 + 2)
}

/// The query `rd`, whose writes the x0 gadget masks.
pub const RD: usize = 7;

/// The queries an execution family's frame holds, ascending: every query an
/// instruction routed to that family can make, and no other.
/// `docs/spec/memory.md` §2.1.
///
/// **This is the one place a family's frame width is chosen.** It is derived
/// from `docs/spec/execution-trace.md` §4 — which queries an instruction class
/// makes — over `program::row_kind`'s routing, and
/// `crates/trace/tests/memory.rs` holds it to that routing instruction by
/// instruction. A frame narrower than its family cannot balance: the events it
/// drops leave their addresses' chains broken, so the honest prover is refused
/// rather than a cheating one admitted. A frame wider than its family carries
/// columns that are 0 on every row, commits and opens them, and discharges
/// their obligations vacuously.
///
/// Panics on the two init families, which run no cycles and have no frame, and
/// on any other id.
pub fn frame_queries(family: u32) -> &'static [usize] {
    match family {
        // lui, auipc, addi, add, sub, and the system row kind: an ecall's own
        // row reads `a7`, `a0`, `a1`, `a2` and writes `a0`, and each of its
        // transfer rows moves one RAM word at slot 3. No `load`: that is a
        // load's word at slot 2, and no instruction here has one.
        family::ADD_SUB_LUI_AUIPC => &[PC, RS1, RS2, ARG1, ARG2, RAM, RD],
        // Register-register, register-immediate, branches and jumps: no RAM
        // query at all, and `arg1`/`arg2` are ecall-only.
        family::JUMP_BRANCH_SLT | family::SHIFT_BITWISE | family::MUL_DIV => &[PC, RS1, RS2, RD],
        // A load's word at slot 2, a store's at slot 3.
        family::MEM_WORD | family::MEM_SUBWORD => &[PC, RS1, RS2, LOAD, RAM, RD],
        // The whole A extension keeps its RAM query at slot 3, `lr.w` included
        // (`docs/spec/execution-trace.md` §7), so it has no `load`.
        family::ATOMICS => &[PC, RS1, RS2, RAM, RD],
        family::INIT_TEARDOWN | family::ZERO_WINDOWS => panic!(
            "family {family} initializes RAM and runs no cycles, so it has no frame; \
             `docs/spec/memory.md` §3.3 is its artifact"
        ),
        other => panic!("family {other} is not in constants::family"),
    }
}

// ---------------------------------------------------------------------------
// The tuple and the leaf
// ---------------------------------------------------------------------------

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn slot(s: u32) -> Coeff {
    Coeff::Challenge(s)
}

/// Query `query`'s tuple, unmasked, over the frame's columns: its read tuple,
/// or with `write` its write tuple. Each part's terms go in slot
/// `constants::memory::PART_*` and are emitted in slot order:
///
/// ```text
/// PART_AS    (AS, m)
/// PART_ADDR  (α_addr, addr)
/// PART_TS    read: (α_ts, read_ts)       write: (α_ts, cycle) × 4, (α_ts, m) × Δ
/// PART_VAL   read: (α_val, read_value)   write: (α_val, write_value)
/// ```
///
/// A coefficient is one literal or one slot, so `α_ts·4·cycle` is a term
/// repeated four times and `α_ts·Δ·m` one repeated `Δ` times. The read tuple
/// has one term per part, so its term `PART_*` is that part.
fn tuple(query: usize, at: usize, write: bool) -> GateDef {
    let mask = frame(at, FIELD_MASK);
    let mut parts: [Vec<(Coeff, PolyAddress)>; 4] = Default::default();
    parts[memory::PART_AS] = vec![(lit(FRAME_SPACE[query] as u64), mask)];
    parts[memory::PART_ADDR] = vec![(slot(challenge_slot::MEM_ALPHA_ADDR), frame(at, FIELD_ADDR))];
    let alpha_ts = slot(challenge_slot::MEM_ALPHA_TS);
    parts[memory::PART_TS] = match write {
        false => vec![(alpha_ts, frame(at, FIELD_READ_TS))],
        true => {
            let mut ts = vec![(alpha_ts, CYCLE); memory::TS_STEP as usize];
            ts.extend(vec![(alpha_ts, mask); FRAME_DELTA[query] as usize]);
            ts
        }
    };
    let value = match write {
        false => FIELD_READ_VALUE,
        true => FIELD_WRITE_VALUE,
    };
    parts[memory::PART_VAL] = vec![(slot(challenge_slot::MEM_ALPHA_VAL), frame(at, value))];
    GateDef::Linear {
        terms: parts.concat(),
        constant: slot(challenge_slot::MEM_GAMMA),
    }
}

/// Query `query`'s read tuple, unmasked: `γ_M + AS·m + α_addr·addr +
/// α_ts·read_ts + α_val·read_value`, a `Linear` over the frame's columns whose
/// term `PART_*` is that part. With `m = 1` it is exactly
/// `T(AS, addr, read_ts, read_value)` of `docs/spec/memory.md` §1. The
/// verifier's boundary evaluates it too, at operand values placed by `PART_*`:
/// `query` 0 is a PC tuple, 1 a REG one.
/// `query` names both the query and its slot, so this is the tuple as a frame
/// holding every query would address it. The verifier's boundary reads only
/// the coefficients and their `PART_*` positions, which no slot changes.
pub fn read_tuple(query: usize) -> GateDef {
    tuple(query, query, false)
}

/// Query `query`'s write tuple, unmasked: `γ_M + AS·m + α_addr·addr +
/// α_ts·(4·cycle + Δ·m) + α_val·write_value`. With `m = 1` it is exactly
/// `T(AS, addr, 4·cycle + Δ, write_value)`.
#[cfg(test)]
fn write_tuple(query: usize) -> GateDef {
    tuple(query, query, true)
}

/// A product-tree leaf, one flat `Quadratic`: at `mask = 1` the tuple, at
/// `mask = 0` exactly 1. `docs/spec/memory.md` §2.2 and §3.3.
///
/// Constant 1. Linear: the tuple's constant `c_0` as `(c_0, mask)`, then
/// `(−1, mask)`, then every tuple term whose operand is the mask, as it is.
/// Products: every other term `(c, x)` as `(c, x, mask)`, in the tuple's order.
/// A term already on the mask enters once, not squared, so the leaf is
/// `mask·tuple + 1 − mask` — `tuple` being the unmasked gate, whose `AS` and
/// `Δ` terms sit on the mask — on a boolean mask only; which is why every mask
/// a leaf reads from a committed column carries a booleanity gate (§2.4, §8).
///
/// Panics on a tuple that is not `Linear`.
fn leaf(tuple: &GateDef, mask: PolyAddress) -> GateDef {
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
fn booleanity(mask: PolyAddress) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(lit(1), mask)],
        products: vec![(Coeff::Literal(Fr::MINUS_ONE), mask, mask)],
    }
}

/// `write_value − read_value = 0`: a read-only query, `rs1` through `load`,
/// writes back what it read.
fn write_back(at: usize) -> GateDef {
    GateDef::Linear {
        terms: vec![
            (lit(1), frame(at, FIELD_WRITE_VALUE)),
            (Coeff::Literal(Fr::MINUS_ONE), frame(at, FIELD_READ_VALUE)),
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
fn x0_gates(at: usize, width: usize) -> [(&'static str, GateDef); 4] {
    let (addr, m) = (frame(at, FIELD_ADDR), frame(at, FIELD_MASK));
    let (inv, z, sel) = (rd_inv(width), rd_is_zero(width), rd_selected(width));
    let minus = Coeff::Literal(Fr::MINUS_ONE);
    [
        (
            "rd_is_zero_inverse",
            GateDef::Quadratic {
                constant: lit(0),
                linear: vec![(lit(1), z), (minus, m)],
                products: vec![(lit(1), addr, inv)],
            },
        ),
        (
            "rd_is_zero_at_nonzero",
            GateDef::Quadratic {
                constant: lit(0),
                linear: vec![],
                products: vec![(lit(1), addr, z)],
            },
        ),
        ("rd_is_zero_boolean", booleanity(z)),
        (
            "rd_write_masked",
            GateDef::Quadratic {
                constant: lit(0),
                linear: vec![(lit(1), frame(at, FIELD_WRITE_VALUE)), (minus, sel)],
                products: vec![(lit(1), z, sel)],
            },
        ),
    ]
}

/// Query `query`'s two timestamp-gap obligations, returned by value, on
/// `lookup_channel::TIMESTAMP` under the selector `M[mask]`, over its high
/// chunk `hi = W[query]`:
///
/// ```text
/// gap_hi_<q> : Linear { [(1, hi)], 0 }
/// gap_lo_<q> : Linear { [(4, cycle), (−1, read_ts), (−2^19, hi)], Δ − 1 }
/// ```
///
/// Both below `2^19` make `gap = 4·cycle + Δ − read_ts − 1 = lo + 2^19·hi` a
/// field element in `[0, 2^38)`: `read_ts < 4·cycle + Δ` as integers, under
/// the counting premise of `docs/spec/memory.md` §4.2. §2.4; `Δ − 1` is the
/// field element, `−1` for the pc.
fn gap_lookups(query: usize, at: usize) -> [LookupExpr; 2] {
    let (name, hi) = (FRAME_NAMES[query], gap_hi(at));
    let selector = frame(at, FIELD_MASK);
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
                    (Coeff::Literal(Fr::MINUS_ONE), frame(at, FIELD_READ_TS)),
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

/// The memory subtree an execution family carries, `docs/spec/memory.md` §2,
/// over `2^trace_vars` rows and the `queries` of [`frame_queries`]: with
/// `w = queries.len()`, `1 + 5w` `M` columns, `w + 3` `W` columns, `2w` leaves
/// padded to the next power of two a side, `w` booleanity gates, one
/// write-back gate per read-only query, the four x0 gates and `2w` gap
/// obligations. Validated and held to [`check_memory`]; panics if either
/// refuses it, or if `queries` is not the pc query followed by a strictly
/// ascending subset of the table.
pub fn frame_artifact(queries: &[usize], trace_vars: u32) -> CircuitArtifact {
    frame_body(queries, trace_vars, frame_gaps(queries), Extras::default())
}

/// [`frame_artifact`] over [`frame_queries`] of `family`: the frame that
/// family proves.
pub fn family_frame_artifact(family: u32, trace_vars: u32) -> CircuitArtifact {
    frame_artifact(frame_queries(family), trace_vars)
}

/// What a family's circuit carries beside its memory frame: the committed
/// columns, virtual tables, enforcing gates and lookups its instruction
/// constraints and its lookup channels add, and the channels that discharge
/// them.
///
/// The frame's own columns come first in every subtree, so `witness` starts at
/// `W[w + 3]` (or `W[w]` for a frame without an `rd` query) and `setup` at
/// `S[0]`. The frame's `2w` gap obligations come first in the lookup list, so
/// `lookups` follows them. An empty `Extras` is [`frame_artifact`], which is
/// exactly S14's frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extras {
    pub witness: Vec<String>,
    pub setup: Vec<String>,
    pub virtuals: Vec<(VirtualKind, String)>,
    pub enforcing: Vec<(String, GateDef)>,
    pub lookups: Vec<LookupExpr>,
    pub channels: Vec<lookup::ChannelSpec>,
}

/// An execution family's circuit: `docs/spec/memory.md` §2's frame over
/// `queries`, whose read and write leaves feed two product trees, plus
/// `extras`, whose lookups feed one fraction tree per channel
/// (`docs/spec/lookup.md` §6).
///
/// The output map is `[read_root, write_root]` at `READ_ROOT` and `WRITE_ROOT`,
/// then each channel's `(num, den)` root pair in `extras.channels` order.
/// Validated, held to [`check_memory`] and to
/// [`lookup::check_discharge`]; panics if any refuses it, or if `queries` is
/// not the pc query followed by a strictly ascending subset of the table.
///
/// **`extras.channels` must not be empty.** A frame carries its own `2w` gap
/// obligations whatever a caller adds, so a channel list of nothing is a
/// circuit every one of whose obligations is undischarged. The one artifact of
/// that shape is S14's [`frame_artifact`], a *component* whose discharge S15
/// owes and whose bytes are frozen fixtures; it is built here rather than
/// through this entry point, and this one refuses the shape outright.
pub fn frame_with_channels_artifact(
    queries: &[usize],
    trace_vars: u32,
    extras: Extras,
) -> CircuitArtifact {
    assert!(
        !extras.channels.is_empty(),
        "memory frame: no channel, and a frame's own {} gap obligations would be discharged \
         by nothing; S14's bare frame is `frame_artifact`",
        2 * queries.len()
    );
    frame_body(queries, trace_vars, frame_gaps(queries), extras)
}

/// A frame's own obligations: two per read (`docs/spec/memory.md` §2.4).
fn frame_gaps(queries: &[usize]) -> Vec<LookupExpr> {
    let mut gaps = Vec::new();
    for (at, &query) in queries.iter().enumerate() {
        gaps.extend(gap_lookups(query, at));
    }
    gaps
}

/// [`frame_with_channels_artifact`] with the frame's own obligations passed
/// in, so the construction's count assertion — two per read
/// (`docs/spec/memory.md` §2.4; S14 must-be-exact 5) — has something to refuse.
fn frame_body(
    queries: &[usize],
    trace_vars: u32,
    gaps: Vec<LookupExpr>,
    extras: Extras,
) -> CircuitArtifact {
    assert!(
        queries.first() == Some(&PC)
            && queries.windows(2).all(|w| w[0] < w[1])
            && queries.iter().all(|&q| q < FRAME_QUERIES),
        "memory frame: a family's queries are the pc query then a strictly ascending subset of \
         the {FRAME_QUERIES} of FRAME_NAMES; {queries:?} is not"
    );
    let width = queries.len();
    let mut columns = vec![String::from("cycle")];
    for &query in queries {
        for field in ["mask", "addr", "read_ts", "read_value", "write_value"] {
            columns.push(format!("{}_{field}", FRAME_NAMES[query]));
        }
    }
    let mut witness: Vec<String> = queries
        .iter()
        .map(|&query| format!("{}_gap_hi", FRAME_NAMES[query]))
        .collect();
    let rd = queries.iter().position(|&query| query == RD);
    if rd.is_some() {
        for name in ["rd_inv", "rd_is_zero", "rd_selected"] {
            witness.push(String::from(name));
        }
    }
    witness.extend(extras.witness);

    assert_eq!(
        gaps.len(),
        2 * width,
        "memory artifact: every read carries two gap obligations, so {width} reads need {} \
         obligations; {} reached the artifact",
        2 * width,
        gaps.len()
    );
    let mut reads = Vec::new();
    let mut writes = Vec::new();
    let mut enforcing = Vec::new();
    let mut lookups = gaps;
    for (at, &query) in queries.iter().enumerate() {
        let (name, mask) = (FRAME_NAMES[query], frame(at, FIELD_MASK));
        reads.push((format!("read_{name}"), leaf(&tuple(query, at, false), mask)));
        writes.push((format!("write_{name}"), leaf(&tuple(query, at, true), mask)));
        enforcing.push((format!("{name}_mask_boolean"), booleanity(mask)));
    }
    for (at, &query) in queries.iter().enumerate() {
        if FRAME_READ_ONLY.contains(&query) {
            enforcing.push((
                format!("{}_writes_back", FRAME_NAMES[query]),
                write_back(at),
            ));
        }
    }
    if let Some(at) = rd {
        for (name, gate) in x0_gates(at, width) {
            enforcing.push((String::from(name), gate));
        }
    }
    enforcing.extend(extras.enforcing);
    lookups.extend(extras.lookups);

    // The row-wise lists pair neighbours, so each side of the tree is a power
    // of two. A family whose query count is not one pads with leaves that are
    // literally 1, the product's identity: they read no column, commit
    // nothing, and carry no obligation.
    let side = width.next_power_of_two();
    for (leaves, name) in [(&mut reads, "read"), (&mut writes, "write")] {
        for i in 0..side - width {
            leaves.push((
                format!("{name}_pad_{i}"),
                GateDef::Linear {
                    terms: vec![],
                    constant: lit(1),
                },
            ));
        }
    }

    assemble(
        trace_vars,
        [columns, witness, extras.setup],
        extras.virtuals,
        [reads, writes],
        enforcing,
        lookups,
        &extras.channels,
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
        &[],
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
        &[],
    )
}

/// A whole memory artifact: two product trees, the read side then the write
/// side, over `leaves`; `enforcing` on gate list 0; row-wise `Product` lists
/// down to `[read, write]`, then `trace_vars` halving lists, and
/// `outputs = [read_root, write_root]` at `READ_ROOT` and `WRITE_ROOT`.
/// `crate::build::assemble` is the assembly; this is the memory argument's
/// share of it.
///
/// Asserts first that `lookups` holds exactly two obligations per read of the
/// read side (`docs/spec/memory.md` §2.4; S14 must-be-exact 5), then validates
/// through `assemble` and runs [`check_memory`], panicking on any refusal.
fn assemble(
    trace_vars: u32,
    layout: [Vec<String>; 3],
    virtuals: Vec<(VirtualKind, String)>,
    leaves: [Vec<(String, GateDef)>; 2],
    enforcing: Vec<(String, GateDef)>,
    lookups: Vec<LookupExpr>,
    channels: &[lookup::ChannelSpec],
) -> CircuitArtifact {
    let [read, write] = leaves;
    assert!(
        read.len() == write.len(),
        "memory artifact: {} read leaves and {} write leaves; the counts are equal",
        read.len(),
        write.len()
    );
    let zero_row_valid = enforcing
        .iter()
        .all(|(name, gate)| build::zero_on_zero_row(name, gate));
    let mut trees = vec![
        lookup::product_tree("read", read),
        lookup::product_tree("write", write),
    ];
    trees.extend(lookup::channel_trees(&lookups, channels, trace_vars));
    let artifact = build::assemble(
        trace_vars,
        layout,
        virtuals,
        trees,
        enforcing,
        lookups,
        zero_row_valid,
    );
    let top = artifact.depth() as u32;
    debug_assert_eq!(
        artifact.outputs.get(..2),
        Some(
            [
                PolyAddress::Inner {
                    layer: top,
                    offset: memory::READ_ROOT as u32,
                },
                PolyAddress::Inner {
                    layer: top,
                    offset: memory::WRITE_ROOT as u32,
                },
            ]
            .as_slice()
        ),
        "the read tree is output {}, the write tree output {}; every channel's root pair \
         follows them",
        memory::READ_ROOT,
        memory::WRITE_ROOT
    );
    if let Err(e) = check_memory(&artifact) {
        panic!("memory artifact: {e}");
    }
    // A frame with no channel is a *component*: S14 froze `frame_artifact`
    // with its obligations declared and their discharge owed to S15, and its
    // fixtures are those bytes. Only a circuit that declares channels claims
    // to discharge anything, and only there is the discharge rule meaningful.
    if !channels.is_empty() {
        if let Err(e) = lookup::check_discharge(&artifact, channels) {
            panic!("memory artifact: {e}");
        }
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
/// 2. **a root that reads a `W` column**: `outputs[READ_ROOT]` or
///    `outputs[WRITE_ROOT]` whose cone reads one, whether or not it names a
///    slot. `W` is committed after the memory challenges, so a root over one
///    is chosen after them and balances any trace;
/// 3. **a global slot over anything but `M`, `S` and `V`**: a gate with a
///    global-slot coefficient that reads a `W` column, an inner column or a
///    cached entry;
/// 4. **unconstrained masks**: a leaf — a producing `Quadratic` of gate list 0
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
    for root in [memory::READ_ROOT, memory::WRITE_ROOT] {
        let Some(&address @ PolyAddress::Inner { offset, .. }) = a.outputs.get(root) else {
            continue;
        };
        if below.get(offset as usize).is_some_and(|(_, w)| *w) {
            let name = a.scratch.iter().find(|s| s.address == address);
            let name = name.map_or("?", |s| s.name.as_str());
            return Err(format!(
                "memory provenance: output {root}, `{name}`, reads a W column, which is committed \
                 after the memory challenges"
            ));
        }
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

    /// S14 acceptance 12's negative control. The `ADD_SUB_LUI_AUIPC` frame's
    /// 14 obligations, less the last gadget's `gap_lo_rd` — an obligation
    /// built and then dropped before the artifact is written — fail the build
    /// at the count assertion, before `validate` or `check_memory` run. The
    /// control beside it is the same call with every obligation, which is
    /// `frame_artifact`.
    #[test]
    #[should_panic(
        expected = "every read carries two gap obligations, so 7 reads need 14 \
                               obligations; 13 reached the artifact"
    )]
    fn a_dropped_gap_obligation_fails_the_build() {
        let queries = frame_queries(family::ADD_SUB_LUI_AUIPC);
        let mut lookups = Vec::new();
        for (at, &query) in queries.iter().enumerate() {
            lookups.extend(gap_lookups(query, at));
        }
        assert_eq!(
            frame_body(queries, 4, lookups.clone(), Extras::default()),
            frame_artifact(queries, 4)
        );
        lookups.pop();
        frame_body(queries, 4, lookups, Extras::default());
    }

    /// The unmasked write tuple, which only the frame's leaves use, is the
    /// read tuple's twin: `crates/constraints/tests/memory.rs` reads both.
    #[test]
    fn a_write_tuple_is_a_linear_gate() {
        assert!(matches!(write_tuple(RD), GateDef::Linear { .. }));
    }

    /// Every execution family's frame builds at its own width — `assemble`
    /// runs `validate` and `check_memory` and panics on either refusal, so
    /// construction succeeding is the assertion — with `1 + 5w` memory
    /// columns, `w + 3` witness columns, `2w` obligations, and a gate list 0
    /// padded to a power of two a side. `ADD_SUB_LUI_AUIPC`, `MEM_WORD` and
    /// `ATOMICS` are the widths that are not powers of two, so they are the
    /// families whose constant-1 pad leaves this exercises.
    #[test]
    fn every_execution_family_builds_its_frame() {
        let widths = [
            (family::ADD_SUB_LUI_AUIPC, 7),
            (family::JUMP_BRANCH_SLT, 4),
            (family::SHIFT_BITWISE, 4),
            (family::MUL_DIV, 4),
            (family::MEM_WORD, 6),
            (family::MEM_SUBWORD, 6),
            (family::ATOMICS, 5),
        ];
        for (id, width) in widths {
            assert_eq!(frame_queries(id).len(), width, "family {id}");
            let a = family_frame_artifact(id, 6);
            assert_eq!(a.memory.len(), 1 + 5 * width, "family {id}");
            assert_eq!(a.witness.len(), width + 3, "family {id}");
            assert_eq!(a.lookups.len(), 2 * width, "family {id}");
            assert_eq!(
                a.layers[0].width as usize,
                2 * width.next_power_of_two(),
                "family {id}"
            );
        }
    }

    /// `INIT_TEARDOWN` runs no cycles, so it has no frame: its artifact is
    /// `image_window_artifact`.
    #[test]
    #[should_panic(expected = "initializes RAM and runs no cycles, so it has no frame")]
    fn init_teardown_has_no_frame() {
        frame_queries(family::INIT_TEARDOWN);
    }

    /// `ZERO_WINDOWS` likewise: its artifact is `zero_window_artifact`.
    #[test]
    #[should_panic(expected = "initializes RAM and runs no cycles, so it has no frame")]
    fn zero_windows_has_no_frame() {
        frame_queries(family::ZERO_WINDOWS);
    }

    /// An id past the table is not a family.
    #[test]
    #[should_panic(expected = "is not in constants::family")]
    fn an_id_off_the_table_is_not_a_family() {
        frame_queries(family::COUNT);
    }

    /// A query list that is not the pc query followed by a strictly ascending
    /// subset is refused before anything is built: the pc query is mandatory,
    /// and a repeat or a descent would give two slots one query's columns.
    #[test]
    #[should_panic(expected = "a family's queries are the pc query then a strictly ascending")]
    fn a_frame_without_the_pc_query_is_refused() {
        frame_artifact(&[RS1, RD], 4);
    }

    /// The same rule the other way: a descending list is not a subset.
    #[test]
    #[should_panic(expected = "a family's queries are the pc query then a strictly ascending")]
    fn a_frame_whose_queries_descend_is_refused() {
        frame_artifact(&[PC, RD, RS1], 4);
    }
}
