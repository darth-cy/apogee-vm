//! The `ADD_SUB_LUI_AUIPC` family's circuit: `add`, `sub`, `addi`, `lui`,
//! `auipc`, and the system row kind with its provable ecalls — `exit`, and one
//! delegation request per registered delegation type
//! (`docs/spec/delegation.md` §5).
//!
//! `docs/spec/shard-proof.md` §8 is normative: the columns, the gates, the
//! lookups and the argument. This file is that section as data, assembled by
//! S15's `memory::frame_with_channels_artifact` beside S14's frame.
//!
//! ```text
//! frame     M[0..41], W[0..11]: pc rs1 rs2 arg1 arg2 ram rd deleg at slots 0..8
//! M[41]     deleg_space: the requested delegation type's address-space tag
//! W[11..17] the claimed decoded row: next_pc rs1 rs2 rd imm mask
//! W[17..23] the mask's six bits; W[23], W[24] is_ecall, is_fence
//! W[25..28] is_deleg_*: one delegation request selector per type
//! W[28..32] wrap, rd_hi, pc_wrap, next_pc_hi
//! W[32..35] one multiplicity per channel: timestamp, range16, decoder
//! S[0..7]   the decoded table, program::lookup_tuple order
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::extra_mask::add_sub_lui_auipc as kind;
use constants::extra_mask::system_code;
use constants::{family, lookup_channel, memory as mem};
use field::Fr;

use crate::lookup::ChannelSpec;
use crate::memory::{
    deleg_space, frame, frame_queries, frame_with_channels_artifact, rd_selected, FamilySpec, ARG1,
    ARG2, DELEG, FIELD_ADDR, FIELD_MASK, FIELD_READ_TS, FIELD_READ_VALUE, FIELD_WRITE_VALUE, PC,
    RAM, RD, RS1, RS2,
};
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

/// Every delegation type this family's ecall rows may request, ascending by
/// family id: `(family, ecall number, address-space tag, frame words)`.
/// `constants::delegation::TYPES` is the one registry; this file builds one
/// selector column and three gates per row of it.
const DELEGATIONS: [(u32, u32, u8, usize); constants::delegation::TYPES.len()] =
    constants::delegation::TYPES;

/// How many delegation types there are, which is how many request selectors
/// this family commits.
const TYPES: usize = DELEGATIONS.len();

// The ecall numbers this family proves are pairwise distinct and each in its
// ABI range, so `ecall_is_exit` and the per-type number gates **partition** its
// ecall rows rather than two of them holding on one row
// (`docs/spec/delegation.md` §2). Distinctness is what makes the partition:
// two selectors set at once would need `a7` to be two numbers at the same time.
// No gate spells a number — each reads `constants::ecall` through the registry
// above, the one place an ecall number lives. A `const` assertion rather than a
// test, because a violation here is a mis-numbered ABI and should not compile.
const _: () = {
    // The three numbers this family pins outside the delegation registry.
    // `ecall_is_exit` and the five per-number gates partition an ecall row
    // only because no two of the six numbers are equal: a row claiming two
    // selectors would need `a7` to be two numbers at once.
    assert!(constants::ecall::READ != constants::ecall::WRITE);
    assert!(constants::ecall::READ != constants::ecall::EXIT);
    assert!(constants::ecall::WRITE != constants::ecall::EXIT);
    let mut i = 0;
    while i < TYPES {
        assert!(constants::ecall::EXIT != DELEGATIONS[i].1);
        assert!(constants::ecall::READ != DELEGATIONS[i].1);
        assert!(constants::ecall::WRITE != DELEGATIONS[i].1);
        assert!(DELEGATIONS[i].1 >= constants::ecall::PRECOMPILE_FIRST);
        assert!(DELEGATIONS[i].1 <= constants::ecall::PRECOMPILE_LAST);
        let mut j = i + 1;
        while j < TYPES {
            assert!(
                DELEGATIONS[i].1 != DELEGATIONS[j].1,
                "two delegation types share an ecall number"
            );
            assert!(
                DELEGATIONS[i].2 != DELEGATIONS[j].2,
                "two delegation types share an address space"
            );
            j += 1;
        }
        i += 1;
    }
};
const _: () = assert!(constants::ecall::EXIT < constants::ecall::ZKVM_IO_FIRST);

/// The family's queries, in slot order: its frame is `memory::frame_queries`'
/// list, and this file addresses its columns by these slots.
const QUERIES: [usize; 8] = [PC, RS1, RS2, ARG1, ARG2, RAM, RD, DELEG];
const SLOT_PC: usize = 0;
const SLOT_RS1: usize = 1;
const SLOT_RS2: usize = 2;
const SLOT_ARG1: usize = 3;
const SLOT_ARG2: usize = 4;
const SLOT_RAM: usize = 5;
const SLOT_RD: usize = 6;
const SLOT_DELEG: usize = 7;

/// The frame's own witness columns: eight gap chunks, then the x0 gadget's
/// three. Everything this file adds follows them.
const FRAME_WITNESS: u32 = 8 + 3;

const fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(i)
}

/// `W[10..16]`: the claimed decoded row, `next_pc, rs1, rs2, rd, imm, mask` —
/// `program::lookup_tuple` after `pc`, which the frame's own pc column is.
pub const DECODED: [PolyAddress; 6] = [
    w(FRAME_WITNESS),
    w(FRAME_WITNESS + 1),
    w(FRAME_WITNESS + 2),
    w(FRAME_WITNESS + 3),
    w(FRAME_WITNESS + 4),
    w(FRAME_WITNESS + 5),
];
const DECODED_NEXT_PC: PolyAddress = DECODED[0];
const DECODED_RS1: PolyAddress = DECODED[1];
const DECODED_RS2: PolyAddress = DECODED[2];
const DECODED_RD: PolyAddress = DECODED[3];
const DECODED_IMM: PolyAddress = DECODED[4];
const DECODED_MASK: PolyAddress = DECODED[5];

/// `W[16..22]`: the packed mask's bits, bit `k` at index `k` —
/// `constants::extra_mask::add_sub_lui_auipc`'s order: system, addi, auipc,
/// add, sub, lui.
pub const KINDS: [PolyAddress; 6] = [
    w(FRAME_WITNESS + 6),
    w(FRAME_WITNESS + 7),
    w(FRAME_WITNESS + 8),
    w(FRAME_WITNESS + 9),
    w(FRAME_WITNESS + 10),
    w(FRAME_WITNESS + 11),
];
const KIND_SYSTEM: PolyAddress = KINDS[kind::SYSTEM as usize];
const KIND_ADDI: PolyAddress = KINDS[kind::ADDI as usize];
const KIND_AUIPC: PolyAddress = KINDS[kind::AUIPC as usize];
const KIND_ADD: PolyAddress = KINDS[kind::ADD as usize];
const KIND_SUB: PolyAddress = KINDS[kind::SUB as usize];
const KIND_LUI: PolyAddress = KINDS[kind::LUI as usize];

/// `W[22]`: 1 exactly on a system row whose code is `ecall`.
pub const IS_ECALL: PolyAddress = w(FRAME_WITNESS + 12);
/// `W[24]`: 1 exactly on a system row whose code is `fence`.
pub const IS_FENCE: PolyAddress = w(FRAME_WITNESS + 13);
/// `W[25..28]`: one **delegation request** selector per type, in
/// [`DELEGATIONS`] order — 1 exactly on an ecall row whose `a7` is that type's
/// number (`docs/spec/delegation.md` §5.1). Each is a free boolean, pinned by
/// the number gates below: an ecall row is an exit or a request of exactly one
/// type, and its `a7` is that call's number.
pub const IS_DELEGATION: [PolyAddress; TYPES] = [
    w(FRAME_WITNESS + 14),
    w(FRAME_WITNESS + 15),
    w(FRAME_WITNESS + 16),
];
/// The keccak-f request selector, S21's `IS_KECCAK`, now the first of
/// [`IS_DELEGATION`].
pub const IS_KECCAK: PolyAddress = IS_DELEGATION[0];
/// 1 exactly on an ecall row whose `a7` is `READ` (S25).
///
/// A free boolean, pinned by [`artifact`]'s `read_number` gate, exactly as a
/// delegation type's selector is. It is what turns on the row's `arg1`,
/// `arg2` and **`ram`** queries: a provable `read` delivers one 4-aligned word
/// into `a1`, on this row, and the whole confinement of that write is two
/// gates here rather than a binding carried across rows
/// (`docs/spec/ecall-abi.md` §4).
pub const IS_READ: PolyAddress = w(FRAME_WITNESS + 14 + TYPES as u32);
/// 1 exactly on an ecall row whose `a7` is `WRITE` (S25).
///
/// It turns on `arg1` and `arg2` and **nothing else**: a `write` makes no RAM
/// query at all, because the query it used to make bound nothing. fd 1 is
/// bound by the guest's own `io_digest` over the bytes it assembled with
/// ordinary loads and stores, which the memory argument does bind
/// (`docs/spec/memory.md` §10).
pub const IS_WRITE: PolyAddress = w(FRAME_WITNESS + 15 + TYPES as u32);
/// The high halfword of the word a `read` delivers.
///
/// The delivered value is advice — nothing pins *what* arrives, which is the
/// point — but it is still a 32-bit word written into RAM, so it carries the
/// range convention's 16+16 pair like every other value a family writes. Root
/// `CLAUDE.md`, "A copied value is not range-checked; a computed one is",
/// names this stage as the one that owes it.
pub const RAM_VALUE_HI: PolyAddress = w(FRAME_WITNESS + 16 + TYPES as u32);
/// The sum's carry, or the difference's borrow.
pub const WRAP: PolyAddress = w(FRAME_WITNESS + 17 + TYPES as u32);
/// The computed `rd` value's high halfword.
pub const RD_HI: PolyAddress = w(FRAME_WITNESS + 18 + TYPES as u32);
/// `next_pc`'s wrap, 0 on every honest row.
pub const PC_WRAP: PolyAddress = w(FRAME_WITNESS + 19 + TYPES as u32);
/// `next_pc`'s high halfword.
pub const NEXT_PC_HI: PolyAddress = w(FRAME_WITNESS + 20 + TYPES as u32);
/// The channels' multiplicities, in channel order — timestamp, range16,
/// decoder — last in the witness subtree (`docs/spec/lookup.md` §7).
pub const MULTIPLICITIES: [PolyAddress; 3] = [
    w(FRAME_WITNESS + 21 + TYPES as u32),
    w(FRAME_WITNESS + 22 + TYPES as u32),
    w(FRAME_WITNESS + 23 + TYPES as u32),
];

/// The decoded table's width, `program::lookup_tuple(ADD_SUB_LUI_AUIPC)`:
/// `pc next_pc rs1 rs2 rd imm extra_mask`, at `S[0..7]`.
pub const TABLE_WIDTH: usize = 7;

/// `ecall_code` is `is_ecall·imm`, which says "the code is `ECALL`" only
/// because that code is 0.
const _: () = assert!(system_code::ECALL == 0);

/// `a7`'s register, which an ecall row reads as its `rs1`.
const A7: u64 = 17;
/// `a0`'s register, which an ecall row reads as its `rs2` and writes as its
/// `rd`.
const A0: u64 = 10;
/// `a1`'s register, the buffer a `read` or a `write` names, read as `arg1`.
const A1: u64 = 11;
/// `a2`'s register, the byte count, read as `arg2`.
const A2: u64 = 12;

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fr::from_u64(v))
}

fn two_32() -> Fr {
    Fr::from_u64(1 << 32)
}

/// `Σ a·x + Σ b·y·z`, constant 0, literal coefficients.
fn quadratic(
    linear: Vec<(Coeff, PolyAddress)>,
    products: Vec<(Coeff, PolyAddress, PolyAddress)>,
) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear,
        products,
    }
}

fn linear(terms: Vec<(Coeff, PolyAddress)>) -> GateDef {
    GateDef::Linear {
        terms,
        constant: lit(0),
    }
}

/// `x − x·x`.
fn booleanity(x: PolyAddress) -> GateDef {
    quadratic(vec![(lit(1), x)], vec![(neg(1), x, x)])
}

/// `x` alone, a lookup expression.
fn column(x: PolyAddress) -> GateDef {
    linear(vec![(lit(1), x)])
}

/// `m_q − m_pc·Σ uses`: query `q` is present exactly on a live row whose kind
/// uses it.
fn mask_rule(mask: PolyAddress, uses: &[PolyAddress]) -> GateDef {
    let m_pc = frame(SLOT_PC, FIELD_MASK);
    quadratic(
        vec![(lit(1), mask)],
        uses.iter().map(|u| (neg(1), m_pc, *u)).collect(),
    )
}

/// `m_q·(a_q − decoded − register·is_ecall)`: a present query's address is the
/// decoded one, or `register` on an ecall row, whose decoded registers are 0.
fn addr_rule(slot: usize, decoded: PolyAddress, register: u64) -> GateDef {
    let m = frame(slot, FIELD_MASK);
    quadratic(
        vec![],
        vec![
            (lit(1), m, frame(slot, FIELD_ADDR)),
            (neg(1), m, decoded),
            (neg(register), m, IS_ECALL),
        ],
    )
}

/// `m_q·(a_q − register)`: a present query's address is that literal register.
///
/// [`addr_rule`]'s sibling, for the two queries whose address comes from the
/// ABI rather than from a decoded field: an `ecall`'s encoding names no
/// registers, so `a1` and `a2` have nothing to be compared against but their
/// numbers.
fn fixed_addr_rule(slot: usize, register: u64) -> GateDef {
    let m = frame(slot, FIELD_MASK);
    quadratic(
        vec![(neg(register), m)],
        vec![(lit(1), m, frame(slot, FIELD_ADDR))],
    )
}

/// `v_q − m_q·v_q`: an absent operand reads 0.
fn value_masked(slot: usize) -> GateDef {
    let (m, v) = (frame(slot, FIELD_MASK), frame(slot, FIELD_READ_VALUE));
    quadratic(vec![(lit(1), v)], vec![(neg(1), m, v)])
}

/// A `RANGE16` obligation under the row's pc mask.
fn range16(name: &str, expression: GateDef) -> LookupExpr {
    LookupExpr {
        name: name.to_string(),
        channel: lookup_channel::RANGE16,
        selector: frame(SLOT_PC, FIELD_MASK),
        tuple: vec![expression],
    }
}

/// `x − 2^16·hi`, the low halfword of a value bounded by the range convention
/// of `docs/spec/memory.md` §7.
fn low_half(x: PolyAddress, hi: PolyAddress) -> GateDef {
    linear(vec![
        (lit(1), x),
        (Coeff::Literal(-Fr::from_u64(1 << 16)), hi),
    ])
}

/// Every provable-ecall selector but the exit's, in gate order: the three
/// delegation requests, then `read` and `write`.
///
/// `is_exit` is the remainder — `is_ecall` minus all of these — so a gate that
/// means "on an exit row" subtracts exactly this list, and a gate that means
/// "on a call row" adds `is_ecall`. One list, so the two cannot drift apart
/// when a number is added.
fn non_exit_ecalls() -> Vec<PolyAddress> {
    let mut all = IS_DELEGATION.to_vec();
    all.push(IS_READ);
    all.push(IS_WRITE);
    all
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/shard-proof.md`
/// §8. `trace_vars` is at least 19, the timestamp channel's width, which the
/// assembly refuses below; a Mercury opening needs it even as well.
///
/// Panics if the family's frame is not the eight queries this file addresses,
/// or if any obligation count is not §8.3's — 16 timestamp (two a query, and
/// S21's `deleg` is the eighth), 6 `RANGE16`, 1 decoder — and on every refusal
/// of the assembly.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    assert_eq!(
        frame_queries(family::ADD_SUB_LUI_AUIPC),
        &QUERIES,
        "add_sub: the family's frame is the eight queries this circuit addresses by slot"
    );
    let m_pc = frame(SLOT_PC, FIELD_MASK);
    let pc = frame(SLOT_PC, FIELD_READ_VALUE);
    let next_pc = frame(SLOT_PC, FIELD_WRITE_VALUE);
    let v_rs1 = frame(SLOT_RS1, FIELD_READ_VALUE);
    let v_rs2 = frame(SLOT_RS2, FIELD_READ_VALUE);
    let v_rd = frame(SLOT_RD, FIELD_READ_VALUE);
    let sel = rd_selected(QUERIES.len());

    let mut witness = names(&[
        "decoded_next_pc",
        "decoded_rs1",
        "decoded_rs2",
        "decoded_rd",
        "decoded_imm",
        "decoded_mask",
        "kind_system",
        "kind_addi",
        "kind_auipc",
        "kind_add",
        "kind_sub",
        "kind_lui",
        "is_ecall",
        "is_fence",
    ]);
    witness.extend(
        DELEGATIONS
            .iter()
            .map(|(family, ..)| format!("is_deleg_{family}")),
    );
    witness.extend(names(&[
        "is_read",
        "is_write",
        "ram_value_hi",
        "wrap",
        "rd_hi",
        "pc_wrap",
        "next_pc_hi",
    ]));
    witness.extend(
        [
            lookup_channel::TIMESTAMP,
            lookup_channel::RANGE16,
            lookup_channel::DECODER,
        ]
        .iter()
        .map(|c| format!("mult_{}", lookup_channel::NAMES[*c as usize])),
    );
    let setup = names(&[
        "table_pc",
        "table_next_pc",
        "table_rs1",
        "table_rs2",
        "table_rd",
        "table_imm",
        "table_extra_mask",
    ]);

    let kind_names = ["system", "addi", "auipc", "add", "sub", "lui"];
    let mut enforcing: Vec<(String, GateDef)> = Vec::new();
    for (k, bit) in KINDS.iter().enumerate() {
        enforcing.push((format!("kind_{}_boolean", kind_names[k]), booleanity(*bit)));
    }
    // One degree-1 constraint ties the packed mask to its bits; one-hotness is
    // the decoder table's domain and nothing else (`docs/spec/lookup.md` §10).
    let mut bits: Vec<(Coeff, PolyAddress)> = KINDS
        .iter()
        .enumerate()
        .map(|(k, bit)| (lit(1 << k), *bit))
        .collect();
    bits.push((neg(1), DECODED_MASK));
    enforcing.push(("decoded_mask_bits".into(), linear(bits)));
    enforcing.push(("is_ecall_boolean".into(), booleanity(IS_ECALL)));
    enforcing.push(("is_fence_boolean".into(), booleanity(IS_FENCE)));
    enforcing.push((
        "system_split".into(),
        linear(vec![
            (lit(1), IS_ECALL),
            (lit(1), IS_FENCE),
            (neg(1), KIND_SYSTEM),
        ]),
    ));
    enforcing.push((
        "ecall_code".into(),
        quadratic(vec![], vec![(lit(1), IS_ECALL, DECODED_IMM)]),
    ));
    enforcing.push((
        "fence_code".into(),
        quadratic(
            vec![(neg(system_code::FENCE as u64), IS_FENCE)],
            vec![(lit(1), IS_FENCE, DECODED_IMM)],
        ),
    ));
    // An ecall row is an exit or a delegation request of exactly one type, and
    // `a7` is that call's number. Each `is_deleg_t` is a free boolean and
    // `is_exit` is `is_ecall - Σ is_deleg_t`, so the pins below leave `a7` no
    // other value: a row claiming two types at once would need `a7` to be two
    // distinct numbers, which the `const` assertion above makes impossible, and
    // one claiming a type and the exit would need it to be 93 as well
    // (`docs/spec/delegation.md` §5.1).
    for (i, (family, number, ..)) in DELEGATIONS.iter().enumerate() {
        let is_t = IS_DELEGATION[i];
        enforcing.push((format!("is_deleg_{family}_boolean"), booleanity(is_t)));
        enforcing.push((
            format!("deleg_{family}_is_an_ecall"),
            quadratic(vec![(lit(1), is_t)], vec![(neg(1), is_t, IS_ECALL)]),
        ));
        enforcing.push((
            format!("deleg_{family}_number"),
            quadratic(
                vec![(neg(*number as u64), is_t)],
                vec![(lit(1), is_t, v_rs1)],
            ),
        ));
    }
    // S25's two, the same three gates apiece: a free boolean, 0 off an ecall
    // row, and `a7` pinned to its number. `read` and `write` are ordinary
    // provable ecalls now, and the only thing that distinguishes them from a
    // delegation request here is what their selectors go on to switch on.
    for (name, is_io, number) in [
        ("read", IS_READ, constants::ecall::READ),
        ("write", IS_WRITE, constants::ecall::WRITE),
    ] {
        enforcing.push((format!("is_{name}_boolean"), booleanity(is_io)));
        enforcing.push((
            format!("is_{name}_is_an_ecall"),
            quadratic(vec![(lit(1), is_io)], vec![(neg(1), is_io, IS_ECALL)]),
        ));
        enforcing.push((
            format!("{name}_number"),
            quadratic(
                vec![(neg(number as u64), is_io)],
                vec![(lit(1), is_io, v_rs1)],
            ),
        ));
    }

    // is_exit·(a7 - EXIT) = 0, with is_exit written out as
    // `is_ecall - Σ is_deleg_t - is_read - is_write`: the remainder of the
    // partition, and the only route to `HALT_PC`.
    {
        let mut linear = vec![(neg(constants::ecall::EXIT as u64), IS_ECALL)];
        let mut products = vec![(lit(1), IS_ECALL, v_rs1)];
        for is_t in non_exit_ecalls() {
            linear.push((lit(constants::ecall::EXIT as u64), is_t));
            products.push((neg(1), is_t, v_rs1));
        }
        enforcing.push(("ecall_is_exit".into(), quadratic(linear, products)));
    }

    enforcing.push((
        "rs1_mask_rule".into(),
        mask_rule(
            frame(SLOT_RS1, FIELD_MASK),
            &[KIND_ADD, KIND_SUB, KIND_ADDI, IS_ECALL],
        ),
    ));
    enforcing.push((
        "rs2_mask_rule".into(),
        mask_rule(frame(SLOT_RS2, FIELD_MASK), &[KIND_ADD, KIND_SUB, IS_ECALL]),
    ));
    // `a1` and `a2` are read by a `read` and by a `write`; the RAM query is a
    // `read`'s alone. Until S25 all three masks were held to 0 — the family
    // proved `EXIT` and the delegation numbers, none of which reads a buffer.
    enforcing.push((
        "arg1_mask_rule".into(),
        mask_rule(frame(SLOT_ARG1, FIELD_MASK), &[IS_READ, IS_WRITE]),
    ));
    enforcing.push((
        "arg2_mask_rule".into(),
        mask_rule(frame(SLOT_ARG2, FIELD_MASK), &[IS_READ, IS_WRITE]),
    ));
    enforcing.push((
        "ram_mask_rule".into(),
        mask_rule(frame(SLOT_RAM, FIELD_MASK), &[IS_READ]),
    ));
    enforcing.push((
        "rd_mask_rule".into(),
        mask_rule(
            frame(SLOT_RD, FIELD_MASK),
            &[
                KIND_ADD, KIND_SUB, KIND_ADDI, KIND_AUIPC, KIND_LUI, IS_ECALL,
            ],
        ),
    ));
    enforcing.push((
        "deleg_mask_rule".into(),
        mask_rule(frame(SLOT_DELEG, FIELD_MASK), &IS_DELEGATION),
    ));
    enforcing.push(("rs1_addr_rule".into(), addr_rule(SLOT_RS1, DECODED_RS1, A7)));
    enforcing.push(("rs2_addr_rule".into(), addr_rule(SLOT_RS2, DECODED_RS2, A0)));
    enforcing.push(("rd_addr_rule".into(), addr_rule(SLOT_RD, DECODED_RD, A0)));
    // `a1` and `a2` have no decoded field to come from — an `ecall`'s encoding
    // names no registers — so their addresses are the two literals, under
    // their own masks.
    enforcing.push(("arg1_addr_rule".into(), fixed_addr_rule(SLOT_ARG1, A1)));
    enforcing.push(("arg2_addr_rule".into(), fixed_addr_rule(SLOT_ARG2, A2)));
    enforcing.push(("rs1_value_masked".into(), value_masked(SLOT_RS1)));
    enforcing.push(("rs2_value_masked".into(), value_masked(SLOT_RS2)));

    // ---- the `read` ecall's RAM write, confined ------------------------
    //
    // These two gates are the whole of S14's open question 10, answered the
    // way that handoff recommended: **one word per read, on the ecall's own
    // row.** Because the query rides the row that reads `a1` and `a2`, the
    // buffer and the count it is confined to are columns of this row, and
    // nothing has to be carried across rows — which this arithmetization has
    // no way to do but the global memory multiset.
    //
    // Together they say: the word written is the word at `a1`, and the call
    // asked for exactly that one word. Everything else a malicious prover
    // might try is already refused elsewhere:
    //
    //   * a RAM query on a row that is not a `read` — `ram_mask_rule`;
    //   * an address that is not a 4-aligned word of a declared RAM window —
    //     it has no init tuple, so the multiset cannot balance
    //     (`docs/spec/memory.md` §9, Coverage);
    //   * a value outside `[0, 2^32)` — the two obligations below;
    //   * *what* the word contains — nothing pins it, and nothing should: the
    //     delivered bytes are advice, and what ties them to `public.input` is
    //     the guest's own `io_digest` over the buffer it read them into
    //     (`docs/spec/memory.md` §10).
    let m_ram = frame(SLOT_RAM, FIELD_MASK);
    enforcing.push((
        "ram_addr_is_the_buffer".into(),
        quadratic(
            vec![],
            vec![
                (lit(1), m_ram, frame(SLOT_RAM, FIELD_ADDR)),
                (neg(1), m_ram, frame(SLOT_ARG1, FIELD_READ_VALUE)),
            ],
        ),
    ));
    enforcing.push((
        "read_count_is_one_word".into(),
        quadratic(
            vec![(neg(constants::ecall::READ_WORD_BYTES as u64), m_ram)],
            vec![(lit(1), m_ram, frame(SLOT_ARG2, FIELD_READ_VALUE))],
        ),
    ));

    // (add + addi + auipc)·(rs1 + rs2 + imm − sel − 2^32·wrap) + auipc·pc: an
    // R-type row's imm is 0, an I-type or U-type row's absent rs2 reads 0, and
    // an auipc row's absent rs1 reads 0, so each kind sees its own two addends.
    let mut sum = Vec::new();
    for bit in [KIND_ADD, KIND_ADDI, KIND_AUIPC] {
        sum.push((lit(1), bit, v_rs1));
        sum.push((lit(1), bit, v_rs2));
        sum.push((lit(1), bit, DECODED_IMM));
        sum.push((neg(1), bit, sel));
        sum.push((Coeff::Literal(-two_32()), bit, WRAP));
    }
    sum.push((lit(1), KIND_AUIPC, pc));
    enforcing.push(("add_addi_auipc".into(), quadratic(vec![], sum)));
    enforcing.push((
        "sub".into(),
        quadratic(
            vec![],
            vec![
                (lit(1), KIND_SUB, v_rs1),
                (neg(1), KIND_SUB, v_rs2),
                (neg(1), KIND_SUB, sel),
                (Coeff::Literal(two_32()), KIND_SUB, WRAP),
            ],
        ),
    ));
    enforcing.push((
        "lui".into(),
        quadratic(
            vec![],
            vec![(lit(1), KIND_LUI, DECODED_IMM), (neg(1), KIND_LUI, sel)],
        ),
    ));
    // The exit row's `a0` write is its read. No other provable ecall's is: a
    // delegation request writes 0 (the first of its three request-side
    // zeroings), and a `read` or a `write` writes the byte count the executor
    // claims — a **free witness**, bounded only by the family's own `rd` pair.
    //
    // Free, and deliberately so. The count is advice like the bytes are: what
    // the guest does with a short answer is the guest's business, and
    // `guest_sdk::read_fd` checks it against the word it offered. Nothing here
    // could check it — the number of bytes a stream had left is not a fact any
    // row holds.
    enforcing.push(("exit_status".into(), {
        let mut products = vec![(lit(1), IS_ECALL, v_rd), (neg(1), IS_ECALL, sel)];
        for is_t in non_exit_ecalls() {
            products.push((neg(1), is_t, v_rd));
            products.push((lit(1), is_t, sel));
        }
        quadratic(vec![], products)
    }));
    // The three request-side zeroings of `docs/spec/delegation.md` §5.2, each
    // gated on the mirror query's own mask. All three, and not two: without
    // the rd zeroing a request writes a register the ABI says it does not;
    // without the timestamp zeroing the requests chain, and N of them close
    // the permutation against one invocation; without the value zeroing the
    // request's read and the invocation's write are different tuples and
    // never cancel.
    let m_deleg = frame(SLOT_DELEG, FIELD_MASK);
    enforcing.push((
        "deleg_writes_no_register".into(),
        quadratic(vec![], vec![(lit(1), m_deleg, sel)]),
    ));
    enforcing.push((
        "deleg_read_ts_zero".into(),
        quadratic(
            vec![],
            vec![(lit(1), m_deleg, frame(SLOT_DELEG, FIELD_READ_TS))],
        ),
    ));
    enforcing.push((
        "deleg_read_value_zero".into(),
        quadratic(
            vec![],
            vec![(lit(1), m_deleg, frame(SLOT_DELEG, FIELD_READ_VALUE))],
        ),
    ));
    // The anchor's address is the frame base the request handed over in `a0`,
    // which is this row's `rs2` read (`docs/spec/delegation.md` §5.2).
    enforcing.push((
        "deleg_addr_rule".into(),
        quadratic(
            vec![],
            vec![
                (lit(1), m_deleg, frame(SLOT_DELEG, FIELD_ADDR)),
                (neg(1), m_deleg, v_rs2),
            ],
        ),
    ));
    // The mirror's leaf names the delegation *type* through the frame's
    // `deleg_space` column, because a leaf may read no `W` column and the type
    // selectors are witnesses (`docs/spec/delegation.md` §5.1). This is the
    // gate that ties the column to them: `deleg_space = Σ tag_t·is_deleg_t`,
    // degree 1, and 0 on every row that requests nothing — each `is_deleg_t`
    // is 0 unless `is_ecall` is 1, and `is_ecall` is 0 on a padding row.
    enforcing.push(("deleg_space_rule".into(), {
        let mut terms = vec![(lit(1), deleg_space(QUERIES.len()))];
        for (i, (.., tag, _)) in DELEGATIONS.iter().enumerate() {
            terms.push((neg(*tag as u64), IS_DELEGATION[i]));
        }
        GateDef::Linear {
            terms,
            constant: lit(0),
        }
    }));
    enforcing.push(("wrap_boolean".into(), booleanity(WRAP)));
    enforcing.push(("pc_wrap_boolean".into(), booleanity(PC_WRAP)));
    // next_pc + 2^32·pc_wrap = decoded_next_pc, or HALT_PC on the exit row.
    // Only an exit is an exit: a delegation request, a `read` and a `write`
    // each fall through, so `is_exit = is_ecall - Σ (the other five)` is what
    // carries the sentinel.
    //
    // Since S25 **every live row advances the pc**. The machine's one
    // `next_pc = pc` row shape was the ecall transfer cycle, and there are no
    // transfer cycles any more (`docs/spec/execution-trace.md` §1).
    enforcing.push(("next_pc_rule".into(), {
        let mut linear = vec![
            (lit(1), next_pc),
            (Coeff::Literal(two_32()), PC_WRAP),
            (neg(1), DECODED_NEXT_PC),
            (neg(mem::HALT_PC as u64), IS_ECALL),
        ];
        let mut products = vec![(lit(1), IS_ECALL, DECODED_NEXT_PC)];
        for is_t in non_exit_ecalls() {
            linear.push((lit(mem::HALT_PC as u64), is_t));
            products.push((neg(1), is_t, DECODED_NEXT_PC));
        }
        quadratic(linear, products)
    }));

    let mut decode = vec![column(pc)];
    decode.extend(DECODED.iter().map(|x| column(*x)));
    let lookups = vec![
        range16("rd_hi_range", column(RD_HI)),
        range16("rd_lo_range", low_half(sel, RD_HI)),
        range16("next_pc_hi_range", column(NEXT_PC_HI)),
        range16("next_pc_lo_range", low_half(next_pc, NEXT_PC_HI)),
        // The word a `read` delivers. Its *content* is advice and nothing
        // pins it, but it is a 32-bit value this family writes into RAM, so
        // it carries the range convention's pair like every other one — root
        // `CLAUDE.md`, "A copied value is not range-checked; a computed one
        // is", which names the I/O-binding stage as owing exactly this. The
        // selector is the row's `m_pc`, as every obligation of this family's
        // is: on a live row that makes no RAM query the write value is 0 and
        // the pair holds with `ram_value_hi = 0`.
        range16("ram_value_hi_range", column(RAM_VALUE_HI)),
        range16(
            "ram_value_lo_range",
            low_half(frame(SLOT_RAM, FIELD_WRITE_VALUE), RAM_VALUE_HI),
        ),
        LookupExpr {
            name: "decode_row".into(),
            channel: lookup_channel::DECODER,
            selector: m_pc,
            tuple: decode,
        },
    ];

    let a = frame_with_channels_artifact(
        &QUERIES,
        trace_vars,
        FamilySpec {
            witness,
            setup,
            virtuals: vec![
                (VirtualKind::Range19, "range19".into()),
                (VirtualKind::Range16, "range16".into()),
            ],
            enforcing,
            lookups,
            channels: channels(),
        },
    );
    // Every obligation is built above and then handed over, so a count is
    // what shows none was dropped on the way (S14 must-be-exact 5, S15's
    // per-channel form).
    for (channel, want) in [
        (lookup_channel::TIMESTAMP, 2 * QUERIES.len()),
        (lookup_channel::RANGE16, 6),
        (lookup_channel::DECODER, 1),
    ] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(
            got,
            want,
            "add_sub: channel `{}` carries {got} obligations, not {want}",
            lookup_channel::NAMES[channel as usize]
        );
    }
    a
}

/// The family's three channels, in output order: the timestamp gaps over
/// `V[range19]`, the 16-bit halves over `V[range16]`, and the decoder over the
/// family's decoded table at `S[0..7]`.
pub fn channels() -> Vec<ChannelSpec> {
    vec![
        ChannelSpec {
            channel: lookup_channel::TIMESTAMP,
            table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
            multiplicity: MULTIPLICITIES[0],
        },
        ChannelSpec {
            channel: lookup_channel::RANGE16,
            table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
            multiplicity: MULTIPLICITIES[1],
        },
        ChannelSpec {
            channel: lookup_channel::DECODER,
            table: (0..TABLE_WIDTH as u32).map(PolyAddress::Setup).collect(),
            multiplicity: MULTIPLICITIES[2],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ebreak`'s code is neither the ecall code nor the fence code, which is
    /// what makes `system_split` with `ecall_code` and `fence_code` refuse every
    /// `ebreak` row.
    #[test]
    fn no_system_code_is_both_or_neither_but_ebreak() {
        assert_ne!(system_code::EBREAK, system_code::ECALL);
        assert_ne!(system_code::EBREAK, system_code::FENCE);
        assert_ne!(system_code::ECALL, system_code::FENCE);
    }
}
