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
//! frame     M[0..26], W[0..8]: pc rs1 rs2 rd deleg at slots 0..5
//! M[26]     deleg_space: the requested delegation type's address-space tag
//! W[8..14]  the claimed decoded row: next_pc rs1 rs2 rd imm mask
//! W[14..20] the mask's six bits; W[20], W[21] is_ecall, is_fence
//! W[22..22+t] is_deleg_*: one request selector per type the circuit knows,
//!           t = 6 in the base format and every type in the recursion format
//! W[22+t..26+t] wrap, rd_hi, pc_wrap, next_pc_hi
//! W[26+t..29+t] one multiplicity per channel: timestamp, range16, decoder
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
    deleg_space, frame, frame_queries, frame_with_channels_artifact, rd_selected, FamilySpec,
    DELEG, FIELD_ADDR, FIELD_MASK, FIELD_READ_TS, FIELD_READ_VALUE, FIELD_WRITE_VALUE, PC, RD, RS1,
    RS2,
};
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

/// Every delegation type an ecall row may request, ascending by family id:
/// `(family, ecall number, address-space tag, frame words)`.
/// `constants::delegation::TYPES` is the one registry; this file builds one
/// selector column and three gates per row of the prefix a circuit knows.
const DELEGATIONS: [(u32, u32, u8, usize); constants::delegation::TYPES.len()] =
    constants::delegation::TYPES;

/// How many delegation types there are.
const TYPES: usize = DELEGATIONS.len();

/// How many the **base format**'s circuit knows, and so how many request
/// selectors [`artifact`] commits: frozen, which is what keeps every base key's
/// bytes while the registry grows. [`recursion_artifact`] knows all [`TYPES`]
/// (`docs/spec/recursion.md` §1.2).
const BASE_TYPES: usize = constants::delegation::BASE_TYPES;
const _: () = assert!(BASE_TYPES <= TYPES);

// The ecall numbers this family proves are pairwise distinct and each in its
// ABI range, so `ecall_is_exit` and the per-type number gates **partition** its
// ecall rows rather than two of them holding on one row
// (`docs/spec/delegation.md` §2). Distinctness is what makes the partition:
// two selectors set at once would need `a7` to be two numbers at the same time.
// No gate spells a number — each reads `constants::ecall` through the registry
// above, the one place an ecall number lives. A `const` assertion rather than a
// test, because a violation here is a mis-numbered ABI and should not compile.
const _: () = {
    let mut i = 0;
    while i < TYPES {
        assert!(constants::ecall::EXIT != DELEGATIONS[i].1);
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
const QUERIES: [usize; 5] = [PC, RS1, RS2, RD, DELEG];
const SLOT_PC: usize = 0;
const SLOT_RS1: usize = 1;
const SLOT_RS2: usize = 2;
const SLOT_RD: usize = 3;
const SLOT_DELEG: usize = 4;

/// The frame's own witness columns: five gap chunks, then the x0 gadget's
/// three. Everything this file adds follows them.
const FRAME_WITNESS: u32 = 5 + 3;

const fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(i)
}

/// `W[8..14]`: the claimed decoded row, `next_pc, rs1, rs2, rd, imm, mask` —
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

/// `W[14..20]`: the packed mask's bits, bit `k` at index `k` —
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

/// `W[20]`: 1 exactly on a system row whose code is `ecall`.
pub const IS_ECALL: PolyAddress = w(FRAME_WITNESS + 12);
/// `W[21]`: 1 exactly on a system row whose code is `fence`.
pub const IS_FENCE: PolyAddress = w(FRAME_WITNESS + 13);
/// `W[22 + i]`: delegation type `i`'s **request** selector, in
/// [`DELEGATIONS`] order — 1 exactly on an ecall row whose `a7` is that type's
/// number (`docs/spec/delegation.md` §5.1). Each is a free boolean, pinned by
/// the number gates below: an ecall row is an exit or a request of exactly one
/// type, and its `a7` is that call's number.
pub const fn is_delegation(i: usize) -> PolyAddress {
    w(FRAME_WITNESS + 14 + i as u32)
}
/// Column `k` past a circuit's `types` request selectors: `wrap`, `rd_hi`,
/// `pc_wrap`, `next_pc_hi`, then the three multiplicities, which stay last in
/// the witness subtree (`docs/spec/lookup.md` §7).
const fn after(types: usize, k: u32) -> PolyAddress {
    w(FRAME_WITNESS + 14 + types as u32 + k)
}
/// The sum's carry, or the difference's borrow, in a circuit knowing `types`.
pub const fn wrap(types: usize) -> PolyAddress {
    after(types, 0)
}
/// The computed `rd` value's high halfword.
pub const fn rd_hi(types: usize) -> PolyAddress {
    after(types, 1)
}
/// `next_pc`'s wrap, 0 on every honest row.
pub const fn pc_wrap(types: usize) -> PolyAddress {
    after(types, 2)
}
/// `next_pc`'s high halfword.
pub const fn next_pc_hi(types: usize) -> PolyAddress {
    after(types, 3)
}
/// The channels' multiplicities, in channel order — timestamp, range16,
/// decoder.
pub const fn multiplicities(types: usize) -> [PolyAddress; 3] {
    [after(types, 4), after(types, 5), after(types, 6)]
}

/// `W[22..28]`: the base format's request selectors.
pub const IS_DELEGATION: [PolyAddress; BASE_TYPES] = [
    is_delegation(0),
    is_delegation(1),
    is_delegation(2),
    is_delegation(3),
    is_delegation(4),
    is_delegation(5),
];
/// The keccak-f request selector, S21's `IS_KECCAK`, now the first of
/// [`IS_DELEGATION`].
pub const IS_KECCAK: PolyAddress = IS_DELEGATION[0];
/// `W[28]`, the base format's [`wrap`].
pub const WRAP: PolyAddress = wrap(BASE_TYPES);
/// `W[29]`, the base format's [`rd_hi`].
pub const RD_HI: PolyAddress = rd_hi(BASE_TYPES);
/// `W[30]`, the base format's [`pc_wrap`].
pub const PC_WRAP: PolyAddress = pc_wrap(BASE_TYPES);
/// `W[31]`, the base format's [`next_pc_hi`].
pub const NEXT_PC_HI: PolyAddress = next_pc_hi(BASE_TYPES);
/// `W[32..35]`, the base format's [`multiplicities`].
pub const MULTIPLICITIES: [PolyAddress; 3] = multiplicities(BASE_TYPES);

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

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/shard-proof.md`
/// §8. `trace_vars` is at least 19, the timestamp channel's width, which the
/// assembly refuses below; a Mercury opening needs it even as well.
///
/// Panics if the family's frame is not the five queries this file addresses,
/// or if any obligation count is not §8.3's — 16 timestamp (two a query, and
/// S21's `deleg` is the eighth), 4 `RANGE16`, 1 decoder — and on every refusal
/// of the assembly.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    build(trace_vars, BASE_TYPES)
}

/// The **recursion format**'s circuit: [`artifact`] knowing every delegation
/// type, the recursion families' included (`docs/spec/recursion.md` §1.2).
pub fn recursion_artifact(trace_vars: u32) -> CircuitArtifact {
    build(trace_vars, TYPES)
}

/// The circuit knowing the first `types` rows of the registry.
fn build(trace_vars: u32, types: usize) -> CircuitArtifact {
    let delegations = &DELEGATIONS[..types];
    let is_deleg: Vec<PolyAddress> = (0..types).map(is_delegation).collect();
    let (wrap, rd_hi, pc_wrap, next_pc_hi) =
        (wrap(types), rd_hi(types), pc_wrap(types), next_pc_hi(types));
    assert_eq!(
        frame_queries(family::ADD_SUB_LUI_AUIPC),
        &QUERIES,
        "add_sub: the family's frame is the five queries this circuit addresses by slot"
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
        delegations
            .iter()
            .map(|(family, ..)| format!("is_deleg_{family}")),
    );
    witness.extend(names(&["wrap", "rd_hi", "pc_wrap", "next_pc_hi"]));
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
    for (i, (family, number, ..)) in delegations.iter().enumerate() {
        let is_t = is_deleg[i];
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
    // is_exit·(a7 - EXIT) = 0, with is_exit written out as is_ecall - Σ is_t.
    {
        let mut linear = vec![(neg(constants::ecall::EXIT as u64), IS_ECALL)];
        let mut products = vec![(lit(1), IS_ECALL, v_rs1)];
        for &is_t in &is_deleg {
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
        mask_rule(frame(SLOT_DELEG, FIELD_MASK), &is_deleg),
    ));
    enforcing.push(("rs1_addr_rule".into(), addr_rule(SLOT_RS1, DECODED_RS1, A7)));
    enforcing.push(("rs2_addr_rule".into(), addr_rule(SLOT_RS2, DECODED_RS2, A0)));
    enforcing.push(("rd_addr_rule".into(), addr_rule(SLOT_RD, DECODED_RD, A0)));
    enforcing.push(("rs1_value_masked".into(), value_masked(SLOT_RS1)));
    enforcing.push(("rs2_value_masked".into(), value_masked(SLOT_RS2)));

    // (add + addi + auipc)·(rs1 + rs2 + imm − sel − 2^32·wrap) + auipc·pc: an
    // R-type row's imm is 0, an I-type or U-type row's absent rs2 reads 0, and
    // an auipc row's absent rs1 reads 0, so each kind sees its own two addends.
    let mut sum = Vec::new();
    for bit in [KIND_ADD, KIND_ADDI, KIND_AUIPC] {
        sum.push((lit(1), bit, v_rs1));
        sum.push((lit(1), bit, v_rs2));
        sum.push((lit(1), bit, DECODED_IMM));
        sum.push((neg(1), bit, sel));
        sum.push((Coeff::Literal(-two_32()), bit, wrap));
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
                (Coeff::Literal(two_32()), KIND_SUB, wrap),
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
    // The exit row's `a0` write is its read. A delegation request's is not:
    // it writes 0, which is the first of the three request-side zeroings.
    enforcing.push(("exit_status".into(), {
        let mut products = vec![(lit(1), IS_ECALL, v_rd), (neg(1), IS_ECALL, sel)];
        for &is_t in &is_deleg {
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
    if types == BASE_TYPES {
        enforcing.push((
            "deleg_writes_no_register".into(),
            quadratic(vec![], vec![(lit(1), m_deleg, sel)]),
        ));
    } else {
        // The recursion format's request writes `a0` exactly what
        // `constants::delegation::a0_after` says: 0 for a base type, and for a
        // recursion type the base it read, `a0`'s `rs2` read, advanced past
        // its frame (`docs/spec/recursion.md` §1.4). Pinned either way, so the
        // zeroing's point — a request writes no value of its own choosing —
        // stands.
        let mut linear = Vec::new();
        let mut products = Vec::new();
        for (i, (.., words)) in delegations.iter().enumerate() {
            products.push((lit(1), is_deleg[i], sel));
            if i >= BASE_TYPES {
                products.push((neg(1), is_deleg[i], v_rs2));
                linear.push((neg(4 * *words as u64), is_deleg[i]));
            }
        }
        enforcing.push(("deleg_a0_rule".into(), quadratic(linear, products)));
    }
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
        for (i, (.., tag, _)) in delegations.iter().enumerate() {
            terms.push((neg(*tag as u64), is_deleg[i]));
        }
        GateDef::Linear {
            terms,
            constant: lit(0),
        }
    }));
    enforcing.push(("wrap_boolean".into(), booleanity(wrap)));
    enforcing.push(("pc_wrap_boolean".into(), booleanity(pc_wrap)));
    // next_pc + 2^32·pc_wrap = decoded_next_pc, or HALT_PC on the exit row.
    // A delegation request is not an exit: its next_pc is the fall-through,
    // so `is_exit = is_ecall - is_keccak` is what carries the sentinel.
    enforcing.push(("next_pc_rule".into(), {
        let mut linear = vec![
            (lit(1), next_pc),
            (Coeff::Literal(two_32()), pc_wrap),
            (neg(1), DECODED_NEXT_PC),
            (neg(mem::HALT_PC as u64), IS_ECALL),
        ];
        let mut products = vec![(lit(1), IS_ECALL, DECODED_NEXT_PC)];
        for &is_t in &is_deleg {
            linear.push((lit(mem::HALT_PC as u64), is_t));
            products.push((neg(1), is_t, DECODED_NEXT_PC));
        }
        quadratic(linear, products)
    }));

    let mut decode = vec![column(pc)];
    decode.extend(DECODED.iter().map(|x| column(*x)));
    let lookups = vec![
        range16("rd_hi_range", column(rd_hi)),
        range16("rd_lo_range", low_half(sel, rd_hi)),
        range16("next_pc_hi_range", column(next_pc_hi)),
        range16("next_pc_lo_range", low_half(next_pc, next_pc_hi)),
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
            channels: channels_at(types),
        },
    );
    // Every obligation is built above and then handed over, so a count is
    // what shows none was dropped on the way (S14 must-be-exact 5, S15's
    // per-channel form).
    for (channel, want) in [
        (lookup_channel::TIMESTAMP, 2 * QUERIES.len()),
        (lookup_channel::RANGE16, 4),
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
    channels_at(BASE_TYPES)
}

/// [`recursion_artifact`]'s channels: [`channels`] with the multiplicities
/// past every type's selector.
pub fn recursion_channels() -> Vec<ChannelSpec> {
    channels_at(TYPES)
}

fn channels_at(types: usize) -> Vec<ChannelSpec> {
    let multiplicities = multiplicities(types);
    vec![
        ChannelSpec {
            channel: lookup_channel::TIMESTAMP,
            table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
            multiplicity: multiplicities[0],
        },
        ChannelSpec {
            channel: lookup_channel::RANGE16,
            table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
            multiplicity: multiplicities[1],
        },
        ChannelSpec {
            channel: lookup_channel::DECODER,
            table: (0..TABLE_WIDTH as u32).map(PolyAddress::Setup).collect(),
            multiplicity: multiplicities[2],
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
